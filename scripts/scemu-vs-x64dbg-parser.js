const fs = require('fs')
const csv = require('csv-parser')

const readCsv = async (filename) => {
  const lines = []
  await new Promise((resolve, reject) => {
    fs.createReadStream(filename)
      .pipe(csv())
      .on('data', (data) => lines.push(data))
      .on('error', reject)
      .on('end', resolve)
  })
  return lines
}

const parseX64DbgRegisterChanges = (input) => {
  if (!input) {
    return []
  }
  const pattern = /([a-z0-9]+: [0-9a-fA-F]+-> [0-9a-fA-F]+)/g
  const matchResults = input.match(pattern)
  if (!matchResults) {
    throw new Error(`Failed to match: ${input}`)
  }
  const registerChanges = matchResults.map(matchResult => {
    const pattern = /([a-z0-9]+): ([0-9a-fA-F]+)-> ([0-9a-fA-F]+)/
    const result = matchResult.match(pattern)
    return {
      registerName: result[1],
      previousValue: BigInt(`0x${result[2]}`).toString(16),
      newValue: BigInt(`0x${result[3]}`).toString(16)
    }
  }).filter(registerChange => {
    // filter out 0th instruction setting the instructions to their own values?
    return registerChange.previousValue !== registerChange.newValue
  })
  registerChanges.sort((a, b) => {
    if (a.registerName < b.registerName) {
      return -1
    } else if (a.registerName > b.registerName) {
      return 1
    }
    return 0
  })
  return registerChanges
}

const parseX64DbgMemoryChanges = (input) => {
  if (!input) {
    return []
  }
  const memoryPattern = /([A-Z0-9]+): ([A-Z0-9]+)-> ([A-Z0-9]+)/g
  const groups = Array.from(input.matchAll(memoryPattern))
  const results = []
  for (let i = 0; i < groups.length; ++i) {
    const group = groups[i]
    const address = BigInt(`0x${group[1]}`).toString(16)
    const previousValue = BigInt(`0x${group[2]}`).toString(16)
    const newValue = BigInt(`0x${group[3]}`).toString(16)
    results.push({
      address,
      previousValue,
      newValue
    })
  }
  return results
}

const parseScemuMemoryChanges = (memTraceLines) => {
  if (memTraceLines.length === 0) {
    return []
  }
  return memTraceLines.map(memTraceLine => {
    return {
      address: memTraceLine.address,
      previousValue: 0, // TODO
      newValue: memTraceLine.value
    }
  })
}

const run = async () => {
  const x64dbgLines = (await readCsv('./scripts/x64dbg-2022-09-19.csv'))
    .map(line => {
      const registerChanges = parseX64DbgRegisterChanges(line.Registers)
      const memoryChanges = parseX64DbgMemoryChanges(line.Memory)
      return {
        rawLine: line,
        rip: parseInt(line.Address, 16).toString(16),
        registerChanges,
        memoryChanges
      }
    })
  const memTraceLinePattern = /mem_trace: pos = ([0-9a-fA-F]+) rip = ([0-9a-fA-F]+) op = ([a-z]+) bits = ([0-9]+) address = 0x([0-9a-fA-F]+) value = 0x([0-9a-fA-F]+) name = '.*'/
  const diffRegLinePattern = /diff_reg: pos = ([0-9a-fA-F]+) rip = ([0-9a-fA-F]+)/
  const changesPattern = /([a-z0-9]+) ([0-9a-fA-F]+) -> ([0-9a-fA-F]+);/g
  const scemuInput = fs.readFileSync('./scripts/scemu-output.txt').toString()
  const scemuSplitInput = scemuInput.split('\n')
  const scemuSplitInputTrimmed = scemuSplitInput.map(line => line.trim())
  const scemuDiffRegLines = scemuSplitInputTrimmed.filter(line => line.indexOf('diff_reg') !== -1)
  const scemuMemTraceLines = scemuSplitInputTrimmed.filter(line => line.indexOf('mem_trace') !== -1)
  const mappedScemuMemTraceLines = scemuMemTraceLines
    .map(memTraceLine => {
      const lineMatchResults = memTraceLine.match(memTraceLinePattern)
      if (!lineMatchResults) {
        throw new Error(`Failed to match: ${memTraceLine}`)
      }
      const position = parseInt(lineMatchResults[1], 10).toString(16)
      const rip = parseInt(lineMatchResults[2], 16).toString(16)
      const operation = lineMatchResults[3]
      const bits = parseInt(lineMatchResults[4], 10).toString(16)
      const address = BigInt(`0x${lineMatchResults[5]}`).toString(16)
      const value = BigInt(`0x${lineMatchResults[6]}`).toString(16)
      return {
        position,
        rip,
        operation,
        bits,
        address,
        value
      }
    })
    .filter(mappedMemTraceLine => mappedMemTraceLine.operation === 'write') // filter out reads
  const scemuLines = scemuDiffRegLines
    .map(diffRegLine => {
      const lineMatchResults = diffRegLine.match(diffRegLinePattern)
      if (!lineMatchResults) {
        throw new Error(`Failed to match: ${diffRegLine}`)
      }
      const position = parseInt(lineMatchResults[1], 10).toString(16)
      const rip = parseInt(lineMatchResults[2], 16).toString(16)
      const memTraceLines = mappedScemuMemTraceLines.filter(mappedScemuMemTraceLine => mappedScemuMemTraceLine.position === position && mappedScemuMemTraceLine.rip === mappedScemuMemTraceLine.rip)
      const registerChangesMatchGroups = Array.from(diffRegLine.matchAll(changesPattern))
      if (!registerChangesMatchGroups || registerChangesMatchGroups.length === 0) {
        return {
          rawLine: {
            diffRegLine,
            memTraceLines
          },
          position,
          rip,
          registerChanges: [],
          memoryChanges: parseScemuMemoryChanges(memTraceLines)
        }
      }
      const registerChanges = []
      for (let i = 0; i < registerChangesMatchGroups.length; ++i) {
        const registerChangesMatchGroup = registerChangesMatchGroups[i]
        for (let x = 1; x < registerChangesMatchGroup.length; x += 3) {
          registerChanges.push({
            registerName: registerChangesMatchGroup[x],
            previousValue: BigInt(`0x${registerChangesMatchGroup[x + 1]}`).toString(16),
            newValue: BigInt(`0x${registerChangesMatchGroup[x + 2]}`).toString(16),
          })
        }
      }
      registerChanges.sort((a, b) => {
        if (a.registerName < b.registerName) {
          return -1
        } else if (a.registerName > b.registerName) {
          return 1
        }
        return 0
      })
      return {
        rawLine: {
          diffRegLine,
          memTraceLines
        },
        position,
        rip,
        registerChanges,
        memoryChanges: parseScemuMemoryChanges(memTraceLines)
      }
    })
  const errors = []
  for (let i = 0; i < x64dbgLines.length; ++i) {
    const x64dbgLine = x64dbgLines[i]
    const scemuLine = scemuLines[i]
    if (!scemuLine) {
      fs.writeFileSync('./scripts/scemu-errors.json', JSON.stringify(errors, undefined, 2))
      throw new Error(`scemu exited before ${x64dbgLine.rip}`)
    }
    const instructionErrors = []
    // rip mismatch
    if (x64dbgLine.rip !== scemuLine.rip) {
      instructionErrors.push({
        message: 'rip mismatch'
      })
      errors.push({
        i,
        iHex: i.toString(16),
        x64dbgLine,
        scemuLine,
        instructionErrors
      })
      fs.writeFileSync('./scripts/scemu-errors.json', JSON.stringify(errors, undefined, 2))
      throw new Error('rip mismatch')
    }
    // register change mismatches (x64dbg)
    for (let x = 0; x < x64dbgLine.registerChanges.length; ++x) {
      const x64dbgRegisterChange = x64dbgLine.registerChanges[x]
      const scemuRegisterChange = scemuLine.registerChanges.find(scemuRegisterChange => scemuRegisterChange.registerName === x64dbgRegisterChange.registerName)
      if (scemuRegisterChange) {
        if (x64dbgRegisterChange.previousValue !== scemuRegisterChange.previousValue) {
          instructionErrors.push({
            index: x,
            message: 'previousValue mismatch',
            x64dbg: x64dbgRegisterChange.previousValue,
            scemu: scemuRegisterChange.previousValue
          })
        }
        if (x64dbgRegisterChange.newValue !== scemuRegisterChange.newValue) {
          instructionErrors.push({
            index: x,
            message: 'newValue mismatch',
            x64dbg: x64dbgRegisterChange.newValue,
            scemu: scemuRegisterChange.newValue
          })
        }
      } else {
        instructionErrors.push({
          index: x,
          message: 'unmatchedRegisterChange mismatch (x64dbg but not scemu)',
          x64dbg: x64dbgRegisterChange.registerName
        })
      }
    }
    // register change mismatches (scemu)
    for (let x = 0; x < scemuLine.registerChanges.length; ++x) {
      const scemuRegisterChange = scemuLine.registerChanges[x]
      const x64dbgRegisterChange = x64dbgLine.registerChanges.find(x64dbgRegisterChange => scemuRegisterChange.registerName === x64dbgRegisterChange.registerName)
      if (!x64dbgRegisterChange) {
        instructionErrors.push({
          index: x,
          message: 'unmatchedRegisterChange mismatch (scemu but not x64dbg)',
          scemu: scemuRegisterChange.registerName
        })
      }
    }
    // memory change mismatches (x64dbg)
    for (let x = 0; x < x64dbgLine.memoryChanges.length; ++x) {
      const x64dbgMemoryChange = x64dbgLine.memoryChanges[x]
      const scemuMemoryChange = scemuLine.memoryChanges.find(scemuMemoryChange => scemuMemoryChange.address === x64dbgMemoryChange.address)
      if (scemuMemoryChange) {
        if (x64dbgMemoryChange.previousValue !== scemuMemoryChange.previousValue) {
          instructionErrors.push({
            index: x,
            message: 'previousValue mismatch',
            x64dbg: x64dbgMemoryChange.previousValue,
            scemu: scemuMemoryChange.previousValue
          })
        }
        if (x64dbgMemoryChange.newValue !== scemuMemoryChange.newValue) {
          instructionErrors.push({
            index: x,
            message: 'newValue mismatch',
            x64dbg: x64dbgMemoryChange.newValue,
            scemu: scemuMemoryChange.newValue
          })
        }
      } else {
        instructionErrors.push({
          index: x,
          message: 'unmatchedMemoryChange mismatch (x64dbg but not scemu)',
          x64dbg: x64dbgMemoryChange.address
        })
      }
    }
    // memory change mismatches (scemu)
    for (let x = 0; x < scemuLine.memoryChanges.length; ++x) {
      const scemuMemoryChange = scemuLine.memoryChanges[x]
      const x64dbgMemoryChange = x64dbgLine.memoryChanges.find(x64dbgMemoryChange => scemuMemoryChange.address === x64dbgMemoryChange.address)
      if (!x64dbgMemoryChange) {
        instructionErrors.push({
          index: x,
          message: 'unmatchedMemoryChange mismatch (scemu but not x64dbg)',
          scemu: scemuMemoryChange.address
        })
      }
    }
    if (instructionErrors.length > 0) {
      errors.push({
        i,
        iHex: i.toString(16),
        x64dbgLine,
        scemuLine,
        instructionErrors
      })
    }
  }
}

run()
