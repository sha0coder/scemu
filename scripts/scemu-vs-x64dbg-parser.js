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
  // TODO: parse more
  return [
    input
  ]
}

const run = async () => {
  const x64dbgLines = (await readCsv('/Users/brandonros/Desktop/scemu/scripts/x64dbg-2022-09-19.csv'))
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
  const linePattern = /diff_reg: rip = ([0-9a-fA-F]+)/
  const changesPattern = /([a-z0-9]+) ([0-9a-fA-F]+) -> ([0-9a-fA-F]+);/g
  const scemuLines = fs.readFileSync('/Users/brandonros/Desktop/scemu/scripts/scemu-output.txt').toString()
    .split('\n')
    .map(line => line.trim())
    .filter(line => line.indexOf('diff_reg') !== -1)
    .map(line => {
      const lineMatchResults = line.match(linePattern)
      if (!lineMatchResults) {
        throw new Error(`Failed to match: ${line}`)
      }
      const rip = parseInt(lineMatchResults[1], 16).toString(16)
      const registerChangesMatchGroups = Array.from(line.matchAll(changesPattern))
      if (!registerChangesMatchGroups || registerChangesMatchGroups.length === 0) {
        return {
          rawLine: line,
          rip,
          registerChanges: [],
          memoryChanges: [] // TODO
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
        rawLine: line,
        rip,
        registerChanges,
        memoryChanges: [
          // TODO
        ]
      }
    })
  const errors = []
  for (let i = 0; i < x64dbgLines.length; ++i) {
    const x64dbgLine = x64dbgLines[i]
    const scemuLine = scemuLines[i]
    if (!scemuLine) {
      fs.writeFileSync('/Users/brandonros/Desktop/scemu/scripts/scemu-errors.json', JSON.stringify(errors, undefined, 2))
      throw new Error(`x64dbg exited before ${x64dbgLine.rip}`)
    }
    const instructionErrors = []
    // rip mismatch
    if (x64dbgLine.rip !== scemuLine.rip) {
      instructionErrors.push({
        message: 'rip mismatch'
      })
      errors.push({
        i,
        x64dbgLine,
        scemuLine,
        instructionErrors
      })
      fs.writeFileSync('/Users/brandonros/Desktop/scemu/scripts/scemu-errors.json', JSON.stringify(errors, undefined, 2))
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
      if (x64dbgRegisterChange) {
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
          message: 'unmatchedRegisterChange mismatch (scemu but not x64dbg)',
          scemu: scemuRegisterChange.registerName
        })
      }
    }
    if (instructionErrors.length > 0) {
      errors.push({
        i,
        x64dbgLine,
        scemuLine,
        instructionErrors
      })
    }
  }
}

run()
