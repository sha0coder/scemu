// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55
#![allow(dead_code)]
//pub const LIB64_BARRIER: u64 = 0x07fefff00000;
//pub const LIB32_BARRIER: u32 = 0x7f000000;

//pub const LIBS32_BARRIER: u64 = 0x80000000;
//pub const LIBS64_BARRIER: u64 = 0x7f0000000000;

pub const LIBS32_MIN: u64 = 0x70000000;
pub const LIBS32_MAX: u64 = 0x7FFFFFFF;
pub const LIBS64_MIN: u64 = 0x7FF000000000;
pub const LIBS64_MAX: u64 = 0x7FFFFFFFFFFF;

pub const STATUS_SUCCESS: u64 = 0x00000000;
pub const STATUS_ACCESS_DENIED: u64 = 0xC0000022;
pub const STATUS_INVALID_HANDLE: u64 = 0xC0000008;
pub const STATUS_NO_MEMORY: u64 = 0xC0000017;
pub const STATUS_ACCESS_VIOLATION: u64 = 0xC0000005;
pub const STATUS_INVALID_PARAMETER: u64 = 0xC000000D;

pub const ERROR_SUCCESS: u64 = 0;
pub const ERROR_INVALID_PARAMETER: u64 = 0x57;
pub const ERROR_INSUFFICIENT_BUFFER: u64 = 122;

pub const CP_UTF7: u64 = 65000;
pub const CP_UTF8: u64 = 65001;

pub const NUM_BYTES_TRACE: usize = 16;
pub const VERSION: u64 = 0x1db10106;

pub const WAIT_TIMEOUT: u64 = 0x00000102;
pub const WAIT_FAILED: u64 = 0xFFFFFFFF;

//vectored exception handler
pub const CALL_FIRST: u32 = 1;
pub const CALL_LAST: u32 = 0;

pub const GENERIC_READ: u32 = 0x80000000;
pub const GENERIC_WRITE: u32 = 0x40000000;

pub const INVALID_HANDLE_VALUE_64: u64 = 0xFFFFFFFFFFFFFFFF;
pub const INVALID_HANDLE_VALUE_32: u64 = 0xFFFFFFFF;

pub const RETURN_THREAD: u32 = 0x11223344;
pub const LIBS_BARRIER: u64 = 0x60000000;
pub const LIBS_BARRIER64: u64 = 0x60000000;
// ntdll: 0x76dc7070

pub const INTERNET_OPTION_ALTER_IDENTITY: u32 = 80;
pub const INTERNET_OPTION_ASYNC: u32 = 30;
pub const INTERNET_OPTION_ASYNC_ID: u32 = 15;
pub const INTERNET_OPTION_ASYNC_PRIORITY: u32 = 16;
pub const INTERNET_OPTION_BYPASS_EDITED_ENTRY: u32 = 64;
pub const INTERNET_OPTION_CACHE_STREAM_HANDLE: u32 = 27;
pub const INTERNET_OPTION_CACHE_TIMESTAMPS: u32 = 69;
pub const INTERNET_OPTION_CALLBACK: u32 = 1;
pub const INTERNET_OPTION_CALLBACK_FILTER: u32 = 54;
pub const INTERNET_OPTION_CLIENT_CERT_CONTEXT: u32 = 84;
pub const INTERNET_OPTION_CODEPAGE: u32 = 68;
pub const INTERNET_OPTION_CODEPAGE_PATH: u32 = 100;
pub const INTERNET_OPTION_CODEPAGE_EXTRA: u32 = 101;
pub const INTERNET_OPTION_COMPRESSED_CONTENT_LENGTH: u32 = 147;
pub const INTERNET_OPTION_CONNECT_BACKOFF: u32 = 4;
pub const INTERNET_OPTION_CONNECT_RETRIES: u32 = 3;
pub const INTERNET_OPTION_CONNECT_TIME: u32 = 55;
pub const INTERNET_OPTION_CONNECT_TIMEOUT: u32 = 2;
pub const INTERNET_OPTION_CONNECTED_STATE: u32 = 50;
pub const INTERNET_OPTION_CONTEXT_VALUE: u32 = 45;
pub const INTERNET_OPTION_CONTROL_RECEIVE_TIMEOUT: u32 = 6;
pub const INTERNET_OPTION_CONTROL_SEND_TIMEOUT: u32 = 5;
pub const INTERNET_OPTION_DATA_RECEIVE_TIMEOUT: u32 = 8;
pub const INTERNET_OPTION_DATA_SEND_TIMEOUT: u32 = 7;

// https://docs.microsoft.com/en-us/windows/win32/wininet/api-flags
pub const INTERNET_FLAG_SECURE: u64 = 0x00800000;

pub const ERROR_NO_MORE_FILES: u64 = 18;
pub const CREATE_SUSPENDED: u64 = 0x00000004;
pub const EXCEPTION_EXECUTE_HANDLER: u64 = 1;

pub const PAGE_NOACCESS: u32 = 0x01;
pub const PAGE_EXECUTE: u32 = 0x00;
pub const PAGE_READONLY: u32 = 0x02;
pub const PAGE_READWRITE: u32 = 0x04;
pub const PAGE_GUARD: u32 = 0x100;
pub const PAGE_NOCACHE: u32 = 0x200;
pub const PAGE_WRITECOMBINE: u32 = 0x400;
pub const MEM_COMMIT: u32 = 0x1000;
pub const MEM_FREE: u32 = 0x10000;
pub const MEM_RESERVE: u32 = 0x2000;
pub const MEM_IMAGE: u32 = 0x1000000;
pub const MEM_MAPPED: u32 = 0x40000;
pub const MEM_PRIVATE: u32 = 0x20000;

// CryptAquireContext Flags
pub const CRYPT_VERIFYCONTEXT: u32 = 0xF0000000;
pub const CRYPT_NEWKEYSET: u32 = 0x00000008;
pub const CRYPT_DELETEKEYSET: u32 = 0x00000010;
pub const CRYPT_MACHINE_KEYSET: u32 = 0x00000020;
pub const CRYPT_SILENT: u32 = 0x00000040;
pub const CRYPT_DEFAULT_CONTAINER_OPTIONAL: u32 = 0x00000080;

// TLS Callback Reason:
pub const DLL_PROCESS_ATTACH: u32 = 1;
pub const DLL_PROCESS_DETACH: u32 = 0;
pub const DLL_THREAD_ATTACH: u32 = 2;
pub const DLL_THREAD_DETACH: u32 = 3;

// processorFeaturePresent
pub const PF_ARM_64BIT_LOADSTORE_ATOMIC: u32 = 25;
pub const PF_ARM_DIVIDE_INSTRUCTION_AVAILABLE: u32 = 24;
pub const PF_ARM_EXTERNAL_CACHE_AVAILABLE: u32 = 26;
pub const PF_ARM_FMAC_INSTRUCTIONS_AVAILABLE: u32 = 27;
pub const PF_ARM_VFP_32_REGISTERS_AVAILABLE: u32 = 18;
pub const PF_3DNOW_INSTRUCTIONS_AVAILABLE: u32 = 7;
pub const PF_CHANNELS_ENABLED: u32 = 16;
pub const PF_COMPARE_EXCHANGE_DOUBLE: u32 = 2;
pub const PF_COMPARE_EXCHANGE128: u32 = 14;
pub const PF_COMPARE64_EXCHANGE128: u32 = 15;
pub const PF_FASTFAIL_AVAILABLE: u32 = 23;
pub const PF_FLOATING_POINT_EMULATED: u32 = 1;
pub const PF_FLOATING_POINT_PRECISION_ERRATA: u32 = 0;
pub const PF_MMX_INSTRUCTIONS_AVAILABLE: u32 = 3;
pub const PF_NX_ENABLED: u32 = 12;
pub const PF_PAE_ENABLED: u32 = 9;
pub const PF_RDTSC_INSTRUCTION_AVAILABLE: u32 = 8;
pub const PF_RDWRFSGSBASE_AVAILABLE: u32 = 22;
pub const PF_SECOND_LEVEL_ADDRESS_TRANSLATION: u32 = 20;
pub const PF_SSE3_INSTRUCTIONS_AVAILABLE: u32 = 13;
pub const PF_SSSE3_INSTRUCTIONS_AVAILABLE: u32 = 36;
pub const PF_SSE4_1_INSTRUCTIONS_AVAILABLE: u32 = 37;
pub const PF_SSE4_2_INSTRUCTIONS_AVAILABLE: u32 = 38;
pub const PF_AVX_INSTRUCTIONS_AVAILABLE: u32 = 39;
pub const PF_AVX2_INSTRUCTIONS_AVAILABLE: u32 = 40;
pub const PF_AVX512F_INSTRUCTIONS_AVAILABLE: u32 = 41;
pub const PF_VIRT_FIRMWARE_ENABLED: u32 = 21;
pub const PF_XMMI_INSTRUCTIONS_AVAILABLE: u32 = 6;
pub const PF_XMMI64_INSTRUCTIONS_AVAILABLE: u32 = 10;
pub const PF_XSAVE_ENABLED: u32 = 17;
pub const PF_ARM_V8_INSTRUCTIONS_AVAILABLE: u32 = 29;
pub const PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE: u32 = 30;
pub const PF_ARM_V8_CRC32_INSTRUCTIONS_AVAILABLE: u32 = 31;
pub const PF_ARM_V81_ATOMIC_INSTRUCTIONS_AVAILABLE: u32 = 34;

pub const EN_US_LOCALE: u32 = 0x0409;

// Crypto Algorithms
pub const CALG_3DES: u32 = 0x00006603;
pub const CALG_3DES_112: u32 = 0x00006609;
pub const CALG_AES: u32 = 0x00006611;
pub const CALG_AES_128: u32 = 0x0000660e;
pub const CALG_AES_192: u32 = 0x0000660f;
pub const CALG_AES_256: u32 = 0x00006610;
pub const CALG_AGREEDKEY_ANY: u32 = 0x0000aa03;
pub const CALG_CYLINK_MEK: u32 = 0x0000660c;
pub const CALG_DES: u32 = 0x00006601;
pub const CALG_DESX: u32 = 0x00006604;
pub const CALG_DH_EPHEM: u32 = 0x0000aa02;
pub const CALG_DH_SF: u32 = 0x0000aa01;
pub const CALG_DSS_SIGN: u32 = 0x00002200;
pub const CALG_ECDH: u32 = 0x0000aa05;
pub const CALG_ECDH_EPHEM: u32 = 0x0000ae06;
pub const CALG_ECDSA: u32 = 0x00002203;
pub const CALG_ECMQV: u32 = 0x0000a001;
pub const CALG_HASH_REPLACE_OWF: u32 = 0x0000800b;
pub const CALG_HUGHES_MD5: u32 = 0x0000a003;
pub const CALG_HMAC: u32 = 0x00008009;
pub const CALG_KEA_KEYX: u32 = 0x0000aa04;
pub const CALG_MAC: u32 = 0x00008005;
pub const CALG_MD2: u32 = 0x00008001;
pub const CALG_MD4: u32 = 0x00008002;
pub const CALG_MD5: u32 = 0x00008003;
pub const CALG_NO_SIGN: u32 = 0x00002000;
pub const CALG_OID_INFO_CNG_ONLY: u32 = 0xffffffff;
pub const CALG_OID_INFO_PARAMETERS: u32 = 0xfffffffe;
pub const CALG_PCT1_MASTER: u32 = 0x00004c04;
pub const CALG_RC2: u32 = 0x00006602;
pub const CALG_RC4: u32 = 0x00006801;
pub const CALG_RC5: u32 = 0x0000660d;
pub const CALG_RSA_KEYX: u32 = 0x0000a400;
pub const CALG_RSA_SIGN: u32 = 0x00002400;
pub const CALG_SCHANNEL_ENC_KEY: u32 = 0x00004c07;
pub const CALG_SCHANNEL_MAC_KEY: u32 = 0x00004c03;
pub const CALG_SCHANNEL_MASTER_HASH: u32 = 0x00004c02;
pub const CALG_SEAL: u32 = 0x00006802;
pub const CALG_SHA: u32 = 0x00008004;
pub const CALG_SHA1: u32 = 0x00008004;
pub const CALG_SHA_256: u32 = 0x0000800c;
pub const CALG_SHA_384: u32 = 0x0000800d;
pub const CALG_SHA_512: u32 = 0x0000800e;
pub const CALG_SKIPJACK: u32 = 0x0000660a;
pub const CALG_SSL2_MASTER: u32 = 0x00004c05;
pub const CALG_SSL3_MASTER: u32 = 0x00004c01;
pub const CALG_SSL3_SHAMD5: u32 = 0x00008008;
pub const CALG_TEK: u32 = 0x0000660b;
pub const CALG_TLS1_MASTER: u32 = 0x00004c06;
pub const CALG_TLS1PRF: u32 = 0x0000800a;

pub fn get_cryptoalgorithm_name(value: u32) -> &'static str {
    match value {
        0x00006603 => "CALG_3DES",
        0x00006609 => "CALG_3DES_112",
        0x00006611 => "CALG_AES",
        0x0000660e => "CALG_AES_128",
        0x0000660f => "CALG_AES_192",
        0x00006610 => "CALG_AES_256",
        0x0000aa03 => "CALG_AGREEDKEY_ANY",
        0x0000660c => "CALG_CYLINK_MEK",
        0x00006601 => "CALG_DES",
        0x00006604 => "CALG_DESX",
        0x0000aa02 => "CALG_DH_EPHEM",
        0x0000aa01 => "CALG_DH_SF",
        0x00002200 => "CALG_DSS_SIGN",
        0x0000aa05 => "CALG_ECDH",
        0x0000ae06 => "CALG_ECDH_EPHEM",
        0x00002203 => "CALG_ECDSA",
        0x0000a001 => "CALG_ECMQV",
        0x0000800b => "CALG_HASH_REPLACE_OWF",
        0x0000a003 => "CALG_HUGHES_MD5",
        0x00008009 => "CALG_HMAC",
        0x0000aa04 => "CALG_KEA_KEYX",
        0x00008005 => "CALG_MAC",
        0x00008001 => "CALG_MD2",
        0x00008002 => "CALG_MD4",
        0x00008003 => "CALG_MD5",
        0x00002000 => "CALG_NO_SIGN",
        0xffffffff => "CALG_OID_INFO_CNG_ONLY",
        0xfffffffe => "CALG_OID_INFO_PARAMETERS",
        0x00004c04 => "CALG_PCT1_MASTER",
        0x00006602 => "CALG_RC2",
        0x00006801 => "CALG_RC4",
        0x0000660d => "CALG_RC5",
        0x0000a400 => "CALG_RSA_KEYX",
        0x00002400 => "CALG_RSA_SIGN",
        0x00004c07 => "CALG_SCHANNEL_ENC_KEY",
        0x00004c03 => "CALG_SCHANNEL_MAC_KEY",
        0x00004c02 => "CALG_SCHANNEL_MASTER_HASH",
        0x00006802 => "CALG_SEAL",
        0x00008004 => "CALG_SHA",
        0x0000800c => "CALG_SHA_256",
        0x0000800d => "CALG_SHA_384",
        0x0000800e => "CALG_SHA_512",
        0x0000660a => "CALG_SKIPJACK",
        0x00004c05 => "CALG_SSL2_MASTER",
        0x00004c01 => "CALG_SSL3_MASTER",
        0x00008008 => "CALG_SSL3_SHAMD5",
        0x0000660b => "CALG_TEK",
        0x00004c06 => "CALG_TLS1_MASTER",
        0x0000800a => "CALG_TLS1PRF",
        _ => "Unknown Algorithm",
    }
}

pub fn get_crypto_key_len(value: u32) -> usize {
    match value {
        0x00006603 => 24, // CALG_3DES
        0x00006609 => 14, // CALG_3DES_112
        0x00006611 => 0,  // CALG_AES, variable: 128, 192, or 256 bits (set dynamically)
        0x0000660e => 16, // CALG_AES_128
        0x0000660f => 24, // CALG_AES_192
        0x00006610 => 32, // CALG_AES_256
        0x0000aa03 => 0,  // CALG_AGREEDKEY_ANY, variable
        0x0000660c => 0,  // CALG_CYLINK_MEK, variable
        0x00006601 => 8,  // CALG_DES
        0x00006604 => 8,  // CALG_DESX
        0x0000aa02 => 0,  // CALG_DH_EPHEM, variable
        0x0000aa01 => 0,  // CALG_DH_SF, variable
        0x00002200 => 0,  // CALG_DSS_SIGN, variable
        0x0000aa05 => 0,  // CALG_ECDH, variable
        0x0000ae06 => 0,  // CALG_ECDH_EPHEM, variable
        0x00002203 => 0,  // CALG_ECDSA, variable
        0x0000a001 => 0,  // CALG_ECMQV, variable
        0x0000800b => 0,  // CALG_HASH_REPLACE_OWF, variable
        0x0000a003 => 0,  // CALG_HUGHES_MD5, variable
        0x00008009 => 0,  // CALG_HMAC, variable
        0x0000aa04 => 0,  // CALG_KEA_KEYX, variable
        0x00008005 => 0,  // CALG_MAC, variable
        0x00008001 => 0,  // CALG_MD2, variable
        0x00008002 => 0,  // CALG_MD4, variable
        0x00008003 => 0,  // CALG_MD5, variable
        0x00002000 => 0,  // CALG_NO_SIGN, variable
        0xffffffff => 0,  // CALG_OID_INFO_CNG_ONLY, variable
        0xfffffffe => 0,  // CALG_OID_INFO_PARAMETERS, variable
        0x00004c04 => 0,  // CALG_PCT1_MASTER, variable
        0x00006602 => 8,  // CALG_RC2
        0x00006801 => 0,  // CALG_RC4, variable length
        0x0000660d => 0,  // CALG_RC5, variable
        0x0000a400 => 0,  // CALG_RSA_KEYX, variable
        0x00002400 => 0,  // CALG_RSA_SIGN, variable
        0x00004c07 => 0,  // CALG_SCHANNEL_ENC_KEY, variable
        0x00004c03 => 0,  // CALG_SCHANNEL_MAC_KEY, variable
        0x00004c02 => 0,  // CALG_SCHANNEL_MASTER_HASH, variable
        0x00006802 => 0,  // CALG_SEAL, variable
        0x00008004 => 0,  // CALG_SHA, variable
        0x0000800c => 0,  // CALG_SHA_256, variable
        0x0000800d => 0,  // CALG_SHA_384, variable
        0x0000800e => 0,  // CALG_SHA_512, variable
        0x0000660a => 0,  // CALG_SKIPJACK, variable
        0x00004c05 => 0,  // CALG_SSL2_MASTER, variable
        0x00004c01 => 0,  // CALG_SSL3_MASTER, variable
        0x00008008 => 0,  // CALG_SSL3_SHAMD5, variable
        0x0000660b => 0,  // CALG_TEK, variable
        0x00004c06 => 0,  // CALG_TLS1_MASTER, variable
        0x0000800a => 0,  // CALG_TLS1PRF, variable
        _ => 0,           // Unknown Algorithm or variable length
    }
}

/// LINUX ////

// elf
pub const PT_LOAD: u32 = 1;

// linux errors
pub const ENOTSOCK: u64 = -1i64 as u64; /* not open sock */
pub const EPERM: u64 = -1i64 as u64; /* permissions error */
pub const ENOENT: u64 = -2i64 as u64; /* No such file or directory */
pub const ESRCH: u64 = -3i64 as u64; /* No such process */
pub const EINTR: u64 = -4i64 as u64; /* Interrupted system call */
pub const EIO: u64 = -5i64 as u64; /* I/O error */
pub const ENXIO: u64 = -6i64 as u64; /* No such device or address */
pub const E2BIG: u64 = -7i64 as u64; /* Argument list too long */
pub const ENOEXEC: u64 = -8i64 as u64; /* Exec format error */
pub const EBADF: u64 = -9i64 as u64; /* Bad file number */
pub const ECHILD: u64 = -10i64 as u64; /* No child processes */
pub const EAGAIN: u64 = -11i64 as u64; /* Try again */
pub const ENOMEM: u64 = -12i64 as u64; /* Out of memory */
pub const EACCES: u64 = -13i64 as u64; /* Permission denied */
pub const EFAULT: u64 = -14i64 as u64; /* Bad address */
pub const ENOTBLK: u64 = -15i64 as u64; /* Block device required */
pub const EBUSY: u64 = -16i64 as u64; /* Device or resource busy */
pub const EEXIST: u64 = -17i64 as u64; /* File exists */
pub const EXDEV: u64 = -18i64 as u64; /* Cross-device link */
pub const ENODEV: u64 = -19i64 as u64; /* No such device */
pub const ENOTDIR: u64 = -20i64 as u64; /* Not a directory */
pub const EISDIR: u64 = -21i64 as u64; /* Is a directory */
pub const EINVAL: u64 = -22i64 as u64; /* Invalid argument */
pub const ENFILE: u64 = -23i64 as u64; /* File table overflow */
pub const EMFILE: u64 = -24i64 as u64; /* Too many open files */
pub const ENOTTY: u64 = -25i64 as u64; /* Not a typewriter */
pub const ETXTBSY: u64 = -26i64 as u64; /* Text file busy */
pub const EFBIG: u64 = -27i64 as u64; /* File too large */
pub const ENOSPC: u64 = -28i64 as u64; /* No space left on device */
pub const ESPIPE: u64 = -29i64 as u64; /* Illegal seek */
pub const EROFS: u64 = -30i64 as u64; /* Read-only file system */
pub const EMLINK: u64 = -31i64 as u64; /* Too many links */
pub const EPIPE: u64 = -32i64 as u64; /* Broken pipe */
pub const EDOM: u64 = -33i64 as u64; /* Math argument out of domain of func */
pub const ERANGE: u64 = -34i64 as u64; /* Math result not representable */

// linux socketcall gateway 32bits
pub const SYS_SOCKET: u32 = 1;
pub const SYS_BIND: u32 = 2;
pub const SYS_CONNECT: u32 = 3;
pub const SYS_LISTEN: u32 = 4;
pub const SYS_ACCEPT: u32 = 5;
pub const SYS_GETSOCKNAME: u32 = 6;
pub const SYS_GETPEERNAME: u32 = 7;
pub const SYS_SOCKETPAIR: u32 = 8;
pub const SYS_SEND: u32 = 9;
pub const SYS_RECV: u32 = 10;
pub const SYS_SENDTO: u32 = 11;
pub const SYS_RECVFROM: u32 = 12;
pub const SYS_SHUTDOWN: u32 = 13;
pub const SYS_SETSOCKOPT: u32 = 14;
pub const SYS_GETSOCKOPT: u32 = 15;
pub const SYS_SENDMSG: u32 = 16;
pub const SYS_RECVMSG: u32 = 17;
pub const SYS_ACCEPT4: u32 = 18;
pub const SYS_RECVMMSG: u32 = 19;
pub const SYS_SENDMMSG: u32 = 20;

// linux syscalls u64bits
pub const NR64_READ: u64 = 0;
pub const NR64_WRITE: u64 = 1;
pub const NR64_OPEN: u64 = 2;
pub const NR64_CLOSE: u64 = 3;
pub const NR64_STAT: u64 = 4;
pub const NR64_FSTAT: u64 = 5;
pub const NR64_LSTAT: u64 = 6;
pub const NR64_POLL: u64 = 7;
pub const NR64_LSEEK: u64 = 8;
pub const NR64_MMAP: u64 = 9;
pub const NR64_MPROTECT: u64 = 10;
pub const NR64_MUNMAP: u64 = 11;
pub const NR64_BRK: u64 = 12;
pub const NR64_RT_SIGACTION: u64 = 13;
pub const NR64_RT_SIGPROCMASK: u64 = 14;
pub const NR64_RT_SIGRETURN: u64 = 15;
pub const NR64_IOCTL: u64 = 16;
pub const NR64_PREAD64: u64 = 17;
pub const NR64_PWRITE64: u64 = 18;
pub const NR64_READV: u64 = 19;
pub const NR64_WRITEV: u64 = 20;
pub const NR64_ACCESS: u64 = 21;
pub const NR64_PIPE: u64 = 22;
pub const NR64_SELECT: u64 = 23;
pub const NR64_SCHED_YIELD: u64 = 24;
pub const NR64_MREMAP: u64 = 25;
pub const NR64_MSYNC: u64 = 26;
pub const NR64_MINCORE: u64 = 27;
pub const NR64_MADVISE: u64 = 28;
pub const NR64_SHMGET: u64 = 29;
pub const NR64_SHMAT: u64 = 30;
pub const NR64_SHMCTL: u64 = 31;
pub const NR64_DUP: u64 = 32;
pub const NR64_DUP2: u64 = 33;
pub const NR64_PAUSE: u64 = 34;
pub const NR64_NANOSLEEP: u64 = 35;
pub const NR64_GETITIMER: u64 = 36;
pub const NR64_ALARM: u64 = 37;
pub const NR64_SETITIMER: u64 = 38;
pub const NR64_GETPID: u64 = 39;
pub const NR64_SENDFILE: u64 = 40;
pub const NR64_SOCKET: u64 = 41;
pub const NR64_CONNECT: u64 = 42;
pub const NR64_ACCEPT: u64 = 43;
pub const NR64_SENDTO: u64 = 44;
pub const NR64_RECVFROM: u64 = 45;
pub const NR64_SENDMSG: u64 = 46;
pub const NR64_RECVMSG: u64 = 47;
pub const NR64_SHUTDOWN: u64 = 48;
pub const NR64_BIND: u64 = 49;
pub const NR64_LISTEN: u64 = 50;
pub const NR64_GETSOCKNAME: u64 = 51;
pub const NR64_GETPEERNAME: u64 = 52;
pub const NR64_SOCKETPAIR: u64 = 53;
pub const NR64_SETSOCKOPT: u64 = 54;
pub const NR64_GETSOCKOPT: u64 = 55;
pub const NR64_CLONE: u64 = 56;
pub const NR64_FORK: u64 = 57;
pub const NR64_VFORK: u64 = 58;
pub const NR64_EXECVE: u64 = 59;
pub const NR64_EXIT: u64 = 60;
pub const NR64_WAIT4: u64 = 61;
pub const NR64_KILL: u64 = 62;
pub const NR64_UNAME: u64 = 63;
pub const NR64_SEMGET: u64 = 64;
pub const NR64_SEMOP: u64 = 65;
pub const NR64_SEMCTL: u64 = 66;
pub const NR64_SHMDT: u64 = 67;
pub const NR64_MSGGET: u64 = 68;
pub const NR64_MSGSND: u64 = 69;
pub const NR64_MSGRCV: u64 = 70;
pub const NR64_MSGCTL: u64 = 71;
pub const NR64_FCNTL: u64 = 72;
pub const NR64_FLOCK: u64 = 73;
pub const NR64_FSYNC: u64 = 74;
pub const NR64_FDATASYNC: u64 = 75;
pub const NR64_TRUNCATE: u64 = 76;
pub const NR64_FTRUNCATE: u64 = 77;
pub const NR64_GETDENTS: u64 = 78;
pub const NR64_GETCWD: u64 = 79;
pub const NR64_CHDIR: u64 = 80;
pub const NR64_FCHDIR: u64 = 81;
pub const NR64_RENAME: u64 = 82;
pub const NR64_MKDIR: u64 = 83;
pub const NR64_RMDIR: u64 = 84;
pub const NR64_CREAT: u64 = 85;
pub const NR64_LINK: u64 = 86;
pub const NR64_UNLINK: u64 = 87;
pub const NR64_SYMLINK: u64 = 88;
pub const NR64_READLINK: u64 = 89;
pub const NR64_CHMOD: u64 = 90;
pub const NR64_FCHMOD: u64 = 91;
pub const NR64_CHOWN: u64 = 92;
pub const NR64_FCHOWN: u64 = 93;
pub const NR64_LCHOWN: u64 = 94;
pub const NR64_UMASK: u64 = 95;
pub const NR64_GETTIMEOFDAY: u64 = 96;
pub const NR64_GETRLIMIT: u64 = 97;
pub const NR64_GETRUSAGE: u64 = 98;
pub const NR64_SYSINFO: u64 = 99;
pub const NR64_TIMES: u64 = 100;
pub const NR64_PTRACE: u64 = 101;
pub const NR64_GETUID: u64 = 102;
pub const NR64_SYSLOG: u64 = 103;
pub const NR64_GETGID: u64 = 104;
pub const NR64_SETUID: u64 = 105;
pub const NR64_SETGID: u64 = 106;
pub const NR64_GETEUID: u64 = 107;
pub const NR64_GETEGID: u64 = 108;
pub const NR64_SETPGID: u64 = 109;
pub const NR64_GETPPID: u64 = 110;
pub const NR64_GETPGRP: u64 = 111;
pub const NR64_SETSID: u64 = 112;
pub const NR64_SETREUID: u64 = 113;
pub const NR64_SETREGID: u64 = 114;
pub const NR64_GETGROUPS: u64 = 115;
pub const NR64_SETGROUPS: u64 = 116;
pub const NR64_SETRESUID: u64 = 117;
pub const NR64_GETRESUID: u64 = 118;
pub const NR64_SETRESGID: u64 = 119;
pub const NR64_GETRESGID: u64 = 120;
pub const NR64_GETPGID: u64 = 121;
pub const NR64_SETFSUID: u64 = 122;
pub const NR64_SETFSGID: u64 = 123;
pub const NR64_GETSID: u64 = 124;
pub const NR64_CAPGET: u64 = 125;
pub const NR64_CAPSET: u64 = 126;
pub const NR64_RT_SIGPENDING: u64 = 127;
pub const NR64_RT_SIGTIMEDWAIT: u64 = 128;
pub const NR64_RT_SIGQUEUEINFO: u64 = 129;
pub const NR64_RT_SIGSUSPEND: u64 = 130;
pub const NR64_SIGALTSTACK: u64 = 131;
pub const NR64_UTIME: u64 = 132;
pub const NR64_MKNOD: u64 = 133;
pub const NR64_USELIB: u64 = 134;
pub const NR64_PERSONALITY: u64 = 135;
pub const NR64_USTAT: u64 = 136;
pub const NR64_STATFS: u64 = 137;
pub const NR64_FSTATFS: u64 = 138;
pub const NR64_SYSFS: u64 = 139;
pub const NR64_GETPRIORITY: u64 = 140;
pub const NR64_SETPRIORITY: u64 = 141;
pub const NR64_SCHED_SETPARAM: u64 = 142;
pub const NR64_SCHED_GETPARAM: u64 = 143;
pub const NR64_SCHED_SETSCHEDULER: u64 = 144;
pub const NR64_SCHED_GETSCHEDULER: u64 = 145;
pub const NR64_SCHED_GET_PRIORITY_MAX: u64 = 146;
pub const NR64_SCHED_GET_PRIORITY_MIN: u64 = 147;
pub const NR64_SCHED_RR_GET_INTERVAL: u64 = 148;
pub const NR64_MLOCK: u64 = 149;
pub const NR64_MUNLOCK: u64 = 150;
pub const NR64_MLOCKALL: u64 = 151;
pub const NR64_MUNLOCKALL: u64 = 152;
pub const NR64_VHANGUP: u64 = 153;
pub const NR64_MODIFY_LDT: u64 = 154;
pub const NR64_PIVOT_ROOT: u64 = 155;
pub const NR64_SYSCTL: u64 = 156;
pub const NR64_PRCTL: u64 = 157;
pub const NR64_ARCH_PRCTL: u64 = 158;
pub const NR64_ADJTIMEX: u64 = 159;
pub const NR64_SETRLIMIT: u64 = 160;
pub const NR64_CHROOT: u64 = 161;
pub const NR64_SYNC: u64 = 162;
pub const NR64_ACCT: u64 = 163;
pub const NR64_SETTIMEOFDAY: u64 = 164;
pub const NR64_MOUNT: u64 = 165;
pub const NR64_UMOUNT2: u64 = 166;
pub const NR64_SWAPON: u64 = 167;
pub const NR64_SWAPOFF: u64 = 168;
pub const NR64_REBOOT: u64 = 169;
pub const NR64_SETHOSTNAME: u64 = 170;
pub const NR64_SETDOMAINNAME: u64 = 171;
pub const NR64_IOPL: u64 = 172;
pub const NR64_IOPERM: u64 = 173;
pub const NR64_CREATE_MODULE: u64 = 174;
pub const NR64_INIT_MODULE: u64 = 175;
pub const NR64_DELETE_MODULE: u64 = 176;
pub const NR64_GET_KERNEL_SYMS: u64 = 177;
pub const NR64_QUERY_MODULE: u64 = 178;
pub const NR64_QUOTACTL: u64 = 179;
pub const NR64_NFSSERVCTL: u64 = 180;
pub const NR64_GETPMSG: u64 = 181;
pub const NR64_PUTPMSG: u64 = 182;
pub const NR64_AFS_SYSCALL: u64 = 183;
pub const NR64_TUXCALL: u64 = 184;
pub const NR64_SECURITY: u64 = 185;
pub const NR64_GETTID: u64 = 186;
pub const NR64_READAHEAD: u64 = 187;
pub const NR64_SETXATTR: u64 = 188;
pub const NR64_LSETXATTR: u64 = 189;
pub const NR64_FSETXATTR: u64 = 190;
pub const NR64_GETXATTR: u64 = 191;
pub const NR64_LGETXATTR: u64 = 192;
pub const NR64_FGETXATTR: u64 = 193;
pub const NR64_LISTXATTR: u64 = 194;
pub const NR64_LLISTXATTR: u64 = 195;
pub const NR64_FLISTXATTR: u64 = 196;
pub const NR64_REMOVEXATTR: u64 = 197;
pub const NR64_LREMOVEXATTR: u64 = 198;
pub const NR64_FREMOVEXATTR: u64 = 199;
pub const NR64_TKILL: u64 = 200;
pub const NR64_TIME: u64 = 201;
pub const NR64_FUTEX: u64 = 202;
pub const NR64_SCHED_SETAFFINITY: u64 = 203;
pub const NR64_SCHED_GETAFFINITY: u64 = 204;
pub const NR64_SET_THREAD_AREA: u64 = 205;
pub const NR64_IO_SETUP: u64 = 206;
pub const NR64_IO_DESTROY: u64 = 207;
pub const NR64_IO_GETEVENTS: u64 = 208;
pub const NR64_IO_SUBMIT: u64 = 209;
pub const NR64_IO_CANCEL: u64 = 210;
pub const NR64_GET_THREAD_AREA: u64 = 211;
pub const NR64_LOOKUP_DCOOKIE: u64 = 212;
pub const NR64_EPOLL_CREATE: u64 = 213;
pub const NR64_EPOLL_CTL_OLD: u64 = 214;
pub const NR64_EPOLL_WAIT_OLD: u64 = 215;
pub const NR64_REMAP_FILE_PAGES: u64 = 216;
pub const NR64_GETDENTS64: u64 = 217;
pub const NR64_SET_TID_ADDRESS: u64 = 218;
pub const NR64_RESTART_SYSCALL: u64 = 219;
pub const NR64_SEMTIMEDOP: u64 = 220;
pub const NR64_FADVISE64: u64 = 221;
pub const NR64_TIMER_CREATE: u64 = 222;
pub const NR64_TIMER_SETTIME: u64 = 223;
pub const NR64_TIMER_GETTIME: u64 = 224;
pub const NR64_TIMER_GETOVERRUN: u64 = 225;
pub const NR64_TIMER_DELETE: u64 = 226;
pub const NR64_CLOCK_SETTIME: u64 = 227;
pub const NR64_CLOCK_GETTIME: u64 = 228;
pub const NR64_CLOCK_GETRES: u64 = 229;
pub const NR64_CLOCK_NANOSLEEP: u64 = 230;
pub const NR64_EXIT_GROUP: u64 = 231;
pub const NR64_EPOLL_WAIT: u64 = 232;
pub const NR64_EPOLL_CTL: u64 = 233;
pub const NR64_TGKILL: u64 = 234;
pub const NR64_UTIMES: u64 = 235;
pub const NR64_VSERVER: u64 = 236;
pub const NR64_MBIND: u64 = 237;
pub const NR64_SET_MEMPOLICY: u64 = 238;
pub const NR64_GET_MEMPOLICY: u64 = 239;
pub const NR64_MQ_OPEN: u64 = 240;
pub const NR64_MQ_UNLINK: u64 = 241;
pub const NR64_MQ_TIMEDSEND: u64 = 242;
pub const NR64_MQ_TIMEDRECEIVE: u64 = 243;
pub const NR64_MQ_NOTIFY: u64 = 244;
pub const NR64_MQ_GETSETATTR: u64 = 245;
pub const NR64_KEXEC_LOAD: u64 = 246;
pub const NR64_WAITID: u64 = 247;
pub const NR64_ADD_KEY: u64 = 248;
pub const NR64_REQUEST_KEY: u64 = 249;
pub const NR64_KEYCTL: u64 = 250;
pub const NR64_IOPRIO_SET: u64 = 251;
pub const NR64_IOPRIO_GET: u64 = 252;
pub const NR64_INOTIFY_INIT: u64 = 253;
pub const NR64_INOTIFY_ADD_WATCH: u64 = 254;
pub const NR64_INOTIFY_RM_WATCH: u64 = 255;
pub const NR64_MIGRATE_PAGES: u64 = 256;
pub const NR64_OPENAT: u64 = 257;
pub const NR64_MKDIRAT: u64 = 258;
pub const NR64_MKNODAT: u64 = 259;
pub const NR64_FCHOWNAT: u64 = 260;
pub const NR64_FUTIMESAT: u64 = 261;
pub const NR64_NEWFSTATAT: u64 = 262;
pub const NR64_UNLINKAT: u64 = 263;
pub const NR64_RENAMEAT: u64 = 264;
pub const NR64_LINKAT: u64 = 265;
pub const NR64_SYMLINKAT: u64 = 266;
pub const NR64_READLINKAT: u64 = 267;
pub const NR64_FCHMODAT: u64 = 268;
pub const NR64_FACCESSAT: u64 = 269;
pub const NR64_PSELECT6: u64 = 270;
pub const NR64_PPOLL: u64 = 271;
pub const NR64_UNSHARE: u64 = 272;
pub const NR64_SET_ROBUST_LIST: u64 = 273;
pub const NR64_GET_ROBUST_LIST: u64 = 274;
pub const NR64_SPLICE: u64 = 275;
pub const NR64_TEE: u64 = 276;
pub const NR64_SYNC_FILE_RANGE: u64 = 277;
pub const NR64_VMSPLICE: u64 = 278;
pub const NR64_MOVE_PAGES: u64 = 279;
pub const NR64_UTIMENSAT: u64 = 280;
pub const NR64_EPOLL_PWAIT: u64 = 281;
pub const NR64_SIGNALFD: u64 = 282;
pub const NR64_TIMERFD_CREATE: u64 = 283;
pub const NR64_EVENTFD: u64 = 284;
pub const NR64_FALLOCATE: u64 = 285;
pub const NR64_TIMERFD_SETTIME: u64 = 286;
pub const NR64_TIMERFD_GETTIME: u64 = 287;
pub const NR64_ACCEPT4: u64 = 288;
pub const NR64_SIGNALFD4: u64 = 289;
pub const NR64_EVENTFD2: u64 = 290;
pub const NR64_EPOLL_CREATE1: u64 = 291;
pub const NR64_DUP3: u64 = 292;
pub const NR64_PIPE2: u64 = 293;
pub const NR64_INOTIFY_INIT1: u64 = 294;
pub const NR64_PREADV: u64 = 295;
pub const NR64_PWRITEV: u64 = 296;
pub const NR64_RT_TGSIGQUEUEINFO: u64 = 297;
pub const NR64_PERF_EVENT_OPEN: u64 = 298;
pub const NR64_RECVMMSG: u64 = 299;
pub const NR64_FANOTIFY_INIT: u64 = 300;
pub const NR64_FANOTIFY_MARK: u64 = 301;
pub const NR64_PRLIMIT64: u64 = 302;
pub const NR64_NAME_TO_HANDLE_AT: u64 = 303;
pub const NR64_OPEN_BY_HANDLE_AT: u64 = 304;
pub const NR64_CLOCK_ADJTIME: u64 = 305;
pub const NR64_SYNCFS: u64 = 306;
pub const NR64_SENDMMSG: u64 = 307;
pub const NR64_SETNS: u64 = 308;
pub const NR64_GETCPU: u64 = 309;
pub const NR64_PROCESS_VM_READV: u64 = 310;
pub const NR64_PROCESS_VM_WRITEV: u64 = 311;
pub const NR64_KCMP: u64 = 312;
pub const NR64_FINIT_MODULE: u64 = 313;
pub const NR64_SCHED_SETATTR: u64 = 314;
pub const NR64_SCHED_GETATTR: u64 = 315;
pub const NR64_RENAMEAT2: u64 = 316;
pub const NR64_SECCOMP: u64 = 317;
pub const NR64_GETRANDOM: u64 = 318;
pub const NR64_MEMFD_CREATE: u64 = 319;
pub const NR64_KEXEC_FILE_LOAD: u64 = 320;
pub const NR64_BPF: u64 = 321;
pub const NR64_EXECVEAT: u64 = 322;
pub const NR64_USERFAULTFD: u64 = 323;
pub const NR64_MEMBARRIER: u64 = 324;
pub const NR64_MLOCK2: u64 = 325;
pub const NR64_COPY_FILE_RANGE: u64 = 326;
pub const NR64_PREADV2: u64 = 327;
pub const NR64_PWRITEV2: u64 = 328;
pub const NR64_PKEY_MPROTECT: u64 = 329;
pub const NR64_PKEY_ALLOC: u64 = 330;
pub const NR64_PKEY_FREE: u64 = 331;
pub const NR64_STATX: u64 = 332;
pub const NR64_IO_PGETEVENTS: u64 = 333;
pub const NR64_RSEQ: u64 = 334;
pub const NR64_PIDFD_SEND_SIGNAL: u64 = 424;
pub const NR64_IO_URING_SETUP: u64 = 425;
pub const NR64_IO_URING_ENTER: u64 = 426;
pub const NR64_IO_URING_REGISTER: u64 = 427;
pub const NR64_OPEN_TREE: u64 = 428;
pub const NR64_MOVE_MOUNT: u64 = 429;
pub const NR64_FSOPEN: u64 = 430;
pub const NR64_FSCONFIG: u64 = 431;
pub const NR64_FSMOUNT: u64 = 432;
pub const NR64_FSPICK: u64 = 433;
pub const NR64_PIDFD_OPEN: u64 = 434;
pub const NR64_CLONE3: u64 = 435;
pub const NR64_CLOSE_RANGE: u64 = 436;
pub const NR64_OPENAT2: u64 = 437;
pub const NR64_PIDFD_GETFD: u64 = 438;
pub const NR64_FACCESSAT2: u64 = 439;
pub const NR64_PROCESS_MADVISE: u64 = 440;
pub const NR64_EPOLL_PWAIT2: u64 = 441;
pub const NR64_MOUNT_SETATTR: u64 = 442;
pub const NR64_QUOTACTL_FD: u64 = 443;
pub const NR64_LANDLOCK_CREATE_RULESET: u64 = 444;
pub const NR64_LANDLOCK_ADD_RULE: u64 = 445;
pub const NR64_LANDLOCK_RESTRICT_SELF: u64 = 446;
pub const NR64_MEMFD_SECRET: u64 = 447;
pub const NR64_PROCESS_MRELEASE: u64 = 448;

pub const ARCH_SET_GS: u64 = 0x1001;
pub const ARCH_SET_FS: u64 = 0x1002;
pub const ARCH_GET_FS: u64 = 0x1003;
pub const ARCH_GET_GS: u64 = 0x1004;

pub const LOCALE_USER_DEFAULT: u64 = 0x400;
pub const LOCALE_SABBREVMONTHNAME1 : u64 = 68;
pub const LOCALE_SABBREVMONTHNAME2 : u64 = 69;
pub const LOCALE_SABBREVMONTHNAME3 : u64 = 70;
pub const LOCALE_SABBREVMONTHNAME4 : u64 = 71;
pub const LOCALE_SABBREVMONTHNAME5 : u64 = 72;
pub const LOCALE_SABBREVMONTHNAME6 : u64 = 73;
pub const LOCALE_SABBREVMONTHNAME7 : u64 = 74;
pub const LOCALE_SABBREVMONTHNAME8 : u64 = 75;
pub const LOCALE_SABBREVMONTHNAME9 : u64 = 76;
pub const LOCALE_SABBREVMONTHNAME10: u64 = 77;
pub const LOCALE_SABBREVMONTHNAME11: u64 = 78;
pub const LOCALE_SABBREVMONTHNAME12: u64 = 79;

pub const UTSNAME: [u8; 390] = [
    0x4c, 0x69, 0x6e, 0x75, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x73, 0x61, 0x74, 0x75, 0x72, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x35, 0x2e, 0x31, 0x30, 0x2e, 0x30, 0x2d, 0x32, 0x33, 0x2d, 0x61, 0x6d, 0x64, 0x36,
    0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x23, 0x31, 0x20, 0x53, 0x4d, 0x50, 0x20, 0x44, 0x65, 0x62, 0x69, 0x61, 0x6e,
    0x20, 0x35, 0x2e, 0x31, 0x30, 0x2e, 0x31, 0x37, 0x39, 0x2d, 0x31, 0x20, 0x28, 0x32, 0x30, 0x32,
    0x33, 0x2d, 0x30, 0x35, 0x2d, 0x31, 0x32, 0x29, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x78, 0x38, 0x36, 0x5f, 0x36, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x6e, 0x6f, 0x6e, 0x65, 0x29, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
