
// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55
#![allow(dead_code)]
pub const STATUS_SUCCESS:u64 = 0x00000000;
pub const STATUS_ACCESS_DENIED:u64 = 0xC0000022;
pub const STATUS_INVALID_HANDLE:u64 = 0xC0000008;
pub const STATUS_NO_MEMORY:u64 = 0xC0000017;
pub const STATUS_ACCESS_VIOLATION:u64 = 0xC0000005;
pub const STATUS_INVALID_PARAMETER:u64 = 0xC000000D;

pub const NUM_BYTES_TRACE:usize = 16;
pub const VERSION:u64 = 0x1db10106;

pub const WAIT_TIMEOUT:u64 = 0x00000102;
pub const WAIT_FAILED:u64 = 0xFFFFFFFF;

//vectored exception handler
pub const CALL_FIRST:u32 = 1;
pub const CALL_LAST:u32 = 0;

pub const INTERNET_OPTION_ALTER_IDENTITY:u32 = 80;
pub const INTERNET_OPTION_ASYNC:u32 = 30;
pub const INTERNET_OPTION_ASYNC_ID:u32 = 15;
pub const INTERNET_OPTION_ASYNC_PRIORITY:u32 = 16;
pub const INTERNET_OPTION_BYPASS_EDITED_ENTRY:u32 = 64;
pub const INTERNET_OPTION_CACHE_STREAM_HANDLE:u32 = 27;
pub const INTERNET_OPTION_CACHE_TIMESTAMPS:u32 = 69;
pub const INTERNET_OPTION_CALLBACK:u32 = 1;
pub const INTERNET_OPTION_CALLBACK_FILTER:u32 = 54;
pub const INTERNET_OPTION_CLIENT_CERT_CONTEXT:u32 = 84;
pub const INTERNET_OPTION_CODEPAGE:u32 = 68;
pub const INTERNET_OPTION_CODEPAGE_PATH:u32 = 100;
pub const INTERNET_OPTION_CODEPAGE_EXTRA:u32 = 101;
pub const INTERNET_OPTION_COMPRESSED_CONTENT_LENGTH:u32 = 147;
pub const INTERNET_OPTION_CONNECT_BACKOFF:u32 = 4;
pub const INTERNET_OPTION_CONNECT_RETRIES:u32 = 3;
pub const INTERNET_OPTION_CONNECT_TIME:u32 = 55;
pub const INTERNET_OPTION_CONNECT_TIMEOUT:u32 = 2;
pub const INTERNET_OPTION_CONNECTED_STATE:u32 = 50;
pub const INTERNET_OPTION_CONTEXT_VALUE:u32 = 45;
pub const INTERNET_OPTION_CONTROL_RECEIVE_TIMEOUT:u32 = 6;
pub const INTERNET_OPTION_CONTROL_SEND_TIMEOUT:u32 = 5;
pub const INTERNET_OPTION_DATA_RECEIVE_TIMEOUT:u32 = 8;
pub const INTERNET_OPTION_DATA_SEND_TIMEOUT:u32 = 7;

// https://docs.microsoft.com/en-us/windows/win32/wininet/api-flags
pub const INTERNET_FLAG_SECURE:u64 = 0x00800000;

pub const ERROR_NO_MORE_FILES:u64 = 18;
pub const CREATE_SUSPENDED:u64 = 0x00000004;
pub const EXCEPTION_EXECUTE_HANDLER:u64 = 1;

pub const PAGE_NOACCESS:u32 = 0x01;
pub const PAGE_EXECUTE:u32 = 0x00;
pub const PAGE_READONLY:u32 = 0x02;
pub const PAGE_READWRITE:u32 = 0x04;
pub const PAGE_GUARD:u32 = 0x100;
pub const PAGE_NOCACHE:u32 = 0x200;
pub const PAGE_WRITECOMBINE:u32 = 0x400;
pub const MEM_COMMIT:u32 = 0x1000;
pub const MEM_FREE:u32 = 0x10000;
pub const MEM_RESERVE:u32 = 0x2000;
pub const MEM_IMAGE:u32 = 0x1000000;
pub const MEM_MAPPED:u32 = 0x40000;
pub const MEM_PRIVATE:u32 = 0x20000;

//// LINUX ////

pub const ENOTSOCK:u64  =       -1i64 as u64;      /* not open sock */
pub const EPERM:u64     =       -1i64 as u64;      /* permissions error */
pub const ENOENT:u64    =       -2i64 as u64;      /* No such file or directory */
pub const ESRCH:u64     =       -3i64 as u64;      /* No such process */
pub const EINTR:u64     =       -4i64 as u64;      /* Interrupted system call */
pub const EIO:u64       =       -5i64 as u64;      /* I/O error */
pub const ENXIO:u64     =       -6i64 as u64;      /* No such device or address */
pub const E2BIG:u64     =       -7i64 as u64;      /* Argument list too long */
pub const ENOEXEC:u64   =       -8i64 as u64;      /* Exec format error */
pub const EBADF:u64     =       -9i64 as u64;      /* Bad file number */
pub const ECHILD:u64    =      -10i64 as u64;      /* No child processes */
pub const EAGAIN:u64    =      -11i64 as u64;      /* Try again */
pub const ENOMEM:u64    =      -12i64 as u64;      /* Out of memory */
pub const EACCES:u64    =      -13i64 as u64;      /* Permission denied */
pub const EFAULT:u64    =      -14i64 as u64;      /* Bad address */
pub const ENOTBLK:u64   =      -15i64 as u64;      /* Block device required */
pub const EBUSY:u64     =      -16i64 as u64;      /* Device or resource busy */
pub const EEXIST:u64    =      -17i64 as u64;      /* File exists */
pub const EXDEV:u64     =      -18i64 as u64;      /* Cross-device link */
pub const ENODEV:u64    =      -19i64 as u64;      /* No such device */
pub const ENOTDIR:u64   =      -20i64 as u64;      /* Not a directory */
pub const EISDIR:u64    =      -21i64 as u64;      /* Is a directory */
pub const EINVAL:u64    =      -22i64 as u64;      /* Invalid argument */
pub const ENFILE:u64    =      -23i64 as u64;      /* File table overflow */
pub const EMFILE:u64    =      -24i64 as u64;      /* Too many open files */
pub const ENOTTY:u64    =      -25i64 as u64;      /* Not a typewriter */
pub const ETXTBSY:u64   =      -26i64 as u64;      /* Text file busy */
pub const EFBIG:u64     =      -27i64 as u64;      /* File too large */
pub const ENOSPC:u64    =      -28i64 as u64;      /* No space left on device */
pub const ESPIPE:u64    =      -29i64 as u64;      /* Illegal seek */
pub const EROFS:u64     =      -30i64 as u64;      /* Read-only file system */
pub const EMLINK:u64    =      -31i64 as u64;      /* Too many links */
pub const EPIPE:u64     =      -32i64 as u64;      /* Broken pipe */
pub const EDOM:u64      =      -33i64 as u64;      /* Math argument out of domain of func */
pub const ERANGE:u64    =      -34i64 as u64;      /* Math result not representable */



pub const SYS_SOCKET:u32 = 1;		
pub const SYS_BIND:u32 = 2;	
pub const SYS_CONNECT:u32 = 3;	
pub const SYS_LISTEN:u32 = 4;		
pub const SYS_ACCEPT:u32 = 5;	
pub const SYS_GETSOCKNAME:u32 = 6;	
pub const SYS_GETPEERNAME:u32 = 7;
pub const SYS_SOCKETPAIR:u32 = 8;	
pub const SYS_SEND:u32 = 9;		
pub const SYS_RECV:u32 = 10;			
pub const SYS_SENDTO:u32 = 11;	
pub const SYS_RECVFROM:u32 = 12;	
pub const SYS_SHUTDOWN:u32 = 13;	
pub const SYS_SETSOCKOPT:u32 = 14;
pub const SYS_GETSOCKOPT:u32 = 15;	
pub const SYS_SENDMSG:u32 =	16;	
pub const SYS_RECVMSG:u32 =	17;	
pub const SYS_ACCEPT4:u32 =	18;	
pub const SYS_RECVMMSG:u32 = 19;	
pub const SYS_SENDMMSG:u32 = 20;
