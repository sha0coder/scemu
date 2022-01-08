
// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55
#![allow(dead_code)]
pub const STATUS_SUCCESS:u32 = 0x00000000;
pub const STATUS_ACCESS_DENIED:u32 = 0xC0000022;
pub const STATUS_INVALID_HANDLE:u32 = 0xC0000008;
pub const STATUS_NO_MEMORY:u32 = 0xC0000017;
pub const STATUS_ACCESS_VIOLATION:u32 = 0xC0000005;
pub const STATUS_INVALID_PARAMETER:u32 = 0xC000000D;

pub const NUM_BYTES_TRACE:usize = 16;
pub const VERSION:u32 = 0x1db10106;

pub const WAIT_TIMEOUT:u32 = 0x00000102;
pub const WAIT_FAILED:u32 = 0xFFFFFFFF;

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
pub const INTERNET_FLAG_SECURE:u32 = 0x00800000;

pub const ERROR_NO_MORE_FILES:u32 = 18;
pub const CREATE_SUSPENDED:u32 = 0x00000004;
pub const EXCEPTION_EXECUTE_HANDLER:u32 = 1;

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

pub const ENOTSOCK:u32  =       -1i32 as u32;      /* not open sock */
pub const EPERM:u32     =       -1i32 as u32;      /* permissions error */
pub const ENOENT:u32    =       -2i32 as u32;      /* No such file or directory */
pub const ESRCH:u32     =       -3i32 as u32;      /* No such process */
pub const EINTR:u32     =       -4i32 as u32;      /* Interrupted system call */
pub const EIO:u32       =       -5i32 as u32;      /* I/O error */
pub const ENXIO:u32     =       -6i32 as u32;      /* No such device or address */
pub const E2BIG:u32     =       -7i32 as u32;      /* Argument list too long */
pub const ENOEXEC:u32   =       -8i32 as u32;      /* Exec format error */
pub const EBADF:u32     =       -9i32 as u32;      /* Bad file number */
pub const ECHILD:u32    =      -10i32 as u32;      /* No child processes */
pub const EAGAIN:u32    =      -11i32 as u32;      /* Try again */
pub const ENOMEM:u32    =      -12i32 as u32;      /* Out of memory */
pub const EACCES:u32    =      -13i32 as u32;      /* Permission denied */
pub const EFAULT:u32    =      -14i32 as u32;      /* Bad address */
pub const ENOTBLK:u32   =      -15i32 as u32;      /* Block device required */
pub const EBUSY:u32     =      -16i32 as u32;      /* Device or resource busy */
pub const EEXIST:u32    =      -17i32 as u32;      /* File exists */
pub const EXDEV:u32     =      -18i32 as u32;      /* Cross-device link */
pub const ENODEV:u32    =      -19i32 as u32;      /* No such device */
pub const ENOTDIR:u32   =      -20i32 as u32;      /* Not a directory */
pub const EISDIR:u32    =      -21i32 as u32;      /* Is a directory */
pub const EINVAL:u32    =      -22i32 as u32;      /* Invalid argument */
pub const ENFILE:u32    =      -23i32 as u32;      /* File table overflow */
pub const EMFILE:u32    =      -24i32 as u32;      /* Too many open files */
pub const ENOTTY:u32    =      -25i32 as u32;      /* Not a typewriter */
pub const ETXTBSY:u32   =      -26i32 as u32;      /* Text file busy */
pub const EFBIG:u32     =      -27i32 as u32;      /* File too large */
pub const ENOSPC:u32    =      -28i32 as u32;      /* No space left on device */
pub const ESPIPE:u32    =      -29i32 as u32;      /* Illegal seek */
pub const EROFS:u32     =      -30i32 as u32;      /* Read-only file system */
pub const EMLINK:u32    =      -31i32 as u32;      /* Too many links */
pub const EPIPE:u32     =      -32i32 as u32;      /* Broken pipe */
pub const EDOM:u32      =      -33i32 as u32;      /* Math argument out of domain of func */
pub const ERANGE:u32    =      -34i32 as u32;      /* Math result not representable */



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
