
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