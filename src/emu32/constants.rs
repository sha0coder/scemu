
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

//vectored exception handler
pub const CALL_FIRST:u32 = 1;
pub const CALL_LAST:u32 = 0;

