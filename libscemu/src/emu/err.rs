use std::error::Error;

#[derive(Debug)]
pub struct ScemuError {
    pub message: String,
}

impl ScemuError {
    pub fn new(message: &str) -> ScemuError {
        ScemuError {
            message: message.to_string(),
        }
    }
}

impl std::fmt::Display for ScemuError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "SCEMU Error: {}", self.message)
    }
}

impl Error for ScemuError {}

