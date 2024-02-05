use thiserror::Error;

/// Common error enum for library functions
#[derive(Debug, Error, Eq, PartialEq)]
pub enum TlvError {
    #[error("TLV read had different type {found}, expected {expected}")]
    TypeMismatch { expected: usize, found: usize },
    #[error("Unexpected end of stream")]
    UnexpectedEndOfStream,
}
