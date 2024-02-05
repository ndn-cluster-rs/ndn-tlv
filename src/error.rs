use thiserror::Error;

/// Common error enum for library functions
#[derive(Debug, Error, Eq, PartialEq)]
pub enum TlvError {
    /// A TLV that was being read had an unexpected type
    #[error("TLV read had different type {found}, expected {expected}")]
    TypeMismatch {
        /// The expected type
        expected: usize,
        /// The actual type read
        found: usize,
    },
    /// The data stream ended, even though more data was expected
    #[error("Unexpected end of stream")]
    UnexpectedEndOfStream,
}
