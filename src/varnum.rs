use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::{error::TlvError, Result, TlvDecode, TlvEncode};

/// A variable-length number as used by TLV encoded values
#[derive(Debug, Clone, Eq)]
pub struct VarNum {
    value: usize,
}

impl VarNum {
    /// Construct a new `VarNum` from a `usize`
    pub fn new(value: usize) -> Self {
        value.into()
    }

    /// The value in this `VarNum` as a `usize`
    pub fn value(&self) -> usize {
        self.value
    }
}

impl PartialEq for VarNum {
    fn eq(&self, other: &Self) -> bool {
        self.value() == other.value()
    }
}

impl From<usize> for VarNum {
    fn from(value: usize) -> Self {
        Self { value }
    }
}

impl From<u64> for VarNum {
    fn from(value: u64) -> Self {
        VarNum::from(value as usize)
    }
}

impl From<u32> for VarNum {
    fn from(value: u32) -> Self {
        VarNum::from(value as usize)
    }
}

impl From<u16> for VarNum {
    fn from(value: u16) -> Self {
        VarNum::from(value as usize)
    }
}

impl From<u8> for VarNum {
    fn from(value: u8) -> Self {
        VarNum::from(value as usize)
    }
}

impl From<isize> for VarNum {
    fn from(value: isize) -> Self {
        VarNum::from(value as usize)
    }
}

impl From<i64> for VarNum {
    fn from(value: i64) -> Self {
        VarNum::from(value as usize)
    }
}

impl From<i32> for VarNum {
    fn from(value: i32) -> Self {
        VarNum::from(value as usize)
    }
}

impl From<i16> for VarNum {
    fn from(value: i16) -> Self {
        VarNum::from(value as usize)
    }
}

impl From<i8> for VarNum {
    fn from(value: i8) -> Self {
        VarNum::from(value as usize)
    }
}

impl TlvEncode for VarNum {
    fn encode(&self) -> Bytes {
        let mut bytes = BytesMut::with_capacity(self.size());

        match self.value() {
            0x00..=0xFC => bytes.put_u8(self.value() as u8),
            0xFD..=0xFFFF => {
                bytes.put_u8(0xFD);
                bytes.put_u16(self.value() as u16);
            }
            0x10000..=0xFFFF_FFFF => {
                bytes.put_u8(0xFE);
                bytes.put_u32(self.value() as u32);
            }
            _ => {
                bytes.put_u8(0xFF);
                bytes.put_u64(self.value() as u64);
            }
        }

        bytes.freeze()
    }

    fn size(&self) -> usize {
        match self.value() {
            0x00..=0xFC => 1,
            0xFD..=0xFFFF => 3,
            0x10000..=0xFFFF_FFFF => 5,
            _ => 9,
        }
    }
}

impl TlvDecode for VarNum {
    fn decode(bytes: &mut Bytes) -> Result<Self> {
        if bytes.remaining() <= 0 {
            return Err(TlvError::UnexpectedEndOfStream);
        }
        let first = bytes.get_u8();
        Ok(match first {
            0x00..=0xFC => first.into(),
            0xFD => {
                if bytes.remaining() < 2 {
                    return Err(TlvError::UnexpectedEndOfStream);
                }
                bytes.get_u16().into()
            }
            0xFE => {
                if bytes.remaining() < 4 {
                    return Err(TlvError::UnexpectedEndOfStream);
                }
                bytes.get_u32().into()
            }
            0xFF => {
                if bytes.remaining() < 8 {
                    return Err(TlvError::UnexpectedEndOfStream);
                }
                bytes.get_u64().into()
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_number() {
        let num = VarNum::from(5u8);
        let encoded = num.encode();
        assert_eq!(num.size(), 1);
        assert_eq!(&encoded[0..=0], &[5]);
        assert_eq!(VarNum::decode(&mut encoded.clone()).unwrap().value(), 5);
    }

    #[test]
    fn low_number3() {
        let num = VarNum::from(0xFFu8);
        let encoded = num.encode();
        assert_eq!(num.size(), 3);
        assert_eq!(&encoded[0..=2], &[0xFD, 00, 0xFF]);
        assert_eq!(VarNum::decode(&mut encoded.clone()).unwrap().value(), 0xFF);
    }

    #[test]
    fn number3() {
        let num = VarNum::from(0xFFFFu16);
        let encoded = num.encode();
        assert_eq!(num.size(), 3);
        assert_eq!(&encoded[0..=2], &[0xFD, 0xFF, 0xFF]);
        assert_eq!(
            VarNum::decode(&mut encoded.clone()).unwrap().value(),
            0xFFFF
        );
    }

    #[test]
    fn number5() {
        let num = VarNum::from(0xFFFF_FFFFu32);
        let encoded = num.encode();
        assert_eq!(num.size(), 5);
        assert_eq!(&encoded[0..=4], &[0xFE, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(
            VarNum::decode(&mut encoded.clone()).unwrap().value(),
            0xFFFF_FFFF
        );
    }

    #[test]
    fn number9() {
        let num = VarNum::from(0xFFFF_FFFF_FFFF_FFFFu64);
        let encoded = num.encode();
        assert_eq!(num.size(), 9);
        assert_eq!(
            &encoded[0..=8],
            &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
        );
        assert_eq!(
            VarNum::decode(&mut encoded.clone()).unwrap().value(),
            0xFFFF_FFFF_FFFF_FFFF
        );
    }
}
