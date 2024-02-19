use bytes::{Buf, BufMut, Bytes, BytesMut};
use derive_more::{AsMut, AsRef, Display};

use crate::{error::TlvError, Result, TlvDecode, TlvEncode};

/// A variable-length number as used by TLV encoded values
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Display, AsRef, AsMut)]
pub struct VarNum {
    value: u64,
}

impl VarNum {
    /// Construct a new `VarNum` from a `u64`
    pub fn new(value: u64) -> Self {
        value.into()
    }

    /// The value in this `VarNum` as a `u64`
    pub fn value(&self) -> u64 {
        self.value
    }
}

impl From<usize> for VarNum {
    fn from(value: usize) -> Self {
        VarNum::from(value as u64)
    }
}

impl From<u64> for VarNum {
    fn from(value: u64) -> Self {
        Self { value }
    }
}

impl From<u32> for VarNum {
    fn from(value: u32) -> Self {
        VarNum::from(value as u64)
    }
}

impl From<u16> for VarNum {
    fn from(value: u16) -> Self {
        VarNum::from(value as u64)
    }
}

impl From<u8> for VarNum {
    fn from(value: u8) -> Self {
        VarNum::from(value as u64)
    }
}

impl From<isize> for VarNum {
    fn from(value: isize) -> Self {
        VarNum::from(value as u64)
    }
}

impl From<i64> for VarNum {
    fn from(value: i64) -> Self {
        VarNum::from(value as u64)
    }
}

impl From<i32> for VarNum {
    fn from(value: i32) -> Self {
        VarNum::from(value as u64)
    }
}

impl From<i16> for VarNum {
    fn from(value: i16) -> Self {
        VarNum::from(value as u64)
    }
}

impl From<i8> for VarNum {
    fn from(value: i8) -> Self {
        VarNum::from(value as u64)
    }
}

impl From<VarNum> for usize {
    fn from(value: VarNum) -> Self {
        value.value as usize
    }
}

impl From<VarNum> for u64 {
    fn from(value: VarNum) -> Self {
        value.value
    }
}

impl From<VarNum> for u32 {
    fn from(value: VarNum) -> Self {
        value.value as u32
    }
}

impl From<VarNum> for u16 {
    fn from(value: VarNum) -> Self {
        value.value as u16
    }
}

impl From<VarNum> for u8 {
    fn from(value: VarNum) -> Self {
        value.value as u8
    }
}

impl From<VarNum> for isize {
    fn from(value: VarNum) -> Self {
        value.value as isize
    }
}

impl From<VarNum> for i64 {
    fn from(value: VarNum) -> Self {
        value.value as i64
    }
}

impl From<VarNum> for i32 {
    fn from(value: VarNum) -> Self {
        value.value as i32
    }
}

impl From<VarNum> for i16 {
    fn from(value: VarNum) -> Self {
        value.value as i16
    }
}

impl From<VarNum> for i8 {
    fn from(value: VarNum) -> Self {
        value.value as i8
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
