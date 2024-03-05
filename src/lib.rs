#![doc = include_str!("../README.md")]
#![warn(missing_docs)]

pub use ::bytes;
pub use ::ndn_tlv_derive::Tlv;
use bytes::{Buf, BufMut, Bytes, BytesMut};
pub use error::TlvError;
pub use tlv::{tlv_critical, tlv_typ_critical, GenericTlv, Tlv};
pub use varnum::VarNum;

mod error;
mod tlv;
mod varnum;

/// Common result type for library functions
pub type Result<T> = std::result::Result<T, TlvError>;

/// Encode data in TLV format
///
/// The value is a TLV record, or part of one
pub trait TlvEncode {
    /// Encode the value as a TLV record or part of one
    fn encode(&self) -> Bytes;
    /// The size of the encoded data in bytes
    fn size(&self) -> usize;
}

/// Decode data in TLV format
///
/// The value is a TLV record, or part of one
pub trait TlvDecode: Sized {
    /// Decode the value from a `bytes::Buf`
    ///
    /// The internal cursor of `bytes` must be advanced to point behind the used data
    /// The implementation may choose to consume a part, or the entire buffer. If the length of the
    /// data is known at the call site, restrict the size of `bytes` to prevent the entire buffer
    /// being consumed.
    fn decode(bytes: &mut Bytes) -> Result<Self>;
}

/// A non-negative integer, not encoded using `VarNum`
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NonNegativeInteger {
    /// An 8-bit integer
    U8(u8),
    /// A 16-bit integer
    U16(u16),
    /// A 32-bit integer
    U32(u32),
    /// A 64-bit integer
    U64(u64),
}

impl Default for NonNegativeInteger {
    fn default() -> Self {
        NonNegativeInteger::U8(0)
    }
}

/// Advance `bytes` until a valid TLV record of type `T` is found
///
/// In `error_on_critical` is true, any unexpected critical TLV records of a different type will lead to an error.
/// Unexpected non-critical TLV records will always be ignored.
pub fn find_tlv<T: Tlv>(bytes: &mut Bytes, error_on_critical: bool) -> Result<()> {
    let mut cur = bytes.clone();

    while cur.has_remaining() {
        let found_typ = VarNum::decode(&mut cur)?;
        if usize::from(found_typ) == T::TYP {
            return Ok(());
        }

        // Wrong type
        if error_on_critical && tlv_typ_critical(found_typ.into()) {
            return Err(TlvError::TypeMismatch {
                expected: T::TYP,
                found: found_typ.into(),
            });
        }

        // non-critical
        let length = VarNum::decode(&mut cur)?;
        cur.advance(length.into());
        bytes.advance(bytes.remaining() - cur.remaining());
    }

    Err(TlvError::UnexpectedEndOfStream)
}

impl TlvEncode for NonNegativeInteger {
    fn encode(&self) -> Bytes {
        let mut bytes = BytesMut::with_capacity(self.size());
        match *self {
            NonNegativeInteger::U8(n) => {
                bytes.put_u8(n);
            }
            NonNegativeInteger::U16(n) => {
                bytes.put_u16(n);
            }
            NonNegativeInteger::U32(n) => {
                bytes.put_u32(n);
            }
            NonNegativeInteger::U64(n) => {
                bytes.put_u64(n);
            }
        }
        bytes.freeze()
    }

    fn size(&self) -> usize {
        match *self {
            NonNegativeInteger::U8(_) => 1,
            NonNegativeInteger::U16(_) => 2,
            NonNegativeInteger::U32(_) => 4,
            NonNegativeInteger::U64(_) => 8,
        }
    }
}

impl TlvDecode for NonNegativeInteger {
    fn decode(bytes: &mut Bytes) -> Result<Self> {
        match bytes.remaining() {
            1 => Ok(Self::U8(bytes.get_u8())),
            2 => Ok(Self::U16(bytes.get_u16())),
            4 => Ok(Self::U32(bytes.get_u32())),
            8 => Ok(Self::U64(bytes.get_u64())),
            _ => Err(TlvError::UnexpectedLength),
        }
    }
}

impl From<u8> for NonNegativeInteger {
    fn from(value: u8) -> Self {
        Self::new(value as u64)
    }
}

impl From<u16> for NonNegativeInteger {
    fn from(value: u16) -> Self {
        Self::new(value as u64)
    }
}

impl From<u32> for NonNegativeInteger {
    fn from(value: u32) -> Self {
        Self::new(value as u64)
    }
}

impl From<u64> for NonNegativeInteger {
    fn from(value: u64) -> Self {
        Self::new(value as u64)
    }
}

impl From<usize> for NonNegativeInteger {
    fn from(value: usize) -> Self {
        Self::new(value as u64)
    }
}

impl From<NonNegativeInteger> for u64 {
    fn from(value: NonNegativeInteger) -> Self {
        match value {
            NonNegativeInteger::U8(n) => n as u64,
            NonNegativeInteger::U16(n) => n as u64,
            NonNegativeInteger::U32(n) => n as u64,
            NonNegativeInteger::U64(n) => n,
        }
    }
}

impl NonNegativeInteger {
    /// Create a `NonNegativeInteger` using the smallest possible representation to fit the given
    /// value
    pub const fn new(value: u64) -> Self {
        if value <= 0xFF {
            NonNegativeInteger::U8(value as u8)
        } else if value <= 0xFFFF {
            NonNegativeInteger::U16(value as u16)
        } else if value <= 0xFFFF_FFFF {
            NonNegativeInteger::U32(value as u32)
        } else {
            NonNegativeInteger::U64(value as u64)
        }
    }

    /// Return the value of this `NonNegativeInteger` as u64
    pub const fn as_u64(&self) -> u64 {
        match *self {
            NonNegativeInteger::U8(value) => value as u64,
            NonNegativeInteger::U16(value) => value as u64,
            NonNegativeInteger::U32(value) => value as u64,
            NonNegativeInteger::U64(value) => value as u64,
        }
    }

    /// Return the value of this `NonNegativeInteger` as usize
    pub const fn as_usize(&self) -> usize {
        match *self {
            NonNegativeInteger::U8(value) => value as usize,
            NonNegativeInteger::U16(value) => value as usize,
            NonNegativeInteger::U32(value) => value as usize,
            NonNegativeInteger::U64(value) => value as usize,
        }
    }
}

impl std::fmt::Display for NonNegativeInteger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        u64::from(*self).fmt(f)
    }
}

impl TlvEncode for Bytes {
    fn encode(&self) -> Bytes {
        self.clone()
    }

    fn size(&self) -> usize {
        self.len()
    }
}

impl TlvDecode for Bytes {
    fn decode(bytes: &mut Bytes) -> Result<Self> {
        Ok(bytes.copy_to_bytes(bytes.remaining()))
    }
}

impl<const N: usize> TlvEncode for [u8; N] {
    fn encode(&self) -> Bytes {
        Bytes::copy_from_slice(&self[..])
    }

    fn size(&self) -> usize {
        N
    }
}

impl<const N: usize> TlvDecode for [u8; N] {
    fn decode(bytes: &mut Bytes) -> Result<Self> {
        if bytes.remaining() < N {
            return Err(TlvError::UnexpectedEndOfStream);
        }
        let mut buf = [0; N];
        bytes.copy_to_slice(&mut buf);
        Ok(buf)
    }
}

impl TlvEncode for u8 {
    fn encode(&self) -> Bytes {
        Bytes::copy_from_slice(&[*self][..])
    }

    fn size(&self) -> usize {
        1
    }
}

impl TlvDecode for u8 {
    fn decode(bytes: &mut Bytes) -> Result<Self> {
        if bytes.remaining() < 1 {
            return Err(TlvError::UnexpectedEndOfStream);
        }
        Ok(bytes.get_u8())
    }
}

impl TlvEncode for i8 {
    fn encode(&self) -> Bytes {
        Bytes::copy_from_slice(&[*self as u8][..])
    }

    fn size(&self) -> usize {
        1
    }
}

impl TlvDecode for i8 {
    fn decode(bytes: &mut Bytes) -> Result<Self> {
        if bytes.remaining() < 1 {
            return Err(TlvError::UnexpectedEndOfStream);
        }
        Ok(bytes.get_i8())
    }
}

impl TlvEncode for u16 {
    fn encode(&self) -> Bytes {
        let mut bytes = BytesMut::with_capacity(self.size());
        bytes.put_u16(*self);
        bytes.freeze()
    }

    fn size(&self) -> usize {
        2
    }
}

impl TlvDecode for u16 {
    fn decode(bytes: &mut Bytes) -> Result<Self> {
        if bytes.remaining() < 2 {
            return Err(TlvError::UnexpectedEndOfStream);
        }
        Ok(bytes.get_u16())
    }
}

impl TlvEncode for i16 {
    fn encode(&self) -> Bytes {
        let mut bytes = BytesMut::with_capacity(self.size());
        bytes.put_i16(*self);
        bytes.freeze()
    }

    fn size(&self) -> usize {
        2
    }
}

impl TlvDecode for i16 {
    fn decode(bytes: &mut Bytes) -> Result<Self> {
        if bytes.remaining() < 2 {
            return Err(TlvError::UnexpectedEndOfStream);
        }
        Ok(bytes.get_i16())
    }
}

impl TlvEncode for u32 {
    fn encode(&self) -> Bytes {
        let mut bytes = BytesMut::with_capacity(self.size());
        bytes.put_u32(*self);
        bytes.freeze()
    }

    fn size(&self) -> usize {
        4
    }
}

impl TlvDecode for u32 {
    fn decode(bytes: &mut Bytes) -> Result<Self> {
        if bytes.remaining() < 4 {
            return Err(TlvError::UnexpectedEndOfStream);
        }
        Ok(bytes.get_u32())
    }
}

impl TlvEncode for i32 {
    fn encode(&self) -> Bytes {
        let mut bytes = BytesMut::with_capacity(self.size());
        bytes.put_i32(*self);
        bytes.freeze()
    }

    fn size(&self) -> usize {
        4
    }
}

impl TlvDecode for i32 {
    fn decode(bytes: &mut Bytes) -> Result<Self> {
        if bytes.remaining() < 4 {
            return Err(TlvError::UnexpectedEndOfStream);
        }
        Ok(bytes.get_i32())
    }
}

impl TlvEncode for u64 {
    fn encode(&self) -> Bytes {
        let mut bytes = BytesMut::with_capacity(self.size());
        bytes.put_u64(*self);
        bytes.freeze()
    }

    fn size(&self) -> usize {
        8
    }
}

impl TlvDecode for u64 {
    fn decode(bytes: &mut Bytes) -> Result<Self> {
        if bytes.remaining() < 8 {
            return Err(TlvError::UnexpectedEndOfStream);
        }
        Ok(bytes.get_u64())
    }
}

impl TlvEncode for i64 {
    fn encode(&self) -> Bytes {
        let mut bytes = BytesMut::with_capacity(self.size());
        bytes.put_i64(*self);
        bytes.freeze()
    }

    fn size(&self) -> usize {
        8
    }
}

impl TlvDecode for i64 {
    fn decode(bytes: &mut Bytes) -> Result<Self> {
        if bytes.remaining() < 8 {
            return Err(TlvError::UnexpectedEndOfStream);
        }
        Ok(bytes.get_i64())
    }
}

impl<T: TlvEncode> TlvEncode for Vec<T> {
    fn encode(&self) -> Bytes {
        let mut bytes = BytesMut::with_capacity(self.size());
        for item in self {
            bytes.put(item.encode());
        }
        bytes.freeze()
    }

    fn size(&self) -> usize {
        self.iter()
            .map(TlvEncode::size)
            .reduce(|x, y| x + y)
            .unwrap_or(0)
    }
}

impl<T: TlvDecode> TlvDecode for Vec<T> {
    fn decode(bytes: &mut Bytes) -> Result<Self> {
        let mut ret = Vec::new();
        while bytes.has_remaining() {
            let remaining = bytes.remaining();
            let mut bytes_clone = bytes.clone();
            let t = T::decode(&mut bytes_clone);
            match t {
                Ok(t) => {
                    ret.push(t);
                    bytes.advance(remaining - bytes_clone.remaining());
                }
                Err(TlvError::TypeMismatch {
                    expected: _,
                    found: _,
                }) => {
                    // Different TLV than what we expected - Vec ended
                    return Ok(ret);
                }
                // End of stream should not be possible unless the data is malformed
                Err(e) => return Err(e),
            }
        }
        Ok(ret)
    }
}

impl<T: TlvEncode> TlvEncode for Option<T> {
    fn encode(&self) -> Bytes {
        match self {
            None => Bytes::new(),
            Some(value) => value.encode(),
        }
    }

    fn size(&self) -> usize {
        match self {
            None => 0,
            Some(value) => value.size(),
        }
    }
}

impl<T: TlvDecode> TlvDecode for Option<T> {
    fn decode(bytes: &mut Bytes) -> Result<Self> {
        let remaining = bytes.remaining();
        let mut bytes_clone = bytes.clone();
        let t = T::decode(&mut bytes_clone);
        match t {
            Ok(value) => {
                bytes.advance(remaining - bytes_clone.remaining());
                Ok(Some(value))
            }
            // Different Type - probably what is next to parse
            Err(TlvError::TypeMismatch {
                expected: _,
                found: _,
            }) => Ok(None),
            // End of stream - no data here
            Err(TlvError::UnexpectedEndOfStream) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

impl TlvEncode for () {
    fn encode(&self) -> Bytes {
        Bytes::new()
    }

    fn size(&self) -> usize {
        0
    }
}

impl TlvDecode for () {
    fn decode(_: &mut Bytes) -> Result<Self> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Eq, PartialEq, Tlv)]
    #[tlv(8, internal = true)]
    pub(crate) struct GenericNameComponent {
        pub(crate) name: Bytes,
    }

    #[derive(Debug, Tlv, PartialEq)]
    #[tlv(7, internal = true)]
    struct Name {
        components: Vec<GenericNameComponent>,
    }

    #[derive(Debug, PartialEq, Eq, Tlv)]
    #[tlv(33, internal = true)]
    struct CanBePrefix;

    #[derive(Debug, PartialEq, Eq, Tlv)]
    #[tlv(129, internal = true)]
    struct VecPartial {
        components: Vec<GenericNameComponent>,
        can_be_prefix: CanBePrefix,
    }

    #[derive(Tlv)]
    #[tlv(143, internal = true)]
    struct HasOption {
        component: Option<GenericNameComponent>,
        can_be_prefix: CanBePrefix,
    }

    #[derive(Tlv)]
    #[tlv(8, internal = true)]
    struct TupleStruct(Bytes);

    #[derive(Debug, Tlv)]
    #[tlv(0, internal = true)]
    enum EnumTest {
        GenericNameComponent(GenericNameComponent),
        CanBePrefix(CanBePrefix),
    }

    #[derive(Debug, Tlv)]
    #[tlv(130, internal = true)]
    struct HasGeneric<T> {
        data: T,
    }

    #[derive(Debug, Tlv)]
    #[tlv(0, internal = true)]
    struct Sequence {
        name1: Name,
        name2: Name,
    }

    #[test]
    fn generic_name_component() {
        let mut data = Bytes::from(&[8, 5, b'h', b'e', b'l', b'l', b'o', 255, 255, 255][..]);
        let component = GenericNameComponent::decode(&mut data).unwrap();

        assert_eq!(data.remaining(), 3);
        assert_eq!(component.name, &b"hello"[..]);
    }

    #[test]
    fn vec_partial() {
        let mut data = Bytes::from(
            &[
                129, 16, 8, 5, b'h', b'e', b'l', b'l', b'o', 8, 5, b'w', b'o', b'r', b'l', b'd',
                33, 0, 255, 255, 255,
            ][..],
        );

        let partial = VecPartial::decode(&mut data).unwrap();
        assert_eq!(data.remaining(), 3);
        assert_eq!(partial.components.len(), 2);
        assert_eq!(partial.components[0].name, &b"hello"[..]);
        assert_eq!(partial.components[1].name, &b"world"[..]);
        assert_eq!(partial.can_be_prefix, CanBePrefix);
    }

    #[test]
    fn option_some() {
        let mut data = Bytes::from(
            &[
                143, 9, 8, 5, b'h', b'e', b'l', b'l', b'o', 33, 0, 255, 255, 255,
            ][..],
        );

        let option = HasOption::decode(&mut data).unwrap();
        assert_eq!(data.remaining(), 3);
        assert!(option.component.is_some());
        assert_eq!(option.component.unwrap().name, &b"hello"[..]);
    }

    #[test]
    fn option_none() {
        let mut data = Bytes::from(&[143, 2, 33, 0, 255, 255, 255][..]);

        let option = HasOption::decode(&mut data).unwrap();
        assert_eq!(data.remaining(), 3);
        assert!(option.component.is_none());
    }

    #[test]
    fn unknown_critical() {
        let mut data = Bytes::from(
            &[
                129, 18, 8, 5, b'h', b'e', b'l', b'l', b'o', 8, 5, b'w', b'o', b'r', b'l', b'd',
                127, 0, 33, 0, 255, 255, 255,
            ][..],
        );

        let partial = VecPartial::decode(&mut data);
        assert_eq!(data.remaining(), 3);
        assert!(partial.is_err());
        assert_eq!(
            partial.unwrap_err(),
            TlvError::TypeMismatch {
                expected: 33,
                found: 127
            }
        );
    }

    #[test]
    fn unknown_non_critical() {
        let mut data = Bytes::from(
            &[
                129, 18, 8, 5, b'h', b'e', b'l', b'l', b'o', 8, 5, b'w', b'o', b'r', b'l', b'd',
                126, 0, 33, 0, 255, 255, 255,
            ][..],
        );

        let partial = VecPartial::decode(&mut data).unwrap();
        assert_eq!(data.remaining(), 3);
        assert_eq!(partial.components.len(), 2);
        assert_eq!(partial.components[0].name, &b"hello"[..]);
        assert_eq!(partial.components[1].name, &b"world"[..]);
        assert_eq!(partial.can_be_prefix, CanBePrefix);
    }

    #[test]
    fn tuple_struct() {
        let mut data = Bytes::from(&[8, 5, b'h', b'e', b'l', b'l', b'o', 255, 255, 255][..]);
        let initial_data = data.clone();
        let component = TupleStruct::decode(&mut data).unwrap();

        assert_eq!(data.remaining(), 3);
        assert_eq!(component.0, &b"hello"[..]);

        let new_data = component.encode();
        assert_eq!(new_data, initial_data[0..7]);
    }

    #[test]
    fn enum_test() {
        let mut data = Bytes::from(&[8, 5, b'h', b'e', b'l', b'l', b'o', 255, 255, 255][..]);
        let initial_data = data.clone();
        let etest = EnumTest::decode(&mut data).unwrap();

        assert_eq!(data.remaining(), 3);
        match etest {
            EnumTest::GenericNameComponent(ref component) => {
                assert_eq!(component.name, &b"hello"[..]);
            }
            _ => panic!("Wrong variant"),
        }

        let new_data = etest.encode();
        assert_eq!(new_data, initial_data[0..7]);
    }

    #[test]
    fn overlength() {
        // Inner TLV escapes the outer TLV
        let mut data = Bytes::from(&[7, 7, 8, 6, b'h', b'e', b'l', b'l', b'o', 255, 255][..]);

        let name = Name::decode(&mut data);
        assert!(name.is_err());
        assert_eq!(name.unwrap_err(), TlvError::UnexpectedEndOfStream);
    }

    #[test]
    fn generic() {
        let mut data = Bytes::from(&[130, 3, 1, 2, 3][..]);

        let decoded = <HasGeneric<Bytes>>::decode(&mut data).unwrap();
        assert_eq!(decoded.data, &[1, 2, 3][..]);
    }

    #[test]
    fn sequence() {
        let mut data = Bytes::from(
            &[
                7, 11, 8, 5, b'h', b'e', b'l', b'l', b'o', 8, 2, b'a', b'b', 7, 5, 8, 3, b'a',
                b's', b'd',
            ][..],
        );

        let sequence = Sequence::decode(&mut data).unwrap();
        assert_eq!(
            sequence.name1,
            Name {
                components: vec![
                    GenericNameComponent {
                        name: Bytes::from_static(b"hello")
                    },
                    GenericNameComponent {
                        name: Bytes::from_static(b"ab")
                    },
                ]
            }
        );
        assert_eq!(
            sequence.name2,
            Name {
                components: vec![GenericNameComponent {
                    name: Bytes::from_static(b"asd")
                },]
            }
        );
    }
}
