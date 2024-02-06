#![doc = include_str!("../README.md")]
#![warn(missing_docs)]

pub use ::bytes;
pub use ::ndn_tlv_derive::Tlv;
use bytes::{Buf, BufMut, Bytes, BytesMut};
pub use error::TlvError;
pub use tlv::Tlv;
pub use tlv::{tlv_critical, tlv_typ_critical};
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

/// Advance `bytes` until a valid TLV record of type `T` is found
///
/// Any unexpected critical TLV records of a different type will lead to an error.
/// Unexpected non-critical TLV records will be ignored.
pub fn find_tlv<T: Tlv>(bytes: &mut Bytes) -> Result<()> {
    let mut cur = bytes.clone();

    while cur.has_remaining() {
        let found_typ = VarNum::decode(&mut cur)?;
        if found_typ.value() == T::TYP {
            return Ok(());
        }

        // Wrong type
        if tlv_typ_critical(found_typ.value()) {
            return Err(TlvError::TypeMismatch {
                expected: T::TYP,
                found: found_typ.value(),
            });
        }

        // non-critical
        let length = VarNum::decode(&mut cur)?;
        cur.advance(length.value());
        bytes.advance(bytes.remaining() - cur.remaining());
    }

    Err(TlvError::UnexpectedEndOfStream)
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
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Eq, PartialEq)]
    pub(crate) struct GenericNameComponent {
        pub(crate) name: Bytes,
    }

    impl Tlv for GenericNameComponent {
        const TYP: usize = 8;

        fn inner_size(&self) -> usize {
            self.name.size()
        }
    }

    impl TlvEncode for GenericNameComponent {
        fn encode(&self) -> Bytes {
            let mut bytes = BytesMut::with_capacity(self.size());
            bytes.put(VarNum::from(Self::TYP).encode());
            bytes.put(VarNum::from(self.inner_size()).encode());
            bytes.put(self.name.encode());

            bytes.freeze()
        }

        fn size(&self) -> usize {
            VarNum::from(Self::TYP).size()
                + VarNum::from(self.inner_size()).size()
                + self.name.size()
        }
    }

    impl TlvDecode for GenericNameComponent {
        fn decode(bytes: &mut Bytes) -> Result<Self> {
            let typ = VarNum::decode(bytes)?;
            if typ.value() != Self::TYP {
                return Err(TlvError::TypeMismatch {
                    expected: Self::TYP,
                    found: typ.value(),
                });
            }
            let length = VarNum::decode(bytes)?;
            let mut inner_data = bytes.copy_to_bytes(length.value());
            let name = Bytes::decode(&mut inner_data)?;

            Ok(Self { name })
        }
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
}
