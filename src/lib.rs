#![doc = include_str!("../README.md")]
#![warn(missing_docs)]

use bytes::{Buf, BufMut, Bytes, BytesMut};
pub use error::TlvError;
pub use tlv::tlv_critical;
pub use tlv::Tlv;
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
                Err(e) => return Err(e),
            }
        }
        Ok(ret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Eq, PartialEq)]
    pub(crate) struct GenericNameComponent {
        pub(crate) typ: VarNum,
        pub(crate) length: VarNum,
        pub(crate) name: Bytes,
    }

    impl Tlv for GenericNameComponent {
        const TYP: usize = 8;
    }

    impl TlvEncode for GenericNameComponent {
        fn encode(&self) -> Bytes {
            let mut bytes = BytesMut::with_capacity(self.size());
            bytes.put(self.typ.encode());
            bytes.put(self.length.encode());
            bytes.put(self.name.encode());

            bytes.freeze()
        }

        fn size(&self) -> usize {
            self.typ.size() + self.length.size() + self.name.size()
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

            Ok(Self { typ, length, name })
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    struct CanBePrefix {
        typ: VarNum,
        length: VarNum,
    }

    impl Tlv for CanBePrefix {
        const TYP: usize = 33;
    }

    impl TlvEncode for CanBePrefix {
        fn encode(&self) -> Bytes {
            let mut bytes = BytesMut::with_capacity(self.size());

            bytes.put(self.typ.encode());
            bytes.put(self.length.encode());

            bytes.freeze()
        }

        fn size(&self) -> usize {
            self.typ.size() + self.length.size()
        }
    }

    impl TlvDecode for CanBePrefix {
        fn decode(bytes: &mut Bytes) -> Result<Self> {
            let typ = VarNum::decode(bytes)?;
            if typ.value() != Self::TYP {
                return Err(TlvError::TypeMismatch {
                    expected: Self::TYP,
                    found: typ.value(),
                });
            }
            let length = VarNum::decode(bytes)?;
            // No error variant for this case, as it only appears in test code
            assert_eq!(length.value(), 0);

            Ok(Self { typ, length })
        }
    }

    #[derive(PartialEq, Eq)]
    struct VecPartial {
        typ: VarNum,
        length: VarNum,
        components: Vec<GenericNameComponent>,
        can_be_prefix: CanBePrefix,
    }

    impl Tlv for VecPartial {
        const TYP: usize = 129;
    }

    impl TlvEncode for VecPartial {
        fn encode(&self) -> Bytes {
            let mut bytes = BytesMut::with_capacity(self.size());

            bytes.put(self.typ.encode());
            bytes.put(self.length.encode());
            bytes.put(self.components.encode());
            bytes.put(self.can_be_prefix.encode());

            bytes.freeze()
        }

        fn size(&self) -> usize {
            self.typ.size()
                + self.length.size()
                + self.components.size()
                + self.can_be_prefix.size()
        }
    }

    impl TlvDecode for VecPartial {
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
            let components = Vec::<GenericNameComponent>::decode(&mut inner_data)?;
            let can_be_prefix = CanBePrefix::decode(&mut inner_data)?;

            Ok(Self {
                typ,
                length,
                components,
                can_be_prefix,
            })
        }
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
        assert_eq!(
            partial.can_be_prefix,
            CanBePrefix {
                typ: VarNum::from(33usize),
                length: VarNum::from(0usize)
            }
        );
    }
}
