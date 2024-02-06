/// A TLV record
pub trait Tlv {
    /// The assigned type number for this TLV record
    const TYP: usize;

    /// The size of the payload contained within this TLV
    ///
    /// Does not include the bytes used for type and length and should be equal to the length value
    /// in the packet.
    fn inner_size(&self) -> usize;

    /// Whether the TLV is critical, see [`tlv_critical`]
    fn critical() -> bool {
        tlv_critical::<Self>()
    }
}

/// Returns whether a TLV is "critical"
///
/// An unknown or out-of-order non-critical TLV can be safely ignored, while a critical TLV must
/// lead to an error
pub const fn tlv_critical<T: Tlv + ?Sized>() -> bool {
    T::TYP < 32 || T::TYP & 1 == 1
}

#[cfg(test)]
mod tests {
    use bytes::{Buf, BufMut, Bytes, BytesMut};

    use crate::tests::GenericNameComponent;
    use crate::{error::TlvError, Result, TlvDecode, TlvEncode, VarNum};

    use super::*;

    #[derive(Debug)]
    struct Name {
        components: Vec<GenericNameComponent>,
    }

    impl Tlv for Name {
        const TYP: usize = 7;

        fn inner_size(&self) -> usize {
            self.components.size()
        }
    }

    impl TlvDecode for Name {
        fn decode(mut bytes: &mut Bytes) -> Result<Self> {
            let typ = VarNum::decode(&mut bytes)?;
            if typ.value() != Self::TYP {
                return Err(TlvError::TypeMismatch {
                    expected: Self::TYP,
                    found: typ.value(),
                });
            }
            let length = VarNum::decode(&mut bytes)?;
            let mut inner_data = bytes.copy_to_bytes(length.value());
            let components = Vec::<GenericNameComponent>::decode(&mut inner_data)?;

            Ok(Self { components })
        }
    }

    impl TlvEncode for Name {
        fn encode(&self) -> Bytes {
            let mut bytes = BytesMut::with_capacity(self.size());
            bytes.put(VarNum::from(Self::TYP).encode());
            bytes.put(VarNum::from(self.inner_size()).encode());
            bytes.put(self.components.encode());

            bytes.freeze()
        }

        fn size(&self) -> usize {
            VarNum::from(Self::TYP).size()
                + VarNum::from(self.inner_size()).size()
                + self.components.size()
        }
    }

    #[test]
    fn generic_name_component() {
        let mut data = Bytes::from(&[8, 5, b'h', b'e', b'l', b'l', b'o', 255, 255, 255][..]);
        let component = GenericNameComponent::decode(&mut data).unwrap();

        assert_eq!(data.remaining(), 3);
        assert_eq!(component.name, &b"hello"[..]);
    }

    #[test]
    fn wrong_type() {
        let mut data = Bytes::from(&[9, 5, b'h', b'e', b'l', b'l', b'o', 255, 255, 255][..]);
        let component = GenericNameComponent::decode(&mut data);

        assert!(component.is_err());
        let error = component.unwrap_err();

        assert_eq!(
            error,
            TlvError::TypeMismatch {
                expected: 8,
                found: 9
            }
        );
    }

    #[test]
    fn name() {
        let mut data = Bytes::from(
            &[
                7, 14, 8, 5, b'h', b'e', b'l', b'l', b'o', 8, 5, b'w', b'o', b'r', b'l', b'd', 255,
                255, 255,
            ][..],
        );
        let name = Name::decode(&mut data).unwrap();

        assert_eq!(data.remaining(), 3);
        assert_eq!(name.components.len(), 2);
        assert_eq!(name.components[0].name, &b"hello"[..]);
        assert_eq!(name.components[1].name, &b"world"[..]);
    }
}
