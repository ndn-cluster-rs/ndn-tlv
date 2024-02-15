use std::io::Read;

use bytes::{BufMut, Bytes, BytesMut};

use crate::{TlvDecode, TlvEncode, TlvError, VarNum};

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

    /// Read a TLV from a type implementing `Read`
    fn from_reader(mut reader: impl Read) -> Result<Self, TlvError>
    where
        Self: TlvDecode,
    {
        let mut header_buf = [0; 18];
        let bytes_read = reader.read(&mut header_buf).map_err(TlvError::IOError)?;
        let mut header_bytes = Bytes::copy_from_slice(&header_buf);

        let typ = VarNum::decode(&mut header_bytes)?;
        if typ.value() as usize != Self::TYP {
            // Technically not necessary, but we can exit early here
            return Err(TlvError::TypeMismatch {
                expected: Self::TYP,
                found: typ.value() as usize,
            });
        }

        let len = VarNum::decode(&mut header_bytes)?;
        let total_len = typ.size() + len.size() + len.value() as usize;

        let mut bytes = BytesMut::with_capacity(total_len);
        bytes.put(&header_buf[0..bytes_read]);

        let mut left_to_read = total_len - bytes_read;
        let mut buf = [0; 1024];
        while left_to_read > 0 {
            let bytes_read = reader
                .read(&mut buf[0..left_to_read])
                .map_err(TlvError::IOError)?;
            bytes.put(&buf[..left_to_read]);
            left_to_read -= bytes_read;
        }

        Self::decode(&mut bytes.freeze())
    }
}

/// Returns whether a TLV is "critical"
///
/// An unknown or out-of-order non-critical TLV can be safely ignored, while a critical TLV must
/// lead to an error
pub const fn tlv_critical<T: Tlv + ?Sized>() -> bool {
    tlv_typ_critical(T::TYP)
}

/// Returns whether a TLV with a given type `typ` is "critical"
///
/// An unknown or out-of-order non-critical TLV can be safely ignored, while a critical TLV must
/// lead to an error
pub const fn tlv_typ_critical(typ: usize) -> bool {
    typ < 32 || typ & 1 == 1
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
            if usize::from(typ) != Self::TYP {
                return Err(TlvError::TypeMismatch {
                    expected: Self::TYP,
                    found: typ.into(),
                });
            }
            let length = VarNum::decode(&mut bytes)?;
            let mut inner_data = bytes.copy_to_bytes(length.into());
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
