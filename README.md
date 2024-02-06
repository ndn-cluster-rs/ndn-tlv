Provides abstractions for working with [TLV-encoded data]

Data that may appear as part of a TLV record should implement [`TlvEncode`] and
[`TlvDecode`]. Types that represent a whole TLV record should implement [`Tlv`]
in addition to [`TlvEncode`] and [`TlvDecode`]

## Example
Here is a quick example of how the library may be used:
```rust
use bytes::{Buf, BufMut, Bytes, BytesMut};
use ndn_tlv::{Tlv, TlvEncode, TlvDecode, Result, VarNum, TlvError};

#[derive(Debug, Eq, PartialEq, Tlv)]
#[tlv(8)]
struct GenericNameComponent {
    typ: VarNum,
    length: VarNum,
    name: Bytes,
}

#[derive(Debug, Tlv)]
#[tlv(7)]
struct Name {
    typ: VarNum,
    length: VarNum,
    components: Vec<GenericNameComponent>,
}
```

Or, if you prefer not to use the derive functionality:
```rust
use bytes::{Buf, BufMut, Bytes, BytesMut};
use ndn_tlv::{Tlv, TlvEncode, TlvDecode, Result, VarNum, TlvError};

#[derive(Debug, Eq, PartialEq)]
struct GenericNameComponent {
    name: Bytes,
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
```

[TLV-encoded data]: https://docs.named-data.net/NDN-packet-spec/current/tlv.html
