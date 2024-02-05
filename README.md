Provides abstractions for working with [TLV-encoded data]

Data that may appear as part of a TLV record should implement [`TlvEncode`] and
[`TlvDecode`]. Types that represent a whole TLV record should implement [`Tlv`]
in addition to [`TlvEncode`] and [`TlvDecode`]

## Example
```
#[derive(Debug)]
struct GenericNameComponent {
    typ: VarNum,
    length: VarNum,
    name: Bytes,
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
    fn decode(mut bytes: impl Buf) -> Result<Self> {
        let typ = VarNum::decode(&mut bytes)?;
        if typ.value() != Self::TYP {
            return Err(TlvError::TypeMismatch {
                expected: Self::TYP,
                found: typ.value(),
            });
        }
        let length = VarNum::decode(&mut bytes)?;
        let mut inner_data = bytes.copy_to_bytes(length.value());
        let name = Bytes::decode(&mut inner_data)?;

        Ok(Self { typ, length, name })
    }
}

#[derive(Debug)]
struct Name {
    typ: VarNum,
    length: VarNum,
    components: Vec<GenericNameComponent>,
}

impl Tlv for Name {
    const TYP: usize = 7;
}

impl TlvDecode for Name {
    fn decode(mut bytes: impl Buf) -> Result<Self> {
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

        Ok(Self {
            typ,
            length,
            components,
        })
    }
}

impl TlvEncode for Name {
    fn encode(&self) -> Bytes {
        let mut bytes = BytesMut::with_capacity(self.size());
        bytes.put(self.typ.encode());
        bytes.put(self.length.encode());
        bytes.put(self.components.encode());

        bytes.freeze()
    }

    fn size(&self) -> usize {
        self.typ.size() + self.length.size() + self.components.size()
    }
}
```

[TLV-encoded data]: https://docs.named-data.net/NDN-packet-spec/current/tlv.html
