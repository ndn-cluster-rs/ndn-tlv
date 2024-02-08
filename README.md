Provides abstractions for working with [TLV-encoded data]

Data that may appear as part of a TLV record should implement [`TlvEncode`] and
[`TlvDecode`]. Types that represent a whole TLV record should implement [`Tlv`]
in addition to [`TlvEncode`] and [`TlvDecode`]

At the core of the library are the three traits [`Tlv`], `[TlvEncode`], and
[`TlvDecode`].

[`Tlv`] should be implemented on types that represent a TLV
record. In other words, types that, in their encoded form, start with a type
and a length.

[`TlvEncode`] and [`TlvDecode`] are used for types that can be encoded/decoded
and may appear in TLV records. All types implementing [`Tlv`] should also
implement [`TlvEncode`] and [`TlvDecode`].

To ease implementing these traits, a derive macro `Tlv` is made available.
Simply derive it on an enum to automatically implement [`TlvEncode`] and
[`TlvDecode`]. On structs, an attribute must be present to set the type ID of
the TLV that this struct represents. [`Tlv`] will also be implemented on
structs. Deriving [`TlvEncode`] and [`TlvDecode`] on structs without [`Tlv`] is
not currently supported.

Please note that this library is under active development and the API is not
stable.

## Example

Here is a quick example of how the library may be used:

```rust
use bytes::{Buf, BufMut, Bytes, BytesMut};
use ndn_tlv::{Tlv, TlvEncode, TlvDecode, Result, VarNum, TlvError};

#[derive(Debug, Tlv, PartialEq)]
#[tlv(8)]
struct GenericNameComponent {
    name: Bytes,
}

#[derive(Debug, Tlv, PartialEq)]
#[tlv(1)]
struct ImplicitSha256DigestComponent {
    name: Bytes,
}

#[derive(Debug, Tlv, PartialEq)]
enum NameComponent {
    GenericNameComponent(GenericNameComponent),
    ImplicitSha256DigestComponent(ImplicitSha256DigestComponent),
}

#[derive(Debug, Tlv, PartialEq)]
#[tlv(7)]
struct Name {
    components: Vec<NameComponent>,
}

fn main() {
    let name = Name {
        components: vec![
            NameComponent::GenericNameComponent(GenericNameComponent {
                name: Bytes::from(&b"hello"[..])
            }),
            NameComponent::GenericNameComponent(GenericNameComponent {
                name: Bytes::from(&b"world"[..])
            }),
        ]
    };

    let data = name.encode();
    assert_eq!(data, &[
            7, 14, 8, 5, b'h', b'e', b'l', b'l', b'o',
                   8, 5, b'w', b'o', b'r', b'l', b'd'
        ][..]);
    let decoded = Name::decode(&mut data.clone()).unwrap();
    assert_eq!(decoded, name);
}
```

[TLV-encoded data]: https://docs.named-data.net/NDN-packet-spec/current/tlv.html
