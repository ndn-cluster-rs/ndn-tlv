# ndn-tlv

[![docs.rs](https://img.shields.io/docsrs/ndn-tlv)](https://docs.rs/ndn-tlv)
[![crates.io](https://img.shields.io/crates/v/ndn-tlv)](https://crates.io/crates/ndn-tlv)
[![license](https://img.shields.io/crates/l/ndn-tlv)](https://github.com/ndn-cluster-rs/ndn-tlv/blob/master/LICENSE)

Provides abstractions for working with [TLV-encoded data].

It defines the core traits for encoding, decoding, and representing TLV
records, so higher-level NDN crates can (de)serialize their packet types
without hand-rolling the wire format themselves.

## Installation

```
cargo add ndn-tlv
```

## How it works

- [`Tlv`] should be implemented on types that represent a whole TLV record --
  ones that, in their encoded form, start with a type and a length.
- [`TlvEncode`] and [`TlvDecode`] are implemented on any type that can be
  encoded/decoded as part of a TLV record's value, including all types that
  implement [`Tlv`].
- A `Tlv` derive macro (from
  [`ndn-tlv-derive`](https://crates.io/crates/ndn-tlv-derive)) implements all
  three traits for you, so you rarely have to write them by hand. See
  [its documentation](derive@Tlv) for how to use it.

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

## Related crates

- [`ndn-app`](https://crates.io/crates/ndn-app) is an application framework for building NDN producers and consumers, built on top of `ndn-protocol`, `ndn-ndnlp`, and `ndn-nfd-mgmt`.
- [`ndn-tlv-derive`](https://crates.io/crates/ndn-tlv-derive) provides the derive macros `ndn-tlv` uses to generate TLV encoding/decoding for structs and enums.
- [`ndn-protocol`](https://crates.io/crates/ndn-protocol) implements the core NDN packet types (Interest, Data, Names, signatures) on top of `ndn-tlv`.
- [`ndn-ndnlp`](https://crates.io/crates/ndn-ndnlp) implements NDNLPv2, the link-layer protocol used to send NDN packets over a transport.
- [`ndn-nfd-mgmt`](https://crates.io/crates/ndn-nfd-mgmt) implements the NFD management protocol, used e.g. to register routes with a local forwarder.

`ndn-tlv` is the base layer of the stack -- every other crate here builds on it.

## License

MIT

---

Produced as part of a Master's thesis in Computer Science.
