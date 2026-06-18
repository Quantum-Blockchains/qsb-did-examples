# QSB DID Examples

This directory contains example clients for the QSB DID and Schema pallets:

- `python_example/`
- `js_example/`

Both examples target `qsb-node` main at commit
`2bdb50360fc21ed4ece841b122f7d9368bd5b15c` and follow the local
`qsb-did-specifications/README.md` method specification.

The DID examples use:

- Multikey ML-DSA-44 for DID creation and the `#update` key,
- `KeyMaterialInput::Multikey` and `KeyMaterialInput::Jwk` when the connected
  runtime exposes the current key material API,
- legacy Multikey-only key calls when the connected runtime still exposes
  `public_key` arguments,
- full DID strings (`did:qsb:<id>`) for DID identifiers,
- key ids as DID URLs (`did:qsb:<id>#fragment`) for revoke, rotate, and role updates,
- `did_getByString` for raw DID state lookup, with direct `Did.DidRecords`
  storage fallback in the example resolvers.

Both examples run a full lifecycle demo and deactivate the DID near the end.
For another full run, remove the configured `DID_STORE_PATH` file or point it to
a new path.
