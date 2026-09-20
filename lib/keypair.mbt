// Named result types shared by the signature and KEM families.

///|
/// A public/secret key pair. A struct rather than `(Bytes, Bytes)` because both
/// halves have the same type: `let (sk, pk) = keygen(...)` compiles, and every
/// signature the program then produces is invalid -- or every verification
/// passes against the wrong key. The fields are read-only outside this package,
/// so a caller can use a key pair but cannot forge one. v0.94.0.
pub struct KeyPair {
  pk : Bytes
  sk : Bytes
}
