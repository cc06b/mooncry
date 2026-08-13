// cSHAKE128/256 and KMAC128/256/XOF vectors. Generated with
// pycryptodome (authoritative SP 800-185 implementation), including
// the official NIST samples below; the KMAC bytepad/encode_string
// construction was additionally differential-tested against
// pycryptodome over 400 random inputs before these vectors were
// committed.

///|
/// SP 800-185 sample key K = 40 41 ... 5f (32 bytes)
let sp185_kmac_key : Bytes = hex_to_bytes(
  "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
)

///|
/// Bytes 00 01 ... n-1
fn sp185_range_bytes(n : Int) -> Bytes {
  let arr = Array::make(n, b'\x00')
  for i in 0..<n {
    arr[i] = i.to_byte()
  }
  Bytes::from_array(arr[:])
}

// ==================== cSHAKE128 (S='Email Signature') ====================

///|
test "cSHAKE128: empty, S=Email Signature" {
  let expected = hex_to_bytes(
    "22af17860970726beae182499c8cf8c2f17700f9856d1ea0d01f489c18b5b9d5",
  )
  assert_true(
    bytes_equal(expected, cshake_128(b"", b"", b"Email Signature", 32)),
  )
}

///|
test "cSHAKE128: abc, S=Email Signature" {
  let expected = hex_to_bytes(
    "d7a9b8839577422dbe3ef0bdd0cc835090552f62a53d4f354b6ba618c6c22b2b",
  )
  assert_true(
    bytes_equal(expected, cshake_128(b"abc", b"", b"Email Signature", 32)),
  )
}

///|
test "cSHAKE128: fox, S=Email Signature" {
  let expected = hex_to_bytes(
    "9983d072c4fddcd9b1174e11a65311a5ff5ec822d2a94a722c28610d5d2eea16",
  )
  assert_true(
    bytes_equal(
      expected,
      cshake_128(
        b"The quick brown fox jumps over the lazy dog", b"", b"Email Signature",
        32,
      ),
    ),
  )
}

///|
test "cSHAKE128: 32B sequence, S=Email Signature" {
  let expected = hex_to_bytes(
    "abee1866a6a37dbe66ec39b4a38ea15544330e00006f4bc4eaa8e592c01d06dc",
  )
  assert_true(
    bytes_equal(
      expected,
      cshake_128(sp185_range_bytes(32), b"", b"Email Signature", 32),
    ),
  )
}

///|
test "cSHAKE128: 200B output spans a second squeeze block" {
  let expected = hex_to_bytes(
    "d7a9b8839577422dbe3ef0bdd0cc835090552f62a53d4f354b6ba618c6c22b2b0168a37996dc06179c6378f8e095daaa5507907bf794bde9c4db94a147e50979084647da8e5713fbef57f814a7546028cd92f4cfc9452e1dec92afd4ab3c9ed655f75245dce3c1f4d3e7c0e639f4ed91c66f078d1c94abdac8ff32e69447d9b657c32b8be7b4392ad32ca1e3aef8e1e189b1f90d737995f3af8f32ed1ce1a3683d78324369a1c21ec16f9def3e991e646ec28ba779601bbcc5d3eca5ac1da59d65d5b699330e5221",
  )
  assert_true(
    bytes_equal(expected, cshake_128(b"abc", b"", b"Email Signature", 200)),
  )
}

// ==================== cSHAKE256 (S='Email Signature') ====================

///|
test "cSHAKE256: empty, S=Email Signature" {
  let expected = hex_to_bytes(
    "a8dd3ab039e3926f6f22c130ef305c2f47a7fe8eb85f93433961c6fe1637619b",
  )
  assert_true(
    bytes_equal(expected, cshake_256(b"", b"", b"Email Signature", 32)),
  )
}

///|
test "cSHAKE256: abc, S=Email Signature" {
  let expected = hex_to_bytes(
    "5582a53550e5a311b65d012336439a011df1185437766283adb2bc7d73ad0d80",
  )
  assert_true(
    bytes_equal(expected, cshake_256(b"abc", b"", b"Email Signature", 32)),
  )
}

///|
test "cSHAKE256: fox, S=Email Signature" {
  let expected = hex_to_bytes(
    "a0ef16207fee1f24102bbf54478daec5cc31eeacd6a0f4636ca57e69c7318f5e",
  )
  assert_true(
    bytes_equal(
      expected,
      cshake_256(
        b"The quick brown fox jumps over the lazy dog", b"", b"Email Signature",
        32,
      ),
    ),
  )
}

///|
test "cSHAKE256: 32B sequence, S=Email Signature" {
  let expected = hex_to_bytes(
    "e7ae23123e1130836ec96121abb008b9e9a6e01d8d11c955cc13322cc905c129",
  )
  assert_true(
    bytes_equal(
      expected,
      cshake_256(sp185_range_bytes(32), b"", b"Email Signature", 32),
    ),
  )
}

///|
test "cSHAKE256: 200B output spans a second squeeze block" {
  let expected = hex_to_bytes(
    "5582a53550e5a311b65d012336439a011df1185437766283adb2bc7d73ad0d80d574d0aa905045a093c5f3a6234c4694d4e5550a75e2bc3592277aae36d3bf8d3ee0dcfd141f244c7898548a07f763ad15c28cea261e62a1385b7343fa929f961a32fcefe80332981da1a8ec0a4e61e39cf7e87626cc47a1afd9745a72550e2b833f20747ee22f099bb0a376a5324bc878c621f456440989760b732b7447c7d73644c72be5b6246cbc31d1cac9ee9210ca9787a876131e4890991066b005810537301032c8a1a286",
  )
  assert_true(
    bytes_equal(expected, cshake_256(b"abc", b"", b"Email Signature", 200)),
  )
}

// ==================== cSHAKE with non-empty N ====================

///|
test "cSHAKE128: abc, N=MyApp, S=Email Signature" {
  let expected = hex_to_bytes(
    "9358d4e526ca7860594bf607411d282d24242115f335dc5ffbdf7bdceee2af9b",
  )
  assert_true(
    bytes_equal(expected, cshake_128(b"abc", b"MyApp", b"Email Signature", 32)),
  )
}

///|
test "cSHAKE128: 32B sequence, N=MyApp, S=Email Signature" {
  let expected = hex_to_bytes(
    "c17ad80856aeb1ab401dbdeac6138d417314cd938dba6c9a01def9a668908c8b",
  )
  assert_true(
    bytes_equal(
      expected,
      cshake_128(sp185_range_bytes(32), b"MyApp", b"Email Signature", 32),
    ),
  )
}

///|
test "cSHAKE128: N or S alone still uses domain 0x04" {
  // N-only and S-only must differ from each other and from SHAKE
  let n_only = cshake_128(b"abc", b"MyApp", b"", 32)
  let s_only = cshake_128(b"abc", b"", b"MyApp", 32)
  assert_true(!bytes_equal(n_only, s_only))
  assert_true(!bytes_equal(n_only, shake_128(b"abc", 32)))
}

// ==================== cSHAKE degeneration to SHAKE ====================

///|
test "cSHAKE128: N=S='' equals SHAKE128 (SP 800-185 §3.3)" {
  let expected = hex_to_bytes(
    "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8",
  )
  assert_true(bytes_equal(expected, cshake_128(b"abc", b"", b"", 32)))
  assert_true(
    bytes_equal(shake_128(b"abc", 32), cshake_128(b"abc", b"", b"", 32)),
  )
}

///|
test "cSHAKE256: N=S='' equals SHAKE256 (SP 800-185 §3.3)" {
  let expected = hex_to_bytes(
    "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739",
  )
  assert_true(bytes_equal(expected, cshake_256(b"abc", b"", b"", 32)))
  assert_true(
    bytes_equal(shake_256(b"abc", 32), cshake_256(b"abc", b"", b"", 32)),
  )
}

// ==================== KMAC128 (L=32) ====================

///|
test "KMAC128: empty, S=My Tagged Application" {
  let expected = hex_to_bytes(
    "24b1b73ed929b066458e446ed9e83edab5edd1183803bc4cb15974b852c75986",
  )
  assert_true(
    bytes_equal(
      expected,
      kmac_128(sp185_kmac_key, b"", b"My Tagged Application", 32),
    ),
  )
}

///|
test "KMAC128: abc, S=My Tagged Application" {
  let expected = hex_to_bytes(
    "3c688e215f54b9c4097a8a237ff6d02b9b223c0bd7390c5db9c1633ad59aa3ab",
  )
  assert_true(
    bytes_equal(
      expected,
      kmac_128(sp185_kmac_key, b"abc", b"My Tagged Application", 32),
    ),
  )
}

///|
test "KMAC128: SP 800-185 sample 1 (X=00010203, S='')" {
  let expected = hex_to_bytes(
    "e5780b0d3ea6f7d3a429c5706aa43a00fadbd7d49628839e3187243f456ee14e",
  )
  assert_true(
    bytes_equal(
      expected,
      kmac_128(sp185_kmac_key, hex_to_bytes("00010203"), b"", 32),
    ),
  )
}

///|
test "KMAC128: SP 800-185 sample 2 (X=00010203, S=tag)" {
  let expected = hex_to_bytes(
    "3b1fba963cd8b0b59e8c1a6d71888b7143651af8ba0a7070c0979e2811324aa5",
  )
  assert_true(
    bytes_equal(
      expected,
      kmac_128(
        sp185_kmac_key,
        hex_to_bytes("00010203"),
        b"My Tagged Application",
        32,
      ),
    ),
  )
}

///|
test "KMAC128: SP 800-185 sample 3 (200-byte X, S=tag)" {
  let expected = hex_to_bytes(
    "1f5b4e6cca02209e0dcb5ca635b89a15e271ecc760071dfd805faa38f9729230",
  )
  assert_true(
    bytes_equal(
      expected,
      kmac_128(
        sp185_kmac_key,
        sp185_range_bytes(200),
        b"My Tagged Application",
        32,
      ),
    ),
  )
}

///|
test "KMAC128: tag length follows out_len" {
  let tag48 = kmac_128(sp185_kmac_key, b"abc", b"", 48)
  assert_true(tag48.length() == 48)
}

// ==================== KMAC256 (L=64) ====================

///|
test "KMAC256: empty, S=My Tagged Application" {
  let expected = hex_to_bytes(
    "f12190a222ce9926846da2743613c5373d09fe067e6ccbc54bebf69bf5c5da2541e0206756f100f97bcd8a431fadab8fcd052d27b7c2e0f0cfc3eecfa0a0e729",
  )
  assert_true(
    bytes_equal(
      expected,
      kmac_256(sp185_kmac_key, b"", b"My Tagged Application", 64),
    ),
  )
}

///|
test "KMAC256: abc, S=My Tagged Application" {
  let expected = hex_to_bytes(
    "398ed759372d877429f0fd6f6a1bd6f4072cb64ab95a1b3554412dcd8bbddf714ad94dbc0f67c13721f6244a4a9bb49f64f2cb9d271fff07b4a3a91d81211dc1",
  )
  assert_true(
    bytes_equal(
      expected,
      kmac_256(sp185_kmac_key, b"abc", b"My Tagged Application", 64),
    ),
  )
}

///|
test "KMAC256: X=00010203, S=My Tagged Application" {
  let expected = hex_to_bytes(
    "20c570c31346f703c9ac36c61c03cb64c3970d0cfc787e9b79599d273a68d2f7f69d4cc3de9d104a351689f27cf6f5951f0103f33f4f24871024d9c27773a8dd",
  )
  assert_true(
    bytes_equal(
      expected,
      kmac_256(
        sp185_kmac_key,
        hex_to_bytes("00010203"),
        b"My Tagged Application",
        64,
      ),
    ),
  )
}

///|
test "KMAC256: 200-byte X, S=My Tagged Application" {
  let expected = hex_to_bytes(
    "b58618f71f92e1d56c1b8c55ddd7cd188b97b4ca4d99831eb2699a837da2e4d970fbacfde50033aea585f1a2708510c32d07880801bd182898fe476876fc8965",
  )
  assert_true(
    bytes_equal(
      expected,
      kmac_256(
        sp185_kmac_key,
        sp185_range_bytes(200),
        b"My Tagged Application",
        64,
      ),
    ),
  )
}

// ==================== KMACXOF128 / KMACXOF256 ====================

///|
test "KMACXOF128: X=00010203, S=My Tagged Application" {
  let expected = hex_to_bytes(
    "31a44527b4ed9f5c6101d11de6d26f0620aa5c341def41299657fe9df1a3b16c",
  )
  assert_true(
    bytes_equal(
      expected,
      kmac_xof_128(
        sp185_kmac_key,
        hex_to_bytes("00010203"),
        b"My Tagged Application",
        32,
      ),
    ),
  )
}

///|
test "KMACXOF128: X=00010203, S=''" {
  let expected = hex_to_bytes(
    "cd83740bbd92ccc8cf032b1481a0f4460e7ca9dd12b08a0c4031178bacd6ec35",
  )
  assert_true(
    bytes_equal(
      expected,
      kmac_xof_128(sp185_kmac_key, hex_to_bytes("00010203"), b"", 32),
    ),
  )
}

///|
test "KMACXOF128: 200-byte X, S=My Tagged Application" {
  let expected = hex_to_bytes(
    "47026c7cd793084aa0283c253ef658490c0db61438b8326fe9bddf281b83ae0f",
  )
  assert_true(
    bytes_equal(
      expected,
      kmac_xof_128(
        sp185_kmac_key,
        sp185_range_bytes(200),
        b"My Tagged Application",
        32,
      ),
    ),
  )
}

///|
test "KMACXOF256: X=00010203, S=My Tagged Application" {
  let expected = hex_to_bytes(
    "1755133f1534752aad0748f2c706fb5c784512cab835cd15676b16c0c6647fa96faa7af634a0bf8ff6df39374fa00fad9a39e322a7c92065a64eb1fb0801eb2b",
  )
  assert_true(
    bytes_equal(
      expected,
      kmac_xof_256(
        sp185_kmac_key,
        hex_to_bytes("00010203"),
        b"My Tagged Application",
        64,
      ),
    ),
  )
}

///|
test "KMACXOF256: 200-byte X, S=My Tagged Application" {
  let expected = hex_to_bytes(
    "d5be731c954ed7732846bb59dbe3a8e30f83e77a4bff4459f2f1c2b4ecebb8ce67ba01c62e8ab8578d2d499bd1bb276768781190020a306a97de281dcc30305d",
  )
  assert_true(
    bytes_equal(
      expected,
      kmac_xof_256(
        sp185_kmac_key,
        sp185_range_bytes(200),
        b"My Tagged Application",
        64,
      ),
    ),
  )
}

///|
test "KMAC vs KMACXOF: same input, different encoding" {
  // right_encode(L) vs right_encode(0) must change the output
  assert_true(
    !bytes_equal(
      kmac_128(sp185_kmac_key, b"abc", b"", 32),
      kmac_xof_128(sp185_kmac_key, b"abc", b"", 32),
    ),
  )
}

// ==================== squeeze regression (out > rate) ====================
// Regression for the sponge squeeze loop: only `rate` bytes may be
// read per permutation round. Outputs longer than the rate previously
// read into the capacity lanes instead of re-permuting.

///|
test "SHAKE128: 200B output squeezes a second block (one-shot)" {
  let expected = hex_to_bytes(
    "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc844c50af32acd3f2cdd066568706f509bc1bdde58295dae3f891a9a0fca5783789a41f8611214ce612394df286a62d1a2252aa94db9c538956c717dc2bed4f232a0294c857c730aa16067ac1062f1201fb0d377cfb9cde4c63599b27f3462bba4a0ed296c801f9ff7f57302bb3076ee145f97a32ae68e76ab66c48d51675bd49acc29082f5647584e6aa01b3f5af057805f973ff8ecb8b226ac32ada6f01c1fcd4818cb006aa5b4cd",
  )
  assert_true(bytes_equal(expected, shake_128(b"abc", 200)))
}

///|
test "SHAKE256: 200B output squeezes a second block (one-shot)" {
  let expected = hex_to_bytes(
    "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e41385141204f329979fd3047a13c5657724ada64d2470157b3cdc288620944d78dbcddbd912993f0913f164fb2ce95131a2d09a3e6d51cbfc622720d7a75c6334e8a2d7ec71a7cc29cf0ea610eeff1a588290a53000faa79932becec0bd3cd0b33a7e5d397fed1ada9442b99903f4dcfd8559ed3950faf40fe6f3b5d710ed3b677513771af6bfe119",
  )
  assert_true(bytes_equal(expected, shake_256(b"abc", 200)))
}
