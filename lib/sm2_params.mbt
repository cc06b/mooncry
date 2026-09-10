// SM2 curve parameters (GB/T 32918.5-2017, sm2p256v1) — programmatically
// extracted from openssl ec_curve.c (_EC_sm2p256v1) by _sm2_extract.py and
// verified: a==p-3, G on curve, n*G==infinity, GB standard example re-derived.
// DO NOT EDIT BY HAND.

///|
let sm2_p_hex = "fffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff"

///|
let sm2_n_hex = "fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123"

///|
let sm2_b_hex = "28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93"

///|
let sm2_gx_hex = "32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7"

///|
let sm2_gy_hex = "bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0"
