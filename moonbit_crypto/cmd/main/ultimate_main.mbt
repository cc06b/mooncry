// Ultimate crypto - 主入口测试文件

fn bytes_to_hex(data: Bytes) -> String {
  let hex = "0123456789abcdef"
  let mut result = ""
  let len = data.length()
  let mut i = 0
  while i < len {
    let b = data[i].to_int() & 0xFF
    result = result + hex[(b >> 4) & 0x0F].to_string() + hex[b & 0x0F].to_string()
    i = i + 1
  }
  result
}

fn test_sha256() -> Unit {
  println("=== SHA-256: ultimate 功能测试 ===")
  println("sha256(\"\") = " + bytes_to_hex(sha256_ultimate(b"")))
  println("sha256(abc) = " + bytes_to_hex(sha256_ultimate(b"abc")))
  let data1 = b"0123456789012345678901234567890123456789012345678901234567890123"
  println("sha256(64字节) = " + bytes_to_hex(sha256_ultimate(data1)))
  let data2 = b"0123456789012345678901234567890123456789012345678901234"
  println("sha256(55字节) = " + bytes_to_hex(sha256_ultimate(data2)))
}

fn test_standard_vectors() -> Unit {
  println("=== 标准测试向量验证 ===")
  let expected_empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  let expected_abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

  let empty_hash = bytes_to_hex(sha256_ultimate(b""))
  let abc_hash = bytes_to_hex(sha256_ultimate(b"abc"))

  if empty_hash == expected_empty {
    println("PASS: sha256(\"\") 正确")
  } else {
    println("FAIL: sha256(\"\")")
    println("  expected: " + expected_empty)
    println("  got:      " + empty_hash)
  }

  if abc_hash == expected_abc {
    println("PASS: sha256(\"abc\") 正确")
  } else {
    println("FAIL: sha256(\"abc\")")
    println("  expected: " + expected_abc)
    println("  got:      " + abc_hash)
  }
}

fn test_aes() -> Unit {
  println("=== AES-128 ultimate 测试 ===")
  let key16 = b"0123456789abcdef"
  let plain16 = b"hello world 1234"
  let enc = aes_encrypt_ultimate(plain16, key16)
  println("加密 " + plain16.length().to_string() + " 字节 -> " + enc.length().to_string() + " 字节密文")
  println("hex: " + bytes_to_hex(enc))

  let key_arr = Array::make(16, b'\x00')
  let pt_arr = Array::make(16, b'\x00')
  let mut i = 0
  while i < 16 {
    key_arr[i] = i.to_byte()
    pt_arr[i] = (i * 17).to_byte()
    i = i + 1
  }
  let key_std = Bytes::from_array(key_arr[:])
  let pt_std = Bytes::from_array(pt_arr[:])

  let enc_std = aes_encrypt_ultimate(pt_std, key_std)
  println("AES-128 ECB 标准测试向量:")
  println("  期望: 69c4e0d86a7b0430d8cdb78070b4c55a")
  println("  实际: " + bytes_to_hex(enc_std))

  let expected_aes = "69c4e0d86a7b0430d8cdb78070b4c55a"
  let actual_aes = bytes_to_hex(enc_std)
  if actual_aes == expected_aes {
    println("PASS: AES-128 ECB 标准测试向量正确")
  } else {
    println("FAIL: AES-128 ECB 标准测试向量不匹配")
  }
}

fn main() -> Unit {
  test_sha256()
  println("")
  test_standard_vectors()
  println("")
  test_aes()
  println("")
  println("所有测试完成")
}
