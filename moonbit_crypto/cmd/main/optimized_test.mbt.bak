
// 测试优化后的加密库
fn bytes_to_hex(data: Bytes) -> String {
  let hex_chars = "0123456789abcdef"
  let len = data.length()
  let mut result = ""
  for i in 0..len {
    let byte = data[i].to_int()
    let hi = (byte >> 4) & 0x0F
    let lo = byte & 0x0F
    let hi_char = if hi < 10 { ('0'.to_int() + hi) } else { ('a'.to_int() + hi - 10) }
    let lo_char = if lo < 10 { ('0'.to_int() + lo) } else { ('a'.to_int() + lo - 10) }
    result = result + (hi_char.to_char().unwrap()).to_string() + (lo_char.to_char().unwrap()).to_string()
  }
  result
}

fn main() {
  println("=== MoonBit 加密库优化版本测试 ===")
  
  println("\n1. SHA-256 测试:")
  let test_data = b"Hello, MoonBit!"
  let hash = sha256(test_data)
  println("输入: Hello, MoonBit!")
  println("哈希: " + bytes_to_hex(hash))
  
  println("\n2. HMAC-SHA256 测试:")
  let key = b"test_key_123"
  let message = b"secret_message"
  let hmac = hmac_sha256(key, message)
  println("HMAC: " + bytes_to_hex(hmac))
  
  println("\n3. AES-128-ECB 测试:")
  let aes_key = b"\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c"
  let plaintext = b"Test AES ECB!"
  
  let encrypted = aes_encrypt_ecb(plaintext, aes_key)
  println("加密: " + bytes_to_hex(encrypted))
  
  let decrypted = aes_decrypt_ecb(encrypted, aes_key)
  println("解密: " + bytes_to_hex(decrypted))
  
  println("\n=== 所有测试完成! ===")
}
