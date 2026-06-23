// 测试 MoonBit Crypto Library 新的模块化API

fn main() -> Unit {
  println("=" * 70)
  println("MoonBit Crypto Library API 测试")
  println("=" * 70)
  println()
  
  // 1. 测试 SHA-256 模块
  println("1. 测试 SHA-256")
  println("-" * 50)
  let data = b"Hello, World!"
  let hash = @sha256.sha256(data)
  println("原始数据: " + @sha256.bytes_to_hex(data))
  println("SHA-256: " + @sha256.bytes_to_hex(hash))
  println("✓ SHA-256 运行成功")
  println()
  
  // 2. 测试 AES 模块
  println("2. 测试 AES-ECB")
  println("-" * 50)
  let key = b"\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c"
  let plaintext = b"Hello, MoonBit Crypto!"
  
  let encrypted_ecb = @aes.encrypt_ecb(plaintext, key)
  let decrypted_ecb = @aes.decrypt_ecb(encrypted_ecb, key)
  
  println("密钥: " + @sha256.bytes_to_hex(key))
  println("明文: " + @sha256.bytes_to_hex(plaintext))
  println("加密: " + @sha256.bytes_to_hex(encrypted_ecb))
  println("解密: " + @sha256.bytes_to_hex(decrypted_ecb))
  
  let ecb_ok = decrypted_ecb == plaintext
  println((if ecb_ok then "✓" else "✗") + " ECB 测试 " + (if ecb_ok then "通过" else "失败"))
  println()
  
  // 3. 测试 CBC
  println("3. 测试 AES-CBC")
  println("-" * 50)
  let iv = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
  
  let encrypted_cbc = @aes.encrypt_cbc(plaintext, key, iv)
  let decrypted_cbc = @aes.decrypt_cbc(encrypted_cbc, key, iv)
  
  println("IV: " + @sha256.bytes_to_hex(iv))
  println("明文: " + @sha256.bytes_to_hex(plaintext))
  println("加密: " + @sha256.bytes_to_hex(encrypted_cbc))
  println("解密: " + @sha256.bytes_to_hex(decrypted_cbc))
  
  let cbc_ok = decrypted_cbc == plaintext
  println((if cbc_ok then "✓" else "✗") + " CBC 测试 " + (if cbc_ok then "通过" else "失败"))
  println()
  
  // 4. 测试 HMAC
  println("4. 测试 HMAC-SHA256")
  println("-" * 50)
  let hmac_key = b"secret-test-key"
  let hmac_message = b"Important data that needs authentication"
  
  let mac = @hmac.hmac_sha256(hmac_key, hmac_message)
  
  println("密钥: " + @sha256.bytes_to_hex(hmac_key))
  println("消息: " + @sha256.bytes_to_hex(hmac_message))
  println("HMAC: " + @sha256.bytes_to_hex(mac))
  println("✓ HMAC 运行成功")
  println()
  
  // 总结
  println("=" * 70)
  let all_ok = ecb_ok && cbc_ok
  println("总测试结果: " + (if all_ok then "✓ 所有测试通过!" else "✗ 部分测试失败"))
  println("=" * 70)
}
