// MoonBit Crypto Library 使用示例
// 展示所有公开API的用法

fn main() -> Unit {
  println("=" * 70)
  println("MoonBit Crypto Library API 使用示例")
  println("=" * 70)
  println()
  
  // 1. SHA-256 哈希
  println("1. SHA-256 哈希")
  println("-" * 50)
  let message = b"Hello, World!"
  let hash = @crypto.sha256(message)
  println("原始消息: " + @crypto.bytes_to_hex(message))
  println("SHA-256哈希: " + @crypto.bytes_to_hex(hash))
  println()
  
  // 2. AES-ECB 加密
  println("2. AES-ECB 加密/解密")
  println("-" * 50)
  let aes_key = b"\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c"
  let plaintext = b"Hello, AES!"
  
  let encrypted = @crypto.encrypt_aes_ecb(plaintext, aes_key)
  let decrypted = @crypto.decrypt_aes_ecb(encrypted, aes_key)
  
  println("密钥: " + @crypto.bytes_to_hex(aes_key))
  println("明文: " + @crypto.bytes_to_hex(plaintext))
  println("加密: " + @crypto.bytes_to_hex(encrypted))
  println("解密: " + @crypto.bytes_to_hex(decrypted))
  println()
  
  // 3. AES-CBC 加密
  println("3. AES-CBC 加密/解密")
  println("-" * 50)
  let iv = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
  let plaintext_cbc = b"Hello, CBC mode!"
  
  let encrypted_cbc = @crypto.encrypt_aes_cbc(plaintext_cbc, aes_key, iv)
  let decrypted_cbc = @crypto.decrypt_aes_cbc(encrypted_cbc, aes_key, iv)
  
  println("IV: " + @crypto.bytes_to_hex(iv))
  println("明文: " + @crypto.bytes_to_hex(plaintext_cbc))
  println("加密: " + @crypto.bytes_to_hex(encrypted_cbc))
  println("解密: " + @crypto.bytes_to_hex(decrypted_cbc))
  println()
  
  // 4. HMAC-SHA256
  println("4. HMAC-SHA256 消息认证")
  println("-" * 50)
  let hmac_key = b"secret-key"
  let hmac_message = b"Hello, HMAC!"
  
  let hmac = @crypto.hmac_sha256(hmac_key, hmac_message)
  
  println("密钥: " + @crypto.bytes_to_hex(hmac_key))
  println("消息: " + @crypto.bytes_to_hex(hmac_message))
  println("HMAC: " + @crypto.bytes_to_hex(hmac))
  println()
  
  // 5. 字符串转换
  println("5. 工具函数")
  println("-" * 50)
  let str = "Hello"
  let bytes = @crypto.string_to_bytes(str)
  println("字符串 '" + str + "' 转换为字节: " + @crypto.bytes_to_hex(bytes))
  println()
  
  // 6. 随机字节
  let rand = @crypto.random_bytes(16)
  println("随机字节: " + @crypto.bytes_to_hex(rand))
  println()
  
  println("=" * 70)
  println("API 使用示例结束")
  println("=" * 70)
}
