// 简单的API测试
// 测试新模块化的API

fn main() -> Unit {
  println("测试 MoonBit Crypto Library API")
  println("================================")
  
  // 测试 SHA-256
  println("\n1. 测试 SHA-256")
  let data = b"Hello, World!"
  let hash = @sha256.sha256(data)
  println("数据: " + @sha256.bytes_to_hex(data))
  println("哈希: " + @sha256.bytes_to_hex(hash))
  
  // 测试 AES-ECB
  println("\n2. 测试 AES-ECB")
  let key = b"\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c"
  let plaintext = b"Test message!"
  let encrypted = @aes.encrypt_ecb(plaintext, key)
  let decrypted = @aes.decrypt_ecb(encrypted, key)
  println("原始: " + @sha256.bytes_to_hex(plaintext))
  println("加密: " + @sha256.bytes_to_hex(encrypted))
  println("解密: " + @sha256.bytes_to_hex(decrypted))
  
  println("\n测试完成!")
}
