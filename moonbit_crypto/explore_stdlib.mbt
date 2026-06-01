
test "explore stdlib" {
  // 测试一些基本操作
  println("探索MoonBit标准库...")
  
  // 测试Int64
  let a = 0x123456789ABCDEF0L
  println("Int64: " + a.to_string())
  
  // 测试UInt32数组
  let arr = [0x11223344U, 0x55667788U]
  println("UInt32数组: [" + arr[0].to_string() + ", " + arr[1].to_string() + "]")
  
  // 测试字节数组
  let bytes = @array.make(16, 0x00)
  bytes[0] = 0x01
  bytes[1] = 0x02
  println("Bytes: " + bytes[0].to_string() + ", " + bytes[1].to_string())
}

