// test_bigint.mbt - BigInt 测试（已移到根目录避免编译冲突）
// 注意: MoonBit 的 Int 类型不支持 256 位大整数，此测试仅用于参考

fn test_bigint_main() -> Unit {
  // secp256k1 曲线参数 P
  let big_num = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
  println("Big number: " + big_num.to_string())
  println("Note: MoonBit Int type does not support 256-bit integers")
}
