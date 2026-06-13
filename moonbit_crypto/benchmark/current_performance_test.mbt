// MoonBit Crypto 当前性能测试
// 测量经过20次优化后的实际效率

import lib/ultra_optimized.*
import lib/simd_crypto.*
import lib/aes_ultra.*

// 生成测试数据
fn generate_data(size: Int) -> Bytes {
  let arr = Array::make(size, b'X')
  Bytes::from_array(arr[:])
}

// SHA-256 性能测试
test "SHA-256 Ultra 性能测试" {
  let test_sizes = [64, 256, 1024, 4096, 16384]
  let iterations = 100
  
  println("=== SHA-256 Ultra 性能测试 ===")
  println("测试数据大小: " + test_sizes.to_string())
  println("迭代次数: " + iterations.to_string())
  println()
  
  // 测试不同大小
  for size in test_sizes {
    let data = generate_data(size)
    
    // 预热
    let _ = sha256_ultra(data)
    
    // 测试
    let start = MoonBit.IO.now()
    for _ in 0..<iterations {
      let _ = sha256_ultra(data)
    }
    let end = MoonBit.IO.now()
    let total_ms = (end - start).to_float() / 1000000.0
    
    // 计算
    let single_ms = total_ms / iterations.to_float()
    let mb_per_sec = (size.to_float() / 1024.0 / 1024.0) / (single_ms / 1000.0)
    
    println("  大小: " + size.to_string() + " B")
    println("    总时间: " + total_ms.to_string() + " ms")
    println("    单次: " + single_ms.to_string() + " ms")
    println("    吞吐量: " + mb_per_sec.to_string() + " MB/s")
    println()
  }
}

// SHA-256 SIMD 性能测试
test "SHA-256 SIMD 性能测试" {
  let test_sizes = [64, 256, 1024, 4096, 16384]
  let iterations = 100
  
  println("=== SHA-256 SIMD 性能测试 ===")
  
  for size in test_sizes {
    let data = generate_data(size)
    
    // 预热
    let _ = sha256_simd(data)
    
    // 测试
    let start = MoonBit.IO.now()
    for _ in 0..<iterations {
      let _ = sha256_simd(data)
    }
    let end = MoonBit.IO.now()
    let total_ms = (end - start).to_float() / 1000000.0
    
    let single_ms = total_ms / iterations.to_float()
    let mb_per_sec = (size.to_float() / 1024.0 / 1024.0) / (single_ms / 1000.0)
    
    println("  大小: " + size.to_string() + " B")
    println("    单次: " + single_ms.to_string() + " ms")
    println("    吞吐量: " + mb_per_sec.to_string() + " MB/s")
    println()
  }
}

// AES 性能测试
test "AES-128 Ultra 性能测试" {
  let key = Bytes::from_array([0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c][:])
  let test_sizes = [16, 64, 256, 1024, 4096, 16384]
  let iterations = 50
  
  println("=== AES-128 Ultra 性能测试 ===")
  println("密钥大小: 16 bytes")
  println("迭代次数: " + iterations.to_string())
  println()
  
  for size in test_sizes {
    let data = generate_data(size)
    
    // 预热
    let encrypted = aes_encrypt_ultra(data, key)
    let _ = aes_decrypt_ultra(encrypted, key)
    
    // 加密测试
    let start = MoonBit.IO.now()
    for _ in 0..<iterations {
      let _ = aes_encrypt_ultra(data, key)
    }
    let end = MoonBit.IO.now()
    let encrypt_ms = (end - start).to_float() / 1000000.0
    
    // 解密测试
    let start2 = MoonBit.IO.now()
    for _ in 0..<iterations {
      let _ = aes_decrypt_ultra(encrypted, key)
    }
    let end2 = MoonBit.IO.now()
    let decrypt_ms = (end2 - start2).to_float() / 1000000.0
    
    let encrypt_single = encrypt_ms / iterations.to_float()
    let decrypt_single = decrypt_ms / iterations.to_float()
    let encrypt_mb = (size.to_float() / 1024.0 / 1024.0) / (encrypt_single / 1000.0)
    let decrypt_mb = (size.to_float() / 1024.0 / 1024.0) / (decrypt_single / 1000.0)
    
    println("  大小: " + size.to_string() + " B")
    println("    加密: " + encrypt_single.to_string() + " ms (" + encrypt_mb.to_string() + " MB/s)")
    println("    解密: " + decrypt_single.to_string() + " ms (" + decrypt_mb.to_string() + " MB/s)")
    println()
  }
}

// 性能对比
test "性能对比总结" {
  println("=== 当前性能总结 ===\n")
  
  let test_data_1k = generate_data(1024)
  let iterations = 200
  
  // Ultra SHA-256
  let start1 = MoonBit.IO.now()
  for _ in 0..<iterations {
    let _ = sha256_ultra(test_data_1k)
  }
  let end1 = MoonBit.IO.now()
  let ultra_ms = (end1 - start1).to_float() / 1000000.0
  
  // SIMD SHA-256
  let start2 = MoonBit.IO.now()
  for _ in 0..<iterations {
    let _ = sha256_simd(test_data_1k)
  }
  let end2 = MoonBit.IO.now()
  let simd_ms = (end2 - start2).to_float() / 1000000.0
  
  let ultra_single = ultra_ms / iterations.to_float()
  let simd_single = simd_ms / iterations.to_float()
  let ultra_mb = (1024.0 / 1024.0 / 1024.0) / (ultra_single / 1000.0)
  let simd_mb = (1024.0 / 1024.0 / 1024.0) / (simd_single / 1000.0)
  
  println("SHA-256 (1KB, 200次):")
  println("  Ultra 版本: " + ultra_single.to_string() + " ms/op, " + ultra_mb.to_string() + " MB/s")
  println("  SIMD  版本: " + simd_single.to_string() + " ms/op, " + simd_mb.to_string() + " MB/s")
  println("  SIMD/Ultra: " + (ultra_ms / simd_ms).to_string() + "x 提升")
  println()
  
  println("🎯 当前MoonBit Crypto库性能水平")
}
