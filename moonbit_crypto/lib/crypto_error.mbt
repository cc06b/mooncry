// MoonBit Crypto 错误处理模块
// 现代化错误处理体系

// 加密错误类型
pub enum CryptoError {
  // 无效参数
  InvalidArgument(String),
  
  // 无效密钥长度
  InvalidKeyLength(Int, Int),
  
  // 无效数据长度
  InvalidDataLength(String),
  
  // 算法不支持
  AlgorithmNotSupported(String),
  
  // 提供者未找到
  ProviderNotFound(String),
  
  // 解密失败（如验证失败）
  DecryptionFailed(String),
  
  // 内部错误
  InternalError(String),
  
  // 不兼容的版本
  VersionMismatch(String),
  
  // 内存不足
  OutOfMemory(String),
  
  // 操作取消
  OperationCancelled,
}

// 错误处理结果类型
pub type Result[T] = CryptoResult[T]

// 错误实现
impl CryptoError {
  // 获取错误消息
  pub fn message(self) -> String {
    match self {
      InvalidArgument(msg) => "无效参数: " + msg,
      InvalidKeyLength(given, expected) => 
        "无效密钥长度: 期望 " + expected.to_string() + " 字节，实际 " + given.to_string() + " 字节",
      InvalidDataLength(msg) => "无效数据长度: " + msg,
      AlgorithmNotSupported(name) => "不支持的算法: " + name,
      ProviderNotFound(name) => "提供者未找到: " + name,
      DecryptionFailed(reason) => "解密失败: " + reason,
      InternalError(msg) => "内部错误: " + msg,
      VersionMismatch(msg) => "版本不兼容: " + msg,
      OutOfMemory(msg) => "内存不足: " + msg,
      OperationCancelled => "操作已取消",
    }
  }
  
  // 获取错误代码
  pub fn code(self) -> Int {
    match self {
      InvalidArgument(_) => 1001,
      InvalidKeyLength(_, _) => 1002,
      InvalidDataLength(_) => 1003,
      AlgorithmNotSupported(_) => 2001,
      ProviderNotFound(_) => 2002,
      DecryptionFailed(_) => 3001,
      InternalError(_) => 9999,
      VersionMismatch(_) => 4001,
      OutOfMemory(_) => 5001,
      OperationCancelled => 6001,
    }
  }
  
  // 判断是否为致命错误
  pub fn is_fatal(self) -> Bool {
    match self {
      InternalError(_) | OutOfMemory(_) => true,
      _ => false,
    }
  }
}

// 结果类型实现
impl<T> CryptoResult<T> {
  // 创建成功结果
  pub fn ok(value: T) -> CryptoResult<T> {
    CryptoResult { result: Some(value), error: None }
  }
  
  // 创建失败结果
  pub fn err(error: CryptoError) -> CryptoResult<T> {
    CryptoResult { result: None, error: Some(error) }
  }
  
  // 检查是否成功
  pub fn is_ok(self) -> Bool {
    match self.result {
      Some(_) => true,
      None => false,
    }
  }
  
  // 检查是否失败
  pub fn is_err(self) -> Bool {
    match self.error {
      Some(_) => true,
      None => false,
    }
  }
  
  // 获取结果值（可能失败）
  pub fn unwrap(self) -> T {
    match self.result {
      Some(v) => v,
      None => panic("尝试解包失败的结果"),
    }
  }
  
  // 获取错误（可能失败）
  pub fn unwrap_err(self) -> CryptoError {
    match self.error {
      Some(e) => e,
      None => panic("尝试解包成功的结果"),
    }
  }
  
  // 获取结果值或默认值
  pub fn unwrap_or(self, default: T) -> T {
    match self.result {
      Some(v) => v,
      None => default,
    }
  }
  
  // 映射结果
  pub fn map[U](self, f: fn(T) -> U) -> CryptoResult[U] {
    match self.result {
      Some(v) => CryptoResult::ok(f(v)),
      None => CryptoResult::err(self.error.unwrap()),
    }
  }
  
  // 链式调用
  pub fn and_then[U](self, f: fn(T) -> CryptoResult[U]) -> CryptoResult[U] {
    match self.result {
      Some(v) => f(v),
      None => CryptoResult::err(self.error.unwrap()),
    }
  }
}

// 验证函数
pub fn validate_key_length(key: Bytes, expected_length: Int) -> Result[Bytes] {
  let len = key.length()
  if len != expected_length {
    return CryptoResult::err(InvalidKeyLength(len, expected_length))
  }
  CryptoResult::ok(key)
}

pub fn validate_min_length(data: Bytes, min_length: Int) -> Result[Bytes] {
  let len = data.length()
  if len < min_length {
    return CryptoResult::err(InvalidDataLength("长度不足，期望至少 " + min_length.to_string() + " 字节"))
  }
  CryptoResult::ok(data)
}

pub fn validate_algorithm_supported(name: String, supported: Array[String]) -> Result[String] {
  for algo in supported {
    if algo == name {
      return CryptoResult::ok(name)
    }
  }
  CryptoResult::err(AlgorithmNotSupported(name))
}
