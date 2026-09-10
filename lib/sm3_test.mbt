///|
fn sm3_slice(b : Bytes, start : Int, len : Int) -> Bytes {
  let a = Array::make(len, (0).to_byte())
  for i in 0..<len {
    a[i] = b[start + i]
  }
  Bytes::from_array(a[:])
}

///|
test "sm3-gb-official-abc" {
  // GB/T 32905-2016 Appendix A Example 1: SM3("abc")
  inspect(
    bytes_to_hex(sm3(b"abc")),
    content="66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
  )
}

///|
test "sm3-gb-official-abcd16" {
  // GB/T 32905-2016 Appendix A Example 2: SM3("abcd" repeated 16 times)
  let msg = b"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"
  inspect(
    bytes_to_hex(sm3(msg)),
    content="debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732",
  )
}

///|
test "sm3-streaming-consistency" {
  // one-shot vs 1-byte-at-a-time vs chunked must agree on the 64-byte message
  let data = b"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"
  let h1 = sm3_new()
  for i in 0..<data.length() {
    let one = Array::make(1, data[i])
    sm3_update(h1, Bytes::from_array(one[:]))
  }
  let d1 = sm3_finalize(h1)
  let h2 = sm3_new()
  sm3_update(h2, sm3_slice(data, 0, 5))
  sm3_update(h2, sm3_slice(data, 5, 55))
  sm3_update(h2, sm3_slice(data, 60, 4))
  let d2 = sm3_finalize(h2)
  inspect(bytes_equal(d1, d2), content="true")
  inspect(
    bytes_to_hex(d1),
    content="debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732",
  )
}

///|
test "sm3-multiblock" {
  // a 200-byte message crosses block and padding boundaries; the two
  // feed schedules must agree
  let arr = Array::make(200, (0).to_byte())
  for i in 0..<200 {
    arr[i] = (i * 7 % 251).to_byte()
  }
  let data = Bytes::from_array(arr[:])
  let one_shot = sm3(data)
  let h = sm3_new()
  sm3_update(h, sm3_slice(data, 0, 63))
  sm3_update(h, sm3_slice(data, 63, 1))
  sm3_update(h, sm3_slice(data, 64, 135))
  sm3_update(h, sm3_slice(data, 199, 1))
  inspect(bytes_equal(one_shot, sm3_finalize(h)), content="true")
}

///|
