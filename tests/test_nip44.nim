## NIP-44 v2 test vectors
## https://github.com/paulmillr/nip44/blob/main/nip44.vectors.json

import std/unittest
import secp256k1
import nimcrypto/utils as cryptoutils
import ../src/nip44

# Helper: parse 32-byte hex x-only pubkey as compressed SkPublicKey (0x02 prefix)
proc pubFromXOnly(hexStr: string): SkPublicKey =
  var raw: array[33, byte]
  raw[0] = 0x02
  let xBytes = cryptoutils.fromHex(hexStr)
  copyMem(addr raw[1], unsafeAddr xBytes[0], 32)
  SkPublicKey.fromRaw(raw).expect("valid pubkey")

proc secFromHex(hexStr: string): SkSecretKey =
  SkSecretKey.fromHex(hexStr).expect("valid seckey")

proc hexFromBytes(b: openArray[byte]): string =
  result = newStringOfCap(b.len * 2)
  const hexChars = "0123456789abcdef"
  for x in b:
    result.add hexChars[x shr 4]
    result.add hexChars[x and 0x0f]

suite "NIP-44 v2 - calc_padded_len":
  test "spec vectors":
    let cases = @[
      (16, 32), (32, 32), (33, 64), (37, 64), (45, 64), (49, 64),
      (64, 64), (65, 96), (100, 128), (111, 128), (200, 224), (250, 256),
      (320, 320), (383, 384), (384, 384), (400, 448), (500, 512), (512, 512),
      (515, 640), (700, 768), (800, 896), (900, 1024), (1020, 1024), (65536, 65536)
    ]
    for (input, expected) in cases:
      check calcPaddedLen(input) == expected

suite "NIP-44 v2 - get_conversation_key":
  test "sec1=1, pub2=G (sec1==pub2 point)":
    let ck = getConversationKey(
      secFromHex("0000000000000000000000000000000000000000000000000000000000000001"),
      pubFromXOnly("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
    )
    check hexFromBytes(ck) == "3b4610cb7189beb9cc29eb3716ecc6102f1247e8f3101a03a1787d8908aeb54e"

  test "sec1=2, pub2=random":
    let ck = getConversationKey(
      secFromHex("0000000000000000000000000000000000000000000000000000000000000002"),
      pubFromXOnly("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdeb")
    )
    check hexFromBytes(ck) == "be234f46f60a250bef52a5ee34c758800c4ca8e5030bf4cc1a31d37ba2104d43"

  test "sec1=random pair 1":
    let ck = getConversationKey(
      secFromHex("315e59ff51cb9209768cf7da80791ddcaae56ac9775eb25b6dee1234bc5d2268"),
      pubFromXOnly("c2f9d9948dc8c7c38321e4b85c8558872eafa0641cd269db76848a6073e69133")
    )
    check hexFromBytes(ck) == "3dfef0ce2a4d80a25e7a328accf73448ef67096f65f79588e358d9a0eb9013f1"

  test "sec1=random pair 2":
    let ck = getConversationKey(
      secFromHex("a1e37752c9fdc1273be53f68c5f74be7c8905728e8de75800b94262f9497c86e"),
      pubFromXOnly("03bb7947065dde12ba991ea045132581d0954f042c84e06d8c00066e23c1a800")
    )
    check hexFromBytes(ck) == "4d14f36e81b8452128da64fe6f1eae873baae2f444b02c950b90e43553f2178b"

  test "sec1=n-2, pub2=0x02":
    let ck = getConversationKey(
      secFromHex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364139"),
      pubFromXOnly("0000000000000000000000000000000000000000000000000000000000000002")
    )
    check hexFromBytes(ck) == "8b6392dbf2ec6a2b2d5b1477fc2be84d63ef254b667cadd31bd3f444c44ae6ba"

suite "NIP-44 v2 - encrypt/decrypt":
  test "roundtrip: plaintext='a'":
    let conversationKey = block:
      var k: array[32, byte]
      let raw = cryptoutils.fromHex("c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d")
      copyMem(addr k[0], unsafeAddr raw[0], 32)
      k
    var nonce: array[32, byte]
    let nonceRaw = cryptoutils.fromHex("0000000000000000000000000000000000000000000000000000000000000001")
    copyMem(addr nonce[0], unsafeAddr nonceRaw[0], 32)
    let payload = encrypt("a", conversationKey, nonce)
    check payload == "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABee0G5VSK0/9YypIObAtDKfYEAjD35uVkHyB0F4DwrcNaCXlCWZKaArsGrY6M9wnuTMxWfp1RTN9Xga8no+kF5Vsb"
    check decrypt(payload, conversationKey) == "a"

  test "decrypt known payload":
    let conversationKey = block:
      var k: array[32, byte]
      let raw = cryptoutils.fromHex("c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d")
      copyMem(addr k[0], unsafeAddr raw[0], 32)
      k
    let payload = "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABee0G5VSK0/9YypIObAtDKfYEAjD35uVkHyB0F4DwrcNaCXlCWZKaArsGrY6M9wnuTMxWfp1RTN9Xga8no+kF5Vsb"
    check decrypt(payload, conversationKey) == "a"

suite "NIP-44 v2 - invalid decrypt":
  test "invalid MAC":
    let conversationKey = block:
      var k: array[32, byte]
      let raw = cryptoutils.fromHex("cff7bd6a3e29a450fd27f6c125d5edeb0987c475fd1e8d97591e0d4d8a89763c")
      copyMem(addr k[0], unsafeAddr raw[0], 32)
      k
    let payload = "Agn/l3ULCEAS4V7LhGFM6IGA17jsDUaFCKhrbXDANholyySBfeh+EN8wNB9gaLlg4j6wdBYh+3oK+mnxWu3NKRbSvQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    expect(AssertionDefect):
      discard decrypt(payload, conversationKey)

  test "invalid payload length: 0":
    let conversationKey = block:
      var k: array[32, byte]
      let raw = cryptoutils.fromHex("5cd2d13b9e355aeb2452afbd3786870dbeecb9d355b12cb0a3b6e9da5744cd35")
      copyMem(addr k[0], unsafeAddr raw[0], 32)
      k
    expect(AssertionDefect):
      discard decrypt("", conversationKey)

  test "unknown encryption version (#)":
    let conversationKey = block:
      var k: array[32, byte]
      let raw = cryptoutils.fromHex("ca2527a037347b91bea0c8a30fc8d9600ffd81ec00038671e3a0f0cb0fc9f642")
      copyMem(addr k[0], unsafeAddr raw[0], 32)
      k
    let payload = "#Atqupco0WyaOW2IGDKcshwxI9xO8HgD/P8Ddt46CbxDbrhdG8VmJdU0MIDf06CUvEvdnr1cp1fiMtlM/GrE92xAc1K5odTpCzUB+mjXgbaqtntBUbTToSUoT0ovrlPwzGjyp"
    expect(AssertionDefect):
      discard decrypt(payload, conversationKey)
