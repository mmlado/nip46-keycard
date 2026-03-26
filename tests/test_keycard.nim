## Tests for keycard.nim helpers that don't require hardware.
## Hardware-dependent tests (openSession, signEvent) are covered by
## end-to-end testing with a real card.

import std/[os, unittest]
import nimcrypto/sha2
import "../src/keycard" as kc

suite "keycard - NostrKeyPath":

  test "path has 5 components":
    check kc.NostrKeyPath.len == 5

  test "path is m/43'/60'/1581'/0'/0":
    # Hardened components have bit 31 set (0x80000000 added)
    check kc.NostrKeyPath[0] == 0x8000002B'u32  # 43'
    check kc.NostrKeyPath[1] == 0x8000003C'u32  # 60'
    check kc.NostrKeyPath[2] == 0x8000062D'u32  # 1581'
    check kc.NostrKeyPath[3] == 0x80000000'u32  # 0'
    check kc.NostrKeyPath[4] == 0x00000000'u32  # 0

suite "keycard - sha256Concat":

  proc sha256(data: openArray[byte]): seq[byte] =
    var ctx: sha256
    ctx.init()
    ctx.update(data)
    let d = ctx.finish()
    result = @(d.data)

  test "sha256Concat(a, b) equals sha256(a || b)":
    let a = @[byte(1), 2, 3]
    let b = @[byte(4), 5, 6]
    let combined = a & b
    check kc.sha256Concat(a, b) == sha256(combined)

  test "sha256Concat is not commutative":
    let a = @[byte(1), 2, 3]
    let b = @[byte(4), 5, 6]
    check kc.sha256Concat(a, b) != kc.sha256Concat(b, a)

  test "sha256Concat with empty first arg":
    let a: seq[byte] = @[]
    let b = @[byte(0xDE), 0xAD, 0xBE, 0xEF]
    check kc.sha256Concat(a, b) == sha256(b)

  test "sha256Concat with empty second arg":
    let a = @[byte(0xDE), 0xAD, 0xBE, 0xEF]
    let b: seq[byte] = @[]
    check kc.sha256Concat(a, b) == sha256(a)

  test "output is always 32 bytes":
    check kc.sha256Concat(@[byte(1)], @[byte(2)]).len == 32
    check kc.sha256Concat(@[], @[]).len == 32

suite "keycard - pairing file roundtrip":

  test "save and load preserves index and key":
    let path = getTempDir() / "test_pairing.bin"
    defer: removeFile(path)
    let original = kc.PairingInfo(
      index: 2,
      key: @[byte(0xAA), 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
             0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00,
             0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
             0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10]
    )
    kc.savePairing(path, original)
    check fileExists(path)
    let loaded = kc.loadPairing(path)
    check loaded.index == original.index
    check loaded.key == original.key

  test "pairing file is exactly 33 bytes":
    let path = getTempDir() / "test_pairing2.bin"
    defer: removeFile(path)
    let p = kc.PairingInfo(index: 0, key: newSeq[byte](32))
    kc.savePairing(path, p)
    check getFileSize(path) == 33

  test "index 0 and index 255 roundtrip":
    for idx in [byte(0), byte(255)]:
      let path = getTempDir() / "test_pairing_idx.bin"
      defer: removeFile(path)
      let p = kc.PairingInfo(index: idx, key: newSeq[byte](32))
      kc.savePairing(path, p)
      let loaded = kc.loadPairing(path)
      check loaded.index == idx
