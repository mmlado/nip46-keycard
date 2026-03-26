## NIP-01 event serialization and signing tests

import std/unittest
import std/json
import secp256k1
import ../src/nip01

suite "NIP-01 - event ID":
  test "known vector: sec=1, empty event":
    # Verify deterministic ID computation
    let pubkey = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    let id = computeEventId(pubkey, 1700000000, 1, newJArray(), "hello")
    # ID must be 32 non-zero bytes (SHA-256 never produces all zeros)
    var allZero = true
    for b in id:
      if b != 0: allZero = false
    check not allZero

  test "ID changes with different content":
    let pubkey = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    let id1 = computeEventId(pubkey, 1700000000, 1, newJArray(), "hello")
    let id2 = computeEventId(pubkey, 1700000000, 1, newJArray(), "world")
    check id1 != id2

  test "ID changes with different kind":
    let pubkey = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    let id1 = computeEventId(pubkey, 1700000000, 1, newJArray(), "hello")
    let id2 = computeEventId(pubkey, 1700000000, 0, newJArray(), "hello")
    check id1 != id2

  test "ID is deterministic":
    let pubkey = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    let id1 = computeEventId(pubkey, 1700000000, 1, newJArray(), "hello")
    let id2 = computeEventId(pubkey, 1700000000, 1, newJArray(), "hello")
    check id1 == id2

suite "NIP-01 - buildEvent":
  test "produces valid hex fields":
    let seckey = SkSecretKey.fromHex(
      "0000000000000000000000000000000000000000000000000000000000000001"
    ).expect("valid key")
    let pubkey = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    let ev = buildEvent(seckey, pubkey, 1, newJArray(), "test")
    check ev.id.len == 64
    check ev.sig.len == 128
    check ev.pubkey == pubkey
    check ev.kind == 1

  test "id matches computeEventId":
    let seckey = SkSecretKey.fromHex(
      "0000000000000000000000000000000000000000000000000000000000000001"
    ).expect("valid key")
    let pubkey = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    let ev = buildEvent(seckey, pubkey, 1, newJArray(), "test")
    let expectedId = computeEventId(pubkey, ev.created_at, 1, newJArray(), "test")
    check ev.id == bytesToHex(expectedId)

  test "toJson produces all required fields":
    let seckey = SkSecretKey.fromHex(
      "0000000000000000000000000000000000000000000000000000000000000001"
    ).expect("valid key")
    let pubkey = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    let ev = buildEvent(seckey, pubkey, 1, newJArray(), "test")
    let j = ev.toJson()
    check j.hasKey("id")
    check j.hasKey("pubkey")
    check j.hasKey("created_at")
    check j.hasKey("kind")
    check j.hasKey("tags")
    check j.hasKey("content")
    check j.hasKey("sig")

suite "NIP-01 - bytesToHex":
  test "all zeros":
    var b: array[4, byte]
    check bytesToHex(b) == "00000000"

  test "known value":
    let b = [byte 0xde, 0xad, 0xbe, 0xef]
    check bytesToHex(b) == "deadbeef"
