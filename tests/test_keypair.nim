import std/[os, unittest, strutils]
import keypair

suite "keypair":

  test "generate produces valid keypair":
    let kp = generate()
    check kp.pubkeyHex().len == 64
    check kp.pubkeyHex() == kp.pubkeyHex().toLowerAscii()

  test "two generated keypairs differ":
    let kp1 = generate()
    let kp2 = generate()
    check kp1.pubkeyHex() != kp2.pubkeyHex()

  test "save and load roundtrip":
    let path = getTempDir() / "test_nip46_signer.key"
    defer: removeFile(path)
    let kp = generate()
    kp.save(path)
    check fileExists(path)
    let loaded = load(path)
    check loaded.pubkeyHex() == kp.pubkeyHex()

  test "key file contains 64 hex chars":
    let path = getTempDir() / "test_nip46_signer2.key"
    defer: removeFile(path)
    let kp = generate()
    kp.save(path)
    let content = readFile(path).strip()
    check content.len == 64
    for c in content:
      check c in "0123456789abcdef"

  test "loadOrGenerate creates file if missing":
    let path = getTempDir() / "test_nip46_new.key"
    defer: removeFile(path)
    check not fileExists(path)
    let kp = loadOrGenerate(path)
    check fileExists(path)
    check kp.pubkeyHex().len == 64

  test "loadOrGenerate returns same key on second call":
    let path = getTempDir() / "test_nip46_existing.key"
    defer: removeFile(path)
    let kp1 = loadOrGenerate(path)
    let kp2 = loadOrGenerate(path)
    check kp1.pubkeyHex() == kp2.pubkeyHex()

  test "pubkeyHex is 32-byte x-only (64 hex chars)":
    let kp = generate()
    check kp.pubkeyHex().len == 64
