import std/[os, unittest, strutils]
import config

# Write a TOML string to a temp file and parse it
proc withTempToml(content: string, body: proc(path: string)) =
  let path = getTempDir() / "test_nip46_config.toml"
  writeFile(path, content)
  try:
    body(path)
  finally:
    removeFile(path)

suite "config":

  test "defaults when file missing":
    let cfg = loadConfig("/nonexistent/path.toml")
    check cfg.relay.urls == @["wss://relay.damus.io"]
    check cfg.keycard.pin == ""
    check cfg.keycard.pairingToken == ""
    check cfg.approval.mode == amInteractive
    check cfg.approval.allowedKinds == @[1]
    check cfg.connection.secret == ""
    check cfg.signer.keyFile.len > 0

  test "relay urls parsed":
    withTempToml("""
[relay]
urls = ["wss://relay.example.com", "wss://nos.lol"]
""") do (path: string):
      let cfg = loadConfig(path)
      check cfg.relay.urls == @["wss://relay.example.com", "wss://nos.lol"]

  test "keycard pin and pairing token":
    withTempToml("""
[keycard]
pin = "123456"
pairing_token = "aabbcc"
""") do (path: string):
      let cfg = loadConfig(path)
      check cfg.keycard.pin == "123456"
      check cfg.keycard.pairingToken == "aabbcc"

  test "approval mode policy":
    withTempToml("""
[approval]
mode = "policy"
allowed_kinds = [0, 1, 3]
""") do (path: string):
      let cfg = loadConfig(path)
      check cfg.approval.mode == amPolicy
      check cfg.approval.allowedKinds == @[0, 1, 3]

  test "approval mode always":
    withTempToml("""
[approval]
mode = "always"
""") do (path: string):
      let cfg = loadConfig(path)
      check cfg.approval.mode == amAlways

  test "connection secret":
    withTempToml("""
[connection]
secret = "mysecret"
""") do (path: string):
      let cfg = loadConfig(path)
      check cfg.connection.secret == "mysecret"

  test "signer key_file tilde expansion":
    withTempToml("""
[signer]
key_file = "~/.config/test/signer.key"
""") do (path: string):
      let cfg = loadConfig(path)
      check not cfg.signer.keyFile.startsWith("~")
      check cfg.signer.keyFile.endsWith(".config/test/signer.key")

  test "signer key_file absolute path unchanged":
    withTempToml("""
[signer]
key_file = "/absolute/path/signer.key"
""") do (path: string):
      let cfg = loadConfig(path)
      check cfg.signer.keyFile == "/absolute/path/signer.key"

  test "partial config keeps other defaults":
    withTempToml("""
[relay]
urls = ["wss://custom.relay"]
""") do (path: string):
      let cfg = loadConfig(path)
      check cfg.relay.urls == @["wss://custom.relay"]
      check cfg.approval.mode == amInteractive   # default preserved
      check cfg.keycard.pin == ""               # default preserved
