import std/[os, strutils]
import parsetoml

type
  ApprovalMode* = enum
    amPolicy  = "policy"
    amAlways  = "always"

  RelayConfig* = object
    urls*: seq[string]

  KeycardConfig* = object
    pin*:          string  ## empty = prompt at startup
    pairingToken*: string  ## hex-encoded 32-byte pairing token (bypasses PBKDF2)

  SignerConfig* = object
    keyFile*: string

  ApprovalConfig* = object
    mode*:         ApprovalMode
    allowedKinds*: seq[int]

  ConnectionConfig* = object
    secret*: string       ## empty = no secret required

  Config* = object
    relay*:      RelayConfig
    keycard*:    KeycardConfig
    signer*:     SignerConfig
    approval*:   ApprovalConfig
    connection*: ConnectionConfig

proc expandPath(p: string): string =
  if p.startsWith("~/"):
    getHomeDir() / p[2..^1]
  else:
    p

proc defaultConfig*(): Config =
  Config(
    relay:      RelayConfig(urls: @["wss://relay.damus.io"]),
    keycard:    KeycardConfig(pin: "", pairingToken: ""),
    signer:     SignerConfig(keyFile: expandPath("~/.config/nip46-keycard/signer.key")),
    approval:   ApprovalConfig(mode: amPolicy, allowedKinds: @[1]),
    connection: ConnectionConfig(secret: ""),
  )

proc loadConfig*(path: string): Config =
  result = defaultConfig()

  if not fileExists(path):
    return

  let t = parsetoml.parseFile(path)

  if t.hasKey("relay"):
    let r = t["relay"]
    if r.hasKey("urls"):
      result.relay.urls = @[]
      for u in r["urls"].getElems():
        result.relay.urls.add(u.getStr())

  if t.hasKey("keycard"):
    let k = t["keycard"]
    if k.hasKey("pin"):
      result.keycard.pin = k["pin"].getStr()
    if k.hasKey("pairing_token"):
      result.keycard.pairingToken = k["pairing_token"].getStr()

  if t.hasKey("signer"):
    let s = t["signer"]
    if s.hasKey("key_file"):
      result.signer.keyFile = expandPath(s["key_file"].getStr())

  if t.hasKey("approval"):
    let a = t["approval"]
    if a.hasKey("mode"):
      result.approval.mode = parseEnum[ApprovalMode](a["mode"].getStr())
    if a.hasKey("allowed_kinds"):
      result.approval.allowedKinds = @[]
      for k in a["allowed_kinds"].getElems():
        result.approval.allowedKinds.add(k.getInt())

  if t.hasKey("connection"):
    let c = t["connection"]
    if c.hasKey("secret"):
      result.connection.secret = c["secret"].getStr()
