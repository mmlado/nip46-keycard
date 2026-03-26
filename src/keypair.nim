import std/[os, strutils]
import nimcrypto/sysrand
import secp256k1

type
  SignerKeypair* = object
    seckey*: SkSecretKey
    pubkey*: SkXOnlyPublicKey

proc pubkeyHex*(kp: SignerKeypair): string =
  toHex(kp.pubkey)

proc fromSecKey(seckey: SkSecretKey): SignerKeypair =
  let pubkey = seckey.toPublicKey().toXOnly()
  SignerKeypair(seckey: seckey, pubkey: pubkey)

proc generate*(): SignerKeypair =
  var rawBytes: array[32, byte]
  if randomBytes(rawBytes) != 32:
    raise newException(IOError, "Failed to generate random bytes")
  let seckey = SkSecretKey.fromRaw(rawBytes).expect("valid secret key")
  fromSecKey(seckey)

proc save*(kp: SignerKeypair, path: string) =
  let dir = parentDir(path)
  if dir.len > 0:
    createDir(dir)
  writeFile(path, toHex(kp.seckey))

proc load*(path: string): SignerKeypair =
  let hex = readFile(path).strip()
  let seckey = SkSecretKey.fromHex(hex).expect("valid secret key in key file")
  fromSecKey(seckey)

proc loadOrGenerate*(path: string): SignerKeypair =
  if fileExists(path):
    result = load(path)
  else:
    result = generate()
    result.save(path)
