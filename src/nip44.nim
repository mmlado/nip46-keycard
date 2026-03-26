## NIP-44 v2 encryption/decryption
## Spec: https://github.com/nostr-protocol/nips/blob/master/44.md
##
## Wire format: base64( version(1) || nonce(32) || ciphertext || mac(32) )
## Crypto:
##   ECDH (unhashed x-coord) -> HKDF-extract(salt="nip44-v2") -> conversation_key
##   HKDF-expand(info=nonce, L=76) -> chacha_key(32) | chacha_nonce(12) | hmac_key(32)
##   ChaCha20 (RFC 8439, counter=0)
##   HMAC-SHA256 over (nonce || ciphertext)

import std/base64
import std/math as stdmath
import nimcrypto/[hmac, sha2]
import secp256k1
import secp256k1/abi
import chacha20

# --------------------------------------------------------------------------- #
# HKDF (RFC 5869) with SHA-256                                                #
# --------------------------------------------------------------------------- #

proc hkdfExtract(salt, ikm: openArray[byte]): array[32, byte] =
  var ctx: HMAC[sha256]
  ctx.init(salt)
  ctx.update(ikm)
  let digest = ctx.finish()
  copyMem(addr result[0], unsafeAddr digest.data[0], 32)

proc hkdfExpand(prk, info: openArray[byte], L: int): seq[byte] =
  ## HKDF-expand outputting L bytes
  result = newSeq[byte](L)
  var t: array[32, byte]
  var pos = 0
  var counter: byte = 1
  while pos < L:
    var ctx: HMAC[sha256]
    ctx.init(prk)
    if counter > 1:
      ctx.update(t)
    ctx.update(info)
    ctx.update([counter])
    let digest = ctx.finish()
    copyMem(addr t[0], unsafeAddr digest.data[0], 32)
    let chunk = min(32, L - pos)
    copyMem(addr result[pos], addr t[0], chunk)
    pos += chunk
    inc counter

# --------------------------------------------------------------------------- #
# ECDH (unhashed x-coordinate, per NIP-44 spec)                               #
# --------------------------------------------------------------------------- #

proc ecdhUnhashed(seckey: SkSecretKey, pubkey: SkPublicKey): array[32, byte] =
  ## Returns the raw 32-byte x-coordinate of the shared point.
  ## NIP-44 explicitly requires the unhashed x-coordinate.
  ## The default libsecp256k1 ECDH hashes the output with SHA-256 — we bypass
  ## that by supplying an identity hash function.
  proc identityHash(output: ptr byte, x32, y32: ptr byte,
                    data: pointer): cint {.cdecl.} =
    copyMem(output, x32, 32)
    result = 1

  let res = ecdh[32](seckey, pubkey, identityHash, nil)
  res.expect("ECDH failed")

# --------------------------------------------------------------------------- #
# Conversation key                                                             #
# --------------------------------------------------------------------------- #

proc getConversationKey*(seckey: SkSecretKey, pubkey: SkPublicKey): array[32, byte] =
  let sharedX = ecdhUnhashed(seckey, pubkey)
  let salt = cast[seq[byte]]("nip44-v2")
  hkdfExtract(salt, sharedX)

# --------------------------------------------------------------------------- #
# Message keys                                                                 #
# --------------------------------------------------------------------------- #

type MessageKeys = object
  chachaKey:   array[32, byte]
  chachaNonce: array[12, byte]
  hmacKey:     array[32, byte]

proc getMessageKeys(conversationKey, nonce: openArray[byte]): MessageKeys =
  let expanded = hkdfExpand(conversationKey, nonce, 76)
  copyMem(addr result.chachaKey[0],   unsafeAddr expanded[0],  32)
  copyMem(addr result.chachaNonce[0], unsafeAddr expanded[32], 12)
  copyMem(addr result.hmacKey[0],     unsafeAddr expanded[44], 32)

# --------------------------------------------------------------------------- #
# Padding                                                                      #
# --------------------------------------------------------------------------- #

proc calcPaddedLen*(unpaddedLen: int): int =
  if unpaddedLen <= 32:
    return 32
  let nextPower = 1 shl (stdmath.log2(float(unpaddedLen - 1)).int + 1)
  let chunk = if nextPower <= 256: 32 else: nextPower div 8
  chunk * ((unpaddedLen - 1) div chunk + 1)

proc pad(plaintext: string): seq[byte] =
  let unpadded = cast[seq[byte]](plaintext)
  let uLen = unpadded.len
  assert uLen >= 1 and uLen <= 65535, "plaintext length out of range"
  let paddedLen = calcPaddedLen(uLen)
  result = newSeq[byte](2 + paddedLen)
  result[0] = byte(uLen shr 8)   # big-endian u16
  result[1] = byte(uLen and 0xff)
  copyMem(addr result[2], unsafeAddr unpadded[0], uLen)
  # remaining bytes are already zero

proc unpad(padded: openArray[byte]): string =
  assert padded.len >= 2, "padded message too short"
  let uLen = (int(padded[0]) shl 8) or int(padded[1])
  assert uLen >= 1, "zero-length plaintext"
  assert padded.len == 2 + calcPaddedLen(uLen), "invalid padding length"
  assert uLen <= padded.len - 2, "plaintext length exceeds buffer"
  result = newString(uLen)
  copyMem(addr result[0], unsafeAddr padded[2], uLen)

# --------------------------------------------------------------------------- #
# MAC                                                                          #
# --------------------------------------------------------------------------- #

proc hmacAad(key, message, aad: openArray[byte]): array[32, byte] =
  ## HMAC-SHA256 over (aad || message)
  var ctx: HMAC[sha256]
  ctx.init(key)
  ctx.update(aad)
  ctx.update(message)
  let digest = ctx.finish()
  copyMem(addr result[0], unsafeAddr digest.data[0], 32)

# --------------------------------------------------------------------------- #
# Public API                                                                   #
# --------------------------------------------------------------------------- #

proc encrypt*(plaintext: string, conversationKey: array[32, byte],
              nonce: array[32, byte]): string =
  let keys = getMessageKeys(conversationKey, nonce)
  var padded = pad(plaintext)

  # ChaCha20 encrypt in-place
  discard chacha20(keys.chachaKey, keys.chachaNonce, 0,
                   addr padded[0], addr padded[0], padded.len)

  let mac = hmacAad(keys.hmacKey, padded, nonce)

  # Assemble: version(1) || nonce(32) || ciphertext || mac(32)
  var raw = newSeq[byte](1 + 32 + padded.len + 32)
  raw[0] = 0x02
  copyMem(addr raw[1],            unsafeAddr nonce[0],  32)
  copyMem(addr raw[33],           addr padded[0],       padded.len)
  copyMem(addr raw[33+padded.len], unsafeAddr mac[0],   32)

  encode(raw)

proc decrypt*(payload: string, conversationKey: array[32, byte]): string =
  assert payload.len >= 132 and payload.len <= 87472, "invalid payload size"
  assert payload[0] != '#', "unsupported encryption version"

  let rawStr = decode(payload)
  let raw = cast[seq[byte]](rawStr)
  assert raw.len >= 99 and raw.len <= 65603, "invalid decoded size"
  assert raw[0] == 0x02'u8, "unsupported version: " & $raw[0]

  var nonce: array[32, byte]
  copyMem(addr nonce[0], unsafeAddr raw[1], 32)

  let ciphertextLen = raw.len - 65  # 1 + 32 + 32
  var ciphertext = newSeq[byte](ciphertextLen)
  copyMem(addr ciphertext[0], unsafeAddr raw[33], ciphertextLen)

  var mac: array[32, byte]
  copyMem(addr mac[0], unsafeAddr raw[33 + ciphertextLen], 32)

  let keys = getMessageKeys(conversationKey, nonce)

  # Verify MAC (constant-time)
  let expected = hmacAad(keys.hmacKey, ciphertext, nonce)
  var diff: byte = 0
  for i in 0..<32:
    diff = diff or (expected[i] xor mac[i])
  assert diff == 0, "invalid MAC"

  # Decrypt in-place
  discard chacha20(keys.chachaKey, keys.chachaNonce, 0,
                   addr ciphertext[0], addr ciphertext[0], ciphertext.len)

  unpad(ciphertext)
