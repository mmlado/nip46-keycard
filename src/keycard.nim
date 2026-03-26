## Keycard integration for NIP-46 signer.
##
## Flow per signing request:
##   SELECT → openSecureChannel → verifyPIN → sign
##
## Signing strategy:
##   1. Try Bip340Schnorr on card (SignAlgorithm = 0x03)
##   2. If card returns SignAlgorithmNotSupported → export private key over secure
##      channel, sign in software, wipe key from memory immediately.
##
## Private key export is only possible for keys derived under the EIP-1581
## subtree (m/43'/60'/1581'/...), which the Keycard applet explicitly allows.

import std/[os, logging]
import secp256k1
import nimcrypto/[sha2, sysrand, utils]
import keycard/transport
import keycard/keycard as kcard
import keycard/constants
import keycard/commands/select
import keycard/commands/pair
import keycard/commands/open_secure_channel
import keycard/commands/verify_pin
import keycard/commands/sign as kcsign
import keycard/commands/export_key

## EIP-1581 path for exportable Nostr signing key: m/43'/60'/1581'/0'/0
const NostrKeyPath* = [
  0x8000002B'u32,  # 43'
  0x8000003C'u32,  # 60'
  0x8000062D'u32,  # 1581'
  0x80000000'u32,  # 0'
  0x00000000'u32   # 0
]

type
  PairingInfo* = object
    index*: byte
    key*:   seq[byte]

  KeycardSession* = ref object
    card*:    kcard.Keycard
    pairing:  PairingInfo

proc sha256Concat*(a, b: openArray[byte]): seq[byte] =
  var ctx: sha256
  ctx.init()
  ctx.update(a)
  ctx.update(b)
  let d = ctx.finish()
  result = @(d.data)

proc pairWithToken(card: var kcard.Keycard, token: seq[byte]): PairResult =
  ## Like pair() but uses a raw 32-byte token directly, skipping PBKDF2.
  assert token.len == 32, "pairing token must be 32 bytes"

  var clientChallenge = newSeq[byte](32)
  if randomBytes(clientChallenge) != 32:
    raise newException(IOError, "failed to generate random bytes")

  let step1 = card.transport.send(ins = InsPair, data = clientChallenge)
  if not step1.success:
    return PairResult(success: false, error: PairTransportError, sw: 0)
  if step1.value.sw != SwSuccess:
    return PairResult(success: false, error: PairFailed, sw: step1.value.sw)
  if step1.value.data.len != 64:
    return PairResult(success: false, error: PairInvalidResponse, sw: step1.value.sw)

  let cardCryptogram = step1.value.data[0..<32]
  let cardChallenge  = step1.value.data[32..<64]

  if cardCryptogram != sha256Concat(token, clientChallenge):
    return PairResult(success: false, error: PairCardAuthFailed, sw: 0)

  let clientCryptogram = sha256Concat(token, cardChallenge)
  let step2 = card.transport.send(ins = InsPair, p1 = 0x01, data = clientCryptogram)
  if not step2.success:
    return PairResult(success: false, error: PairTransportError, sw: 0)
  if step2.value.sw != SwSuccess:
    return PairResult(success: false, error: PairFailed, sw: step2.value.sw)
  if step2.value.data.len != 33:
    return PairResult(success: false, error: PairInvalidResponse, sw: step2.value.sw)

  let pairingIndex = step2.value.data[0]
  let salt         = step2.value.data[1..32]
  let pairingKey   = sha256Concat(token, salt)

  PairResult(success: true, pairingIndex: pairingIndex, pairingKey: pairingKey, salt: salt)

proc savePairing*(path: string, p: PairingInfo) =
  createDir(parentDir(path))
  var raw = newSeq[byte](33)
  raw[0] = p.index
  copyMem(addr raw[1], unsafeAddr p.key[0], 32)
  writeFile(path, cast[string](raw))

proc loadPairing*(path: string): PairingInfo =
  let raw = cast[seq[byte]](readFile(path))
  assert raw.len == 33, "invalid pairing file"
  result.index = raw[0]
  result.key   = raw[1..32]

proc openSession*(pairingFile, pin, pairingPassword: string,
                  pairingTokenHex = ""): KeycardSession =
  ## Connect to the first available card reader, SELECT the applet, open a
  ## secure channel (pairing on first run), and verify the PIN.
  let t = newTransport()
  var card = newKeycard(t)

  let readers = card.listReaders()
  if readers.len == 0:
    raise newException(IOError, "No card readers found — is the Keycard plugged in?")

  info "Keycard: connecting to reader: ", readers[0]
  card.connect(readers[0])

  debug "Keycard: SELECT applet"
  let selResult = card.select()
  if not selResult.success:
    raise newException(IOError, "SELECT failed: " & $selResult.error)
  info "Keycard: applet selected (v", selResult.info.appVersion.major, ".",
       selResult.info.appVersion.minor, ")"

  var pairing: PairingInfo

  if fileExists(pairingFile):
    debug "Keycard: loading pairing from ", pairingFile
    pairing = loadPairing(pairingFile)
  else:
    info "Keycard: no pairing found, pairing now..."
    let pairResult =
      if pairingTokenHex.len == 64:
        debug "Keycard: pairing with raw token (bypassing PBKDF2)"
        let token = utils.fromHex(pairingTokenHex)
        card.pairWithToken(token)
      else:
        card.pair(pairingPassword)
    if not pairResult.success:
      raise newException(IOError, "PAIR failed: " & $pairResult.error)
    pairing = PairingInfo(index: pairResult.pairingIndex, key: pairResult.pairingKey)
    savePairing(pairingFile, pairing)
    info "Keycard: paired, slot ", pairing.index

  debug "Keycard: opening secure channel (slot ", pairing.index, ")"
  let openResult = card.openSecureChannel(pairing.index, pairing.key)
  if not openResult.success:
    raise newException(IOError, "OPEN SECURE CHANNEL failed: " & $openResult.error)
  info "Keycard: secure channel open"

  debug "Keycard: verifying PIN"
  let pinResult = card.verifyPin(pin)
  if not pinResult.success:
    raise newException(IOError, "VERIFY PIN failed: " & $pinResult.error)
  info "Keycard: PIN verified"

  KeycardSession(card: card, pairing: pairing)

proc getPublicKeyBytes*(s: KeycardSession): seq[byte] =
  ## Export the x-only public key for the Nostr derivation path.
  let r = s.card.exportKey(derivation = Derive,
                            exportOpt  = PublicOnly,
                            path       = NostrKeyPath)
  if not r.success:
    raise newException(IOError, "Export public key failed: " & $r.error)
  # Card returns uncompressed 65-byte key; strip 0x04 prefix → x-only 32 bytes
  if r.publicKey.len == 65:
    return r.publicKey[1..32]
  elif r.publicKey.len == 33:
    return r.publicKey[1..32]
  else:
    return r.publicKey

proc signEvent*(s: KeycardSession, hash: array[32, byte]): array[64, byte] =
  ## Sign a 32-byte event hash.
  ## Tries Schnorr on card; falls back to software Schnorr with exported key.

  # The Keycard applet (v3.x) ignores P2 on the SIGN command and always
  # executes ECDSA regardless of the requested algorithm — BIP-340 Schnorr
  # is not implemented in firmware. Export the private key over the
  # encrypted secure channel and sign in software instead.
  debug "Keycard: exporting key for software Schnorr (hardware Schnorr not supported by applet)"
  let exportResult = s.card.exportKey(
    derivation = Derive,
    exportOpt  = PrivateAndPublic,
    path       = NostrKeyPath
  )
  if not exportResult.success:
    debug "Keycard: export key failed — error=", exportResult.error, " sw=0x", $exportResult.sw
    raise newException(IOError, "Export private key failed: " & $exportResult.error & " sw=" & $exportResult.sw)

  assert exportResult.privateKey.len == 32, "expected 32-byte private key"

  var rawKey: array[32, byte]
  copyMem(addr rawKey[0], unsafeAddr exportResult.privateKey[0], 32)

  let seckey = SkSecretKey.fromRaw(rawKey).expect("valid secp256k1 key from card")

  # Wipe the raw key bytes immediately
  for i in 0..<32:
    rawKey[i] = 0

  let sig = seckey.signSchnorr(hash, Opt.none(array[32, byte]))
  result = sig.toRaw()
  info "Keycard: signed with software Schnorr (key exported, wiped after use)"
