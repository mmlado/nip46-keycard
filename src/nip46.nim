## NIP-46 remote signer — request dispatcher.
##
## Handles: connect, get_public_key, sign_event, ping
## Encryption: NIP-44 v2 (conversation key = ECDH(signer_seckey, client_pubkey))

import std/[asyncdispatch, json, logging]
import nimcrypto/[sysrand, utils]
import secp256k1
import nip44
import nip01
import keycard as kc
import config

proc xOnlyToFullPubkey*(xOnlyHex: string): SkPublicKey =
  ## Convert a 32-byte x-only pubkey hex to a compressed SkPublicKey (0x02 prefix).
  var raw: array[33, byte]
  raw[0] = 0x02
  let xBytes = utils.fromHex(xOnlyHex)
  assert xBytes.len == 32, "expected 32-byte x-only pubkey"
  copyMem(addr raw[1], unsafeAddr xBytes[0], 32)
  SkPublicKey.fromRaw(raw).expect("valid pubkey from x-only")

proc nip46Encrypt(seckey: SkSecretKey, clientPubkeyHex, plaintext: string): string =
  let clientPubkey = xOnlyToFullPubkey(clientPubkeyHex)
  let convKey = getConversationKey(seckey, clientPubkey)
  var nonce: array[32, byte]
  if randomBytes(nonce) != 32:
    raise newException(IOError, "failed to generate random nonce")
  encrypt(plaintext, convKey, nonce)

proc nip46Decrypt(seckey: SkSecretKey, clientPubkeyHex, payload: string): string =
  let clientPubkey = xOnlyToFullPubkey(clientPubkeyHex)
  let convKey = getConversationKey(seckey, clientPubkey)
  decrypt(payload, convKey)

proc handleRequest*(seckey: SkSecretKey, signerPubkeyHex, userPubkeyHex: string,
                    cardSession: kc.KeycardSession,
                    approval: ApprovalConfig,
                    event: JsonNode): Future[JsonNode] {.async.} =
  ## Decrypt and dispatch a kind:24133 NIP-46 request.
  ## Returns a signed kind:24133 reply event, or nil on error.
  let clientPubkeyHex = event["pubkey"].getStr()

  let plaintext = try:
    nip46Decrypt(seckey, clientPubkeyHex, event["content"].getStr())
  except CatchableError as e:
    warn "NIP-46 decrypt failed: ", e.msg
    return nil

  let req = try: parseJson(plaintext)
  except CatchableError as e:
    warn "NIP-46 bad JSON: ", e.msg
    return nil

  let reqId  = req["id"].getStr()
  let meth   = req["method"].getStr()
  let params = if req.hasKey("params"): req["params"] else: newJArray()

  debug "NIP-46 ", meth, " from ", clientPubkeyHex[0..7], "..."

  var resultStr = ""
  var errorStr  = ""

  case meth
  of "connect":
    # params: [client_pubkey, secret?, perms?]
    # TODO: verify secret against config when approval policy requires it
    resultStr = "ack"
  of "get_public_key":
    resultStr = userPubkeyHex
  of "sign_event":
    if params.len == 0:
      errorStr = "missing event parameter"
    else:
      try:
        let ev = if params[0].kind == JString: parseJson(params[0].getStr())
                 else: params[0]
        let kind = ev["kind"].getInt()

        let approved = case approval.mode
          of amAlways: true
          of amPolicy: kind in approval.allowedKinds

        if not approved:
          info "Rejected sign_event kind ", kind, " (not in allowed_kinds)"
          errorStr = "kind " & $kind & " not approved by policy"
        else:
          let tags      = if ev.hasKey("tags"): ev["tags"] else: newJArray()
          let evContent = ev["content"].getStr()
          let created   = ev["created_at"].getBiggestInt()

          let id = computeEventId(userPubkeyHex, created, kind, tags, evContent)

          let sigBytes =
            if cardSession != nil:
              debug "Signing via Keycard (kind:", kind, " id:", bytesToHex(id)[0..7], "...)"
              cardSession.signEvent(id)
            else:
              debug "Signing via software (kind:", kind, " id:", bytesToHex(id)[0..7], "...)"
              seckey.signSchnorr(id, Opt.none(array[32, byte])).toRaw()

          let signed = %*{
            "id":         bytesToHex(id),
            "pubkey":     userPubkeyHex,
            "created_at": created,
            "kind":       kind,
            "tags":       tags,
            "content":    evContent,
            "sig":        bytesToHex(sigBytes)
          }
          resultStr = $signed
      except CatchableError as e:
        errorStr = "sign_event failed: " & e.msg
  of "ping":
    resultStr = "pong"
  else:
    errorStr = "unsupported method: " & meth

  let response =
    if errorStr.len > 0:
      %*{"id": reqId, "result": "", "error": errorStr}
    else:
      %*{"id": reqId, "result": resultStr, "error": newJNull()}

  let replyContent = nip46Encrypt(seckey, clientPubkeyHex, $response)
  let replyTags    = %*[["p", clientPubkeyHex]]
  let replyEvent   = buildEvent(seckey, signerPubkeyHex, 24133, replyTags, replyContent)

  info "NIP-46 reply: ", meth, " -> ", (if errorStr.len > 0: "error" else: "ok")
  return replyEvent.toJson()
