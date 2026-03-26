## NIP-01 event serialization, ID computation, and Schnorr signing.

import std/[json, times]
import nimcrypto/sha2
import secp256k1

type
  NostrEvent* = object
    id*:         string
    pubkey*:     string
    created_at*: int64
    kind*:       int
    tags*:       JsonNode
    content*:    string
    sig*:        string

proc bytesToHex*(b: openArray[byte]): string =
  const hexChars = "0123456789abcdef"
  result = newStringOfCap(b.len * 2)
  for x in b:
    result.add hexChars[x shr 4]
    result.add hexChars[x and 0x0f]

proc computeEventId*(pubkey: string, created_at: int64, kind: int,
                     tags: JsonNode, content: string): array[32, byte] =
  ## SHA-256 of the canonical NIP-01 serialization.
  let serialized = $(%*[0, pubkey, created_at, kind, tags, content])
  var ctx: sha256
  ctx.init()
  ctx.update(cast[seq[byte]](serialized))
  let digest = ctx.finish()
  copyMem(addr result[0], unsafeAddr digest.data[0], 32)

proc buildEvent*(seckey: SkSecretKey, pubkeyHex: string, kind: int,
                 tags: JsonNode, content: string): NostrEvent =
  let created_at = getTime().toUnix()
  let id = computeEventId(pubkeyHex, created_at, kind, tags, content)
  let sig = seckey.signSchnorr(id, Opt.none(array[32, byte]))
  NostrEvent(
    id:         bytesToHex(id),
    pubkey:     pubkeyHex,
    created_at: created_at,
    kind:       kind,
    tags:       tags,
    content:    content,
    sig:        toHex(sig)
  )

proc toJson*(ev: NostrEvent): JsonNode =
  %*{
    "id":         ev.id,
    "pubkey":     ev.pubkey,
    "created_at": ev.created_at,
    "kind":       ev.kind,
    "tags":       ev.tags,
    "content":    ev.content,
    "sig":        ev.sig
  }
