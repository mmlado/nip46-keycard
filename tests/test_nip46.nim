## NIP-46 dispatcher tests — approval policy and request routing.
## Uses in-process calls (no relay/card needed).

import std/[asyncdispatch, json, unittest]
import secp256k1
import nimcrypto/sysrand
import ../src/nip44
import ../src/nip01
import ../src/config
import ../src/nip46

# Test keypairs (deterministic)
const
  SignerSecHex = "0000000000000000000000000000000000000000000000000000000000000001"
  ClientSecHex = "0000000000000000000000000000000000000000000000000000000000000002"

proc signerSec(): SkSecretKey =
  SkSecretKey.fromHex(SignerSecHex).expect("signer key")

proc clientSec(): SkSecretKey =
  SkSecretKey.fromHex(ClientSecHex).expect("client key")

proc signerPubHex(): string =
  toHex(signerSec().toPublicKey().toXOnly())

proc clientPubHex(): string =
  toHex(clientSec().toPublicKey().toXOnly())

# Build a fake kind:24133 event as the client would send it
proc makeRequest(meth: string, params: JsonNode): JsonNode =
  let ss = signerSec()
  let clientPub = clientSec().toPublicKey()

  # Encrypt from client to signer
  var raw: array[33, byte]
  raw[0] = 0x02
  let xBytes = toHex(signerSec().toPublicKey().toXOnly())
  # Use xOnlyToFullPubkey from nip46
  let signerFullPub = xOnlyToFullPubkey(signerPubHex())
  let convKey = getConversationKey(clientSec(), signerFullPub)

  var nonce: array[32, byte]
  discard randomBytes(nonce)

  let payload = %*{"id": "test-req-id", "method": meth, "params": params}
  let encrypted = encrypt($payload, convKey, nonce)

  %*{
    "id":         "evtid",
    "pubkey":     clientPubHex(),
    "created_at": 1700000000,
    "kind":       24133,
    "tags":       [["p", signerPubHex()]],
    "content":    encrypted
  }

proc alwaysApproval(): ApprovalConfig =
  ApprovalConfig(mode: amAlways, allowedKinds: @[])

proc policyApproval(kinds: seq[int]): ApprovalConfig =
  ApprovalConfig(mode: amPolicy, allowedKinds: kinds)

proc dispatch(meth: string, params: JsonNode,
              approval = alwaysApproval()): JsonNode =
  let event = makeRequest(meth, params)
  let reply = waitFor handleRequest(signerSec(), signerPubHex(), signerPubHex(),
                                    nil, approval, event)
  # Decrypt the reply content
  let clientFullPub = xOnlyToFullPubkey(clientPubHex())
  let convKey = getConversationKey(signerSec(), clientFullPub)
  let plain = decrypt(reply["content"].getStr(), convKey)
  parseJson(plain)

suite "NIP-46 - connect":
  test "returns ack":
    let r = dispatch("connect", %*[clientPubHex()])
    check r["result"].getStr() == "ack"
    check r["error"].kind == JNull

suite "NIP-46 - get_public_key":
  test "returns user pubkey":
    let r = dispatch("get_public_key", newJArray())
    check r["result"].getStr() == signerPubHex()

suite "NIP-46 - ping":
  test "returns pong":
    let r = dispatch("ping", newJArray())
    check r["result"].getStr() == "pong"

suite "NIP-46 - sign_event":
  test "signs a kind:1 note":
    let unsignedEv = %*{
      "kind":       1,
      "content":    "hello from test",
      "tags":       [],
      "created_at": 1700000000
    }
    let r = dispatch("sign_event", %*[unsignedEv])
    check r["error"].kind == JNull
    let signed = parseJson(r["result"].getStr())
    check signed["id"].getStr().len == 64
    check signed["sig"].getStr().len == 128
    check signed["pubkey"].getStr() == signerPubHex()

  test "sign_event with stringified event param":
    let unsignedEv = %*{
      "kind":       1,
      "content":    "stringified",
      "tags":       [],
      "created_at": 1700000000
    }
    # noStrudel sends params[0] as a JSON string
    let r = dispatch("sign_event", %*[$unsignedEv])
    check r["error"].kind == JNull
    let signed = parseJson(r["result"].getStr())
    check signed["sig"].getStr().len == 128

suite "NIP-46 - approval policy":
  test "amAlways approves any kind":
    let unsignedEv = %*{"kind": 9, "content": "", "tags": [], "created_at": 1700000000}
    let r = dispatch("sign_event", %*[unsignedEv], alwaysApproval())
    check r["error"].kind == JNull

  test "amPolicy approves allowed kind":
    let unsignedEv = %*{"kind": 1, "content": "", "tags": [], "created_at": 1700000000}
    let r = dispatch("sign_event", %*[unsignedEv], policyApproval(@[1, 0]))
    check r["error"].kind == JNull

  test "amPolicy rejects disallowed kind":
    let unsignedEv = %*{"kind": 4, "content": "", "tags": [], "created_at": 1700000000}
    let r = dispatch("sign_event", %*[unsignedEv], policyApproval(@[1, 0]))
    check r["error"].getStr().len > 0
    check r["result"].getStr() == ""

suite "NIP-46 - unknown method":
  test "returns error":
    let r = dispatch("delete_account", newJArray())
    check r["error"].getStr().len > 0
