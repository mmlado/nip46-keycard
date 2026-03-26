import std/[asyncdispatch, json, logging, os, strutils]
import relay
import config
import keypair
import nip46
import keycard as kc

const DefaultConfigPath = "config.toml"

proc makeMessageHandler(kp: SignerKeypair,
                        userPubkey: string,
                        cardSession: kc.KeycardSession,
                        approval: ApprovalConfig,
                        conns: ref seq[RelayConn]): MessageHandler =
  let signerPubkey = kp.pubkeyHex()

  result = proc(msg: JsonNode) {.async.} =
    let msgType = msg[0].getStr()
    case msgType
    of "EVENT":
      let event = msg[2]
      if event["kind"].getInt() == 24133:
        let reply = await handleRequest(kp.seckey, signerPubkey, userPubkey,
                                        cardSession, approval, event)
        if reply != nil:
          let envelope = %*["EVENT", reply]
          for conn in conns[]:
            await conn.send(envelope)
    of "OK":
      debug "Event accepted: ", msg[1].getStr()
    of "NOTICE":
      info "Relay notice: ", msg[1].getStr()
    of "EOSE":
      debug "EOSE for sub: ", msg[1].getStr()
    else:
      discard

proc main() {.async.} =
  addHandler(newConsoleLogger(fmtStr = "$time [$levelname] "))

  let configPath = if paramCount() > 0: paramStr(1) else: DefaultConfigPath
  let cfg = loadConfig(configPath)

  if cfg.relay.urls.len == 0:
    fatal "No relay URLs configured"
    quit(1)

  let kp = loadOrGenerate(cfg.signer.keyFile)
  info "Signer pubkey: ", kp.pubkeyHex()

  # Try to open Keycard session
  var cardSession: kc.KeycardSession = nil

  let pairingFile = cfg.signer.keyFile & ".pairing"

  try:
    cardSession = kc.openSession(pairingFile, cfg.keycard.pin,
                                 cfg.keycard.pin,
                                 cfg.keycard.pairingToken)
    info "Keycard connected"
  except CatchableError as e:
    warn "Keycard not available, using software signing: ", e.msg

  # Determine user pubkey: from Keycard if available, else signer key
  let userPubkey =
    if cardSession != nil:
      try:
        let pubBytes = cardSession.getPublicKeyBytes()
        var hex = newStringOfCap(64)
        const hexChars = "0123456789abcdef"
        for b in pubBytes:
          hex.add hexChars[b shr 4]
          hex.add hexChars[b and 0x0f]
        info "User pubkey (from Keycard): ", hex
        hex
      except CatchableError as e:
        warn "Could not get Keycard pubkey, using signer key: ", e.msg
        kp.pubkeyHex()
    else:
      kp.pubkeyHex()

  var conns = new seq[RelayConn]
  info "Approval mode: ", cfg.approval.mode
  let handler = makeMessageHandler(kp, userPubkey, cardSession, cfg.approval, conns)

  for url in cfg.relay.urls:
    let conn = newRelayConn(url, kp.pubkeyHex(), handler)
    await conn.start()
    conns[].add(conn)

  let secret = if cfg.connection.secret.len > 0: "&secret=" & cfg.connection.secret else: ""
  echo ""
  echo "bunker://" & kp.pubkeyHex() & "?relay=" & cfg.relay.urls[0] & secret
  echo ""

  while true:
    await sleepAsync(1_000)

when isMainModule:
  waitFor main()
