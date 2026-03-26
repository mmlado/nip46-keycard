import std/[asyncdispatch, json, logging]
import ws

const
  ReconnectDelayMs  = 3_000
  ReconnectMaxDelay = 30_000

type
  MessageHandler* = proc(msg: JsonNode): Future[void] {.async.}

  RelayConn* = ref object
    url*:     string
    pubkey*:  string
    handler*: MessageHandler
    ws:       WebSocket
    running:  bool

proc newRelayConn*(url: string, pubkey: string, handler: MessageHandler): RelayConn =
  RelayConn(url: url, pubkey: pubkey, handler: handler, running: false)

proc send*(r: RelayConn, msg: JsonNode) {.async.} =
  await r.ws.send($msg)

proc sendSubscription(r: RelayConn) {.async.} =
  let req = %*["REQ", "nip46", {"kinds": [24133], "#p": [r.pubkey]}]
  await r.send(req)
  info "Subscribed for pubkey: ", r.pubkey

proc runLoop(r: RelayConn) {.async.} =
  var delay = ReconnectDelayMs
  while r.running:
    try:
      info "Connecting to relay: ", r.url
      r.ws = await newWebSocket(r.url)
      info "Connected to relay: ", r.url
      delay = ReconnectDelayMs
      await r.sendSubscription()
      while r.ws.readyState == Open:
        let raw = await r.ws.receiveStrPacket()
        if raw.len == 0:
          continue
        let msg = parseJson(raw)
        await r.handler(msg)
    except WebSocketError as e:
      warn "WebSocket error: ", e.msg
    except JsonParsingError as e:
      warn "Failed to parse relay message: ", e.msg
    except Exception as e:
      warn "Relay connection lost: ", e.msg

    if r.running:
      info "Reconnecting in ", delay, "ms..."
      await sleepAsync(delay)
      delay = min(delay * 2, ReconnectMaxDelay)

proc start*(r: RelayConn) {.async.} =
  r.running = true
  asyncCheck r.runLoop()

proc stop*(r: RelayConn) =
  r.running = false
  if r.ws != nil:
    r.ws.close()
