# nip46-keycard

A NIP-46 remote signer daemon that bridges Nostr signing requests to a [Status Keycard](https://keycard.tech) hardware wallet over USB.

Private keys are stored on the card's secure element and never exist in plaintext on disk. Any NIP-46-compatible client (Coracle, noStrudel, Snort) can use it as a drop-in signer.

## Demo

https://github.com/mmlado/nip46-keycard/blob/main/docs/demo.mp4

## How it works

```
Nostr Client  ──NIP-46──▶  Relay  ──NIP-46──▶  nip46-keycard  ──PC/SC──▶  Keycard
```

1. The daemon subscribes to a Nostr relay and listens for encrypted kind:24133 events addressed to the signer key.
2. Incoming requests are decrypted with NIP-44 v2 and dispatched to the appropriate handler.
3. For `sign_event`, the daemon attempts a BIP-340 Schnorr signature on the Keycard. If the card firmware does not yet support Schnorr (`SW=0x6A81`), it exports the private key over the encrypted secure channel, signs in software, and wipes the key from memory immediately.
4. The response is encrypted with NIP-44 and published back to the relay.

## Requirements

- Nim ≥ 2.0
- A Status Keycard and a USB PC/SC reader
- pcscd running (`sudo systemctl start pcscd`)

## Installation

```sh
git clone https://github.com/mmlado/nip46-keycard
cd nip46-keycard
nimble build -d:release
```

## Keycard setup

The card must be initialised before first use. Use [keycard-cli](https://github.com/status-im/keycard-cli) or any Keycard-compatible app to:

1. Initialise the card with a PIN, PUK, and pairing password.
2. Generate a key on the card (`generateKey`).

On first run, the daemon will pair with the card using the configured pairing password and store the pairing index and key in `<key_file>.pairing`. Keep this file private.

## Configuration

Copy `config.example.toml` to `config.toml` and edit:

```toml
[relay]
# One or more Nostr relay WebSocket URLs
urls = ["wss://relay.damus.io", "wss://nos.lol"]

[keycard]
# PIN for the Keycard — leave empty to be prompted at startup (not yet implemented)
pin = ""
pairing_token = ""

[signer]
# Path to the signer keypair file — generated on first run if absent
key_file = "~/.config/nip46-keycard/signer.key"

[approval]
# "policy" — auto-approve only the event kinds listed below
# "always" — approve everything (testing only)
mode = "policy"

# Event kinds to auto-approve when mode = "policy"
# kind 0 = profile metadata, kind 1 = short text note, kind 3 = contact list
allowed_kinds = [0, 1, 3]

[connection]
# Optional shared secret embedded in the bunker:// URL.
# Clients must provide this secret in the connect request.
secret = ""
```

## Running

```sh
./nip46keycard config.toml
```

On startup the daemon opens the Keycard session, connects to the configured relays, and prints a `bunker://` URL. On the first signing request it exports the private key over the encrypted secure channel, signs with BIP-340 Schnorr in software, and wipes the key from memory immediately:

```
./nip46keycard config.toml
12:02:04 [INFO] Signer pubkey: 4f6915de49dbfe3457bcedaf217a25ac188222f96e1a17aa518eb57e5ccf0c89
12:02:04 [INFO] Keycard: connecting to reader: Generic USB2.0-CRW [Smart Card Reader Interface] (20070818000000000) 00 00
12:02:04 [INFO] Keycard: applet selected (v3.1)
12:02:04 [DEBUG] Keycard: loading pairing from /home/mmlado/.config/nip46-keycard/signer.key.pairing
12:02:04 [INFO] Keycard: secure channel open
12:02:05 [INFO] Keycard: PIN verified
12:02:05 [INFO] Keycard connected
12:02:05 [INFO] User pubkey (from Keycard): 1ed7d46f37d4f0f5f35538679bf77fd9b0a839041acf3a1dbbae5a3e0fd347e1
12:02:05 [INFO] Approval mode: policy
12:02:05 [INFO] Connected to relay: wss://nos.lol
12:02:05 [INFO] Connected to relay: wss://relay.damus.io

bunker://4f6915de49dbfe3457bcedaf217a25ac188222f96e1a17aa518eb57e5ccf0c89?relay=wss://relay.damus.io

12:02:10 [DEBUG] NIP-46 sign_event from 4bab9608...
12:02:10 [DEBUG] Keycard: exporting key for software Schnorr (hardware Schnorr not supported by applet)
12:02:11 [INFO] Keycard: signed with software Schnorr (key exported, wiped after use)
12:02:11 [INFO] NIP-46 reply: sign_event -> ok
12:02:11 [DEBUG] Event accepted: e9c77d6fb92bc9b8091de2e5c3cc65950dd2872280493326028dde46575e908b
```

Copy the `bunker://` URL and paste it into your Nostr client's NIP-46 / remote signer field.

If no Keycard is detected the daemon falls back to software signing using the signer keypair and logs a warning.

## Client integration

### noStrudel

1. Open [nostrudel.ninja](https://nostrudel.ninja)
2. Click the account icon → **Add Account** → **Nostr Connect (NIP-46)**
3. Paste the `bunker://` URL

### Coracle

1. Open [coracle.social](https://coracle.social)
2. Settings → Keys → **Login with bunker URL**
3. Paste the `bunker://` URL

## Supported NIP-46 methods

| Method | Description |
|--------|-------------|
| `connect` | Establish a session with the client |
| `get_public_key` | Return the user's Nostr public key |
| `sign_event` | Sign an event (subject to approval policy) |
| `ping` | Keepalive — returns `"pong"` |

## Running tests

```sh
nimble test
```

## Known limitations

- **Schnorr signing is performed in software.** The Keycard applet (v3.x) ignores the algorithm byte on the `SIGN` command and always executes ECDSA — BIP-340 Schnorr is not implemented in firmware. The daemon exports the private key over the encrypted secure channel (the EIP-1581 subtree is the only path the applet permits this for), signs in software using BIP-340 Schnorr, and immediately wipes the key from memory. The private key is only accessible when the physical card is present and the PIN is verified. When the applet gains native Schnorr support, switching to on-card signing requires changing one call in `keycard.nim`.
- PIN must be stored in `config.toml` — interactive prompting is not supported.
- NIP-04 and NIP-44 encrypt/decrypt methods are not supported (out of scope per LP-0009).
- NFC transport is not supported.

## License

Apache-2.0
