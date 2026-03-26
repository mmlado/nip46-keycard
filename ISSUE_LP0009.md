# LP-0009: Clarification Request — Schnorr Signing and Keycard

## Summary

While implementing LP-0009 in Nim (working NIP-46 proxy, tested end-to-end with noStrudel), we hit a question about the intended Keycard integration approach. We are requesting clarification before submitting.

---

## The Issue

**Nostr requires BIP-340 Schnorr signatures.** NIP-01 mandates Schnorr on secp256k1 for all events. There is no fallback — every NIP-46-compatible client (Coracle, noStrudel, Snort) will reject events signed with anything else.

**The current Keycard applet only supports ECDSA.** The `SIGN` command produces secp256k1 ECDSA signatures. BIP-340 Schnorr (`algorithm = 0x03`) is defined in the applet protocol as a placeholder but returns `SW_FUNCTION_NOT_SUPPORTED (0x6A81)` on real hardware today.

---

## What We Are Doing

We have implemented the following approach, which we believe satisfies the spirit of the prize:

1. **Try Schnorr on card first** (`SIGN` with algorithm `0x03`). If the applet ever gains Schnorr support, signing moves fully onto the card with no code changes needed.

2. **Fallback: export key + software Schnorr.** If the card returns `0x6A81`, we use `EXPORT KEY` with `PrivateAndPublic` on the EIP-1581 subtree (`m/43'/60'/1581'/0'/0`) — the only path the Keycard applet allows private key export for. The 32-byte private key is transmitted over the encrypted secure channel, used for Schnorr signing in the daemon, then wiped from memory immediately.

This means:
- The private key **cannot be used without the physical Keycard and correct PIN**.
- The key **never exists in plaintext on disk**.
- The hardware enforces access control even if it cannot execute the final signing operation itself.

---

## Questions for the Prize Committee

1. **Is this approach acceptable?** Hardware-enforced key protection with software Schnorr as a fallback until the applet gains native Schnorr support.

2. **Is a Keycard firmware update planned** to add BIP-340 Schnorr? If so, is the prize timeline aligned with that?

3. If the intended approach differs from what we describe, any guidance would be appreciated.

---

## Our Current Status

For reference, our Nim implementation currently has:
- Full NIP-46 relay connection with exponential backoff reconnect
- NIP-44 v2 encryption/decryption (tested against official spec vectors)
- `connect`, `get_public_key`, `sign_event` — tested end-to-end with noStrudel
- Keycard integration: SELECT → pair → open secure channel → verify PIN → try Schnorr → fallback to export + software sign + wipe
- Graceful fallback to pure software signing when no card is present
