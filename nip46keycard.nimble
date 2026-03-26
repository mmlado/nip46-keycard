# Package

version       = "0.1.0"
author        = "Mladen Milankovic"
description   = "NIP-46 Nostr remote signer proxy backed by Keycard hardware"
license       = "Apache-2.0"
srcDir        = "src"
bin           = @["nip46keycard"]


# Dependencies

requires "nim >= 2.0.0"
requires "ws >= 0.5.0"
requires "parsetoml >= 0.7.0"
requires "nimcrypto >= 0.5.4"
requires "https://github.com/status-im/nim-secp256k1 >= 0.0.1"
requires "https://git.sr.ht/~ehmry/chacha20 >= 0.0.1"

task test, "Run all unit tests":
  const extraPaths = " --path:/home/mmlado/projects/logos/keycard-nim/src" &
                     " --path:/home/mmlado/projects/logos/pcsc-nim/src" &
                     " -d:ssl"
  exec "nim c -r tests/test_nip44.nim"
  exec "nim c -r tests/test_nip01.nim"
  exec "nim c -r --path:src tests/test_config.nim"
  exec "nim c -r --path:src tests/test_keypair.nim"
  exec "nim c -r --path:src" & extraPaths & " tests/test_keycard.nim"
  exec "nim c -r" & extraPaths & " tests/test_nip46.nim"
