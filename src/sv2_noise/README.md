# SV2 Noise native core

This directory contains the pool's native Stratum V2 responder protocol implementation:

`Noise_NX_Secp256k1+EllSwift_ChaChaPoly_SHA256`

The pool links it statically through the C ABI in `include/sv2_noise.h`.

The runtime receives a server static secret and pre-signed certificate; the authority private key
stays offline.

Certificate validity is inclusive: both `valid_from` and `not_valid_after` are valid instants. The
server does not apply an initiator clock-skew allowance.

The library does not perform socket I/O, parse messages, read files, obtain the time, or own caller
buffers. A session owns only its transport keys, nonces, and terminal state.

## Build

```sh
cmake -S src/sv2_noise -B build/sv2-noise -DCMAKE_BUILD_TYPE=Release
cmake --build build/sv2-noise
ctest --test-dir build/sv2-noise --output-on-failure
```

The static library uses OpenSSL 3 and libsecp256k1.

libsecp256k1 is **not vendored**: the build environment installs the pinned release in the same
way as Glaze and mimalloc (see `docker/Dockerfile` and the root `Dockerfile`).

| | |
| --- | --- |
| Upstream | <https://github.com/bitcoin-core/secp256k1> |
| Version | `v0.8.0` |
| License | MIT ([notice](LICENSE-secp256k1)) |
| Configuration | PIC static, hidden visibility, API visibility attributes off; `extrakeys` + `schnorrsig` + `ellswift` on; ECDH, recovery, MuSig, tests, exhaustive tests, ctime tests, benchmarks, examples and Valgrind support off |

`find_package(libsecp256k1 CONFIG REQUIRED)` resolves the installed package. Point
`CMAKE_PREFIX_PATH` at its install prefix if it is not on the default search path.

libsecp256k1 links `PRIVATE` everywhere and is compiled with hidden visibility, so it stays behind
this library's own C interface.

The credential tool and tests are controlled by `SV2_NOISE_BUILD_CREDENTIAL_TOOL` and
`SV2_NOISE_BUILD_TESTS`. They default on for standalone builds, and the root `CMakeLists.txt`
enables both so the main test run covers this core.

## Offline credential provisioning

`sv2-noise-credentials` writes raw files and never overwrites them. Generate the server keypair:

```sh
sv2-noise-credentials keypair server-static.secret server-static.public
```

Copy `server-static.public` to the offline authority host, then issue the certificate:

```sh
sv2-noise-credentials keypair authority.secret authority.public
sv2-noise-credentials issue \
    authority.secret server-static.public \
    server-authority.public server.cert \
    VALID_FROM_UNIX NOT_VALID_AFTER_UNIX
```

Copy `server-authority.public` and `server.cert` to the server. The runtime inputs are
`server-static.secret` (32 bytes, mode 0600), `server-authority.public` (32 bytes), and
`server.cert` (74 bytes). Keep `authority.secret` offline; the runtime neither needs nor accepts
it.

Publish the Base58Check authority key through a trusted channel:

```sh
authority_key="$(sv2-noise-credentials print-authority-key server-authority.public)"
printf 'stratum2+tcp://pool.example:3334/%s\n' "$authority_key"
```

An existing secret must be a 32-byte secp256k1 scalar with mode 0600. Validity values are inclusive
unsigned 32-bit Unix seconds, and the end must be later than the start.

## Interoperability

The responder API interoperates with SRI `noise_sv2` 1.4.2 at commit
`c1a7991394254c806f97a5feb4f4be771596ce69`, including certificate rejection with the wrong
authority key.

See `include/sv2_noise.h` for ownership, framing, and terminal-state rules.
