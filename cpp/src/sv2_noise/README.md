# SV2 Noise native core

This directory contains the native implementation of the Stratum V2 responder protocol used by
both pools:

`Noise_NX_Secp256k1+EllSwift_ChaChaPoly_SHA256`

The C++ pool links it statically. Python loads the shared build through the stable C ABI in
`include/sv2_noise.h`.

The runtime receives a server static secret and pre-signed certificate; the authority private key
stays offline.

Certificate validity is inclusive: both `valid_from` and `not_valid_after` are valid instants. The
server does not apply an initiator clock-skew allowance.

The library does not perform socket I/O, parse messages, read files, obtain the time, or own caller
buffers. A session owns only its transport keys, nonces, and terminal state.

## Build

```sh
cmake -S cpp/src/sv2_noise -B build/sv2-noise -DCMAKE_BUILD_TYPE=Release
cmake --build build/sv2-noise
ctest --test-dir build/sv2-noise --output-on-failure
```

The build produces a static library by default. Set `SV2_NOISE_BUILD_SHARED=ON` to build
`libsv2_noise.so` for Python. It uses OpenSSL 3 and libsecp256k1.

libsecp256k1 is **not vendored**: the build environment installs it, pinned by commit, exactly the
way Glaze and mimalloc are installed (see `cpp/docker/Dockerfile` and `cpp/Dockerfile`).

| | |
| --- | --- |
| Upstream | <https://github.com/bitcoin-core/secp256k1> |
| Commit | `1a53f4961f337b4d166c25fce72ef0dc88806618` (release `v0.7.1`) |
| License | MIT ([notice](LICENSE-secp256k1)) |
| Configuration | PIC static, hidden visibility, API visibility attributes off; `extrakeys` + `schnorrsig` + `ellswift` on; ECDH, recovery, MuSig, tests, exhaustive tests, ctime tests, benchmarks, examples and Valgrind support off |

The pin is by **commit, not tag** -- Git tags are mutable and this library performs the BIP340
certificate verification. `find_package(libsecp256k1 CONFIG REQUIRED)` resolves it; point
`CMAKE_PREFIX_PATH` at your install prefix if it is not on the default search path.

libsecp256k1 links `PRIVATE` everywhere and is compiled with hidden visibility, so it stays behind
this library's own C interface.

Builds can disable the library, the credential tool, or the tests through the `SV2_NOISE_BUILD_*`
CMake options. The tool and tests default on only for top-level builds; the pool's own
`cpp/CMakeLists.txt` turns the tests and the credential tool on explicitly so `ctest` covers this
core too.

## Python binding

`python/erikslund_pool/sv2/noise.py` owns native credential and session handles through `ctypes`.
The production Python image builds the same pinned source as a shared library, so protocol and
cryptographic behavior cannot drift between implementations.

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
