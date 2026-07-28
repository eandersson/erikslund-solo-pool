"""Unit tests for SV2 Noise credential ownership and native-binding boundaries."""

import ctypes
import io
import pathlib
import tempfile
import typing
import unittest
from unittest.mock import Mock
from unittest.mock import patch

from erikslund_pool.sv2 import noise as sv2_noise


def _certificate(expiry_timestamp: int) -> bytes:
    return (
        sv2_noise.CERTIFICATE_FORMAT_VERSION.to_bytes(2, "little")
        + (expiry_timestamp - 100).to_bytes(4, "little")
        + expiry_timestamp.to_bytes(4, "little")
        + b"c" * 64
    )


class _ReadIntoOnlyFile:
    def __init__(
        self,
        data: bytes,
        *,
        chunk_size: int = 7,
        fail_after_reads: int | None = None,
    ) -> None:
        self._data = data
        self._offset = 0
        self._chunk_size = chunk_size
        self._fail_after_reads = fail_after_reads
        self.read_count = 0
        self.destination_owner: bytearray | None = None

    def __enter__(self) -> typing.Self:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self, _size: int = -1) -> bytes:
        raise AssertionError("static secret must not be materialized as immutable bytes")

    def readinto(self, destination: memoryview) -> int:
        self.destination_owner = destination.obj
        if self._fail_after_reads == self.read_count:
            raise OSError("simulated secret read failure")
        self.read_count += 1
        remaining = len(self._data) - self._offset
        selected_size = min(len(destination), remaining, self._chunk_size)
        for offset in range(selected_size):
            destination[offset] = self._data[self._offset + offset]
        self._offset += selected_size
        return selected_size


class _FailingExitLock:
    def __enter__(self) -> None:
        return None

    def __exit__(self, *_args: object) -> None:
        raise MemoryError("simulated lock-exit failure")


class FakeCredentialBackend:
    def __init__(self) -> None:
        self.static_secret_reference: bytearray | None = None
        self.authority_public_key = b""
        self.certificate = b""
        self.unix_timestamp = 0
        self.freed_credentials: list[int] = []
        self.freed_sessions: list[int] = []
        self.load_error: BaseException | None = None

    def load_credentials(
        self,
        static_secret_key: bytearray,
        authority_public_key: bytes,
        certificate: bytes,
        unix_timestamp: int,
    ) -> int:
        self.static_secret_reference = static_secret_key
        self.authority_public_key = authority_public_key
        self.certificate = certificate
        self.unix_timestamp = unix_timestamp
        if self.load_error is not None:
            raise self.load_error
        return 7

    def free_credentials(self, credentials_handle: int) -> None:
        self.freed_credentials.append(credentials_handle)

    def responder_handshake(
        self,
        credentials_handle: int,
        act1: bytes,
        unix_timestamp: int,
    ) -> tuple[bytes, int]:
        if credentials_handle != 7 or not act1 or unix_timestamp <= 0:
            raise AssertionError((credentials_handle, act1, unix_timestamp))
        return b"2" * sv2_noise.ACT2_SIZE, 11

    def free_session(self, session_handle: int) -> None:
        self.freed_sessions.append(session_handle)

    def encrypt_header(self, session_handle: int, plaintext: bytes) -> bytes:
        raise AssertionError((session_handle, plaintext))

    def decrypt_header(self, session_handle: int, ciphertext: bytes) -> bytes:
        raise AssertionError((session_handle, ciphertext))

    def encrypt_payload(self, session_handle: int, plaintext: bytes) -> bytes:
        raise AssertionError((session_handle, plaintext))

    def decrypt_payload(
        self,
        session_handle: int,
        ciphertext: bytes,
        plaintext_length: int,
    ) -> bytes:
        raise AssertionError((session_handle, ciphertext, plaintext_length))


class TestNoiseCredentials(unittest.TestCase):
    def test_static_secret_reads_unbuffered_into_wipeable_storage(self) -> None:
        backend = FakeCredentialBackend()
        static_file = _ReadIntoOnlyFile(b"s" * sv2_noise.SECRET_KEY_SIZE)
        public_files = [
            io.BytesIO(b"a" * sv2_noise.PUBLIC_KEY_SIZE),
            io.BytesIO(b"c" * sv2_noise.CERTIFICATE_SIZE),
        ]

        with patch(
            "erikslund_pool.sv2.noise.pathlib.Path.open",
            side_effect=[static_file, *public_files],
        ) as open_file:
            credentials = sv2_noise.NoiseCredentials.from_files(
                backend,
                "static-secret.raw",
                "authority-public.raw",
                "certificate.raw",
            )

        first_open = open_file.call_args_list[0]
        self.assertEqual(first_open.args, ("rb",))
        self.assertEqual(first_open.kwargs, {"buffering": 0})
        self.assertGreater(static_file.read_count, 1)
        self.assertIs(static_file.destination_owner, backend.static_secret_reference)
        self.assertEqual(
            backend.static_secret_reference,
            bytearray(sv2_noise.SECRET_KEY_SIZE),
        )
        credentials.close()

    def test_static_secret_read_failure_wipes_partially_filled_storage(self) -> None:
        static_file = _ReadIntoOnlyFile(
            b"s" * sv2_noise.SECRET_KEY_SIZE,
            fail_after_reads=1,
        )

        with (
            patch(
                "erikslund_pool.sv2.noise.pathlib.Path.open",
                return_value=static_file,
            ),
            self.assertRaisesRegex(OSError, "simulated secret read failure"),
        ):
            sv2_noise.NoiseCredentials.from_files(
                FakeCredentialBackend(),
                "static-secret.raw",
                "authority-public.raw",
                "certificate.raw",
            )

        self.assertIsNotNone(static_file.destination_owner)
        self.assertEqual(
            static_file.destination_owner,
            bytearray(sv2_noise.SECRET_KEY_SIZE + 1),
        )

    def test_loads_exact_raw_files_and_wipes_secret_buffer(self) -> None:
        backend = FakeCredentialBackend()
        expiry_timestamp = 1_900_000_000
        certificate = _certificate(expiry_timestamp)
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = pathlib.Path(temporary_directory)
            static_path = directory / "static-secret.raw"
            authority_path = directory / "authority-public.raw"
            certificate_path = directory / "certificate.raw"
            static_path.write_bytes(b"s" * sv2_noise.SECRET_KEY_SIZE)
            authority_path.write_bytes(b"a" * sv2_noise.PUBLIC_KEY_SIZE)
            certificate_path.write_bytes(certificate)

            credentials = sv2_noise.NoiseCredentials.from_files(
                backend,
                static_path,
                authority_path,
                certificate_path,
                clock=lambda: 1_234.9,
            )

        self.assertIsNotNone(backend.static_secret_reference)
        self.assertEqual(
            backend.static_secret_reference,
            bytearray(sv2_noise.SECRET_KEY_SIZE),
        )
        self.assertEqual(
            backend.authority_public_key,
            b"a" * sv2_noise.PUBLIC_KEY_SIZE,
        )
        self.assertEqual(backend.certificate, certificate)
        self.assertEqual(backend.unix_timestamp, 1_234)
        self.assertEqual(credentials.certificate_expiry_timestamp, expiry_timestamp)
        credentials.close()
        credentials.close()
        self.assertEqual(backend.freed_credentials, [7])

    def test_rejects_non_exact_raw_file_before_native_load(self) -> None:
        backend = FakeCredentialBackend()
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = pathlib.Path(temporary_directory)
            static_path = directory / "static-secret.raw"
            authority_path = directory / "authority-public.raw"
            certificate_path = directory / "certificate.raw"
            static_path.write_bytes(b"s" * (sv2_noise.SECRET_KEY_SIZE - 1))
            authority_path.write_bytes(b"a" * sv2_noise.PUBLIC_KEY_SIZE)
            certificate_path.write_bytes(b"c" * sv2_noise.CERTIFICATE_SIZE)

            with self.assertRaisesRegex(
                sv2_noise.NoiseCredentialSizeError,
                "exactly 32 raw bytes",
            ):
                sv2_noise.NoiseCredentials.from_files(
                    backend,
                    static_path,
                    authority_path,
                    certificate_path,
                )

        self.assertIsNone(backend.static_secret_reference)

    def test_wipes_secret_buffer_when_native_verification_fails(self) -> None:
        backend = FakeCredentialBackend()
        expiry_timestamp = 1_900_000_000
        native_error = sv2_noise.NoiseNativeError(
            "load responder credentials",
            sv2_noise.STATUS_CERTIFICATE_EXPIRED,
            "certificate expired",
        )
        backend.load_error = native_error
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = pathlib.Path(temporary_directory)
            static_path = directory / "static-secret.raw"
            authority_path = directory / "authority-public.raw"
            certificate_path = directory / "certificate.raw"
            static_path.write_bytes(b"s" * sv2_noise.SECRET_KEY_SIZE)
            authority_path.write_bytes(b"a" * sv2_noise.PUBLIC_KEY_SIZE)
            certificate_path.write_bytes(_certificate(expiry_timestamp))

            with self.assertRaises(sv2_noise.NoiseNativeError) as raised:
                sv2_noise.NoiseCredentials.from_files(
                    backend,
                    static_path,
                    authority_path,
                    certificate_path,
                )

        self.assertEqual(
            backend.static_secret_reference,
            bytearray(sv2_noise.SECRET_KEY_SIZE),
        )
        self.assertIs(raised.exception, native_error)
        self.assertEqual(raised.exception.status, sv2_noise.STATUS_CERTIFICATE_EXPIRED)
        self.assertEqual(
            raised.exception.certificate_expiry_timestamp,
            expiry_timestamp,
        )

    def test_library_load_error_preserves_exact_certificate_expiry(self) -> None:
        backend = FakeCredentialBackend()
        expiry_timestamp = 1_900_000_000
        library_error = sv2_noise.NoiseLibraryError("native library unavailable")
        backend.load_error = library_error
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = pathlib.Path(temporary_directory)
            static_path = directory / "static-secret.raw"
            authority_path = directory / "authority-public.raw"
            certificate_path = directory / "certificate.raw"
            static_path.write_bytes(b"s" * sv2_noise.SECRET_KEY_SIZE)
            authority_path.write_bytes(b"a" * sv2_noise.PUBLIC_KEY_SIZE)
            certificate_path.write_bytes(_certificate(expiry_timestamp))

            with self.assertRaises(sv2_noise.NoiseLibraryError) as raised:
                sv2_noise.NoiseCredentials.from_files(
                    backend,
                    static_path,
                    authority_path,
                    certificate_path,
                )

        self.assertIs(raised.exception, library_error)
        self.assertEqual(
            raised.exception.certificate_expiry_timestamp,
            expiry_timestamp,
        )

    def test_constructor_failure_frees_loaded_native_credentials(self) -> None:
        backend = FakeCredentialBackend()
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = pathlib.Path(temporary_directory)
            static_path = directory / "static-secret.raw"
            authority_path = directory / "authority-public.raw"
            certificate_path = directory / "certificate.raw"
            static_path.write_bytes(b"s" * sv2_noise.SECRET_KEY_SIZE)
            authority_path.write_bytes(b"a" * sv2_noise.PUBLIC_KEY_SIZE)
            certificate_path.write_bytes(_certificate(1_900_000_000))

            with (
                patch(
                    "erikslund_pool.sv2.noise.threading.Lock",
                    side_effect=MemoryError("simulated lock allocation failure"),
                ),
                self.assertRaisesRegex(MemoryError, "simulated lock allocation failure"),
            ):
                sv2_noise.NoiseCredentials.from_files(
                    backend,
                    static_path,
                    authority_path,
                    certificate_path,
                )

        self.assertEqual(backend.freed_credentials, [7])
        self.assertEqual(
            backend.static_secret_reference,
            bytearray(sv2_noise.SECRET_KEY_SIZE),
        )

    def test_secret_wipe_failure_frees_loaded_native_credentials(self) -> None:
        backend = FakeCredentialBackend()
        wipe = sv2_noise._wipe

        def wipe_then_fail(secret: bytearray) -> None:
            wipe(secret)
            raise MemoryError("simulated post-load wipe failure")

        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = pathlib.Path(temporary_directory)
            static_path = directory / "static-secret.raw"
            authority_path = directory / "authority-public.raw"
            certificate_path = directory / "certificate.raw"
            static_path.write_bytes(b"s" * sv2_noise.SECRET_KEY_SIZE)
            authority_path.write_bytes(b"a" * sv2_noise.PUBLIC_KEY_SIZE)
            certificate_path.write_bytes(_certificate(1_900_000_000))

            with (
                patch("erikslund_pool.sv2.noise._wipe", side_effect=wipe_then_fail),
                self.assertRaisesRegex(MemoryError, "simulated post-load wipe failure"),
            ):
                sv2_noise.NoiseCredentials.from_files(
                    backend,
                    static_path,
                    authority_path,
                    certificate_path,
                )

        self.assertEqual(backend.freed_credentials, [7])
        self.assertEqual(
            backend.static_secret_reference,
            bytearray(sv2_noise.SECRET_KEY_SIZE),
        )

    def test_handshake_wrapper_failure_frees_raw_native_session(self) -> None:
        backend = FakeCredentialBackend()
        credentials = sv2_noise.NoiseCredentials(backend, 7)

        with (
            patch(
                "erikslund_pool.sv2.noise.NoiseSession",
                side_effect=MemoryError("simulated session allocation failure"),
            ),
            self.assertRaisesRegex(MemoryError, "simulated session allocation failure"),
        ):
            credentials.handshake(b"act1")

        self.assertEqual(backend.freed_sessions, [11])
        credentials.close()

    def test_handshake_lock_exit_failure_frees_raw_native_session(self) -> None:
        backend = FakeCredentialBackend()
        credentials = sv2_noise.NoiseCredentials(backend, 7)
        original_lock = credentials._lock
        credentials._lock = _FailingExitLock()

        with self.assertRaisesRegex(MemoryError, "simulated lock-exit failure"):
            credentials.handshake(b"act1")

        self.assertEqual(backend.freed_sessions, [11])
        credentials._lock = original_lock
        credentials.close()


class TestNativeNoiseBinding(unittest.TestCase):
    def test_library_is_not_loaded_by_backend_construction(self) -> None:
        with patch("erikslund_pool.sv2.noise.ctypes.CDLL") as load_library:
            sv2_noise.NativeNoiseBackend("unused-library.so")

        load_library.assert_not_called()

    def test_encrypted_payload_size_matches_chunk_boundaries(self) -> None:
        cases = {
            0: 0,
            1: 17,
            65_518: 65_534,
            65_519: 65_535,
            65_520: 65_552,
            131_038: 131_070,
        }
        for plaintext_length, expected in cases.items():
            with self.subTest(plaintext_length=plaintext_length):
                self.assertEqual(
                    sv2_noise.encrypted_payload_size(plaintext_length),
                    expected,
                )

    def test_encrypted_payload_size_rejects_out_of_range(self) -> None:
        for plaintext_length in (-1, sv2_noise.MAX_FRAME_PAYLOAD_SIZE + 1):
            with (
                self.subTest(plaintext_length=plaintext_length),
                self.assertRaises(ValueError),
            ):
                sv2_noise.encrypted_payload_size(plaintext_length)

    def test_native_credential_error_frees_non_null_out_pointer(self) -> None:
        backend = sv2_noise.NativeNoiseBackend("unused-library.so")
        api = Mock()

        def fail_load(*arguments: object) -> int:
            credentials_out = ctypes.cast(
                arguments[-1],
                ctypes.POINTER(ctypes.c_void_p),
            )
            credentials_out[0] = ctypes.c_void_p(1_234)
            return sv2_noise.STATUS_CERTIFICATE_EXPIRED

        api.library.sv2_noise_credentials_load.side_effect = fail_load
        api.status_detail.return_value = "certificate expired"
        backend._api = api

        with self.assertRaises(sv2_noise.NoiseNativeError) as raised:
            backend.load_credentials(
                bytearray(b"s" * sv2_noise.SECRET_KEY_SIZE),
                b"a" * sv2_noise.PUBLIC_KEY_SIZE,
                _certificate(1_900_000_000),
                1_900_000_001,
            )

        self.assertEqual(raised.exception.status, sv2_noise.STATUS_CERTIFICATE_EXPIRED)
        freed_pointer = api.library.sv2_noise_credentials_free.call_args.args[0]
        self.assertEqual(freed_pointer.value, 1_234)

    def test_native_credential_call_exception_frees_written_out_pointer(self) -> None:
        backend = sv2_noise.NativeNoiseBackend("unused-library.so")
        api = Mock()
        memory_error = MemoryError("simulated ctypes conversion failure")

        def fail_after_write(*arguments: object) -> int:
            credentials_out = ctypes.cast(
                arguments[-1],
                ctypes.POINTER(ctypes.c_void_p),
            )
            credentials_out[0] = ctypes.c_void_p(2_345)
            raise memory_error

        api.library.sv2_noise_credentials_load.side_effect = fail_after_write
        backend._api = api

        with self.assertRaises(MemoryError) as raised:
            backend.load_credentials(
                bytearray(b"s" * sv2_noise.SECRET_KEY_SIZE),
                b"a" * sv2_noise.PUBLIC_KEY_SIZE,
                _certificate(1_900_000_000),
                1_900_000_001,
            )

        self.assertIs(raised.exception, memory_error)
        freed_pointer = api.library.sv2_noise_credentials_free.call_args.args[0]
        self.assertEqual(freed_pointer.value, 2_345)

    def test_invalid_act2_length_frees_non_null_native_session(self) -> None:
        backend = sv2_noise.NativeNoiseBackend("unused-library.so")
        api = Mock()

        def malformed_handshake(*arguments: object) -> int:
            act2_length_out = ctypes.cast(
                arguments[-2],
                ctypes.POINTER(ctypes.c_size_t),
            )
            session_out = ctypes.cast(
                arguments[-1],
                ctypes.POINTER(ctypes.c_void_p),
            )
            act2_length_out[0] = sv2_noise.ACT2_SIZE - 1
            session_out[0] = ctypes.c_void_p(5_678)
            return sv2_noise.STATUS_OK

        api.library.sv2_noise_responder_handshake.side_effect = malformed_handshake
        backend._api = api

        with self.assertRaisesRegex(
            sv2_noise.NoiseLibraryError,
            "returned 233 bytes",
        ):
            backend.responder_handshake(
                7,
                b"1" * sv2_noise.ACT1_SIZE,
                1_900_000_000,
            )

        freed_pointer = api.library.sv2_noise_session_free.call_args.args[0]
        self.assertEqual(freed_pointer.value, 5_678)

    def test_native_handshake_call_exception_frees_written_session_pointer(self) -> None:
        backend = sv2_noise.NativeNoiseBackend("unused-library.so")
        api = Mock()
        memory_error = MemoryError("simulated ctypes conversion failure")

        def fail_after_write(*arguments: object) -> int:
            session_out = ctypes.cast(
                arguments[-1],
                ctypes.POINTER(ctypes.c_void_p),
            )
            session_out[0] = ctypes.c_void_p(6_789)
            raise memory_error

        api.library.sv2_noise_responder_handshake.side_effect = fail_after_write
        backend._api = api

        with self.assertRaises(MemoryError) as raised:
            backend.responder_handshake(
                7,
                b"1" * sv2_noise.ACT1_SIZE,
                1_900_000_000,
            )

        self.assertIs(raised.exception, memory_error)
        freed_pointer = api.library.sv2_noise_session_free.call_args.args[0]
        self.assertEqual(freed_pointer.value, 6_789)


if __name__ == "__main__":
    unittest.main()
