"""Lazy native binding and explicit ownership for the SV2 Noise responder."""

import ctypes
import os
import pathlib
import struct
import threading
import time
import typing
from collections.abc import Callable

SECRET_KEY_SIZE = 32
PUBLIC_KEY_SIZE = 32
CERTIFICATE_SIZE = 74
CERTIFICATE_FORMAT_VERSION = 0
CERTIFICATE_VERSION_OFFSET = 0
CERTIFICATE_EXPIRY_OFFSET = 6
ACT1_SIZE = 64
ACT2_SIZE = 234
HEADER_SIZE = 6
ENCRYPTED_HEADER_SIZE = 22
TAG_SIZE = 16
MAX_PAYLOAD_CHUNK_SIZE = 65_519
MAX_FRAME_PAYLOAD_SIZE = 0xFF_FFFF

STATUS_OK = 0
STATUS_CERTIFICATE_NOT_YET_VALID = 8
STATUS_CERTIFICATE_EXPIRED = 9
STATUS_AUTHENTICATION_FAILURE = 12
CREDENTIAL_VALIDITY_ERROR_STATUSES = frozenset(
    {
        STATUS_CERTIFICATE_NOT_YET_VALID,
        STATUS_CERTIFICATE_EXPIRED,
    }
)
_CERTIFICATE_VERSION_FIELD = struct.Struct("<H")
_CERTIFICATE_EXPIRY_FIELD = struct.Struct("<I")


class NoiseError(ConnectionError):
    """Base class for native SV2 Noise failures."""

    def __init__(self, *args: object) -> None:
        super().__init__(*args)
        self.certificate_expiry_timestamp: int | None = None


class NoiseLibraryError(NoiseError):
    """The native SV2 Noise library could not be loaded or violated its ABI."""


class NoiseNativeError(NoiseError):
    def __init__(self, operation: str, status: int, detail: str) -> None:
        super().__init__(f"{operation}: {detail} (status {status})")
        self.operation = operation
        self.status = status


class NoiseAuthenticationError(NoiseNativeError):
    pass


class NoiseCredentialSizeError(ValueError):
    pass


class NoiseBackend(typing.Protocol):
    """Low-level operations implemented by the native binding and test fakes."""

    def load_credentials(
        self,
        static_secret_key: bytearray,
        authority_public_key: bytes,
        certificate: bytes,
        unix_timestamp: int,
    ) -> int: ...

    def free_credentials(self, credentials_handle: int) -> None: ...

    def responder_handshake(
        self,
        credentials_handle: int,
        act1: bytes,
        unix_timestamp: int,
    ) -> tuple[bytes, int]: ...

    def free_session(self, session_handle: int) -> None: ...

    def encrypt_header(self, session_handle: int, plaintext: bytes) -> bytes: ...

    def decrypt_header(self, session_handle: int, ciphertext: bytes) -> bytes: ...

    def encrypt_payload(self, session_handle: int, plaintext: bytes) -> bytes: ...

    def decrypt_payload(
        self,
        session_handle: int,
        ciphertext: bytes,
        plaintext_length: int,
    ) -> bytes: ...


class _NativeApi:
    """Configured function table for one loaded shared library."""

    def __init__(self, library_path: pathlib.Path) -> None:
        try:
            self.library = ctypes.CDLL(os.fspath(library_path))
        except OSError as error:
            raise NoiseLibraryError(
                f"could not load SV2 Noise library {library_path}: {error}"
            ) from error
        try:
            self._configure_functions()
        except AttributeError as error:
            raise NoiseLibraryError(
                f"SV2 Noise library {library_path} is missing a required symbol: {error}"
            ) from error

    def _configure_functions(self) -> None:
        byte_pointer = ctypes.POINTER(ctypes.c_uint8)
        void_pointer_pointer = ctypes.POINTER(ctypes.c_void_p)
        size_pointer = ctypes.POINTER(ctypes.c_size_t)

        self.library.sv2_noise_status_string.argtypes = [ctypes.c_int]
        self.library.sv2_noise_status_string.restype = ctypes.c_char_p

        self.library.sv2_noise_credentials_load.argtypes = [
            byte_pointer,
            ctypes.c_size_t,
            byte_pointer,
            ctypes.c_size_t,
            byte_pointer,
            ctypes.c_size_t,
            ctypes.c_uint32,
            void_pointer_pointer,
        ]
        self.library.sv2_noise_credentials_load.restype = ctypes.c_int
        self.library.sv2_noise_credentials_free.argtypes = [ctypes.c_void_p]
        self.library.sv2_noise_credentials_free.restype = None

        self.library.sv2_noise_responder_handshake.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint32,
            byte_pointer,
            ctypes.c_size_t,
            byte_pointer,
            ctypes.c_size_t,
            size_pointer,
            void_pointer_pointer,
        ]
        self.library.sv2_noise_responder_handshake.restype = ctypes.c_int

        self.library.sv2_noise_payload_ciphertext_size.argtypes = [
            ctypes.c_size_t,
            size_pointer,
        ]
        self.library.sv2_noise_payload_ciphertext_size.restype = ctypes.c_int

        for function_name in ("sv2_noise_encrypt_header", "sv2_noise_decrypt_header"):
            function = getattr(self.library, function_name)
            function.argtypes = [
                ctypes.c_void_p,
                byte_pointer,
                ctypes.c_size_t,
                byte_pointer,
                ctypes.c_size_t,
                size_pointer,
            ]
            function.restype = ctypes.c_int

        self.library.sv2_noise_encrypt_payload.argtypes = [
            ctypes.c_void_p,
            byte_pointer,
            ctypes.c_size_t,
            byte_pointer,
            ctypes.c_size_t,
            size_pointer,
        ]
        self.library.sv2_noise_encrypt_payload.restype = ctypes.c_int
        self.library.sv2_noise_decrypt_payload.argtypes = [
            ctypes.c_void_p,
            byte_pointer,
            ctypes.c_size_t,
            ctypes.c_size_t,
            byte_pointer,
            ctypes.c_size_t,
            size_pointer,
        ]
        self.library.sv2_noise_decrypt_payload.restype = ctypes.c_int

        self.library.sv2_noise_session_free.argtypes = [ctypes.c_void_p]
        self.library.sv2_noise_session_free.restype = None

    def status_detail(self, status: int) -> str:
        detail = typing.cast(
            bytes | None,
            self.library.sv2_noise_status_string(status),
        )
        if detail is None:
            return "unknown error"
        return detail.decode("utf-8", errors="replace")


class NativeNoiseBackend:
    """Call the project-owned C ABI without loading it until the first operation."""

    def __init__(self, library_path: str | os.PathLike[str]) -> None:
        self._library_path = pathlib.Path(library_path)
        self._api: _NativeApi | None = None
        self._load_lock = threading.Lock()

    def load_credentials(
        self,
        static_secret_key: bytearray,
        authority_public_key: bytes,
        certificate: bytes,
        unix_timestamp: int,
    ) -> int:
        api = self._get_api()
        static_buffer = _mutable_input_buffer(static_secret_key)
        authority_buffer = _input_buffer(authority_public_key)
        certificate_buffer = _input_buffer(certificate)
        credentials = ctypes.c_void_p()
        try:
            status = int(
                api.library.sv2_noise_credentials_load(
                    static_buffer,
                    len(static_secret_key),
                    authority_buffer,
                    len(authority_public_key),
                    certificate_buffer,
                    len(certificate),
                    _as_uint32_time(unix_timestamp),
                    ctypes.byref(credentials),
                )
            )
            self._raise_status(api, "load responder credentials", status)
            credentials_handle = credentials.value
            if credentials_handle is None:
                raise NoiseLibraryError("load responder credentials returned a null handle")
            return credentials_handle
        except BaseException:
            try:
                api.library.sv2_noise_credentials_free(credentials)
            except (OSError, ValueError, TypeError, ctypes.ArgumentError, MemoryError):
                pass
            raise

    def free_credentials(self, credentials_handle: int) -> None:
        self._get_api().library.sv2_noise_credentials_free(
            ctypes.c_void_p(credentials_handle)
        )

    def responder_handshake(
        self,
        credentials_handle: int,
        act1: bytes,
        unix_timestamp: int,
    ) -> tuple[bytes, int]:
        api = self._get_api()
        act1_buffer = _input_buffer(act1)
        act2_buffer = _output_buffer(ACT2_SIZE)
        act2_length = ctypes.c_size_t()
        session = ctypes.c_void_p()
        try:
            status = int(
                api.library.sv2_noise_responder_handshake(
                    ctypes.c_void_p(credentials_handle),
                    _as_uint32_time(unix_timestamp),
                    act1_buffer,
                    len(act1),
                    act2_buffer,
                    ACT2_SIZE,
                    ctypes.byref(act2_length),
                    ctypes.byref(session),
                )
            )
            self._raise_status(api, "complete responder handshake", status)
            _require_output_length("complete responder handshake", act2_length.value, ACT2_SIZE)
            session_handle = session.value
            if session_handle is None:
                raise NoiseLibraryError("complete responder handshake returned a null session")
            return bytes(act2_buffer), session_handle
        except BaseException:
            try:
                api.library.sv2_noise_session_free(session)
            except (OSError, ValueError, TypeError, ctypes.ArgumentError, MemoryError):
                pass
            raise

    def free_session(self, session_handle: int) -> None:
        self._get_api().library.sv2_noise_session_free(ctypes.c_void_p(session_handle))

    def encrypt_header(self, session_handle: int, plaintext: bytes) -> bytes:
        return self._transform_fixed(
            "encrypt frame header",
            "sv2_noise_encrypt_header",
            session_handle,
            plaintext,
            HEADER_SIZE,
            ENCRYPTED_HEADER_SIZE,
        )

    def decrypt_header(self, session_handle: int, ciphertext: bytes) -> bytes:
        return self._transform_fixed(
            "authenticate frame header",
            "sv2_noise_decrypt_header",
            session_handle,
            ciphertext,
            ENCRYPTED_HEADER_SIZE,
            HEADER_SIZE,
        )

    def encrypt_payload(self, session_handle: int, plaintext: bytes) -> bytes:
        api = self._get_api()
        output_length = self._payload_ciphertext_size(api, len(plaintext))
        return self._call_native(
            api,
            "encrypt frame payload",
            "sv2_noise_encrypt_payload",
            session_handle,
            plaintext,
            output_length,
        )

    def decrypt_payload(
        self,
        session_handle: int,
        ciphertext: bytes,
        plaintext_length: int,
    ) -> bytes:
        api = self._get_api()
        expected_ciphertext_length = self._payload_ciphertext_size(api, plaintext_length)
        if len(ciphertext) != expected_ciphertext_length:
            raise ValueError(
                f"encrypted payload must be exactly {expected_ciphertext_length} bytes"
            )
        input_buffer = _input_buffer(ciphertext)
        output_buffer = _output_buffer(plaintext_length)
        output_length = ctypes.c_size_t()
        status = int(
            api.library.sv2_noise_decrypt_payload(
                ctypes.c_void_p(session_handle),
                input_buffer,
                len(ciphertext),
                plaintext_length,
                output_buffer,
                plaintext_length,
                ctypes.byref(output_length),
            )
        )
        self._raise_status(api, "authenticate frame payload", status)
        _require_output_length(
            "authenticate frame payload",
            output_length.value,
            plaintext_length,
        )
        return bytes(output_buffer)

    def _get_api(self) -> _NativeApi:
        with self._load_lock:
            if self._api is None:
                self._api = _NativeApi(self._library_path)
            return self._api

    def _transform_fixed(
        self,
        operation: str,
        function_name: str,
        session_handle: int,
        value: bytes,
        expected_input_length: int,
        expected_output_length: int,
    ) -> bytes:
        if len(value) != expected_input_length:
            raise ValueError(f"{operation} input must be exactly {expected_input_length} bytes")
        return self._call_native(
            self._get_api(),
            operation,
            function_name,
            session_handle,
            value,
            expected_output_length,
        )

    def _call_native(
        self,
        api: _NativeApi,
        operation: str,
        function_name: str,
        session_handle: int,
        value: bytes,
        expected_output_length: int,
    ) -> bytes:
        input_buffer = _input_buffer(value)
        output_buffer = _output_buffer(expected_output_length)
        output_length = ctypes.c_size_t()
        function = getattr(api.library, function_name)
        status = int(
            function(
                ctypes.c_void_p(session_handle),
                input_buffer,
                len(value),
                output_buffer,
                expected_output_length,
                ctypes.byref(output_length),
            )
        )
        self._raise_status(api, operation, status)
        _require_output_length(operation, output_length.value, expected_output_length)
        return bytes(output_buffer)

    def _payload_ciphertext_size(self, api: _NativeApi, plaintext_length: int) -> int:
        output_length = ctypes.c_size_t()
        status = int(
            api.library.sv2_noise_payload_ciphertext_size(
                plaintext_length,
                ctypes.byref(output_length),
            )
        )
        self._raise_status(api, "calculate encrypted payload size", status)
        return output_length.value

    @staticmethod
    def _raise_status(api: _NativeApi, operation: str, status: int) -> None:
        if status == STATUS_OK:
            return
        error_type = (
            NoiseAuthenticationError
            if status == STATUS_AUTHENTICATION_FAILURE
            else NoiseNativeError
        )
        raise error_type(operation, status, api.status_detail(status))


class NoiseCredentials:
    """Verified responder credentials with explicit native-handle ownership."""

    def __init__(
        self,
        backend: NoiseBackend,
        credentials_handle: int,
        *,
        certificate_expiry_timestamp: int | None = None,
    ) -> None:
        self._backend = backend
        self._credentials_handle: int | None = credentials_handle
        self._certificate_expiry_timestamp = certificate_expiry_timestamp
        self._lock = threading.Lock()

    @classmethod
    def from_files(
        cls,
        backend: NoiseBackend,
        static_secret_key_path: str | os.PathLike[str],
        authority_public_key_path: str | os.PathLike[str],
        certificate_path: str | os.PathLike[str],
        *,
        clock: Callable[[], float] = time.time,
    ) -> typing.Self:
        """Load and verify the three fixed-size raw responder credential files."""
        static_secret_key = _read_secret_file(
            static_secret_key_path,
            SECRET_KEY_SIZE,
        )
        credentials_handle: int | None = None
        try:
            try:
                credentials_handle, certificate_expiry_timestamp = (
                    _load_native_credentials(
                        backend,
                        static_secret_key,
                        static_secret_key_path,
                        authority_public_key_path,
                        certificate_path,
                        clock,
                    )
                )
            finally:
                _wipe(static_secret_key)
            return cls(
                backend,
                credentials_handle,
                certificate_expiry_timestamp=certificate_expiry_timestamp,
            )
        except BaseException:
            if credentials_handle is not None:
                try:
                    backend.free_credentials(credentials_handle)
                except (OSError, ValueError, RuntimeError, MemoryError):
                    pass
            raise

    @property
    def certificate_expiry_timestamp(self) -> int | None:
        """Return the inclusive certificate expiry when its format is understood."""
        return self._certificate_expiry_timestamp

    def handshake(
        self,
        act1: bytes,
        *,
        clock: Callable[[], float] = time.time,
    ) -> tuple[bytes, NoiseSession]:
        """Authenticate one initiator and return Act2 with owned transport state."""
        session_handle: int | None = None
        try:
            with self._lock:
                credentials_handle = self._require_open()
                act2, session_handle = self._backend.responder_handshake(
                    credentials_handle,
                    act1,
                    _as_uint32_time(int(clock())),
                )
            if session_handle is None:
                raise NoiseLibraryError("handshake backend returned a null session")
            if len(act2) != ACT2_SIZE:
                raise NoiseLibraryError(
                    f"complete responder handshake returned {len(act2)} Act2 bytes; "
                    f"expected {ACT2_SIZE}"
                )
            return act2, NoiseSession(self._backend, session_handle)
        except BaseException:
            if session_handle is not None:
                try:
                    self._backend.free_session(session_handle)
                except (OSError, ValueError, RuntimeError, MemoryError):
                    pass
            raise

    def close(self) -> None:
        with self._lock:
            if self._credentials_handle is None:
                return
            credentials_handle = self._credentials_handle
            self._credentials_handle = None
            self._backend.free_credentials(credentials_handle)

    def _require_open(self) -> int:
        if self._credentials_handle is None:
            raise NoiseError("SV2 Noise credentials are closed")
        return self._credentials_handle


class NoiseSession:
    """Serialize access to one native Noise transport and own its handle."""

    def __init__(self, backend: NoiseBackend, session_handle: int) -> None:
        self._backend = backend
        self._session_handle: int | None = session_handle
        self._lock = threading.Lock()

    def encrypt_header(self, plaintext: bytes) -> bytes:
        with self._lock:
            return self._backend.encrypt_header(self._require_open(), plaintext)

    def decrypt_header(self, ciphertext: bytes) -> bytes:
        with self._lock:
            return self._backend.decrypt_header(self._require_open(), ciphertext)

    def encrypt_payload(self, plaintext: bytes) -> bytes:
        with self._lock:
            return self._backend.encrypt_payload(self._require_open(), plaintext)

    def decrypt_payload(self, ciphertext: bytes, plaintext_length: int) -> bytes:
        with self._lock:
            return self._backend.decrypt_payload(
                self._require_open(),
                ciphertext,
                plaintext_length,
            )

    def close(self) -> None:
        with self._lock:
            if self._session_handle is None:
                return
            session_handle = self._session_handle
            self._session_handle = None
            self._backend.free_session(session_handle)

    def _require_open(self) -> int:
        if self._session_handle is None:
            raise NoiseError("SV2 Noise session is closed")
        return self._session_handle


def encrypted_payload_size(plaintext_length: int) -> int:
    """Return the current-spec payload ciphertext size without native allocation."""
    if not 0 <= plaintext_length <= MAX_FRAME_PAYLOAD_SIZE:
        raise ValueError(
            f"plaintext_length must be between 0 and {MAX_FRAME_PAYLOAD_SIZE}"
        )
    if plaintext_length == 0:
        return 0
    chunk_count = (
        plaintext_length + MAX_PAYLOAD_CHUNK_SIZE - 1
    ) // MAX_PAYLOAD_CHUNK_SIZE
    return plaintext_length + chunk_count * TAG_SIZE


def _as_uint32_time(unix_timestamp: int) -> int:
    if not 0 <= unix_timestamp <= 0xFFFF_FFFF:
        raise ValueError("Unix time must fit an unsigned 32-bit integer")
    return unix_timestamp


def _input_buffer(value: bytes) -> ctypes.Array[ctypes.c_uint8] | None:
    if not value:
        return None
    return (ctypes.c_uint8 * len(value)).from_buffer_copy(value)


def _mutable_input_buffer(value: bytearray) -> ctypes.Array[ctypes.c_uint8] | None:
    if not value:
        return None
    return (ctypes.c_uint8 * len(value)).from_buffer(value)


def _output_buffer(size: int) -> ctypes.Array[ctypes.c_uint8]:
    return (ctypes.c_uint8 * size)()


def _load_native_credentials(
    backend: NoiseBackend,
    static_secret_key: bytearray,
    static_secret_key_path: str | os.PathLike[str],
    authority_public_key_path: str | os.PathLike[str],
    certificate_path: str | os.PathLike[str],
    clock: Callable[[], float],
) -> tuple[int, int | None]:
    _require_file_size(
        static_secret_key_path,
        static_secret_key,
        SECRET_KEY_SIZE,
        "static secret key",
    )
    authority_public_key = _read_public_file(
        authority_public_key_path,
        PUBLIC_KEY_SIZE,
    )
    _require_file_size(
        authority_public_key_path,
        authority_public_key,
        PUBLIC_KEY_SIZE,
        "authority public key",
    )
    certificate = _read_public_file(
        certificate_path,
        CERTIFICATE_SIZE,
    )
    _require_file_size(
        certificate_path,
        certificate,
        CERTIFICATE_SIZE,
        "certificate",
    )
    certificate_expiry_timestamp = _certificate_expiry_timestamp(certificate)
    try:
        credentials_handle = backend.load_credentials(
            static_secret_key,
            authority_public_key,
            certificate,
            _as_uint32_time(int(clock())),
        )
    except NoiseError as error:
        error.certificate_expiry_timestamp = certificate_expiry_timestamp
        raise
    if credentials_handle is None:
        raise NoiseLibraryError("credential backend returned a null handle")
    return credentials_handle, certificate_expiry_timestamp


def _certificate_expiry_timestamp(certificate: bytes) -> int | None:
    version = _CERTIFICATE_VERSION_FIELD.unpack_from(
        certificate,
        CERTIFICATE_VERSION_OFFSET,
    )[0]
    if version != CERTIFICATE_FORMAT_VERSION:
        return None
    return _CERTIFICATE_EXPIRY_FIELD.unpack_from(
        certificate,
        CERTIFICATE_EXPIRY_OFFSET,
    )[0]


def _read_public_file(path: str | os.PathLike[str], expected_size: int) -> bytes:
    with pathlib.Path(path).open("rb") as raw_file:
        return raw_file.read(expected_size + 1)


def _read_secret_file(path: str | os.PathLike[str], expected_size: int) -> bytearray:
    """Read directly into wipeable storage without buffered or immutable copies."""
    secret = bytearray(expected_size + 1)
    bytes_read = 0
    try:
        with pathlib.Path(path).open("rb", buffering=0) as raw_file:
            secret_view = memoryview(secret)
            try:
                while bytes_read < len(secret):
                    destination = secret_view[bytes_read:]
                    try:
                        chunk_size = raw_file.readinto(destination)
                    finally:
                        destination.release()
                    if chunk_size is None:
                        raise OSError(f"secret file {path} did not complete a blocking read")
                    if chunk_size == 0:
                        break
                    bytes_read += chunk_size
            finally:
                secret_view.release()
        del secret[bytes_read:]
        return secret
    except BaseException:
        _wipe(secret)
        raise


def _require_file_size(
    path: str | os.PathLike[str],
    value: bytes | bytearray,
    expected_size: int,
    name: str,
) -> None:
    if len(value) != expected_size:
        actual_size = (
            f"at least {len(value)}"
            if len(value) > expected_size
            else str(len(value))
        )
        raise NoiseCredentialSizeError(
            f"{name} file {path} must contain exactly {expected_size} raw bytes; "
            f"got {actual_size}"
        )


def _require_output_length(operation: str, actual: int, expected: int) -> None:
    if actual != expected:
        raise NoiseLibraryError(
            f"{operation} returned {actual} bytes; expected {expected}"
        )


def _wipe(secret: bytearray) -> None:
    for offset in range(len(secret)):
        secret[offset] = 0
