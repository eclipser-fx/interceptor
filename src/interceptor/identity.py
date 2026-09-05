"""Local Ed25519 signing identity.

On first use, the library creates a per-user signing identity under ``~/.interceptor``
(override with the ``INTERCEPTOR_EVIDENCE_HOME`` environment variable):

* ``signing_key.pem``  — Ed25519 private key, PKCS#8 PEM, mode ``0600``
* ``verify_key.pem``   — Ed25519 public key, SubjectPublicKeyInfo PEM

The directory is created with mode ``0700`` where the platform supports it.
No shared or default key is ever embedded; private-key material is never
printed and never included in events.

``key_id`` is derived from the public key: ``ed25519:`` followed by the first
16 hex characters of the SHA-256 of the raw 32-byte public key. The full
SHA-256 hex is exposed as the *fingerprint* via ``interceptor key-info``.

Signature scheme (matching the guard runtime receipt convention): the signer
computes ``digest = SHA-256(canonical_unsigned_payload_bytes)`` and produces
``Ed25519.sign(digest)``, base64-encoded. Verification recomputes the digest
and verifies the signature against it.
"""

from __future__ import annotations

import base64
import os
import stat
import threading
from pathlib import Path
from typing import Any, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .canonical import sha256_hex
from .errors import IdentityError, SigningError

PRIVATE_KEY_FILENAME = "signing_key.pem"
PUBLIC_KEY_FILENAME = "verify_key.pem"
JOURNAL_FILENAME = "journal.jsonl"
TRUSTED_KEYS_DIRNAME = "trusted_keys"

#: Serializes first-use key creation within the process. Without it, threads
#: racing on a fresh evidence home each generate a key and truncate-write the
#: same file, producing a corrupt PEM that fails every later load.
_identity_lock = threading.Lock()


def evidence_home() -> Path:
    """The evidence home directory (``INTERCEPTOR_EVIDENCE_HOME`` or ``~/.interceptor``)."""
    override = os.environ.get("INTERCEPTOR_EVIDENCE_HOME")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".interceptor"


def default_journal_path() -> Path:
    return evidence_home() / JOURNAL_FILENAME


class SigningIdentity(Protocol):
    """What the guard needs from an identity; an observer integration can supply
    another implementation (e.g. a managed key) without touching guard code."""

    @property
    def key_id(self) -> str: ...

    def sign(self, digest: bytes) -> str:
        """Base64 Ed25519 signature over *digest* bytes."""
        ...


class LocalSigningIdentity:
    """File-backed Ed25519 identity in the evidence home directory."""

    def __init__(self, private_key: Ed25519PrivateKey, home: Path) -> None:
        self._private_key = private_key
        self._home = home
        self._public_raw = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    @classmethod
    def load_or_create(cls, home: Path | None = None) -> LocalSigningIdentity:
        home = home or evidence_home()
        with _identity_lock:
            return cls._load_or_create_locked(home)

    @classmethod
    def _load_or_create_locked(cls, home: Path) -> LocalSigningIdentity:
        private_path = home / PRIVATE_KEY_FILENAME
        public_path = home / PUBLIC_KEY_FILENAME
        try:
            if private_path.exists():
                _require_private_permissions(private_path)
                private_key = _load_private_key(private_path)
            else:
                home.mkdir(parents=True, exist_ok=True)
                _restrict_dir(home)
                private_key = Ed25519PrivateKey.generate()
                _write_private_key(private_path, private_key)
                _write_public_key(public_path, private_key.public_key())
            # Self-heal a missing public key file (it is derivable).
            if not public_path.exists():
                _write_public_key(public_path, private_key.public_key())
            # Keep the current key in the trusted set, so events signed before
            # a rotation stay verifiable alongside ones signed after it.
            register_public_key(private_key.public_key(), home)
        except OSError as exc:
            raise IdentityError(f"cannot create or load signing identity in {home}: {exc}") from exc
        return cls(private_key, home)

    @property
    def home(self) -> Path:
        return self._home

    @property
    def public_key_path(self) -> Path:
        return self._home / PUBLIC_KEY_FILENAME

    @property
    def fingerprint(self) -> str:
        """Full SHA-256 hex of the raw 32-byte public key."""
        return sha256_hex(self._public_raw)

    @property
    def key_id(self) -> str:
        return f"ed25519:{self.fingerprint[:16]}"

    def sign(self, digest: bytes) -> str:
        try:
            signature = self._private_key.sign(digest)
        except Exception as exc:  # cryptography raises library-specific errors
            raise SigningError(f"Ed25519 signing failed: {exc}") from exc
        return base64.b64encode(signature).decode("ascii")

    def public_key(self) -> Ed25519PublicKey:
        return self._private_key.public_key()


def load_public_key(path: Path) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(path.read_bytes())
    except (OSError, ValueError) as exc:
        raise IdentityError(f"cannot load public key from {path}: {exc}") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise IdentityError(f"{path} is not an Ed25519 public key")
    return key


def _password_bytes(password: bytes | str | None) -> bytes | None:
    """Normalize a key password, or None for an unencrypted key."""
    if password is None:
        return None
    if isinstance(password, bytes):
        if not password:
            raise IdentityError("key password must not be empty")
        return password
    encoded = password.encode("utf-8")
    if not encoded:
        raise IdentityError("key password must not be empty")
    return encoded


def load_private_key(path: Path, password: bytes | str | None = None) -> Ed25519PrivateKey:
    """Load an Ed25519 private key (PKCS#8 PEM), e.g. a countersigning key.

    Pass *password* for keys written with :func:`generate_private_key` password
    encryption. A wrong password fails closed with :class:`IdentityError`.
    """
    try:
        key = _load_private_key(path, _password_bytes(password))
    except IdentityError as exc:
        raise IdentityError(f"cannot load private key from {path}: {exc}") from exc
    return key


def generate_private_key(path: Path, password: bytes | str | None = None) -> Ed25519PrivateKey:
    """Generate a fresh Ed25519 key at *path* (mode ``0600``), refusing to overwrite.

    Pass *password* to encrypt the PEM with best-available encryption (X25519
    keys in TPMs/HSMs stay out of the file entirely — use
    :class:`CallbackSigningIdentity` for those); omit it for an unencrypted key.
    """
    if path.exists():
        raise IdentityError(f"refusing to overwrite existing key at {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    try:
        _write_private_key(path, key, _password_bytes(password))
    except OSError as exc:
        raise IdentityError(f"cannot write private key to {path}: {exc}") from exc
    return key


class CallbackSigningIdentity:
    """A signing identity backed by an external signer (TPM, HSM, cloud KMS).

    The private key never enters this process: *sign* receives the 32-byte
    digest and returns the base64 Ed25519 signature, exactly like
    :meth:`LocalSigningIdentity.sign`. Key custody (PINs, sessions, handles)
    stays with the callback. Verification needs only *public_key*, unchanged.
    """

    def __init__(
        self,
        public_key: Ed25519PublicKey,
        sign: Any,
        *,
        key_id: str | None = None,
    ) -> None:
        raw = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self._public_key = public_key
        self._fingerprint = sha256_hex(raw)
        self._sign_fn = sign
        self._key_id = key_id or f"ed25519:{self._fingerprint[:16]}"

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def fingerprint(self) -> str:
        return self._fingerprint

    def sign(self, digest: bytes) -> str:
        try:
            signature = self._sign_fn(digest)
        except Exception as exc:
            raise SigningError(f"external signer failed: {exc}") from exc
        if not isinstance(signature, str):
            raise SigningError("external signer must return a base64 string")
        return signature

    def public_key(self) -> Ed25519PublicKey:
        return self._public_key


class EphemeralSigningIdentity:
    """A signing identity from an in-memory key — never written to disk.

    Used for second-party counter-signatures, where the countersigning key
    must not live in the evidence home it attests to.
    """

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        raw = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self._private_key = private_key
        self._fingerprint = sha256_hex(raw)

    @classmethod
    def from_file(
        cls, path: str | Path, password: bytes | str | None = None
    ) -> EphemeralSigningIdentity:
        return cls(load_private_key(Path(path), password))

    @classmethod
    def generate(cls) -> EphemeralSigningIdentity:
        return cls(Ed25519PrivateKey.generate())

    @property
    def key_id(self) -> str:
        return f"ed25519:{self._fingerprint[:16]}"

    @property
    def fingerprint(self) -> str:
        return self._fingerprint

    def sign(self, digest: bytes) -> str:
        try:
            signature = self._private_key.sign(digest)
        except Exception as exc:
            raise SigningError(f"Ed25519 signing failed: {exc}") from exc
        return base64.b64encode(signature).decode("ascii")

    def public_key(self) -> Ed25519PublicKey:
        return self._private_key.public_key()


def public_key_fingerprint(key: Ed25519PublicKey) -> str:
    raw = key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return sha256_hex(raw)


def key_id_for(key: Ed25519PublicKey) -> str:
    return f"ed25519:{public_key_fingerprint(key)[:16]}"


def verify_signature(key: Ed25519PublicKey, digest: bytes, signature_b64: str) -> bool:
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except Exception:
        return False
    try:
        key.verify(signature, digest)
        return True
    except InvalidSignature:
        return False


def trusted_keys_dir(home: Path | None = None) -> Path:
    """Directory holding every public key the operator still trusts."""
    return (home or evidence_home()) / TRUSTED_KEYS_DIRNAME


def register_public_key(key: Ed25519PublicKey, home: Path | None = None) -> Path:
    """Add *key* to the trusted set (idempotent), returning its file path.

    The trusted set is what verification defaults to. Rotating the signing key
    keeps the outgoing public key here, so old evidence does not become
    unverifiable at the moment the key changes.
    """
    directory = trusted_keys_dir(home)
    path = directory / f"{public_key_fingerprint(key)}.pem"
    if path.exists():
        return path
    directory.mkdir(parents=True, exist_ok=True)
    _write_public_key(path, key)
    return path


def load_trusted_public_keys(home: Path | None = None) -> tuple[Ed25519PublicKey, ...]:
    """Every trusted public key, sorted by key id for deterministic order.

    Falls back to the single ``verify_key.pem`` for homes created before the
    trusted set existed.
    """
    directory = trusted_keys_dir(home)
    keys: list[Ed25519PublicKey] = []
    if directory.exists():
        for path in sorted(directory.glob("*.pem")):
            keys.append(load_public_key(path))
    if not keys:
        fallback = (home or evidence_home()) / PUBLIC_KEY_FILENAME
        if fallback.exists():
            keys.append(load_public_key(fallback))
    return tuple(keys)


ROTATION_EVENT_TYPE = "rotation"


def record_rotation_event(
    *,
    prior_key_id: str,
    sign: Any,
    successor: Ed25519PublicKey,
    journal_path: Path,
    home: Path | None = None,
) -> dict[str, Any]:
    """Append a signed key-rotation record to *journal_path*.

    The event is signed by the *prior* (outgoing) key, so a verifier holding
    the trusted set sees an in-chain authorization: ``prior_key_id`` (== the
    signing ``key_id``) names its ``successor_key_id`` + full fingerprint.
    Returns the appended event. Raises :class:`IdentityError` on I/O failure.
    """
    from .journal import (
        EVENT_SCHEMA_VERSION,
        FileJournal,
        finalize_event,
        new_event_id,
        utc_timestamp,
    )

    successor_fingerprint = public_key_fingerprint(successor)
    successor_key_id = key_id_for(successor)
    store = FileJournal(journal_path)

    def build(previous_hash: str | None) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": EVENT_SCHEMA_VERSION,
            "event_type": ROTATION_EVENT_TYPE,
            "event_id": new_event_id(),
            "timestamp_utc": utc_timestamp(),
            "key_id": prior_key_id,
            "previous_event_hash": previous_hash,
            "prior_key_id": prior_key_id,
            "successor_key_id": successor_key_id,
            "successor_fingerprint": successor_fingerprint,
        }
        return finalize_event(payload, sign)

    try:
        return store.append_event(build)
    except Exception as exc:
        raise IdentityError(f"cannot record key rotation in {journal_path}: {exc}") from exc


def rotate_key(
    home: Path | None = None,
    *,
    journal_path: Path | None = None,
    record: bool = True,
) -> LocalSigningIdentity:
    """Replace the local signing key and keep the outgoing one trusted.

    Generates a new Ed25519 key, overwrites ``signing_key.pem`` and
    ``verify_key.pem``, and registers the new public key in the trusted set.
    The outgoing public key is registered first, so events signed before the
    rotation continue to verify against the default trusted set.

    When *record* is true (default) and a prior key exists, a ``rotation``
    event signed by the outgoing key is appended to the journal first, so the
    succession is witnessed in-chain instead of living only in the local
    ``trusted_keys/`` directory. Pass ``record=False`` for offline/test use.
    """
    home = home or evidence_home()
    prior_private: Ed25519PrivateKey | None = None
    prior_key_id: str | None = None
    for candidate in (home / PUBLIC_KEY_FILENAME, home / PRIVATE_KEY_FILENAME):
        try:
            if candidate.name == PRIVATE_KEY_FILENAME and candidate.exists():
                _require_private_permissions(candidate)
                prior_private = _load_private_key(candidate)
                prior_key_id = key_id_for(prior_private.public_key())
                register_public_key(prior_private.public_key(), home)
            elif candidate.name == PUBLIC_KEY_FILENAME and candidate.exists():
                register_public_key(load_public_key(candidate), home)
        except (IdentityError, OSError):
            continue  # a stale or unreadable file must not block rotation

    private_path = home / PRIVATE_KEY_FILENAME
    public_path = home / PUBLIC_KEY_FILENAME
    home.mkdir(parents=True, exist_ok=True)
    _restrict_dir(home)
    new_key = Ed25519PrivateKey.generate()

    if record and prior_private is not None and prior_key_id is not None:
        target = journal_path or (home / JOURNAL_FILENAME)
        if target.exists():
            try:
                import base64 as _b64

                def _sign(digest: bytes) -> str:
                    assert prior_private is not None
                    return _b64.b64encode(prior_private.sign(digest)).decode("ascii")

                record_rotation_event(
                    prior_key_id=prior_key_id,
                    sign=_sign,
                    successor=new_key.public_key(),
                    journal_path=target,
                    home=home,
                )
            except IdentityError:
                pass  # rotation must not fail because the witness append failed;
                # the trusted_keys/ registration below still preserves verifiability.

    try:
        _write_private_key(private_path, new_key)
        _write_public_key(public_path, new_key.public_key())
    except OSError as exc:
        raise IdentityError(f"cannot rotate signing identity in {home}: {exc}") from exc
    register_public_key(new_key.public_key(), home)
    return LocalSigningIdentity(new_key, home)


def _require_private_permissions(path: Path) -> None:
    """Refuse to sign with a private key other local users can read.

    Creating the key restricts it to ``0600``, but that says nothing about the
    key as found on a later run. Keys get copied between machines, restored
    from backups that flatten permissions, committed to a repository, or
    written into a container image with a permissive umask. Signing with a
    readable key produces evidence that looks exactly as authoritative as
    evidence signed with a protected one, which is the problem: the signature
    attests to a key anyone on the host could have used.

    Skipped where POSIX permission bits are not meaningful.
    """
    if os.name != "posix":
        return
    try:
        mode = path.stat().st_mode
    except OSError:
        return
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise IdentityError(
            f"private key {path} is accessible to other users "
            f"(mode {stat.filemode(mode)}); refusing to sign with it. "
            f"Fix with: chmod 600 {path}"
        )


def _load_private_key(path: Path, password: bytes | None = None) -> Ed25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(path.read_bytes(), password=password)
    except (OSError, ValueError, TypeError) as exc:
        raise IdentityError(f"cannot load private key from {path}: {exc}") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise IdentityError(f"{path} is not an Ed25519 private key")
    return key


def _write_private_key(path: Path, key: Ed25519PrivateKey, password: bytes | None = None) -> None:
    encryption: serialization.KeySerializationEncryption = (
        serialization.BestAvailableEncryption(password)
        if password is not None
        else serialization.NoEncryption()
    )
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )
    _write_restricted(path, pem, stat.S_IRUSR | stat.S_IWUSR)


def _write_public_key(path: Path, key: Ed25519PublicKey) -> None:
    pem = key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    path.write_bytes(pem)


def _write_restricted(path: Path, data: bytes, mode: int) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    try:
        fd = os.open(path, flags, mode)
    except OSError as exc:
        raise IdentityError(f"cannot write {path}: {exc}") from exc
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    try:
        os.chmod(path, mode)
    except OSError:
        pass  # best-effort on platforms without POSIX permissions


def _restrict_dir(path: Path) -> None:
    try:
        os.chmod(path, stat.S_IRWXU)
    except OSError:
        pass  # best-effort on platforms without POSIX permissions
