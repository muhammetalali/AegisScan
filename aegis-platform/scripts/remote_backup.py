#!/usr/bin/env python3
"""Client-side encrypted, S3-compatible PostgreSQL backup transport for AegisScan."""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import stat
import struct
import sys
import tempfile
from contextlib import suppress
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO
from urllib.parse import urlparse

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

os.umask(0o077)

SCHEMA = "aegisscan.remote-backup.v1"
MAGIC = b"AEGISBK1"
HEADER_LIMIT = 16 * 1024
TAG_SIZE = 16
CHUNK_SIZE = 1024 * 1024
MAX_MANIFEST_SIZE = 64 * 1024
BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


class BackupError(RuntimeError):
    pass


def _canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _read_private_file(path: Path, *, max_bytes: int) -> bytes:
    if not path.is_file():
        raise BackupError(f"required private file does not exist: {path}")
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise BackupError(f"private file must not be readable or writable by group/others: {path}")
    data = path.read_bytes()
    if not data or len(data) > max_bytes:
        raise BackupError(f"private file has invalid size: {path}")
    return data


def _load_root_key(path: Path) -> bytes:
    raw = _read_private_file(path, max_bytes=256)
    if len(raw) == 32:
        return raw
    try:
        text = raw.decode("ascii").strip().encode("ascii")
    except UnicodeDecodeError as exc:
        raise BackupError("encryption key file has invalid encoding") from exc
    candidates: list[bytes] = []
    with suppress(ValueError):
        candidates.append(bytes.fromhex(text.decode("ascii")))
    with suppress(Exception):
        candidates.append(base64.b64decode(text, validate=True))
    for candidate in candidates:
        if len(candidate) == 32:
            return candidate
    raise BackupError(
        "encryption key file must contain exactly 32 raw bytes, "
        "64 hex characters, or base64 for 32 bytes"
    )


def _load_credentials(path: Path) -> dict[str, str]:
    raw = _read_private_file(path, max_bytes=16 * 1024)
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BackupError("S3 credentials file must be valid JSON") from exc
    if not isinstance(payload, dict):
        raise BackupError("S3 credentials file must contain a JSON object")
    access_key = str(payload.get("access_key_id", "")).strip()
    secret_key = str(payload.get("secret_access_key", "")).strip()
    session_token = str(payload.get("session_token", "")).strip()
    if not access_key or len(access_key) > 512:
        raise BackupError("S3 access_key_id is missing or invalid")
    if not secret_key or len(secret_key) > 4096:
        raise BackupError("S3 secret_access_key is missing or invalid")
    result = {
        "aws_access_key_id": access_key,
        "aws_secret_access_key": secret_key,
    }
    if session_token:
        result["aws_session_token"] = session_token
    return result


def _key_id(root_key: bytes) -> str:
    return hashlib.sha256(b"aegisscan-backup-key-id-v1\x00" + root_key).hexdigest()[:24]


def _derive_key(root_key: bytes, salt: bytes, purpose: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"AegisScan/" + purpose,
    ).derive(root_key)


def _file_sha256(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _verify_sidecar(source: Path, source_sha256: str) -> None:
    sidecar = Path(str(source) + ".sha256")
    if not sidecar.is_file():
        raise BackupError(f"source SHA-256 sidecar is required: {sidecar}")
    try:
        fields = sidecar.read_text(encoding="utf-8").strip().split()
    except UnicodeDecodeError as exc:
        raise BackupError("source SHA-256 sidecar must be UTF-8 text") from exc
    if not fields or not hmac.compare_digest(fields[0].lower(), source_sha256.lower()):
        raise BackupError("source SHA-256 sidecar does not match the dump")


def _sanitize_source_name(name: str) -> str:
    safe = SAFE_NAME_RE.sub("-", name).strip(".-")
    return (safe or "postgres.dump")[:180]


def _encrypt_file(
    source: Path,
    encrypted: Path,
    root_key: bytes,
    backup_id: str,
) -> dict[str, Any]:
    source_sha256, source_size = _file_sha256(source)
    _verify_sidecar(source, source_sha256)

    salt = os.urandom(16)
    nonce = os.urandom(12)
    data_key = _derive_key(root_key, salt, b"remote-backup-data-v1")
    header = {
        "algorithm": "AES-256-GCM",
        "backup_id": backup_id,
        "created_at": datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "kdf": "HKDF-SHA256",
        "key_id": _key_id(root_key),
        "nonce_b64": base64.b64encode(nonce).decode("ascii"),
        "salt_b64": base64.b64encode(salt).decode("ascii"),
        "schema": SCHEMA,
        "source_name": _sanitize_source_name(source.name),
        "source_sha256": source_sha256,
        "source_size": source_size,
    }
    header_bytes = _canonical_json(header)
    if len(header_bytes) > HEADER_LIMIT:
        raise BackupError("encrypted backup header exceeds limit")
    prefix = MAGIC + struct.pack(">I", len(header_bytes)) + header_bytes

    encrypted.parent.mkdir(parents=True, exist_ok=True)
    partial = Path(str(encrypted) + ".partial")
    cipher_hash = hashlib.sha256()
    encryptor = Cipher(algorithms.AES(data_key), modes.GCM(nonce)).encryptor()
    encryptor.authenticate_additional_data(prefix)
    try:
        with source.open("rb") as src, partial.open("wb") as dst:
            os.chmod(partial, 0o600)
            dst.write(prefix)
            cipher_hash.update(prefix)
            while True:
                chunk = src.read(CHUNK_SIZE)
                if not chunk:
                    break
                encrypted_chunk = encryptor.update(chunk)
                dst.write(encrypted_chunk)
                cipher_hash.update(encrypted_chunk)
            final_chunk = encryptor.finalize()
            if final_chunk:
                dst.write(final_chunk)
                cipher_hash.update(final_chunk)
            tag = encryptor.tag
            dst.write(tag)
            cipher_hash.update(tag)
            dst.flush()
            os.fsync(dst.fileno())
        os.replace(partial, encrypted)
        os.chmod(encrypted, 0o600)
    finally:
        with suppress(FileNotFoundError):
            partial.unlink()

    header["cipher_sha256"] = cipher_hash.hexdigest()
    header["cipher_size"] = encrypted.stat().st_size
    return header


def _read_envelope_header(
    stream: BinaryIO,
    total_size: int,
) -> tuple[dict[str, Any], bytes, int]:
    magic = stream.read(len(MAGIC))
    if magic != MAGIC:
        raise BackupError("encrypted backup magic/version is invalid")
    raw_len = stream.read(4)
    if len(raw_len) != 4:
        raise BackupError("encrypted backup header is truncated")
    header_len = struct.unpack(">I", raw_len)[0]
    if header_len <= 0 or header_len > HEADER_LIMIT:
        raise BackupError("encrypted backup header length is invalid")
    header_bytes = stream.read(header_len)
    if len(header_bytes) != header_len:
        raise BackupError("encrypted backup header is truncated")
    try:
        header = json.loads(header_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BackupError("encrypted backup header JSON is invalid") from exc
    if not isinstance(header, dict) or header.get("schema") != SCHEMA:
        raise BackupError("encrypted backup schema is invalid")
    prefix = magic + raw_len + header_bytes
    ciphertext_size = total_size - len(prefix) - TAG_SIZE
    if ciphertext_size < 0:
        raise BackupError("encrypted backup payload is truncated")
    return header, prefix, ciphertext_size


def _decrypt_file(
    encrypted: Path,
    output: Path,
    root_key: bytes,
    expected: dict[str, Any],
) -> dict[str, Any]:
    total_size = encrypted.stat().st_size
    with encrypted.open("rb") as src:
        header, prefix, ciphertext_size = _read_envelope_header(src, total_size)
        for field in ("backup_id", "key_id", "source_sha256", "source_size"):
            if header.get(field) != expected.get(field):
                raise BackupError(
                    f"encrypted header does not match authenticated manifest: {field}"
                )
        if (
            header.get("algorithm") != "AES-256-GCM"
            or header.get("kdf") != "HKDF-SHA256"
        ):
            raise BackupError("unsupported encrypted backup algorithm")
        if header.get("key_id") != _key_id(root_key):
            raise BackupError("provided encryption key does not match backup key_id")
        try:
            salt = base64.b64decode(str(header["salt_b64"]), validate=True)
            nonce = base64.b64decode(str(header["nonce_b64"]), validate=True)
        except Exception as exc:
            raise BackupError("encrypted backup KDF/nonce metadata is invalid") from exc
        if len(salt) != 16 or len(nonce) != 12:
            raise BackupError("encrypted backup KDF/nonce metadata has invalid length")

        src.seek(total_size - TAG_SIZE)
        tag = src.read(TAG_SIZE)
        src.seek(len(prefix))
        data_key = _derive_key(root_key, salt, b"remote-backup-data-v1")
        decryptor = Cipher(
            algorithms.AES(data_key),
            modes.GCM(nonce, tag),
        ).decryptor()
        decryptor.authenticate_additional_data(prefix)

        output.parent.mkdir(parents=True, exist_ok=True)
        partial = Path(str(output) + ".partial")
        digest = hashlib.sha256()
        written = 0
        remaining = ciphertext_size
        try:
            with partial.open("wb") as dst:
                os.chmod(partial, 0o600)
                while remaining:
                    chunk = src.read(min(CHUNK_SIZE, remaining))
                    if not chunk:
                        raise BackupError("encrypted backup ciphertext is truncated")
                    remaining -= len(chunk)
                    plaintext = decryptor.update(chunk)
                    dst.write(plaintext)
                    digest.update(plaintext)
                    written += len(plaintext)
                final_chunk = decryptor.finalize()
                if final_chunk:
                    dst.write(final_chunk)
                    digest.update(final_chunk)
                    written += len(final_chunk)
                dst.flush()
                os.fsync(dst.fileno())

            expected_size = int(header["source_size"])
            expected_sha = str(header["source_sha256"]).lower()
            if written != expected_size or not hmac.compare_digest(
                digest.hexdigest(),
                expected_sha,
            ):
                raise BackupError("decrypted backup plaintext integrity check failed")
            os.replace(partial, output)
            os.chmod(output, 0o600)
        except Exception:
            with suppress(FileNotFoundError):
                partial.unlink()
            raise

    sidecar = Path(str(output) + ".sha256")
    sidecar.write_text(
        f"{header['source_sha256']}  {output.name}\n",
        encoding="utf-8",
    )
    os.chmod(sidecar, 0o600)
    return header


def _manifest_unsigned(
    envelope: dict[str, Any],
    bucket: str,
    object_key: str,
) -> dict[str, Any]:
    return {
        "algorithm": envelope["algorithm"],
        "backup_id": envelope["backup_id"],
        "bucket": bucket,
        "cipher_sha256": envelope["cipher_sha256"],
        "cipher_size": envelope["cipher_size"],
        "created_at": envelope["created_at"],
        "key_id": envelope["key_id"],
        "object_key": object_key,
        "schema": SCHEMA,
        "source_name": envelope["source_name"],
        "source_sha256": envelope["source_sha256"],
        "source_size": envelope["source_size"],
    }


def _manifest_key(root_key: bytes) -> bytes:
    return _derive_key(
        root_key,
        b"AegisScanManifest",
        b"remote-backup-manifest-v1",
    )


def _sign_manifest(
    unsigned: dict[str, Any],
    root_key: bytes,
) -> dict[str, Any]:
    signature = hmac.new(
        _manifest_key(root_key),
        _canonical_json(unsigned),
        hashlib.sha256,
    ).hexdigest()
    return {**unsigned, "manifest_hmac_sha256": signature}


def _verify_manifest(
    manifest: dict[str, Any],
    root_key: bytes,
) -> dict[str, Any]:
    if manifest.get("schema") != SCHEMA:
        raise BackupError("remote backup manifest schema is invalid")
    signature = str(manifest.get("manifest_hmac_sha256", ""))
    if len(signature) != 64:
        raise BackupError("remote backup manifest signature is missing or invalid")
    unsigned = dict(manifest)
    unsigned.pop("manifest_hmac_sha256", None)
    expected = hmac.new(
        _manifest_key(root_key),
        _canonical_json(unsigned),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(signature, expected):
        raise BackupError("remote backup manifest authentication failed")
    if manifest.get("key_id") != _key_id(root_key):
        raise BackupError("provided encryption key does not match manifest key_id")
    return unsigned


def _validate_endpoint(endpoint: str, allow_http: bool) -> None:
    parsed = urlparse(endpoint)
    if parsed.scheme not in ({"http", "https"} if allow_http else {"https"}):
        raise BackupError("S3 endpoint must use HTTPS")
    if (
        not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise BackupError(
            "S3 endpoint must be an absolute origin without URL credentials, "
            "query, or fragment"
        )
    host = parsed.hostname.strip().lower()
    unsafe = host in {"localhost", "metadata.google.internal"}
    with suppress(ValueError):
        address = ipaddress.ip_address(host)
        unsafe = (
            unsafe
            or address.is_loopback
            or address.is_link_local
            or address.is_unspecified
            or address.is_multicast
        )
    if unsafe and not allow_http:
        raise BackupError(
            "S3 endpoint must not use loopback, link-local, unspecified, "
            "multicast, or metadata hosts"
        )


def _validate_bucket(bucket: str) -> None:
    if (
        not BUCKET_RE.fullmatch(bucket)
        or ".." in bucket
        or ".-" in bucket
        or "-." in bucket
    ):
        raise BackupError("S3 bucket name is invalid")


def _validate_prefix(prefix: str) -> str:
    value = prefix.strip("/")
    if (
        not value
        or len(value) > 512
        or any(part in {"", ".", ".."} for part in value.split("/"))
        or "//" in value
    ):
        raise BackupError("S3 object prefix is invalid")
    return value


def _sanitize_s3_environment() -> None:
    blocked = {
        "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
        "AWS_SECURITY_TOKEN", "AWS_PROFILE", "AWS_DEFAULT_PROFILE",
        "AWS_SHARED_CREDENTIALS_FILE", "AWS_CONFIG_FILE",
        "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_ARN", "AWS_ROLE_SESSION_NAME",
        "AWS_ENDPOINT_URL", "AWS_CA_BUNDLE",
        "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
        "http_proxy", "https_proxy", "all_proxy", "no_proxy",
        "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",
    }
    for key in list(os.environ):
        if key in blocked or key.startswith("AWS_ENDPOINT_URL_"):
            os.environ.pop(key, None)
    os.environ["AWS_EC2_METADATA_DISABLED"] = "true"


def _s3_client(args: argparse.Namespace):
    _sanitize_s3_environment()
    _validate_endpoint(args.endpoint, args.allow_http)
    _validate_bucket(args.bucket)
    credentials = _load_credentials(Path(args.credentials_file))
    verify: bool | str = True
    if args.ca_bundle:
        ca = Path(args.ca_bundle)
        if not ca.is_file():
            raise BackupError("S3 CA bundle does not exist")
        verify = str(ca)
    return boto3.client(
        "s3",
        endpoint_url=args.endpoint,
        region_name=args.region,
        verify=verify,
        config=Config(
            signature_version="s3v4",
            connect_timeout=10,
            read_timeout=60,
            retries={"max_attempts": 3, "mode": "standard"},
            s3={"addressing_style": args.addressing_style},
        ),
        **credentials,
    )


def _require_bucket(
    s3: Any,
    bucket: str,
    require_versioning: bool,
) -> None:
    s3.head_bucket(Bucket=bucket)
    if require_versioning:
        status = (s3.get_bucket_versioning(Bucket=bucket) or {}).get("Status")
        if status != "Enabled":
            raise BackupError("remote backup bucket versioning must be Enabled")


def _read_s3_object_bounded(
    s3: Any,
    bucket: str,
    key: str,
    limit: int,
) -> bytes:
    response = s3.get_object(Bucket=bucket, Key=key)
    body = response["Body"]
    data = body.read(limit + 1)
    if len(data) > limit:
        raise BackupError("remote manifest exceeds size limit")
    return data


def _download_s3_object(
    s3: Any,
    bucket: str,
    key: str,
    destination: Path,
) -> tuple[str, int]:
    destination.parent.mkdir(parents=True, exist_ok=True)
    partial = Path(str(destination) + ".partial")
    digest = hashlib.sha256()
    size = 0
    try:
        response = s3.get_object(Bucket=bucket, Key=key)
        body = response["Body"]
        with partial.open("wb") as dst:
            os.chmod(partial, 0o600)
            while True:
                chunk = body.read(CHUNK_SIZE)
                if not chunk:
                    break
                dst.write(chunk)
                digest.update(chunk)
                size += len(chunk)
            dst.flush()
            os.fsync(dst.fileno())
        os.replace(partial, destination)
        os.chmod(destination, 0o600)
    finally:
        with suppress(FileNotFoundError):
            partial.unlink()
    return digest.hexdigest(), size


def _push(args: argparse.Namespace) -> dict[str, Any]:
    source = Path(args.source).resolve()
    if not source.is_file():
        raise BackupError("source PostgreSQL dump does not exist")
    root_key = _load_root_key(Path(args.encryption_key_file))
    s3 = _s3_client(args)
    _require_bucket(s3, args.bucket, args.require_versioning)
    prefix = _validate_prefix(args.prefix)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_id = f"{stamp}-{os.urandom(8).hex()}"
    source_name = _sanitize_source_name(source.name)
    object_key = f"{prefix}/{backup_id}/{source_name}.aegis.enc"
    manifest_key = f"{prefix}/{backup_id}/manifest.json"

    work_dir = (
        Path(args.work_dir).resolve()
        if args.work_dir
        else source.parent
    )
    work_dir.mkdir(parents=True, exist_ok=True)
    encrypted = work_dir / f".{source_name}.{backup_id}.aegis.enc"
    envelope = _encrypt_file(source, encrypted, root_key, backup_id)
    unsigned = _manifest_unsigned(envelope, args.bucket, object_key)
    manifest = _sign_manifest(unsigned, root_key)
    manifest_bytes = _canonical_json(manifest) + b"\n"

    try:
        s3.upload_file(
            str(encrypted),
            args.bucket,
            object_key,
            ExtraArgs={
                "ContentType": "application/octet-stream",
                "Metadata": {
                    "aegis-schema": SCHEMA,
                    "aegis-backup-id": backup_id,
                    "aegis-cipher-sha256": envelope["cipher_sha256"],
                    "aegis-key-id": envelope["key_id"],
                },
            },
        )
        head = s3.head_object(Bucket=args.bucket, Key=object_key)
        if int(head.get("ContentLength", -1)) != int(envelope["cipher_size"]):
            raise BackupError(
                "remote encrypted object size verification failed"
            )
        metadata = {
            str(k).lower(): str(v)
            for k, v in (head.get("Metadata") or {}).items()
        }
        if (
            metadata.get("aegis-cipher-sha256")
            != envelope["cipher_sha256"]
        ):
            raise BackupError(
                "remote encrypted object metadata verification failed"
            )

        # Manifest is the commit marker and is uploaded only after payload HEAD
        # verification succeeds.
        s3.put_object(
            Bucket=args.bucket,
            Key=manifest_key,
            Body=manifest_bytes,
            ContentType="application/json",
            Metadata={
                "aegis-schema": SCHEMA,
                "aegis-backup-id": backup_id,
            },
        )
        committed = _read_s3_object_bounded(
            s3,
            args.bucket,
            manifest_key,
            MAX_MANIFEST_SIZE,
        )
        if committed != manifest_bytes:
            raise BackupError(
                "remote manifest commit verification failed"
            )
    finally:
        if not args.keep_encrypted_local:
            with suppress(FileNotFoundError):
                encrypted.unlink()

    return {
        "backup_id": backup_id,
        "bucket": args.bucket,
        "cipher_sha256": envelope["cipher_sha256"],
        "manifest_key": manifest_key,
        "object_key": object_key,
        "schema": SCHEMA,
        "source_sha256": envelope["source_sha256"],
        "source_size": envelope["source_size"],
        "status": "committed",
    }


def _restore(args: argparse.Namespace) -> dict[str, Any]:
    root_key = _load_root_key(Path(args.encryption_key_file))
    s3 = _s3_client(args)
    _require_bucket(s3, args.bucket, args.require_versioning)

    manifest_bytes = _read_s3_object_bounded(
        s3,
        args.bucket,
        args.manifest_key,
        MAX_MANIFEST_SIZE,
    )
    try:
        manifest = json.loads(manifest_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BackupError(
            "remote backup manifest JSON is invalid"
        ) from exc
    if not isinstance(manifest, dict):
        raise BackupError(
            "remote backup manifest must be a JSON object"
        )

    unsigned = _verify_manifest(manifest, root_key)
    if unsigned.get("bucket") != args.bucket:
        raise BackupError(
            "remote backup manifest bucket does not match requested bucket"
        )
    object_key = str(unsigned.get("object_key", ""))
    prefix = _validate_prefix(args.prefix)
    if not object_key.startswith(prefix + "/"):
        raise BackupError(
            "remote backup manifest object key escapes configured prefix"
        )

    output = Path(args.output).resolve()
    work_dir = (
        Path(args.work_dir).resolve()
        if args.work_dir
        else output.parent
    )
    work_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        prefix=".aegis-remote-",
        suffix=".enc",
        dir=work_dir,
        delete=False,
    ) as temp:
        encrypted = Path(temp.name)
    os.chmod(encrypted, 0o600)

    try:
        cipher_sha256, cipher_size = _download_s3_object(
            s3,
            args.bucket,
            object_key,
            encrypted,
        )
        if not hmac.compare_digest(
            cipher_sha256,
            str(unsigned.get("cipher_sha256", "")),
        ):
            raise BackupError(
                "downloaded encrypted object SHA-256 verification failed"
            )
        if cipher_size != int(unsigned.get("cipher_size", -1)):
            raise BackupError(
                "downloaded encrypted object size verification failed"
            )
        header = _decrypt_file(
            encrypted,
            output,
            root_key,
            unsigned,
        )
    finally:
        with suppress(FileNotFoundError):
            encrypted.unlink()

    return {
        "backup_id": header["backup_id"],
        "manifest_key": args.manifest_key,
        "output": str(output),
        "schema": SCHEMA,
        "source_sha256": header["source_sha256"],
        "source_size": header["source_size"],
        "status": "restored-locally",
    }


def _add_remote_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--endpoint",
        default=os.getenv("AEGIS_BACKUP_S3_ENDPOINT"),
        required=os.getenv("AEGIS_BACKUP_S3_ENDPOINT") is None,
    )
    parser.add_argument(
        "--region",
        default=os.getenv("AEGIS_BACKUP_S3_REGION", "us-east-1"),
    )
    parser.add_argument(
        "--bucket",
        default=os.getenv("AEGIS_BACKUP_S3_BUCKET"),
        required=os.getenv("AEGIS_BACKUP_S3_BUCKET") is None,
    )
    parser.add_argument(
        "--prefix",
        default=os.getenv(
            "AEGIS_BACKUP_S3_PREFIX",
            "aegisscan/postgres",
        ),
    )
    parser.add_argument(
        "--credentials-file",
        default=os.getenv("AEGIS_BACKUP_S3_CREDENTIALS_FILE"),
        required=os.getenv("AEGIS_BACKUP_S3_CREDENTIALS_FILE") is None,
    )
    parser.add_argument(
        "--encryption-key-file",
        default=os.getenv("AEGIS_BACKUP_ENCRYPTION_KEY_FILE"),
        required=os.getenv("AEGIS_BACKUP_ENCRYPTION_KEY_FILE") is None,
    )
    parser.add_argument(
        "--ca-bundle",
        default=os.getenv("AEGIS_BACKUP_S3_CA_BUNDLE"),
    )
    parser.add_argument(
        "--addressing-style",
        choices=("auto", "path", "virtual"),
        default=os.getenv(
            "AEGIS_BACKUP_S3_ADDRESSING_STYLE",
            "path",
        ),
    )
    parser.add_argument(
        "--allow-http",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--require-versioning",
        action="store_true",
        default=os.getenv(
            "AEGIS_BACKUP_REQUIRE_VERSIONING",
            "true",
        ).strip().lower()
        in {"1", "true", "yes", "on"},
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    push = sub.add_parser(
        "push",
        help="encrypt and commit one verified PostgreSQL dump to remote storage",
    )
    _add_remote_args(push)
    push.add_argument("--source", required=True)
    push.add_argument("--work-dir")
    push.add_argument(
        "--keep-encrypted-local",
        action="store_true",
    )

    restore = sub.add_parser(
        "restore",
        help="download, authenticate, decrypt and recover one remote backup",
    )
    _add_remote_args(restore)
    restore.add_argument("--manifest-key", required=True)
    restore.add_argument("--output", required=True)
    restore.add_argument("--work-dir")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = (
            _push(args)
            if args.command == "push"
            else _restore(args)
        )
    except (
        BackupError,
        BotoCoreError,
        ClientError,
        InvalidTag,
        OSError,
        ValueError,
    ) as exc:
        print(
            json.dumps(
                {
                    "schema": SCHEMA,
                    "status": "failed",
                    "error": str(exc),
                }
            ),
            file=sys.stderr,
        )
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
