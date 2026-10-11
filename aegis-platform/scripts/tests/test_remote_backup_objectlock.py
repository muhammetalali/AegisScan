"""Regression for B2 S3 Object Lock uploads through the canonical backup transport.

Run in the backup runtime with:
    python -m unittest discover -s /app/scripts/tests -p test_remote_backup_objectlock.py
No network calls or production secrets are required.
"""
from __future__ import annotations

import base64
import hashlib
import io
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import remote_backup as backup


class RecordingVersionedBucket:
    def __init__(self):
        self.cipher = None
        self.metadata = None
        self.manifest = None
        self.upload_calls = 0
        self.put_calls = 0

    def head_bucket(self, *, Bucket):
        return {}

    def get_bucket_versioning(self, *, Bucket):
        return {"Status": "Enabled"}

    def upload_file(self, filename, bucket, key, *, ExtraArgs):
        self.upload_calls += 1
        self.cipher = Path(filename).read_bytes()
        self.metadata = ExtraArgs["Metadata"]
        expected = base64.b64encode(hashlib.sha256(self.cipher).digest()).decode("ascii")
        assert ExtraArgs["ChecksumSHA256"] == expected
        assert ExtraArgs["ContentType"] == "application/octet-stream"
        assert self.metadata["aegis-cipher-sha256"] == hashlib.sha256(self.cipher).hexdigest()

    def head_object(self, *, Bucket, Key):
        assert self.cipher is not None
        return {
            "ContentLength": len(self.cipher),
            "VersionId": "encrypted-object-version",
            "Metadata": self.metadata,
        }

    def put_object(self, *, Bucket, Key, Body, ContentType, Metadata, ChecksumSHA256):
        self.put_calls += 1
        self.manifest = Body
        assert ContentType == "application/json"
        assert ChecksumSHA256 == base64.b64encode(hashlib.sha256(Body).digest()).decode("ascii")
        assert Metadata["aegis-schema"] == backup.SCHEMA
        return {"VersionId": "signed-manifest-version"}

    def get_object(self, *, Bucket, Key, VersionId):
        assert VersionId == "signed-manifest-version"
        return {"Body": io.BytesIO(self.manifest)}


class ObjectLockBackupTests(unittest.TestCase):
    def test_s3_client_uses_explicit_checksums_without_automatic_chunked_trailers(self):
        args = types.SimpleNamespace(
            endpoint="https://s3.eu-central-003.backblazeb2.com",
            region="eu-central-003",
            bucket="aegisscan-test-backups",
            addressing_style="path",
            allow_http=False,
            credentials_file="/does/not/matter",
            ca_bundle=None,
        )
        with patch.object(backup, "_load_credentials", return_value={
            "aws_access_key_id": "test-id", "aws_secret_access_key": "test-secret",
        }), patch.object(backup.boto3, "client") as client:
            backup._s3_client(args)
        config = client.call_args.kwargs["config"]
        self.assertEqual(config.request_checksum_calculation, "when_required")
        self.assertEqual(config.response_checksum_validation, "when_required")
        self.assertEqual(config.signature_version, "s3v4")

    def test_real_encryption_commits_versioned_cipher_and_manifest_with_sha256(self):
        with tempfile.TemporaryDirectory(prefix="aegis-backup-objectlock-test-") as temp_dir:
            root = Path(temp_dir)
            source = root / "test.dump"
            source.write_bytes(b"test-postgresql-custom-dump-payload")
            checksum = hashlib.sha256(source.read_bytes()).hexdigest()
            Path(str(source) + ".sha256").write_text(f"{checksum}  {source.name}\n")
            key_file = root / "encryption.key"
            key_file.write_bytes(bytes(range(32)))
            os.chmod(key_file, 0o600)
            args = types.SimpleNamespace(
                source=str(source),
                work_dir=str(root),
                encryption_key_file=str(key_file),
                bucket="aegisscan-test-backups",
                prefix="aegisscan/postgres",
                require_versioning=True,
                keep_encrypted_local=False,
            )
            s3 = RecordingVersionedBucket()
            with patch.object(backup, "_s3_client", return_value=s3):
                result = backup._push(args)
            self.assertEqual(result["status"], "committed")
            self.assertEqual(result["object_version_id"], "encrypted-object-version")
            self.assertEqual(result["manifest_version_id"], "signed-manifest-version")
            self.assertEqual(result["source_sha256"], checksum)
            self.assertEqual(s3.upload_calls, 1)
            self.assertEqual(s3.put_calls, 1)
            self.assertEqual(s3.cipher[:len(backup.MAGIC)], backup.MAGIC)
            self.assertFalse(list(root.glob("*.aegis.enc")))
            self.assertFalse(list(root.glob(".*.aegis.enc")))


if __name__ == "__main__":
    unittest.main()
