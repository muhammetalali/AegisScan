from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import io
import json
from argparse import Namespace
import pytest

PATH = Path(__file__).parents[1] / "aegis-platform/scripts/remote_backup.py"
SPEC = spec_from_file_location("remote_backup", PATH)
assert SPEC and SPEC.loader
remote = module_from_spec(SPEC)
SPEC.loader.exec_module(remote)

class FakeS3:
    def __init__(self):
        self.objects = {}
        self.versioning = "Enabled"
    def head_bucket(self, **kwargs):
        return {}
    def get_bucket_versioning(self, **kwargs):
        return {"Status": self.versioning}
    def upload_file(self, filename, bucket, key, ExtraArgs=None):
        self.objects[(bucket, key)] = {"body": Path(filename).read_bytes(), "metadata": dict((ExtraArgs or {}).get("Metadata", {}))}
    def head_object(self, **kwargs):
        item = self.objects[(kwargs["Bucket"], kwargs["Key"])]
        return {"ContentLength": len(item["body"]), "Metadata": item["metadata"]}
    def put_object(self, **kwargs):
        body = kwargs["Body"]
        if isinstance(body, str):
            body = body.encode()
        self.objects[(kwargs["Bucket"], kwargs["Key"])] = {"body": bytes(body), "metadata": dict(kwargs.get("Metadata", {}))}
        return {}
    def get_object(self, **kwargs):
        return {"Body": io.BytesIO(self.objects[(kwargs["Bucket"], kwargs["Key"])]["body"])}

def private(path, data):
    path.write_bytes(data)
    path.chmod(0o600)
    return path

def fixture_files(tmp_path):
    marker = b"AegisScan-remote-backup-plaintext-proof\n"
    source = private(tmp_path / "aegisscan-aegisdb-proof.dump", marker * 5000)
    digest, _ = remote._file_sha256(source)
    sidecar = private(Path(str(source) + ".sha256"), f"{digest}  {source.name}\n".encode())
    key = private(tmp_path / "backup.key", bytes(range(32)))
    credentials = private(tmp_path / "s3.json", json.dumps({"access_key_id": "ci-access", "secret_access_key": "ci-secret-value"}).encode())
    return source, sidecar, key, credentials, marker

def make_args(tmp_path, key, credentials, **overrides):
    values = dict(endpoint="http://127.0.0.1:9000", region="us-east-1", bucket="aegis-backups",
                  prefix="aegisscan/postgres", credentials_file=str(credentials), encryption_key_file=str(key),
                  ca_bundle=None, addressing_style="path", allow_http=True, require_versioning=True,
                  work_dir=str(tmp_path / "work"), keep_encrypted_local=False, source=None, manifest_key=None, output=None)
    values.update(overrides)
    return Namespace(**values)

def test_remote_round_trip_survives_local_loss(tmp_path, monkeypatch):
    source, sidecar, key, credentials, marker = fixture_files(tmp_path)
    store = FakeS3()
    monkeypatch.setattr(remote, "_s3_client", lambda _args: store)
    pushed = remote._push(make_args(tmp_path, key, credentials, source=str(source)))
    encrypted = store.objects[("aegis-backups", pushed["object_key"])]["body"]
    assert pushed["status"] == "committed"
    assert encrypted.startswith(remote.MAGIC)
    assert marker not in encrypted
    source.unlink()
    sidecar.unlink()
    restored = tmp_path / "restored.dump"
    result = remote._restore(make_args(tmp_path, key, credentials, manifest_key=pushed["manifest_key"], output=str(restored)))
    assert result["status"] == "restored-locally"
    assert restored.read_bytes() == marker * 5000
    assert Path(str(restored) + ".sha256").is_file()

def test_manifest_modification_is_rejected(tmp_path, monkeypatch):
    source, _, key, credentials, _ = fixture_files(tmp_path)
    store = FakeS3()
    monkeypatch.setattr(remote, "_s3_client", lambda _args: store)
    pushed = remote._push(make_args(tmp_path, key, credentials, source=str(source)))
    item_key = ("aegis-backups", pushed["manifest_key"])
    manifest = json.loads(store.objects[item_key]["body"])
    manifest["object_key"] = "aegisscan/postgres/replaced/object.enc"
    store.objects[item_key]["body"] = remote._canonical_json(manifest) + b"\n"
    with pytest.raises(remote.BackupError, match="authentication failed"):
        remote._restore(make_args(tmp_path, key, credentials, manifest_key=pushed["manifest_key"], output=str(tmp_path / "out.dump")))

def test_ciphertext_modification_is_rejected(tmp_path, monkeypatch):
    source, _, key, credentials, _ = fixture_files(tmp_path)
    store = FakeS3()
    monkeypatch.setattr(remote, "_s3_client", lambda _args: store)
    pushed = remote._push(make_args(tmp_path, key, credentials, source=str(source)))
    item_key = ("aegis-backups", pushed["object_key"])
    damaged = bytearray(store.objects[item_key]["body"])
    damaged[len(damaged) // 2] ^= 1
    store.objects[item_key]["body"] = bytes(damaged)
    with pytest.raises(remote.BackupError, match="SHA-256 verification failed"):
        remote._restore(make_args(tmp_path, key, credentials, manifest_key=pushed["manifest_key"], output=str(tmp_path / "out.dump")))

def test_wrong_key_and_open_permissions_are_rejected(tmp_path, monkeypatch):
    source, _, key, credentials, _ = fixture_files(tmp_path)
    store = FakeS3()
    monkeypatch.setattr(remote, "_s3_client", lambda _args: store)
    pushed = remote._push(make_args(tmp_path, key, credentials, source=str(source)))
    wrong = private(tmp_path / "wrong.key", b"Z" * 32)
    with pytest.raises(remote.BackupError, match="authentication failed|key_id"):
        remote._restore(make_args(tmp_path, wrong, credentials, manifest_key=pushed["manifest_key"], output=str(tmp_path / "wrong.dump")))
    key.chmod(0o644)
    with pytest.raises(remote.BackupError, match="group/others"):
        remote._load_root_key(key)

def test_versioning_and_https_are_fail_closed(tmp_path, monkeypatch):
    source, _, key, credentials, _ = fixture_files(tmp_path)
    store = FakeS3()
    store.versioning = None
    monkeypatch.setattr(remote, "_s3_client", lambda _args: store)
    with pytest.raises(remote.BackupError, match="versioning"):
        remote._push(make_args(tmp_path, key, credentials, source=str(source)))
    with pytest.raises(remote.BackupError, match="HTTPS"):
        remote._validate_endpoint("http://backup.example.com:9000", allow_http=False)
    with pytest.raises(remote.BackupError, match="loopback"):
        remote._validate_endpoint("https://127.0.0.1:9000", allow_http=False)
