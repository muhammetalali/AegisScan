from pathlib import Path

SCRIPT = Path("aegis-platform/scripts/production_aws_backup_bootstrap.sh")


def _text() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def test_aws_backup_bootstrap_enforces_bucket_security_controls():
    text = _text()
    assert "put-public-access-block" in text
    assert "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true" in text
    assert "put-bucket-ownership-controls" in text
    assert "BucketOwnerEnforced" in text
    assert "put-bucket-encryption" in text
    assert '"SSEAlgorithm": "AES256"' in text
    assert "put-bucket-versioning" in text
    assert "Status=Enabled" in text
    assert "DenyInsecureTransport" in text
    assert '"aws:SecureTransport": "false"' in text


def test_aws_backup_iam_is_prefix_scoped_and_has_no_delete_authority():
    text = _text()
    for action in (
        "s3:GetBucketLocation",
        "s3:GetBucketVersioning",
        "s3:ListBucket",
        "s3:ListBucketMultipartUploads",
        "s3:AbortMultipartUpload",
        "s3:GetObject",
        "s3:GetObjectVersion",
        "s3:ListMultipartUploadParts",
        "s3:PutObject",
    ):
        assert action in text
    assert 'arn:aws:s3:::$BUCKET/$BACKUP_PREFIX/*' in text
    assert "s3:DeleteObject" not in text
    assert "s3:DeleteBucket" not in text
    assert "AdministratorAccess" not in text
    assert text.count('"Action": "s3:*"') == 1
    deny = text.index('"Action": "s3:*"')
    assert '"Effect": "Deny"' in text[max(0, deny - 220):deny]


def test_aws_backup_bootstrap_never_prints_service_secret_and_rolls_back_failed_key():
    text = _text()
    assert 'aws iam create-access-key --user-name "$IAM_USER" --output json >"$TMP_DIR/access-key.json"' in text
    assert 'aws iam delete-access-key --user-name "$IAM_USER" --access-key-id "$NEW_ACCESS_KEY_ID"' in text
    assert "printf '%s\\n' \"$SERVICE_SECRET_KEY\"" not in text
    assert 'echo "$SERVICE_SECRET_KEY"' not in text
    assert "SecretAccessKey" in text
    assert "HOST_MATERIAL_CREATED=0" in text
    assert "COMMITTED=0" in text
    assert "partial AegisScan production material exists; refusing to overwrite or rotate secrets" in text


def test_aws_backup_bootstrap_requires_authenticated_aws_and_private_operator_inputs():
    text = _text()
    assert "aws sts get-caller-identity" in text
    assert "AWS authentication is not ready. Run 'aws login --remote' and retry." in text
    assert "AEGIS_PRODUCTION_DOMAIN is required" in text
    assert "AEGIS_AUTHORIZED_SCAN_TARGETS is required" in text
    assert "AEGIS_ALERT_WEBHOOK_FILE is required" in text
    assert "module._private_source(Path(sys.argv[4]), max_bytes=8192)" in text
    assert "module._validate_https_origin(webhook, \"alert webhook\")" in text


def test_aws_backup_bootstrap_finishes_through_secret_init_and_preflight():
    text = _text()
    assert "module.initialize(" in text
    assert 'output_env=Path("/etc/aegisscan/production.env")' in text
    assert 'secrets_dir=Path("/etc/aegisscan/secrets")' in text
    assert "/etc/aegisscan/secrets/s3-credentials.json" in text
    assert "/etc/aegisscan/secrets/backup-encryption.key" in text
    assert 'exec python3 "$AEGIS_PREFLIGHT" --skip-tls' in text
    assert '"schema":"aegisscan.production-aws-backup-bootstrap.v1"' in text
