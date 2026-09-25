#!/bin/sh
set -eu

umask 077

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
SECRET_INIT="$SCRIPT_DIR/production_secret_init.py"
PREFLIGHT="$SCRIPT_DIR/production_preflight.py"

AWS_REGION="${AEGIS_AWS_REGION:-eu-central-1}"
IAM_USER="aegisscan-prod-backup"
POLICY_NAME="AegisScanProductionBackup"
BACKUP_PREFIX="aegisscan/postgres"
DOMAIN="${AEGIS_PRODUCTION_DOMAIN:-}"
AUTHORIZED_TARGETS="${AEGIS_AUTHORIZED_SCAN_TARGETS:-}"
ALERT_WEBHOOK_FILE="${AEGIS_ALERT_WEBHOOK_FILE:-}"

fail() {
  printf '%s\n' "$*" >&2
  exit 1
}

command -v aws >/dev/null 2>&1 || fail "AWS CLI v2 is required"
command -v python3 >/dev/null 2>&1 || fail "python3 is required"
command -v sudo >/dev/null 2>&1 || fail "sudo is required"
[ -f "$SECRET_INIT" ] || fail "production_secret_init.py is unavailable"
[ -f "$PREFLIGHT" ] || fail "production_preflight.py is unavailable"

case "$AWS_REGION" in
  ''|*[!a-z0-9-]*) fail "AEGIS_AWS_REGION must contain only lowercase letters, digits and hyphens" ;;
esac

[ -n "$DOMAIN" ] || fail "AEGIS_PRODUCTION_DOMAIN is required"
[ -n "$AUTHORIZED_TARGETS" ] || fail "AEGIS_AUTHORIZED_SCAN_TARGETS is required"
[ -n "$ALERT_WEBHOOK_FILE" ] || fail "AEGIS_ALERT_WEBHOOK_FILE is required"
[ -f "$ALERT_WEBHOOK_FILE" ] || fail "AEGIS_ALERT_WEBHOOK_FILE does not exist"

python3 - "$SECRET_INIT" "$DOMAIN" "$AUTHORIZED_TARGETS" "$ALERT_WEBHOOK_FILE" <<'PY'
import importlib.util
import sys
from pathlib import Path

module_path = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("aegis_production_secret_init", module_path)
if spec is None or spec.loader is None:
    raise SystemExit("cannot import production_secret_init.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

module._validate_domain(sys.argv[2])
module._validate_targets([sys.argv[3]])
raw = module._private_source(Path(sys.argv[4]), max_bytes=8192)
try:
    webhook = raw.decode("utf-8").strip()
except UnicodeDecodeError as exc:
    raise SystemExit("AEGIS_ALERT_WEBHOOK_FILE must be UTF-8") from exc
module._validate_https_origin(webhook, "alert webhook")
PY

export AWS_PAGER=""
if ! CALLER_JSON="$(aws sts get-caller-identity --output json 2>/dev/null)"; then
  fail "AWS authentication is not ready. Run 'aws login --remote' and retry."
fi
ACCOUNT_ID="$(printf '%s' "$CALLER_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["Account"])')"
CALLER_ARN="$(printf '%s' "$CALLER_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["Arn"])')"
case "$ACCOUNT_ID" in
  ''|*[!0-9]*) fail "AWS account ID is invalid" ;;
esac

BUCKET="${AEGIS_BACKUP_S3_BUCKET:-aegisscan-prod-backup-${ACCOUNT_ID}-${AWS_REGION}}"
python3 - "$BUCKET" <<'PY'
import re
import sys
value = sys.argv[1]
if (
    not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", value)
    or ".." in value
    or ".-" in value
    or "-." in value
):
    raise SystemExit("AEGIS_BACKUP_S3_BUCKET is invalid")
PY
BACKUP_ENDPOINT="https://s3.${AWS_REGION}.amazonaws.com"

TMP_DIR="$(mktemp -d)"
NEW_ACCESS_KEY_ID=""
HOST_MATERIAL_CREATED=0
COMMITTED=0

cleanup() {
  rc=$?
  trap - EXIT HUP INT TERM
  if [ "$rc" -ne 0 ] && [ "$COMMITTED" -ne 1 ]; then
    if [ "$HOST_MATERIAL_CREATED" -eq 1 ]; then
      sudo rm -f \
        /etc/aegisscan/production.env \
        /etc/aegisscan/secrets/s3-credentials.json \
        /etc/aegisscan/secrets/backup-encryption.key >/dev/null 2>&1 || true
    fi
    if [ -n "$NEW_ACCESS_KEY_ID" ]; then
      aws iam delete-access-key --user-name "$IAM_USER" --access-key-id "$NEW_ACCESS_KEY_ID" >/dev/null 2>&1 || true
    fi
  fi
  rm -rf "$TMP_DIR"
  exit "$rc"
}
trap cleanup EXIT HUP INT TERM

printf 'aws_account_id=%s\n' "$ACCOUNT_ID"
printf 'aws_caller_arn=%s\n' "$CALLER_ARN"
printf 'backup_region=%s\n' "$AWS_REGION"
printf 'backup_bucket=%s\n' "$BUCKET"

if aws s3api head-bucket --bucket "$BUCKET" >/dev/null 2>&1; then
  printf 'backup_bucket_state=existing\n'
else
  if [ "$AWS_REGION" = "us-east-1" ]; then
    aws s3api create-bucket --bucket "$BUCKET" >/dev/null
  else
    aws s3api create-bucket \
      --bucket "$BUCKET" \
      --create-bucket-configuration "LocationConstraint=$AWS_REGION" >/dev/null
  fi
  printf 'backup_bucket_state=created\n'
fi

aws s3api put-public-access-block \
  --bucket "$BUCKET" \
  --public-access-block-configuration \
  'BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true'

aws s3api put-bucket-ownership-controls \
  --bucket "$BUCKET" \
  --ownership-controls 'Rules=[{ObjectOwnership=BucketOwnerEnforced}]'

cat >"$TMP_DIR/encryption.json" <<'JSON'
{
  "Rules": [
    {
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "AES256"
      },
      "BucketKeyEnabled": false
    }
  ]
}
JSON
aws s3api put-bucket-encryption \
  --bucket "$BUCKET" \
  --server-side-encryption-configuration "file://$TMP_DIR/encryption.json"

aws s3api put-bucket-versioning \
  --bucket "$BUCKET" \
  --versioning-configuration Status=Enabled

cat >"$TMP_DIR/lifecycle.json" <<'JSON'
{
  "Rules": [
    {
      "ID": "AbortIncompleteMultipartUploads",
      "Status": "Enabled",
      "Filter": {"Prefix": ""},
      "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 7}
    }
  ]
}
JSON
aws s3api put-bucket-lifecycle-configuration \
  --bucket "$BUCKET" \
  --lifecycle-configuration "file://$TMP_DIR/lifecycle.json"

aws s3api put-bucket-tagging \
  --bucket "$BUCKET" \
  --tagging 'TagSet=[{Key=Project,Value=AegisScan},{Key=Environment,Value=Production},{Key=Purpose,Value=EncryptedBackup}]'

cat >"$TMP_DIR/bucket-policy.json" <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyInsecureTransport",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::$BUCKET",
        "arn:aws:s3:::$BUCKET/*"
      ],
      "Condition": {
        "Bool": {"aws:SecureTransport": "false"}
      }
    }
  ]
}
EOF
aws s3api put-bucket-policy --bucket "$BUCKET" --policy "file://$TMP_DIR/bucket-policy.json"

test "$(aws s3api get-bucket-versioning --bucket "$BUCKET" --query Status --output text)" = "Enabled"
test "$(aws s3api get-bucket-encryption --bucket "$BUCKET" --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm' --output text)" = "AES256"
test "$(aws s3api get-public-access-block --bucket "$BUCKET" --query 'PublicAccessBlockConfiguration.[BlockPublicAcls,IgnorePublicAcls,BlockPublicPolicy,RestrictPublicBuckets]' --output text)" = "True	True	True	True"

if ! aws iam get-user --user-name "$IAM_USER" >/dev/null 2>&1; then
  aws iam create-user \
    --user-name "$IAM_USER" \
    --tags Key=Project,Value=AegisScan Key=Environment,Value=Production Key=Purpose,Value=EncryptedBackup >/dev/null
fi

cat >"$TMP_DIR/iam-policy.json" <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "BucketMetadata",
      "Effect": "Allow",
      "Action": [
        "s3:GetBucketLocation",
        "s3:GetBucketVersioning",
        "s3:ListBucket",
        "s3:ListBucketMultipartUploads"
      ],
      "Resource": "arn:aws:s3:::$BUCKET"
    },
    {
      "Sid": "EncryptedBackupObjects",
      "Effect": "Allow",
      "Action": [
        "s3:AbortMultipartUpload",
        "s3:GetObject",
        "s3:GetObjectVersion",
        "s3:ListMultipartUploadParts",
        "s3:PutObject"
      ],
      "Resource": "arn:aws:s3:::$BUCKET/$BACKUP_PREFIX/*"
    }
  ]
}
EOF
aws iam put-user-policy \
  --user-name "$IAM_USER" \
  --policy-name "$POLICY_NAME" \
  --policy-document "file://$TMP_DIR/iam-policy.json"

HOST_STATE="$(sudo sh -c '
n=0
for f in /etc/aegisscan/production.env /etc/aegisscan/secrets/s3-credentials.json /etc/aegisscan/secrets/backup-encryption.key; do
  if [ -s "$f" ]; then n=$((n + 1)); fi
done
printf "%s" "$n"
')"
case "$HOST_STATE" in
  3)
    sudo env AEGIS_PREFLIGHT="$PREFLIGHT" sh -c '
      set -a
      . /etc/aegisscan/production.env
      set +a
      exec python3 "$AEGIS_PREFLIGHT" --skip-tls
    '
    COMMITTED=1
    printf '{"schema":"aegisscan.production-aws-backup-bootstrap.v1","status":"already-initialized","bucket":"%s","iam_user":"%s","region":"%s"}\n' "$BUCKET" "$IAM_USER" "$AWS_REGION"
    exit 0
    ;;
  0) ;;
  *) fail "partial AegisScan production material exists; refusing to overwrite or rotate secrets" ;;
esac

EXISTING_KEYS="$(aws iam list-access-keys --user-name "$IAM_USER" --query 'AccessKeyMetadata[].AccessKeyId' --output text)"
[ -z "$EXISTING_KEYS" ] || fail "IAM user already has an access key but host material is absent; rotate/reconcile explicitly before continuing"

aws iam create-access-key --user-name "$IAM_USER" --output json >"$TMP_DIR/access-key.json"
chmod 0600 "$TMP_DIR/access-key.json"
NEW_ACCESS_KEY_ID="$(python3 - "$TMP_DIR/access-key.json" <<'PY'
import json
import sys
payload = json.load(open(sys.argv[1], encoding="utf-8"))
print(payload["AccessKey"]["AccessKeyId"])
PY
)"

python3 - "$TMP_DIR/access-key.json" "$TMP_DIR/s3-credentials.json" <<'PY'
import json
import os
import sys
source, target = sys.argv[1:3]
payload = json.load(open(source, encoding="utf-8"))["AccessKey"]
result = {
    "access_key_id": payload["AccessKeyId"],
    "secret_access_key": payload["SecretAccessKey"],
}
with open(target, "x", encoding="utf-8") as handle:
    json.dump(result, handle, sort_keys=True)
    handle.write("\n")
os.chmod(target, 0o600)
PY

SERVICE_ACCESS_KEY="$(python3 - "$TMP_DIR/s3-credentials.json" <<'PY'
import json,sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["access_key_id"])
PY
)"
SERVICE_SECRET_KEY="$(python3 - "$TMP_DIR/s3-credentials.json" <<'PY'
import json,sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["secret_access_key"])
PY
)"

(
  unset AWS_PROFILE AWS_DEFAULT_PROFILE AWS_SESSION_TOKEN AWS_SECURITY_TOKEN AWS_WEB_IDENTITY_TOKEN_FILE AWS_ROLE_ARN AWS_ROLE_SESSION_NAME
  export AWS_ACCESS_KEY_ID="$SERVICE_ACCESS_KEY"
  export AWS_SECRET_ACCESS_KEY="$SERVICE_SECRET_KEY"
  export AWS_DEFAULT_REGION="$AWS_REGION"
  export AWS_PAGER=""
  aws s3api head-bucket --bucket "$BUCKET" >/dev/null
  test "$(aws s3api get-bucket-versioning --bucket "$BUCKET" --query Status --output text)" = "Enabled"
)
unset SERVICE_ACCESS_KEY SERVICE_SECRET_KEY

PYTHON_BIN="$(command -v python3)"
sudo env \
  AEGIS_SECRET_INIT="$SECRET_INIT" \
  AEGIS_DOMAIN="$DOMAIN" \
  AEGIS_TARGETS="$AUTHORIZED_TARGETS" \
  AEGIS_ALERT_FILE="$ALERT_WEBHOOK_FILE" \
  AEGIS_BACKUP_ENDPOINT="$BACKUP_ENDPOINT" \
  AEGIS_BACKUP_BUCKET_VALUE="$BUCKET" \
  AEGIS_BACKUP_REGION_VALUE="$AWS_REGION" \
  AEGIS_S3_CREDENTIALS_SOURCE="$TMP_DIR/s3-credentials.json" \
  "$PYTHON_BIN" - <<'PY'
import importlib.util
import json
import os
from pathlib import Path

module_path = Path(os.environ["AEGIS_SECRET_INIT"])
spec = importlib.util.spec_from_file_location("aegis_production_secret_init", module_path)
if spec is None or spec.loader is None:
    raise SystemExit("cannot import production_secret_init.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

alert_raw = module._private_source(Path(os.environ["AEGIS_ALERT_FILE"]), max_bytes=8192)
alert_webhook = alert_raw.decode("utf-8").strip()
result = module.initialize(
    domain=os.environ["AEGIS_DOMAIN"],
    authorized_targets=[os.environ["AEGIS_TARGETS"]],
    alert_webhook=alert_webhook,
    backup_endpoint=os.environ["AEGIS_BACKUP_ENDPOINT"],
    backup_bucket=os.environ["AEGIS_BACKUP_BUCKET_VALUE"],
    backup_region=os.environ["AEGIS_BACKUP_REGION_VALUE"],
    s3_credentials_source=Path(os.environ["AEGIS_S3_CREDENTIALS_SOURCE"]),
    output_env=Path("/etc/aegisscan/production.env"),
    secrets_dir=Path("/etc/aegisscan/secrets"),
)
print(json.dumps(result, sort_keys=True))
PY
HOST_MATERIAL_CREATED=1

sudo env AEGIS_PREFLIGHT="$PREFLIGHT" sh -c '
  set -a
  . /etc/aegisscan/production.env
  set +a
  exec python3 "$AEGIS_PREFLIGHT" --skip-tls
'

COMMITTED=1
printf '{"schema":"aegisscan.production-aws-backup-bootstrap.v1","status":"success","bucket":"%s","iam_user":"%s","region":"%s"}\n' "$BUCKET" "$IAM_USER" "$AWS_REGION"
