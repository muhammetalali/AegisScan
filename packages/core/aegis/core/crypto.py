"""أدوات التشفير — Crypto Utilities.

الإصلاح الحرج #1: المفاتيح تُخزَّن وتُعاد استخدامها بدل التوليد العشوائي
في كل تشغيل (الذي كان يجعل السجلات المشفرة قديماً غير قابلة للقراءة).
"""

import logging
from pathlib import Path
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger("aegis.crypto")

FERNET_PREFIX = "enc:"


def load_or_create_key(key_file: str = ".aegis.key") -> bytes:
    """تحميل مفتاح موجود أو إنشاء مفتاح دائم جديد.

    المفتاح نفسه يجب حمايته (نقله إلى Vault في الإنتاج).
    """
    path = Path(key_file)
    if path.exists():
        key = path.read_bytes().strip()
        if key:
            return key

    key = Fernet.generate_key()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(key)
    try:
        path.chmod(0o600)
    except OSError:
        pass
    logger.info("تم إنشاء مفتاح تشفير دائم: %s", path)
    return key


def encrypt_text(text: str, key: bytes) -> str:
    """تشفير نص وإرجاعه مع بادئة enc: لتمييزه عند القراءة."""
    cipher = Fernet(key)
    return FERNET_PREFIX + cipher.encrypt(text.encode("utf-8")).decode("ascii")


def decrypt_text(token: str, key: bytes) -> Optional[str]:
    """فك تشفير نص مسبق البادئة؛ يُرجع None عند الفشل."""
    if not token.startswith(FERNET_PREFIX):
        return token
    try:
        cipher = Fernet(key)
        return cipher.decrypt(token[len(FERNET_PREFIX):].encode("ascii")).decode(
            "utf-8"
        )
    except (InvalidToken, ValueError):
        logger.warning("فشل فك تشفير قيمة — مفتاح غير مطابق على الأرجح")
        return None


def is_encrypted(value: str) -> bool:
    return value.startswith(FERNET_PREFIX)
