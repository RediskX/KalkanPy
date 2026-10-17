"""
kalkan_sign.py — формирование подписей ГОСТ 2015 (СТ РК ГОСТ Р 34.10-2015) и CMS.

Независимая реализация (без бинарников НУЦ):
    * самоподписанный сертификат ГОСТ 2015 (для тестов и локальных нужд);
    * RAW-подпись (обычная подпись Base64, «как в ЭСФ»);
    * CMS/PKCS#7 (подпись с сертификатом).

Формат бинарных кодировок закреплён по реальным сертификатам НУЦ:
    signatureAlgorithm = SEQUENCE{ OID 1.2.398.3.10.1.1.2.3.2, NULL }
    subjectPublicKeyInfo.algorithm =
        SEQUENCE{ OID 1.2.398.3.10.1.1.2.2,
                  SEQUENCE{ OID 1.2.398.3.10.1.1.2.2.1, OID 1.2.398.3.10.1.3.3 } }
    subjectPublicKey = BIT STRING( 04 81 80 <X||Y> )  — X,Y по 64 байта, little-endian.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from cryptography import x509 as cx509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import NameOID
from typing import Optional

from gostcrypto import gosthash, gostsignature

from kalkan_verify import (OID, _le_each, _curve_name, load_certificate,
                           public_key_from_spki, streebog, verify_signature)

__all__ = [
    "der_sequence", "der_setof", "der_oid", "der_integer",
    "create_self_signed_certificate",
    "raw_sign", "raw_verify",
    "sign_cms",
]

# --- минимальный DER-писатель ---------------------------------------------

def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(content)) + content


def der_sequence(*items: bytes) -> bytes:
    return _tlv(0x30, b"".join(items))


def der_setof(*items: bytes) -> bytes:
    return _tlv(0x31, b"".join(sorted(items)))      # DER: SET OF сортируется


def der_integer(value: int) -> bytes:
    if value == 0:
        body = b"\x00"
    else:
        body = value.to_bytes((value.bit_length() + 7) // 8, "big")
        if body[0] & 0x80:
            body = b"\x00" + body
    return _tlv(0x02, body)


def der_octet_string(value: bytes) -> bytes:
    return _tlv(0x04, value)


def der_bit_string(value: bytes, unused: int = 0) -> bytes:
    return _tlv(0x03, bytes([unused]) + value)


def der_null() -> bytes:
    return b"\x05\x00"


def der_utf8(text: str) -> bytes:
    return _tlv(0x0C, text.encode("utf-8"))


def der_printable(text: str) -> bytes:
    return _tlv(0x13, text.encode("ascii"))


def der_utctime(dt: datetime) -> bytes:
    if dt.year >= 2050:
        return _tlv(0x18, dt.strftime("%Y%m%d%H%M%SZ").encode("ascii"))  # GeneralizedTime
    return _tlv(0x17, dt.strftime("%y%m%d%H%M%SZ").encode("ascii"))      # UTCTime


def der_oid(dotted: str) -> bytes:
    parts = [int(x) for x in dotted.split(".")]
    out = bytes([40 * parts[0] + parts[1]])
    for value in parts[2:]:
        chunk = []
        while value:
            chunk.append(value & 0x7F)
            value >>= 7
        chunk = chunk[::-1] or [0]
        for i in range(len(chunk) - 1):
            chunk[i] |= 0x80
        out += bytes(chunk)
    return _tlv(0x06, out)


def _ctx(index: int, content: bytes) -> bytes:
    """Контекстно-зависимый тег (EXPLICIT/constructed) [index]."""
    return _tlv(0xA0 | index, content)


# --- идентификаторы алгоритмов ГОСТ 2015 (ТОЧНО как в сертификатах НУЦ) ----

def _sig_algorithm_id() -> bytes:
    return der_sequence(der_oid(OID["kz_gost2015_sig"]), der_null())


def _spki_algorithm_id() -> bytes:
    return der_sequence(
        der_oid(OID["kz_gost2015_key"]),
        der_sequence(der_oid(OID["kz_gost2015_hash"]), der_oid("1.2.398.3.10.1.3.3")),
    )


def _name(common_name: str, country: str = "KZ") -> bytes:
    return der_sequence(
        der_setof(der_sequence(der_oid("2.5.4.3"), der_utf8(common_name))),
        der_setof(der_sequence(der_oid("2.5.4.6"), der_printable(country))),
    )


def _subject_public_key_info(public_key_be: bytes) -> bytes:
    size = len(public_key_be) // 2
    point_le = public_key_be[:size][::-1] + public_key_be[size:][::-1]
    return der_sequence(_spki_algorithm_id(), der_bit_string(der_octet_string(point_le)))


def _signer(size: int):
    curve = gostsignature.CURVES_R_1323565_1_024_2019[_curve_name(size)]
    mode = gostsignature.MODE_256 if size == 32 else gostsignature.MODE_512
    return gostsignature.new(mode, curve)


def _sign_der(private_key_be: bytes, digest_be: bytes) -> bytes:
    """
    Подпись в DER-конвенции НУЦ.

    digest_be — Стрибог-хэш в big-endian (как streebog()). Внутри хэш разворачивается
    в little-endian — ровно так его трактует verify_signature() при проверке.
    Возвращает r||s (каждая половина little-endian).
    """
    size = len(private_key_be)
    obj = _signer(size)
    signature = bytes(obj.sign(bytearray(private_key_be), bytearray(digest_be[::-1])))
    return _le_each(signature, size)


# --- самоподписанный сертификат ГОСТ 2015 ---------------------------------

def create_self_signed_certificate(private_key_be: bytes,
                                   common_name: str = "KALKANPY GOST2015 TEST",
                                   country: str = "KZ",
                                   days: int = 3650,
                                   serial: Optional[int] = None) -> bytes:
    """
    Строит самоподписанный сертификат ГОСТ 2015 и возвращает его DER.

    Годится как тестовый/локальный сертификат для проверки RAW и CMS.
    Ключ: private_key_be — приватный ключ (32 или 64 байта, big-endian, как у gostcrypto).
    """
    size = len(private_key_be)
    _curve_name(size)                                   # валидация размера
    obj = _signer(size)
    public_key_be = bytes(obj.public_key_generate(bytearray(private_key_be)))

    if serial is None:
        serial = secrets.randbits(size * 8 - 1) or 1

    now = datetime.now(timezone.utc).replace(microsecond=0)
    name = _name(common_name, country)
    tbs = der_sequence(
        _ctx(0, der_integer(2)),                        # version v3
        der_integer(serial),
        _sig_algorithm_id(),
        name,                                           # issuer
        der_sequence(der_utctime(now), der_utctime(now + timedelta(days=days))),
        name,                                           # subject
        _subject_public_key_info(public_key_be),
    )
    digest = streebog(tbs, size)
    signature = _sign_der(private_key_be, digest)
    return der_sequence(tbs, _sig_algorithm_id(), der_bit_string(signature))


# --- RAW-подпись («как в ЭСФ»: обычная подпись, обычно Base64) -------------

def raw_sign(private_key_be: bytes, data: bytes) -> bytes:
    """RAW-подпись ГОСТ 2015 над data (возвращает r||s в конвенции НУЦ)."""
    return _sign_der(private_key_be, streebog(data, len(private_key_be)))


def raw_verify(signature: bytes, data: bytes, certificate_der: bytes,
               prehashed: bool = False) -> bool:
    """
    Проверяет RAW-подпись ГОСТ 2015 по сертификату подписанта.

    prehashed=True, если в data лежит уже готовый Стрибог-хэш (big-endian).
    """
    size = len(signature) // 2
    digest = data if prehashed else streebog(data, size)
    cert = load_certificate(certificate_der)
    _, pk = public_key_from_spki(cert["tbs_certificate"]["subject_public_key_info"].dump())
    return verify_signature(pk, digest, signature, size)


# --- CMS / PKCS#7 (подпись с сертификатом) ---------------------------------

CMS_DATA = "1.2.840.113549.1.7.1"
CMS_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
OID_SIGNING_TIME = "1.2.840.113549.1.9.5"
OID_SIGNING_CERT_V2 = "1.2.840.113549.1.9.16.2.47"   # CAdES-BES (RFC 5035)


def _attribute(oid_str: str, *values: bytes) -> bytes:
    return der_sequence(der_oid(oid_str), der_setof(*values))


def cms_sign(sign_digest, size: int, data: bytes, certificate_der: bytes,
             detached: bool = False, signing_time: Optional[datetime] = None,
             extra_certs: Optional[list] = None) -> bytes:
    """
    Собирает CMS SignedData (CAdES-BES), а подпись считает внешний источник.

    sign_digest(digest_be) -> signature (r||s, little-endian по половине) — например,
    C_Sign на токене (PKCS#11) либо _sign_der для локального ключа;
    size             — размер половины подписи/хэша (32 = ГОСТ-256, 64 = ГОСТ-512);
    certificate_der  — DER сертификата подписанта (не PEM);
    extra_certs      — дополнительно вкладываемые DER-сертификаты (например, цепочка);
    detached=True    — подпись без содержимого (для внешнего файла).
    """
    cert = load_certificate(certificate_der)
    serial = cert["tbs_certificate"]["serial_number"].native
    issuer = cert["tbs_certificate"]["issuer"].dump()

    if signing_time is None:
        signing_time = datetime.now(timezone.utc).replace(microsecond=0)

    digest_oid = OID["kz_gost2015_hash512"] if size == 64 else OID["kz_gost2015_hash"]

    # CAdES-BES: certHash = SHA-256(сертификата), hashAlgorithm опущен (default)
    ess_cert_id = der_sequence(der_octet_string(hashlib.sha256(certificate_der).digest()))
    signing_cert_v2 = der_sequence(der_sequence(ess_cert_id))

    attrs = [
        _attribute(OID_CONTENT_TYPE, der_oid(CMS_DATA)),
        _attribute(OID_SIGNING_TIME, der_utctime(signing_time)),
        _attribute(OID_SIGNING_CERT_V2, signing_cert_v2),
        _attribute(OID_MESSAGE_DIGEST, der_octet_string(streebog(data, size))),
    ]
    attrs_sorted = b"".join(sorted(attrs))              # DER SET OF — сортировка
    signed_attrs_set = _tlv(0x31, attrs_sorted)

    signature = sign_digest(streebog(signed_attrs_set, size))

    signer_info = der_sequence(
        der_integer(1),                                 # version
        der_sequence(issuer, der_integer(serial)),      # sid: IssuerAndSerialNumber
        der_sequence(der_oid(digest_oid), der_null()),       # digestAlgorithm (NULL, как у DLL)
        _tlv(0xA0, attrs_sorted),                        # signedAttrs [0] IMPLICIT
        _sig_algorithm_id(),                             # signatureAlgorithm
        der_octet_string(signature),                     # signature
    )

    # certificates [0] IMPLICIT SET OF — для строгого DER элементы сортируются
    all_certs = sorted([certificate_der] + list(extra_certs or []))

    encap = der_sequence(
        der_oid(CMS_DATA),
        b"" if detached else _ctx(0, der_octet_string(data)),
    )
    signed_data = der_sequence(
        der_integer(1),
        der_setof(der_sequence(der_oid(digest_oid), der_null())),   # digestAlgorithms (NULL)
        encap,
        _ctx(0, b"".join(all_certs)),                                # certificates [0]
        der_setof(signer_info),                                      # signerInfos
    )
    return der_sequence(der_oid(CMS_SIGNED_DATA), _ctx(0, signed_data))


def sign_cms(private_key_be: bytes, data: bytes, certificate_der: bytes,
             detached: bool = False, signing_time: Optional[datetime] = None,
             extra_certs: Optional[list] = None) -> bytes:
    """
    Формирует CMS SignedData с подписью ГОСТ 2015 и встраивает сертификат.

    private_key_be   — приватный ключ (32/64 байта, big-endian);
    certificate_der  — DER сертификата подписанта (не PEM);
    extra_certs      — дополнительно вкладываемые DER-сертификаты (например, цепочка);
    detached=True    — подпись без содержимого (для внешнего файла).

    Подпись на локальном ключе; для подписи на токене — kalkan_pkcs11.sign_cms.
    """
    size = len(private_key_be)
    _curve_name(size)                                   # валидация размера
    return cms_sign(lambda digest: _sign_der(private_key_be, digest), size,
                    data, certificate_der, detached, signing_time, extra_certs)




# --- RSA (Kalkan поддерживает и RSA: sha256WithRSAEncryption) --------------

RSA_SHA256 = "1.2.840.113549.1.1.11"
SHA256_OID = "2.16.840.1.101.3.4.2.1"


def _rsa_sig_alg() -> bytes:
    return der_sequence(der_oid(RSA_SHA256), der_null())


def create_self_signed_rsa_certificate(private_key,
                                       common_name: str = "KALKANPY RSA TEST",
                                       days: int = 3650) -> bytes:
    """Самоподписанный RSA-сертификат (SHA-256) → DER. private_key — cryptography RSA."""
    name = cx509.Name([
        cx509.NameAttribute(NameOID.COMMON_NAME, common_name),
        cx509.NameAttribute(NameOID.COUNTRY_NAME, "KZ"),
    ])
    now = datetime.now(timezone.utc)
    certificate = (
        cx509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(cx509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + timedelta(days=days))
        .sign(private_key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.DER)


def raw_sign_rsa(private_key, data: bytes) -> bytes:
    """RAW-подпись RSA PKCS#1 v1.5 / SHA-256."""
    return private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())


def sign_cms_rsa(private_key, data: bytes, certificate_der: bytes,
                 detached: bool = False, signing_time: Optional[datetime] = None) -> bytes:
    """CMS SignedData с RSA-подписью (sha256WithRSAEncryption)."""
    cert = load_certificate(certificate_der)
    serial = cert["tbs_certificate"]["serial_number"].native
    issuer = cert["tbs_certificate"]["issuer"].dump()

    if signing_time is None:
        signing_time = datetime.now(timezone.utc).replace(microsecond=0)

    ess_cert_id = der_sequence(der_octet_string(hashlib.sha256(certificate_der).digest()))
    signing_cert_v2 = der_sequence(der_sequence(ess_cert_id))

    attrs = [
        _attribute(OID_CONTENT_TYPE, der_oid(CMS_DATA)),
        _attribute(OID_SIGNING_TIME, der_utctime(signing_time)),
        _attribute(OID_SIGNING_CERT_V2, signing_cert_v2),
        _attribute(OID_MESSAGE_DIGEST, der_octet_string(hashlib.sha256(data).digest())),
    ]
    attrs_sorted = b"".join(sorted(attrs))
    signed_attrs_set = _tlv(0x31, attrs_sorted)

    signature = private_key.sign(bytes(signed_attrs_set), padding.PKCS1v15(), hashes.SHA256())

    signer_info = der_sequence(
        der_integer(1),
        der_sequence(issuer, der_integer(serial)),
        der_sequence(der_oid(SHA256_OID)),               # digestAlgorithm
        _tlv(0xA0, attrs_sorted),                        # signedAttrs
        _rsa_sig_alg(),                                  # signatureAlgorithm
        der_octet_string(signature),
    )
    encap = der_sequence(
        der_oid(CMS_DATA),
        b"" if detached else _ctx(0, der_octet_string(data)),
    )
    signed_data = der_sequence(
        der_integer(1),
        der_setof(der_sequence(der_oid(SHA256_OID))),    # digestAlgorithms
        encap,
        _ctx(0, certificate_der),                        # certificates
        der_setof(signer_info),                          # signerInfos
    )
    return der_sequence(der_oid(CMS_SIGNED_DATA), _ctx(0, signed_data))

