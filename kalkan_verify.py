"""
kalkan_verify.py — независимая проверка ЭЦП НУЦ РК (СТ РК ГОСТ Р 34.10-2015 / 34.11-2015).

Назначение
----------
Проверка подписей и сертификатов криптопровайдера НУЦ РК (pki.gov.kz),
который продаётся как KalkanCrypt SDK, БЕЗ использования бинарников НУЦ
(KalkanCrypt.dll, KalkanCryptCOM.dll, libkalkancryptwr, NCALayer).

Криптография берётся из открытого ГОСТ-стека:
    * gostcrypto  — Стрибог (ГОСТ Р 34.11-2012/2015) и подпись (ГОСТ Р 34.10-2012/2015);
    * asn1crypto  — разбор ASN.1 (X.509, CMS/PKCS#7);
    * стандартная библиотека — разбор DER-точки ключа (asn1crypto не знает ГОСТ-OID в SPKI).

Проверено экспериментально на образцах из SDK (см. README.md):
    OK самоподпись корневого тест-сертификата НУЦ 2022 (512-бит);
    OK подпись тест-сертификата НCA, выданного корнем;
    OK самоподпись НCA не проходит (ожидаемо: его подписал корень).

Конвенции кодирования (определены перебором и закреплены здесь)
----------------------------------------------------------------
ГОСТ-подписи НУЦ РК кодируются в стиле RFC 4491 («little-endian»):
    * координаты ключа  — X||Y, каждая половина little-endian;
    * значение подписи   — r||s, каждая половина little-endian;
    * хэш Стрибог        — результат разворачивается (little-endian).
gostcrypto использует big-endian, поэтому в verify_signature() всё
соответствующим образом разворачивается (см. _le_each).

OID казахстанской ветки (1.2.398.3.10.*)
----------------------------------------
    ключ    ГОСТ 2015 : 1.2.398.3.10.1.1.2.2
    хэш     ГОСТ 2015 : 1.2.398.3.10.1.1.2.2.1
    подпись ГОСТ 2015 : 1.2.398.3.10.1.1.2.3.2
    устаревшие (СТ РК ГОСТ Р 34.310-2004 / 34.311 ~ 34.10-2001 / 34.11-94):
    подпись : 1.2.398.3.10.1.1.1.1 (в CMS) и 1.2.398.3.10.1.1.1.2 (в сертификате)
    хэш     : 1.2.398.3.10.1.3.1
Устаревшие алгоритмы реализованы в kalkan_legacy (28147-89 + 34.11-94 + 34.10-2001)
и проверены на реальных объектах НУЦ РК: сертификатах и CMS (см. test_legacy.py).

Зависимости: gostcrypto, asn1crypto.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Optional

from asn1crypto import cms, x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import load_der_x509_certificate
from gostcrypto import gosthash, gostsignature

from kalkan_legacy import curve_by_oid, gost341194_kz, verify_signature_2001

__all__ = [
    "OID",
    "UnsupportedAlgorithm",
    "streebog",
    "public_key_from_spki",
    "verify_signature",
    "verify_rsa",
    "spki_algorithm_oid",
    "verify_certificate",
    "verify_certificate_chain",
    "verify_cms",
    "load_certificate",
    "load_cms",
]

# --- RSA (Kalkan поддерживает и ГОСТ, и RSA) ------------------------------
OID_RSA = "1.2.840.113549.1.1.1"
RSA_SIG_ALGS = {
    "1.2.840.113549.1.1.5": "sha1",
    "1.2.840.113549.1.1.11": "sha256",
    "1.2.840.113549.1.1.12": "sha384",
    "1.2.840.113549.1.1.13": "sha512",
}
HASH_BY_OID = {
    "1.3.14.3.2.26": "sha1",
    "2.16.840.1.101.3.4.2.1": "sha256",
    "2.16.840.1.101.3.4.2.2": "sha384",
    "2.16.840.1.101.3.4.2.3": "sha512",
}
_CRYPTO_HASHES = {"sha1": hashes.SHA1, "sha256": hashes.SHA256,
                  "sha384": hashes.SHA384, "sha512": hashes.SHA512}

# --- OID ------------------------------------------------------------------

OID = {
    "kz_gost2015_key": "1.2.398.3.10.1.1.2.2",
    "kz_gost2015_hash": "1.2.398.3.10.1.1.2.2.1",
    "kz_gost2015_hash512": "1.2.398.3.10.1.3.3",
    "kz_gost2015_sig": "1.2.398.3.10.1.1.2.3.2",
    "kz_legacy_sig": "1.2.398.3.10.1.1.1.1",
    "kz_legacy_sig_cert": "1.2.398.3.10.1.1.1.2",
    "kz_legacy_hash": "1.2.398.3.10.1.3.1",
    "cms_signed_data": "1.2.840.113549.1.7.2",
    "cms_message_digest": "1.2.840.113549.1.9.4",
    "cms_content_type": "1.2.840.113549.1.9.3",
    "cms_signing_time": "1.2.840.113549.1.9.5",
}


class UnsupportedAlgorithm(Exception):
    """Алгоритм подписи/хэша не поддержан (OID вне ГОСТ 2015 / устаревшего ГОСТ / RSA)."""


# --- разбор DER (минимальный, чтобы не зависеть от знаний asn1crypto о ГОСТ) ---

def _read_tlv(buf: bytes, pos: int):
    """Читает один TLV; возвращает (tag, value, next_pos)."""
    if pos + 2 > len(buf):
        raise ValueError("обрыв TLV: нет заголовка")
    tag = buf[pos]
    pos += 1
    length = buf[pos]
    pos += 1
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or pos + n > len(buf):
            raise ValueError("обрыв TLV: некорректная длина")
        length = int.from_bytes(buf[pos:pos + n], "big")
        pos += n
    if pos + length > len(buf):
        raise ValueError("обрыв TLV: значение за границей буфера")
    value = buf[pos:pos + length]
    return tag, value, pos + length


def _curve_name(size: int) -> str:
    if size == 32:
        return "id-tc26-gost-3410-2012-256-paramSetA"
    if size == 64:
        return "id-tc26-gost-3410-12-512-paramSetA"
    raise UnsupportedAlgorithm(f"неизвестный размер ключа/подписи: {size} байт")


def _le_each(value: bytes, size: int) -> bytes:
    """Развернуть каждую из двух половин (r||s или X||Y) в little-endian."""
    return value[:size][::-1] + value[size:][::-1]


def _oid_dotted(value: bytes) -> str:
    first = value[0]
    parts = [first // 40, first % 40]
    acc = 0
    for byte in value[1:]:
        acc = (acc << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(acc)
            acc = 0
    return ".".join(map(str, parts))


def spki_algorithm_oid(spki_der: bytes) -> str:
    """OID алгоритма открытого ключа из SubjectPublicKeyInfo."""
    _, body, _ = _read_tlv(spki_der, 0)
    _, algid, _ = _read_tlv(body, 0)
    _, oid_value, _ = _read_tlv(algid, 0)
    return _oid_dotted(oid_value)


def verify_rsa(certificate_der: bytes, data: bytes, signature: bytes,
               hash_name: str) -> bool:
    """Проверка RSA (PKCS#1 v1.5) подписи открытым ключом сертификата."""
    try:
        public_key = load_der_x509_certificate(certificate_der).public_key()
        public_key.verify(signature, data, padding.PKCS1v15(), _CRYPTO_HASHES[hash_name]())
        return True
    except Exception:
        return False



# --- криптография ----------------------------------------------------------

def streebog(data: bytes, size: int) -> bytes:
    """Стрибог (ГОСТ Р 34.11-2012/2015) длиной size байт (32 или 64), big-endian."""
    name = "streebog%d" % (size * 8)
    return bytes(gosthash.new(name, data=bytearray(data)).digest())


def public_key_from_spki(spki_der: bytes):
    """
    Достаёт открытый ключ ГОСТ из SubjectPublicKeyInfo.

    Возвращает (size, key_be): size — размер половины в байтах, key_be — X||Y
    (big-endian, в порядке DER). Для ГОСТ точка завёрнута в OCTET STRING: 04 <len> <X||Y>.
    """
    _, body, _ = _read_tlv(spki_der, 0)          # SEQUENCE
    _, _, off1 = _read_tlv(body, 0)              # AlgorithmIdentifier
    tag2, bits_field, _ = _read_tlv(body, off1)  # BIT STRING
    if tag2 != 0x03:
        raise ValueError("ожидался BIT STRING в SubjectPublicKeyInfo")
    bits = bits_field[1:]                        # отбросить байт «unused bits»

    if bits and bits[0] == 0x04:                 # OCTET STRING (RFC 4491)
        if bits[1] & 0x80:
            n = bits[1] & 0x7F
            point = bits[2 + n:]
        else:
            point = bits[2:]
    else:
        point = bits[1:]                         # 04||X||Y без обёртки

    size = len(point) // 2
    _curve_name(size)                            # валидация размера
    return size, point


def verify_signature(public_key_be: bytes, digest_be: bytes,
                     signature_raw: bytes, size: int) -> bool:
    """
    Проверяет ГОСТ-подпись в конвенции НУЦ РК (little-endian).

    public_key_be : X||Y (big-endian, как в DER);
    digest_be     : Стрибог-хэш (big-endian, как выдаёт streebog());
    signature_raw : r||s (big-endian, как в DER).
    """
    curve = gostsignature.CURVES_R_1323565_1_024_2019[_curve_name(size)]
    mode = gostsignature.MODE_256 if size == 32 else gostsignature.MODE_512
    obj = gostsignature.new(mode, curve)

    pk_le = _le_each(public_key_be, size)
    hash_le = digest_be[::-1]
    sig_le = _le_each(signature_raw, size)
    return bool(obj.verify(bytearray(pk_le), bytearray(hash_le), bytearray(sig_le)))


# --- сертификаты -----------------------------------------------------------

def load_certificate(data: bytes) -> x509.Certificate:
    """Загружает сертификат из DER или PEM."""
    if b"-----BEGIN" in data:
        from asn1crypto import pem
        _, _, data = pem.unarmor(data)
    return x509.Certificate.load(data)


def _encode_tlv(tag: int, content: bytes) -> bytes:
    """Минимальный DER-кодировщик TLV (для восстановления сырых байтов объектов)."""
    length = len(content)
    if length < 0x80:
        header = bytes([tag, length])
    else:
        raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
        header = bytes([tag, 0x80 | len(raw)]) + raw
    return header + content


def _raw_der(value) -> bytes:
    """
    DER объекта без повторной сериализации через asn1crypto.

    asn1crypto не знает казахстанские ГОСТ-OID в SPKI и падает (KeyError) при
    повторном dump() таких сертификатов, поэтому берём исходные байты содержимого.
    """
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    contents = getattr(value, "contents", None)
    if isinstance(contents, (bytes, bytearray)):
        return _encode_tlv(0x30, bytes(contents))
    return value.dump()


def _tlv_slice(buf: bytes, pos: int = 0):
    """Полные байты одного TLV и позиция после него."""
    _, _, nxt = _read_tlv(buf, pos)
    return buf[pos:nxt], nxt


def _tbs_from_cert(cert_der: bytes) -> bytes:
    """DER tbsCertificate — ровно те байты, которые подписаны (первый элемент Certificate)."""
    _, body, _ = _read_tlv(cert_der, 0)                 # содержимое Certificate = SEQ SEQUENCE
    tbs, _ = _tlv_slice(body, 0)
    return tbs


def _spki_from_cert(cert_der: bytes) -> bytes:
    """DER SubjectPublicKeyInfo из сырого сертификата (без asn1crypto)."""
    tbs = _tbs_from_cert(cert_der)
    _, body, _ = _read_tlv(tbs, 0)                      # содержимое SEQUENCE tbsCertificate
    first_tag, _, nxt = _read_tlv(body, 0)
    pos = nxt if first_tag == 0xA0 else 0               # version [0] EXPLICIT — пропустить
    fields = []
    while pos < len(body):
        _, _, nxt = _read_tlv(body, pos)
        fields.append(body[pos:nxt])
        pos = nxt
    # после version: serial, signature, issuer, validity, subject, spki[, extensions]
    return fields[5] if len(fields) >= 6 else fields[-1]


def _spki_key_params(spki_der: bytes) -> bytes:
    """DER параметров алгоритма ключа из SubjectPublicKeyInfo (KeyParams)."""
    _, body, _ = _read_tlv(spki_der, 0)
    alg_body = _read_tlv(body, 0)[1]
    params = _read_tlv(alg_body, _read_tlv(alg_body, 0)[2])[1]
    return params


def _legacy_curve_of(cert_der: bytes) -> dict:
    """
    Параметры кривой 34.10-2001 по сертификату: KeyParams -> OID набора параметров.

    Для устаревших сертификатов НУЦ РК поле KeyParams = SEQUENCE { curveOID, digestOID }.
    Неизвестный набор параметров — это UnsupportedAlgorithm (цепочка его обрабатывает),
    а не «упали с исключением на мусоре».
    """
    spki = _spki_from_cert(cert_der)
    params = _spki_key_params(spki)
    try:
        curve_oid = _oid_dotted(_read_tlv(params, 0)[1])
    except (ValueError, IndexError) as ex:
        raise UnsupportedAlgorithm(f"не разобраны параметры ключа: {ex}") from ex
    try:
        return curve_by_oid(curve_oid)
    except ValueError as ex:
        raise UnsupportedAlgorithm(str(ex)) from ex


def certificate_eku(cert_der: bytes) -> set:
    """Набор Extended Key Usage сертификата (имена asn1crypto); пусто, если расширения нет."""
    cert = load_certificate(cert_der)
    ext = _extension(cert, "extended_key_usage")
    if ext is None:
        return set()
    return set(_parsed_native(ext) or [])


def spki_public_key_bits(spki_der: bytes) -> bytes:
    """
    Содержимое BIT STRING открытого ключа (без байта unused bits).

    Именно эти байты RFC 6960 предписывает хэшировать в issuerKeyHash запроса OCSP
    (а не весь SubjectPublicKeyInfo).
    """
    _, body, _ = _read_tlv(spki_der, 0)
    _, _, off1 = _read_tlv(body, 0)                     # AlgorithmIdentifier
    tag2, bits_field, _ = _read_tlv(body, off1)
    if tag2 != 0x03:
        raise ValueError("ожидался BIT STRING в SubjectPublicKeyInfo")
    return bits_field[1:]


def verify_certificate(cert_der: bytes, issuer_der: bytes) -> bool:
    """
    Проверяет подпись сертификата cert_der открытым ключом issuer_der (ГОСТ 2015, устаревший
    ГОСТ 34.10-2001 или RSA).

    Негодные по криптографии данные (в т.ч. подпись не той длины, ключ не из набора
    параметров) — это ``False``. Неразбираемый DER (совсем не сертификат) — ``ValueError``:
    это ошибка вызывающего; политические обёртки (``verify_certificate_chain``,
    ``verify_cms``) такие входы сами превращают в отказ.
    """
    cert = load_certificate(cert_der)
    algo = cert["signature_algorithm"]["algorithm"].dotted
    sig = bytes(cert["signature_value"].native)
    tbs_der = _tbs_from_cert(cert_der)

    if algo in RSA_SIG_ALGS:
        return verify_rsa(issuer_der, tbs_der, sig, RSA_SIG_ALGS[algo])

    if algo in (OID["kz_legacy_sig"], OID["kz_legacy_sig_cert"]):
        try:
            curve = _legacy_curve_of(issuer_der)
            issuer_size, issuer_pk = public_key_from_spki(_spki_from_cert(issuer_der))
            return verify_signature_2001(issuer_pk, gost341194_kz(tbs_der), sig, curve,
                                         "little")
        except (UnsupportedAlgorithm, ValueError):
            return False                        # негодный вход — отказ, а не исключение
    if algo != OID["kz_gost2015_sig"]:
        raise UnsupportedAlgorithm(f"неизвестный алгоритм подписи {algo}")

    size = len(sig) // 2

    issuer = load_certificate(issuer_der)
    issuer_size, issuer_pk = public_key_from_spki(_spki_from_cert(issuer_der))
    if issuer_size != size:
        raise UnsupportedAlgorithm(
            f"размер ключа издателя ({issuer_size}) не совпадает с подписью ({size})")

    return verify_signature(issuer_pk, streebog(tbs_der, size), sig, size)



# --- CMS / PKCS#7 ----------------------------------------------------------

def load_cms(data: bytes) -> cms.ContentInfo:
    """Загружает CMS из DER, PEM или base64-текста."""
    if b"-----BEGIN" in data:
        from asn1crypto import pem
        _, _, der = pem.unarmor(data)
    elif data[:1] == b"\x30":                 # уже DER (SEQUENCE)
        der = data
    else:
        import base64
        import re
        der = base64.b64decode(re.sub(rb"[^A-Za-z0-9+/=]", b"", data))
    return cms.ContentInfo.load(der)


def _signer_certificate(certs, si):
    """Сопоставляет сертификат подписанту по IssuerAndSerialNumber."""
    sid = si["sid"]
    if sid.name != "issuer_and_serial_number":
        return certs[0] if certs else None
    serial = sid.chosen["serial_number"].native
    issuer_der = sid.chosen["issuer"].dump()
    for c in certs:
        tbs = c["tbs_certificate"]
        if tbs["serial_number"].native != serial:
            continue
        if tbs["issuer"].dump() == issuer_der:
            return c
    candidates = [c for c in certs
                  if c["tbs_certificate"]["serial_number"].native == serial]
    if len(candidates) == 1:                          # запасной вариант: только если кандидат один
        return candidates[0]
    return certs[0] if certs else None


def _extension(cert, name: str):
    """Расширение сертификата по имени (basic_constraints/key_usage) либо None."""
    exts = cert["tbs_certificate"]["extensions"]
    if not exts:
        return None
    for ext in exts:
        if ext["extn_id"].native == name:
            return ext
    return None


def _parsed_native(ext):
    """Значение расширения в «нативном» виде (asn1crypto отдаёт объект или dict/set)."""
    parsed = ext["extn_value"].parsed
    return parsed.native if hasattr(parsed, "native") else parsed


def _is_ca(cert):
    """(это ли УЦ, path_len_constraint) по BasicConstraints.

    Отсутствие расширения означает «не УЦ»: сертификат обычного пользователя не
    может выпускать другие сертификаты (именно это проверяет KalkanCrypt.dll).
    """
    ext = _extension(cert, "basic_constraints")
    if ext is None:
        return False, None
    parsed = _parsed_native(ext) or {}
    return bool(parsed.get("ca", False)), parsed.get("path_len_constraint")


def _key_cert_sign_allowed(cert) -> bool:
    """Если keyUsage задан, в нём должен быть keyCertSign."""
    ext = _extension(cert, "key_usage")
    if ext is None:
        return True                                     # расширения нет — не ограничиваем
    return "key_cert_sign" in set(_parsed_native(ext) or [])


def _as_utc(moment):
    """Наивное время трактуем как UTC (в сертификатах время всегда с зоной)."""
    if moment is None:
        return None
    return moment.replace(tzinfo=timezone.utc) if moment.tzinfo is None else moment


def _valid_at(cert, moment) -> bool:
    validity = cert["tbs_certificate"]["validity"]
    return validity["not_before"].native <= moment <= validity["not_after"].native


def _chain_ok(cert, certs, anchor_der: bytes, check_time=None) -> bool:
    """
    Строит цепочку cert → … → trust anchor и проверяет её полноценно:
    подписи звеньев, признак УЦ (BasicConstraints/keyUsage), path len и сроки.
    """
    anchor = load_certificate(anchor_der)
    anchor_subject = anchor["tbs_certificate"]["subject"].dump()

    chain = [(cert, _raw_der(cert))]
    current = cert
    for _ in range(len(certs) + 2):
        issuer_dn = current["tbs_certificate"]["issuer"].dump()
        if issuer_dn == anchor_subject:
            break
        nxt = next((c for c in certs
                    if c["tbs_certificate"]["subject"].dump() == issuer_dn), None)
        if nxt is None or any(nxt is node for node, _ in chain):
            return False
        chain.append((nxt, _raw_der(nxt)))
        current = nxt

    moment = _as_utc(check_time) or datetime.now(timezone.utc)

    for node, _ in chain + [(anchor, anchor_der)]:      # сроки действия всех звеньев
        if not _valid_at(node, moment):
            return False

    for i in range(1, len(chain)):                      # каждый издатель обязан быть УЦ
        node = chain[i][0]
        ca, path_len = _is_ca(node)
        if not ca or not _key_cert_sign_allowed(node):
            return False
        if path_len is not None and (i - 1) > path_len:
            return False

    anchor_ca, anchor_path_len = _is_ca(anchor)          # pathLen доверенного корня
    if anchor_ca and anchor_path_len is not None and (len(chain) - 1) > anchor_path_len:
        return False

    for i, (node, node_der) in enumerate(chain):
        issuer_der = chain[i + 1][1] if i + 1 < len(chain) else anchor_der
        try:
            if not verify_certificate(node_der, issuer_der):
                return False
        except UnsupportedAlgorithm:
            return False
    return True


def _signed_attrs_analysis(signed_attrs, content, digest_func, econtent_type):
    """
    Разбор подписанных атрибутов по RFC 5652 (§5.3 — обязательные атрибуты,
    §11.2 — уникальность имён).

    Возвращает (проблема, digest_ok):
      * проблема — None | "no_signed_attrs" | "bad_signed_attrs";
      * digest_ok — True/False/None (None, если message-digest не найден).

    Отказ, а не «прочитали первое похожее значение»: повтор имени атрибута,
    несколько значений message-digest, отсутствие или несовпадение content-type
    с типом содержимого — всё это признак неоднозначного CMS.
    """
    if signed_attrs is None or len(signed_attrs) == 0:
        return "no_signed_attrs", None
    seen = set()
    for attr in signed_attrs:
        oid = attr["type"].dotted
        if oid in seen:
            return "bad_signed_attrs", None          # §11.2: имя атрибута не повторяется
        seen.add(oid)
    md_attr = _attr_by_oid(signed_attrs, OID["cms_message_digest"])
    ct_attr = _attr_by_oid(signed_attrs, OID["cms_content_type"])
    if md_attr is None or ct_attr is None:
        return "bad_signed_attrs", None              # §5.3: оба атрибута обязательны
    if len(md_attr["values"]) != 1 or len(ct_attr["values"]) != 1:
        return "bad_signed_attrs", None
    declared = ct_attr["values"][0]
    declared_oid = getattr(declared, "dotted", None) or str(declared.native)
    if declared_oid != econtent_type:
        return "bad_signed_attrs", None              # content-type ≠ тип содержимого
    md = bytes(md_attr["values"][0].native)
    return None, md == digest_func(content)


def _attr_by_oid(attrs, oid: str):
    """Атрибут по OID либо None."""
    for attr in attrs:
        if attr["type"].dotted == oid:
            return attr
    return None


def _verify_one_signer(si, certs, content, econtent_type, trust_anchor_der, check_time):
    """
    Проверка одного SignerInfo. Возвращает словарь результата.

    Исключения наружу не выпускаются: вызывающий ловит их и помечает подписанта
    состоянием «error», чтобы один негодный подписант не рушил весь разбор CMS.
    """
    digest_oid = si["digest_algorithm"]["algorithm"].dotted
    sig_oid = si["signature_algorithm"]["algorithm"].dotted
    signer = {"digest_oid": digest_oid, "signature_oid": sig_oid,
              "digest_ok": None, "signature_ok": None,
              "chain_ok": None, "time_ok": None, "state": "unknown"}

    legacy = (digest_oid == OID["kz_legacy_hash"]
              or sig_oid in (OID["kz_legacy_sig"], OID["kz_legacy_sig_cert"]))
    sig = bytes(si["signature"].native)
    cert_der = None
    key_oid = None
    hash_name = None

    # 1) проверка OID и подготовка функции хэша (от неё зависит разбор атрибутов)
    if legacy:
        if digest_oid != OID["kz_legacy_hash"] or sig_oid not in (
                OID["kz_legacy_sig"], OID["kz_legacy_sig_cert"]):
            signer["state"] = "unsupported_oid"
            return signer
        digest_func = gost341194_kz
    else:
        cert_probe = _signer_certificate(certs, si)
        if cert_probe is not None:
            cert_der = _raw_der(cert_probe)
            key_oid = spki_algorithm_oid(_spki_from_cert(cert_der))
        if key_oid == OID_RSA:
            # signatureAlgorithm может быть как конкретным (sha256WithRSA…), так и
            # rsaEncryption — тогда хеш берётся из digestAlgorithm (встречается в
            # контейнерах НУЦ, см. ZipCon-образец SDK)
            hash_name = RSA_SIG_ALGS.get(sig_oid)
            if hash_name is None and sig_oid == OID_RSA:
                hash_name = HASH_BY_OID.get(digest_oid)
            if hash_name is None:
                signer["state"] = "unsupported_oid"
                return signer
            digest_func = lambda data, _h=hash_name: hashlib.new(_h, data).digest()
        else:
            if digest_oid not in (OID["kz_gost2015_hash"], OID["kz_gost2015_hash512"]) \
                    or sig_oid != OID["kz_gost2015_sig"]:
                signer["state"] = "unsupported_oid"
                return signer
            digest_func = lambda data, _s=len(sig) // 2: streebog(data, _s)

    # 2) подписанные атрибуты: обязательные, без повторов (RFC 5652 §5.3/§11.2)
    signed_attrs = si["signed_attrs"]
    has_attrs = signed_attrs is not None and len(signed_attrs) > 0
    if not has_attrs and not legacy:
        signer["state"] = "no_signed_attrs"
        return signer

    set_der = None
    if has_attrs:
        set_der = bytearray(signed_attrs.dump())
        if len(set_der) < 2:
            signer["state"] = "bad_signed_attrs"
            return signer
        set_der[0] = 0x31
        problem, digest_ok = _signed_attrs_analysis(
            signed_attrs, content, digest_func, econtent_type)
        if problem is not None:
            signer["state"] = problem
            return signer
        signer["digest_ok"] = digest_ok

    cert = _signer_certificate(certs, si)
    if cert is None:
        signer["state"] = "no_certificate"
        return signer

    if legacy:
        cert_der = _raw_der(cert)
        try:
            curve = _legacy_curve_of(cert_der)
            _, pk = public_key_from_spki(_spki_from_cert(cert_der))
            payload = bytes(set_der) if set_der is not None else content
            signer["signature_ok"] = verify_signature_2001(
                pk, gost341194_kz(payload), sig, curve, "little")
        except (UnsupportedAlgorithm, ValueError) as ex:
            signer["state"] = f"unsupported_curve: {ex}"
            return signer
    elif key_oid == OID_RSA:
        signer["signature_ok"] = verify_rsa(cert.dump(), bytes(set_der), sig, hash_name)
    else:
        size = len(sig) // 2
        _, pk = public_key_from_spki(_spki_from_cert(_raw_der(cert)))
        signer["signature_ok"] = verify_signature(pk, streebog(bytes(set_der), size),
                                                  sig, size)

    if trust_anchor_der is not None:
        signer["chain_ok"] = _chain_ok(cert, certs, trust_anchor_der, check_time)
    if check_time is not None:
        validity = cert["tbs_certificate"]["validity"]
        signer["time_ok"] = (validity["not_before"].native <= check_time
                             <= validity["not_after"].native)

    ok = (bool(signer["digest_ok"]) and bool(signer["signature_ok"])
          and signer["chain_ok"] is not False and signer["time_ok"] is not False)
    signer["state"] = "ok" if ok else "failed"
    return signer


def verify_cms(cms_bytes: bytes, detached_content: Optional[bytes] = None,
               trust_anchor_der: Optional[bytes] = None,
               check_time=None) -> dict:
    """
    Проверяет подписанное сообщение CMS (SignedData) с ГОСТ 2015.

    По умолчанию — только криптография (digest + подпись). Если задан trust_anchor_der,
    дополнительно строится и проверяется цепочка до него; если задан check_time —
    проверяется срок действия сертификата подписанта. Результаты: chain_ok/time_ok.
    """
    ci = load_cms(cms_bytes)
    if ci["content_type"].dotted != OID["cms_signed_data"]:
        raise UnsupportedAlgorithm("ожидался CMS SignedData (1.2.840.113549.1.7.2)")
    check_time = _as_utc(check_time)                    # наивное время трактуем как UTC
    sd = ci["content"]
    econtent_type = sd["encap_content_info"]["content_type"].dotted

    encap = sd["encap_content_info"]["content"]
    embedded = None
    if encap is not None:
        raw = getattr(encap, "contents", None)          # сырые байты eContent
        if not isinstance(raw, (bytes, bytearray)):
            native = encap.native
            raw = native if isinstance(native, (bytes, bytearray)) else None
        if isinstance(raw, (bytes, bytearray)):
            embedded = bytes(raw)
    content = detached_content if detached_content is not None else embedded
    if content is None:
        content = b""

    certs = [c.chosen for c in sd["certificates"] if c.name == "certificate"] \
        if sd["certificates"] else []
    result = {"content": content, "signers": [],
              "signer_infos": list(sd["signer_infos"]) if sd["signer_infos"] else []}

    for si in sd["signer_infos"]:
        try:
            result["signers"].append(_verify_one_signer(
                si, certs, content, econtent_type, trust_anchor_der, check_time))
        except (ValueError, UnsupportedAlgorithm, IndexError, KeyError, TypeError) as ex:
            result["signers"].append({
                "digest_oid": None, "signature_oid": None, "digest_ok": None,
                "signature_ok": None, "chain_ok": None, "time_ok": None,
                "state": f"error: {type(ex).__name__}"})

    return result


def verify_certificate_chain(chain: list, trust_anchor_der: bytes,
                             check_time=None) -> bool:
    """
    Проверяет цепочку сертификатов до доверенного корня.
    chain[0] — конечный сертификат, далее по возрастанию; последний подписан trust_anchor.

    Кроме подписей проверяются: сроки действия (check_time либо «сейчас»), признак УЦ
    (BasicConstraints CA + keyUsage keyCertSign) у всех издателей и path length.

    Негодный вход (битый DER, чужой алгоритм, отозванная структура) — это отказ
    ``False``: политика доверия не должна падать исключением из-за одного звена.
    """
    try:
        certs = [load_certificate(c) for c in chain]
        anchor = load_certificate(trust_anchor_der)
    except (ValueError, UnsupportedAlgorithm, IndexError, KeyError, TypeError):
        return False
    moment = _as_utc(check_time) or datetime.now(timezone.utc)

    for node in certs + [anchor]:
        if not _valid_at(node, moment):
            return False
    for i in range(1, len(certs)):
        ca, path_len = _is_ca(certs[i])
        if not ca or not _key_cert_sign_allowed(certs[i]):
            return False
        if path_len is not None and (i - 1) > path_len:
            return False

    anchor_ca, anchor_path_len = _is_ca(anchor)          # pathLen доверенного корня
    if anchor_ca and anchor_path_len is not None and (len(certs) - 1) > anchor_path_len:
        return False

    for i, cert_der in enumerate(chain):
        issuer_der = chain[i + 1] if i + 1 < len(chain) else trust_anchor_der
        try:
            if not verify_certificate(cert_der, issuer_der):
                return False
        except (UnsupportedAlgorithm, ValueError, IndexError, KeyError):
            return False                                # чужой OID/негодный вход — не доверено
    return True
