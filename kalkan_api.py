"""
kalkan_api.py — фасад, повторяющий поведение SignData/VerifyData из KalkanCryptCOM.

Приводит вход/выход к тем же форматам, что и Калкан, по флагам:
    вход : текст (без флага), KC_IN_BASE64, KC_IN_FILE (путь к файлу), KC_IN_PEM (CMS)
    выход: KC_OUT_DER (сырые/DER), KC_OUT_BASE64, KC_OUT_PEM (CMS: -----BEGIN CMS-----)
    RAW  : KC_SIGN_DRAFT;  CMS: KC_SIGN_CMS (+KC_WITH_CERT, +KC_DETACHED_DATA)

Форматы сверены с настоящим KalkanCrypt.dll:
    RAW  OUT_BASE64 -> base64(128 б); OUT_DER/OUT_PEM -> сырые 128 б;
    CMS  OUT_BASE64 -> base64(DER); OUT_DER -> DER; OUT_PEM -> -----BEGIN CMS----- (строки по 64).

Семантика KC_IN_BASE64 (как у Калкана):
    при подписи  — кодировка ПОДПИСЫВАЕМЫХ данных (data);
    при проверке — кодировка ПОДПИСИ (in_sign), а in_data передаётся как есть.
"""

from __future__ import annotations

import base64
import os
import re
from typing import Optional, Tuple

from kalkan_sign import raw_sign, raw_verify, sign_cms
from kalkan_verify import verify_cms

# флаги (KalkanCryptCOM)
KC_SIGN_DRAFT = 0x1
KC_SIGN_CMS = 0x2
KC_IN_PEM = 0x4
KC_IN_DER = 0x8
KC_IN_BASE64 = 0x10
KC_IN2_BASE64 = 0x20
KC_DETACHED_DATA = 0x40
KC_WITH_CERT = 0x80
KC_OUT_PEM = 0x200
KC_OUT_DER = 0x400
KC_OUT_BASE64 = 0x800
KC_IN_FILE = 0x8000

__all__ = ["sign_data", "verify_data", "KC_SIGN_DRAFT", "KC_SIGN_CMS",
           "KC_IN_BASE64", "KC_IN_FILE", "KC_IN_PEM", "KC_OUT_PEM",
           "KC_OUT_DER", "KC_OUT_BASE64", "KC_DETACHED_DATA", "KC_WITH_CERT"]

_CMS_PEM_RE = re.compile(rb"-----BEGIN CMS-----(.*?)-----END CMS-----", re.S)


def _plain_input(value, flags: int) -> bytes:
    """Вход как есть: путь к файлу при KC_IN_FILE, иначе байты (без base64-декодирования)."""
    if value is None:                                   # None/"" — пустой вход, а не b"None"
        raw = b""
    else:
        raw = value if isinstance(value, bytes) else str(value).encode("utf-8")
    if flags & KC_IN_FILE:
        try:
            with open(raw.decode("utf-8"), "rb") as handle:
                raw = handle.read()
        except OSError as ex:
            raise ValueError(f"KC_IN_FILE: не удалось прочитать файл: {ex}") from ex
    return raw


def _read_input(value, flags: int) -> bytes:
    """Приводит вход (подпись) к байтам: файл (KC_IN_FILE) и/или base64 (KC_IN_BASE64)."""
    raw = _plain_input(value, flags)
    if flags & KC_IN_BASE64:
        raw = base64.b64decode(re.sub(rb"[^A-Za-z0-9+/=]", b"", raw))
    return raw


def _pem_cms(der: bytes) -> bytes:
    b64 = base64.b64encode(der)
    lines = b"\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
    return b"-----BEGIN CMS-----\n" + lines + b"\n-----END CMS-----"


def _parse_pem_cms(value: bytes) -> bytes:
    match = _CMS_PEM_RE.search(value)
    if match:
        return base64.b64decode(re.sub(rb"\s+", b"", match.group(1)))
    return value


def _encode_output(der: bytes, flags: int, is_cms: bool) -> bytes:
    if flags & KC_OUT_BASE64:
        return base64.b64encode(der)
    if is_cms and flags & KC_OUT_PEM:
        return _pem_cms(der)
    return der                                   # OUT_DER / OUT_PEM для RAW — сырые байты


def sign_data(input_data, flags: int, private_key_be: bytes,
              certificate_der: bytes) -> bytes:
    """Аналог KalkanCryptCOM.SignData: возвращает подпись в формате по флагам."""
    if (flags & KC_SIGN_CMS) and (flags & KC_SIGN_DRAFT):
        # у вендора эти режимы взаимоисключающие — молча выбирать CMS нельзя
        raise ValueError("KC_SIGN_CMS и KC_SIGN_DRAFT одновременно недопустимы")
    data = _read_input(input_data, flags)
    if flags & KC_SIGN_CMS:
        der = sign_cms(private_key_be, data, certificate_der,
                       detached=bool(flags & KC_DETACHED_DATA))
        return _encode_output(der, flags, is_cms=True)
    if flags & KC_SIGN_DRAFT:
        return _encode_output(raw_sign(private_key_be, data), flags, is_cms=False)
    raise ValueError("нужен KC_SIGN_DRAFT или KC_SIGN_CMS")


def verify_data(in_data, in_sign, flags: int,
                certificate_der: Optional[bytes] = None) -> dict:
    """
    Аналог KalkanCryptCOM.VerifyData.

    Возвращает {"ok": bool, "state": str, "data": bytes, ...} — data повторяет содержимое
    (для attached CMS) в кодировке KC_OUT_*.
    """
    signature = _read_input(in_sign, flags)
    if flags & KC_IN_PEM:
        signature = _parse_pem_cms(signature)

    if flags & KC_SIGN_CMS:
        detached = bool(flags & KC_DETACHED_DATA)
        content_in = _plain_input(in_data, flags) if detached else None
        result = verify_cms(signature, detached_content=content_in)
        signers = result["signers"]
        if not signers:
            return {"ok": False, "state": "no_signers", "data": result.get("content", b"")}
        signer = signers[0]
        content = result["content"]
        if content and (flags & KC_OUT_BASE64):
            content = base64.b64encode(content)
        return {"ok": signer["state"] == "ok", "state": signer["state"],
                "digest_ok": signer["digest_ok"], "signature_ok": signer["signature_ok"],
                "data": content}

    if flags & KC_SIGN_DRAFT:
        data = _plain_input(in_data, flags) if in_data not in (None, "", b"") else b""
        if certificate_der is None:
            raise ValueError("для проверки RAW нужен сертификат (certificate_der)")
        ok = raw_verify(signature, data, certificate_der)
        return {"ok": ok, "state": "ok" if ok else "failed",
                "signature_ok": ok, "data": b""}

    raise ValueError("нужен KC_SIGN_DRAFT или KC_SIGN_CMS")


def sign_xml(xml_bytes, private_key_be: bytes, certificate_der: bytes) -> bytes:
    """
    Аналог SignXML: enveloped-XMLDSig (ГОСТ 2015). Возвращает подписанный XML (bytes).

    Алгоритмы совпадают с KalkanCrypt.dll: #gost34311 (хэш) и #gost34310-gost34311 (подпись).
    """
    from kalkan_xmldsig import sign_xml as _sign_xml
    data = xml_bytes if isinstance(xml_bytes, bytes) else str(xml_bytes).encode("utf-8")
    return _sign_xml(private_key_be, data, certificate_der)


def verify_xml(xml_bytes, certificate_der: bytes = None) -> dict:
    """Аналог VerifyXML: {ok, reference_ok, signature_ok}."""
    from kalkan_xmldsig import verify_xml as _verify_xml
    data = xml_bytes if isinstance(xml_bytes, bytes) else str(xml_bytes).encode("utf-8")
    res = _verify_xml(data, certificate_der)
    return {"ok": bool(res["reference_ok"] and res["signature_ok"]),
            "reference_ok": res["reference_ok"], "signature_ok": res["signature_ok"]}

