"""
kalkan_revoke.py — проверка отзыва: CRL и OCSP (ГОСТ 2015 или RSA).

CRL: разбор списка, проверка подписи УЦ (ГОСТ/RSA) и наличия серийника.
OCSP: запрос к сервису УЦ (asn1crypto.ocsp), разбор ответа и (при желании) проверка
подписи ответа сертификатом издателя.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional

from asn1crypto import crl as ascrl
from asn1crypto import ocsp as asocsp

from kalkan_verify import (RSA_SIG_ALGS, OID, UnsupportedAlgorithm, _as_utc,
                           _spki_from_cert, certificate_eku, load_certificate,
                           public_key_from_spki, spki_public_key_bits, streebog,
                           verify_certificate, verify_rsa, verify_signature)

__all__ = ["load_crl", "crl_signature_ok", "crl_is_revoked", "check_crl", "ocsp_check",
           "ocsp_request_bytes"]


# --- CRL -------------------------------------------------------------------

def load_crl(data: bytes) -> ascrl.CertificateList:
    if b"-----BEGIN" in data:
        from asn1crypto import pem
        _, _, data = pem.unarmor(data)
    return ascrl.CertificateList.load(data)


def _verify_signed(tbs: bytes, sig: bytes, algo: str, signer_der: bytes) -> bool:
    """Проверяет подпись произвольного объекта (CRL/OCSP) ключом подписанта (ГОСТ или RSA)."""
    if algo in RSA_SIG_ALGS:
        return verify_rsa(signer_der, tbs, sig, RSA_SIG_ALGS[algo])
    if algo == OID["kz_gost2015_sig"]:
        size, pk = public_key_from_spki(_spki_of(signer_der))
        return verify_signature(pk, streebog(tbs, size), sig, size)
    raise UnsupportedAlgorithm(f"подпись списка/ответа не поддержана: {algo}")


def _spki_of(cert_der: bytes) -> bytes:
    """SubjectPublicKeyInfo из сырого сертификата (asn1crypto не знает ГОСТ-OID в SPKI)."""
    from kalkan_verify import _spki_from_cert
    return _spki_from_cert(cert_der)


def crl_signature_ok(crl: ascrl.CertificateList, issuer_der: bytes) -> bool:
    algo = crl["signature_algorithm"]["algorithm"].dotted
    return _verify_signed(crl["tbs_cert_list"].dump(),
                          bytes(crl["signature"].native), algo, issuer_der)


def crl_revoked_serials(crl: ascrl.CertificateList) -> list:
    revoked = crl["tbs_cert_list"]["revoked_certificates"]
    return [rc["user_certificate"].native for rc in (revoked or [])]


def crl_is_revoked(crl: ascrl.CertificateList, serial: int) -> bool:
    return serial in crl_revoked_serials(crl)


def check_crl(cert_der: bytes, issuer_der: bytes, crl_der: bytes,
              check_time=None) -> dict:
    """
    Результат проверки сертификата по CRL: подпись списка, отзыв, сроки действия.

    Дельта-CRL (расширение 2.5.29.27 deltaCRLIndicator) не объединяется с базовым
    списком: результат помечается is_delta=True и supported=False — по такому списку
    «не отозван» утверждать нельзя.
    """
    crl = load_crl(crl_der)
    cert = load_certificate(cert_der)
    serial = cert["tbs_certificate"]["serial_number"].native
    tbs = crl["tbs_cert_list"]

    is_delta = False
    for ext in (tbs["crl_extensions"] or []):
        if ext["extn_id"].dotted == "2.5.29.27":
            is_delta = True

    result = {"signature_ok": crl_signature_ok(crl, issuer_der),
              "revoked": crl_is_revoked(crl, serial),
              "this_update": tbs["this_update"].native,
              "next_update": tbs["next_update"].native if tbs["next_update"] else None,
              "is_delta": is_delta, "supported": not is_delta, "time_ok": None}
    if check_time is not None and result["next_update"] is not None:
        if check_time.tzinfo is None:                   # наивное время трактуем как UTC
            from datetime import timezone
            check_time = check_time.replace(tzinfo=timezone.utc)
        result["time_ok"] = result["this_update"] <= check_time <= result["next_update"]
    return result


# --- OCSP ------------------------------------------------------------------

def _cert_id_components(cert_der: bytes, issuer_der: bytes, hash_name: str) -> dict:
    """Тройка CertID для запроса: хэш имени УЦ, хэш КЛЮЧА УЦ и серийный номер."""
    cert = load_certificate(cert_der)
    issuer = load_certificate(issuer_der)
    return {
        "hash_oid": _hash_oid(hash_name),
        "name_hash": _digest(issuer["tbs_certificate"]["subject"].dump(), hash_name),
        # RFC 6960: issuerKeyHash — хэш СОДЕРЖИМОГО BIT STRING открытого ключа,
        # а не всего SubjectPublicKeyInfo (иначе отвечик отвечает «unknown»)
        "key_hash": _digest(spki_public_key_bits(_spki_of(issuer_der)), hash_name),
        "serial": cert["tbs_certificate"]["serial_number"].native,
    }


def ocsp_request_bytes(cert_der: bytes, issuer_der: bytes,
                       hash_name: str = "sha1") -> bytes:
    """DER OCSPRequest для сертификата (issuerNameHash/issuerKeyHash по RFC 6960)."""
    parts = _cert_id_components(cert_der, issuer_der, hash_name)
    cert_id = asocsp.CertId({
        "hash_algorithm": {"algorithm": parts["hash_oid"]},
        "issuer_name_hash": parts["name_hash"],
        "issuer_key_hash": parts["key_hash"],
        "serial_number": parts["serial"],
    })
    return asocsp.OCSPRequest({
        "tbs_request": {"request_list": [{"req_cert": cert_id}]}
    }).dump()


def _name_key(name) -> list:
    """
    Канонический ключ имени для сопоставления: набор (OID атрибута, значение).

    Порядок RDN и тип строки (PrintableString/UTF8String) не важны — у реального
    отвечика НУЦ DN в responder_id и в сертификате побайтово НЕ совпадают.
    """
    items = []
    for rdn in name.chosen:
        for ava in rdn:
            value = ava["value"].native
            if isinstance(value, str):
                value = " ".join(value.split()).lower()
            items.append((ava["type"].dotted, value))
    return sorted(items, key=lambda pair: (pair[0], str(pair[1])))


def _responder_certificate(basic, responder_id):
    """
    DER сертификата отвечика из ответа.

    Порядок поиска: точное совпадение имени -> каноническое (порядок/тип строки не важны)
    -> по KeyHash (sha1 от содержимого BIT STRING ключа) -> единственный сертификат
    с EKU OCSP Signing. Если ничего не подошло — None (подпись будет проверяться ключом
    УЦ и, скорее всего, не сойдётся: «первый попавшийся» сертификат не берём).
    """
    from kalkan_verify import _raw_der
    entries = basic["certs"] if basic["certs"] else []
    # в OCSP это SEQUENCE OF Certificate (без CHOICE), в CMS — CHOICE certificate/other
    certs = [e.chosen if hasattr(e, "chosen") else e for e in entries]
    if not certs:
        return None

    if responder_id.name == "by_name":
        want_name = responder_id.chosen
        for c in certs:
            if c["tbs_certificate"]["subject"].dump() == want_name.dump():
                return _raw_der(c)                       # точное совпадение
        want_key = _name_key(want_name)
        for c in certs:
            if _name_key(c["tbs_certificate"]["subject"]) == want_key:
                return _raw_der(c)                       # семантическое совпадение
    elif responder_id.name == "by_key":
        want = bytes(responder_id.chosen.native)
        for c in certs:
            try:
                have = hashlib.sha1(
                    spki_public_key_bits(_spki_from_cert(_raw_der(c)))).digest()
            except (ValueError, UnsupportedAlgorithm):
                continue                                # сомнительный сертификат — пропускаем
            if want == have:
                return _raw_der(c)

    ocsp_signers = [c for c in certs if _has_ocsp_eku(c)]   # единственный OCSP-подписант
    if len(certs) == 1 and ocsp_signers:
        return _raw_der(certs[0])
    return None


def _has_ocsp_eku(cert) -> bool:
    exts = cert["tbs_certificate"]["extensions"]
    for ext in (exts or []):
        if ext["extn_id"].native == "extended_key_usage":
            parsed = ext["extn_value"].parsed
            names = parsed.native if hasattr(parsed, "native") else parsed
            return "ocsp_signing" in set(names or [])
    return False


def _hash_oid(name: str) -> str:
    return {"sha1": "1.3.14.3.2.26", "sha256": "2.16.840.1.101.3.4.2.1",
            "sha384": "2.16.840.1.101.3.4.2.2", "sha512": "2.16.840.1.101.3.4.2.3",
            "streebog256": "1.2.398.3.10.1.1.2.2.1",
            "streebog512": "1.2.398.3.10.1.3.3"}[name]


def _digest(data: bytes, hash_name: str) -> bytes:
    if hash_name == "streebog256":
        return streebog(data, 32)
    if hash_name == "streebog512":
        return streebog(data, 64)
    import hashlib
    return hashlib.new(hash_name, data).digest()


def ocsp_check(cert_der: bytes, issuer_der: bytes, url: str,
               hash_name: str = "sha1", timeout: int = 15,
               verify_signature_response: bool = False) -> dict:
    """Отправляет OCSP-запрос и разбирает ответ. status: good/revoked/unknown."""
    import urllib.request

    request = ocsp_request_bytes(cert_der, issuer_der, hash_name)
    http = urllib.request.Request(url, data=request,
                                  headers={"Content-Type": "application/ocsp-request"},
                                  method="POST")
    with urllib.request.urlopen(http, timeout=timeout) as response:
        body = response.read()
    parts = _cert_id_components(cert_der, issuer_der, hash_name)
    return ocsp_parse_response(body, parts, issuer_der, verify_signature_response)


def ocsp_parse_response(body: bytes, parts: dict, issuer_der: bytes,
                        verify_signature: bool = False) -> dict:
    """
    Разбор (и опционально проверка) OCSP-ответа для уже известного CertID.

    Ответ принимается только если в нём есть SingleResponse ИМЕННО запрошенного
    сертификата (серийник + хэши имени и ключа УЦ совпали); подпись ответа
    проверяется сертификатом отвечика (из ответа), если он вложен, иначе ключом УЦ.
    """
    resp = asocsp.OCSPResponse.load(body)
    result = {"response_status": resp["response_status"].native, "status": None,
              "status_trusted": False, "fresh": None, "this_update": None,
              "produced_at": None, "next_update": None, "signature_ok": None,
              "responder": None, "responder_trusted": None, "responder_ocsp_eku": None,
              "note": None}
    if result["response_status"] != "successful":
        return result

    basic = resp["response_bytes"]["response"].parsed
    tbs = basic["tbs_response_data"]
    result["produced_at"] = tbs["produced_at"].native

    single = None
    for candidate in tbs["responses"]:
        cid = candidate["cert_id"]
        if (cid["serial_number"].native == parts["serial"]
                and cid["hash_algorithm"]["algorithm"].dotted == parts["hash_oid"]
                and bytes(cid["issuer_name_hash"].native) == parts["name_hash"]
                and bytes(cid["issuer_key_hash"].native) == parts["key_hash"]):
            single = candidate
            break
    if single is None:
        result["note"] = "в ответе нет SingleResponse для запрошенного сертификата"
        return result

    cert_status = single["cert_status"]
    result["status"] = cert_status.name
    if cert_status.name == "revoked":
        result["revocation_time"] = cert_status.chosen["revocation_time"].native
    result["this_update"] = single["this_update"].native
    if single["next_update"]:
        result["next_update"] = single["next_update"].native

    if verify_signature:
        algo = basic["signature_algorithm"]["algorithm"].dotted
        signer_der = _responder_certificate(basic, tbs["responder_id"])
        # RFC 6960: если ответ подписан самим УЦ, EKU OCSP Signing не требуется
        if signer_der is None or signer_der == issuer_der:
            signer_der, result["responder"] = issuer_der, "issuer"
        else:
            result["responder"] = "responder-certificate"
        result["signature_ok"] = _verify_signed(tbs.dump(),
                                                bytes(basic["signature"].native),
                                                algo, signer_der)

        reasons = []
        if not result["signature_ok"]:
            reasons.append("подпись ответа не подтверждена")
        if result["responder"] == "responder-certificate":
            try:
                result["responder_trusted"] = verify_certificate(signer_der, issuer_der)
            except Exception:
                result["responder_trusted"] = False
            if result["responder_trusted"] is not True:
                reasons.append("сертификат отвечика не доверен УЦ")
            # делегированный отвечик обязан иметь EKU id-kp-OCSPSigning
            try:
                has_ocsp_eku = "ocsp_signing" in certificate_eku(signer_der)
            except Exception:
                has_ocsp_eku = False
            result["responder_ocsp_eku"] = has_ocsp_eku
            if not has_ocsp_eku:
                reasons.append("у сертификата отвечика нет EKU OCSP Signing")

        fresh, fresh_note = _response_freshness(result)   # свежесть ответа (анти-replay)
        result["fresh"] = fresh
        if not fresh:
            reasons.append(fresh_note)

        result["status_trusted"] = not reasons
        if reasons:
            result["note"] = "; ".join(reasons) + " — статус не подтверждён"
            result["status"] = None
    else:
        result["note"] = "подпись ответа не проверялась (verify_signature_response=False)"
    return result


def _response_freshness(result: dict) -> tuple:
    """Свежесть ответа OCSP: this_update <= now <= next_update (с допуском 5 минут)."""
    now = datetime.now(timezone.utc)
    skew = timedelta(minutes=5)
    this_update, next_update = result.get("this_update"), result.get("next_update")
    if this_update is not None and _as_utc(this_update) > now + skew:
        return False, "this_update ответа OCSP в будущем"
    if next_update is not None:
        if now > _as_utc(next_update) + skew:
            return False, "ответ OCSP просрочен (next_update в прошлом)"
        return True, None
    produced_at = result.get("produced_at")    # next_update нет — ограничиваем возраст ответа
    if produced_at is None:
        return True, None
    if now > _as_utc(produced_at) + timedelta(hours=24):
        return False, "ответ OCSP старше суток, а next_update не указан"
    return True, None
