"""
kalkan_tsa.py — метки времени (RFC 3161 / TSA) для КZ-стека, независимо.

Умеет:
  * собрать TimeStampReq (SHA-256 или ГОСТ Стрибог-256);
  * отправить его на TSA (по умолчанию http://tsp.pki.gov.kz);
  * разобрать TimeStampResp и достать время подписи (genTime) и сам токен.

Проверка цепочки TSA-токена делается тем же ГОСТ-ядром (kalkan_verify).

ВНИМАНИЕ: здесь токен только ПОЛУЧАЕТСЯ и РАЗБИРАЕТСЯ (genTime/serial/policy).
Криптографически токен не проверяется (подпись TSA, messageImprint, nonce),
поэтому genTime нельзя считать доверенным без отдельной проверки.
"""

from __future__ import annotations

import hashlib
import os
import urllib.request
from typing import Optional, Tuple

from asn1crypto import algos, cms, core, tsp

from kalkan_verify import (UnsupportedAlgorithm, load_certificate, streebog, verify_certificate,
                           verify_cms)

DEFAULT_TSA_URL = "http://tsp.pki.gov.kz"

# OID хэшей
OID_SHA256 = "2.16.840.1.101.3.4.2.1"
OID_GOST2015_HASH = "1.2.398.3.10.1.1.2.2.1"   # хэш ГОСТ Р 34.11-2015 (НУЦ РК)
OID_TC26_HASH_256 = "1.2.643.7.1.1.2.2"


def _digest(data: bytes, hash_name: str) -> Tuple[str, bytes]:
    if hash_name == "sha256":
        return OID_SHA256, hashlib.sha256(data).digest()
    if hash_name in ("gost", "streebog256"):
        return OID_GOST2015_HASH, streebog(data, 32)
    raise ValueError(f"неподдержанный хэш: {hash_name}")


def build_timestamp_request(data: bytes, hash_name: str = "sha256",
                            nonce: Optional[int] = None) -> bytes:
    """Строит DER запроса RFC 3161 для данных data."""
    oid, digest = _digest(data, hash_name)
    if nonce is None:
        nonce = int.from_bytes(os.urandom(8), "big")
    request = tsp.TimeStampReq({
        "version": 1,
        "message_imprint": tsp.MessageImprint({
            "hash_algorithm": algos.DigestAlgorithm({"algorithm": oid}),
            "hashed_message": digest,
        }),
        "nonce": core.Integer(nonce),
        "cert_req": True,
    })
    return request.dump()


def parse_timestamp_response(response_der: bytes) -> dict:
    """Разбирает TimeStampResp: статус, время (genTime), токен (DER)."""
    resp = tsp.TimeStampResp.load(response_der)
    result = {"status": resp["status"]["status"].native,
              "gen_time": None, "token_der": None}
    try:
        token = resp["time_stamp_token"]
        token_der = token.dump()
    except Exception:
        return result
    if not token_der:
        return result
    result["token_der"] = token_der
    try:
        content_info = cms.ContentInfo.load(token_der)
        signed_data = content_info["content"]
        econtent = signed_data["encap_content_info"]["content"]
        raw = getattr(econtent, "contents", None) or econtent.native
        tst_info = tsp.TSTInfo.load(bytes(raw))
        result["gen_time"] = tst_info["gen_time"].native
        result["serial_number"] = tst_info["serial_number"].native
        result["policy"] = tst_info["policy"].native
    except Exception as ex:
        result["parse_error"] = str(ex)
    return result


def get_timestamp(data: bytes, url: str = DEFAULT_TSA_URL,
                  hash_name: str = "sha256", timeout: int = 15) -> dict:
    """Отправляет запрос на TSA и возвращает разобранный ответ (с nonce запроса)."""
    nonce = int.from_bytes(os.urandom(8), "big")
    request = build_timestamp_request(data, hash_name, nonce=nonce)
    req = urllib.request.Request(
        url, data=request,
        headers={"Content-Type": "application/timestamp-query"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read()
    out = parse_timestamp_response(body)
    out["response_der"] = body
    out["nonce"] = nonce
    return out


# --- проверка токена метки времени ----------------------------------------

_IMPRINT_HASHES = {
    OID_SHA256: ("sha256", None),
    "1.3.14.3.2.26": ("sha1", None),
    OID_GOST2015_HASH: ("streebog256", None),
    "1.2.398.3.10.1.3.3": ("streebog512", None),
}


def _imprint_digest(data: bytes, alg_oid: str) -> bytes:
    """Даёт хэш messageImprint. Неизвестный алгоритм — не угадываем, а отвергаем."""
    if alg_oid not in _IMPRINT_HASHES:
        raise UnsupportedAlgorithm(f"хэш messageImprint не поддержан: {alg_oid}")
    name = _IMPRINT_HASHES[alg_oid][0]
    if name == "streebog256":
        return streebog(data, 32)
    if name == "streebog512":
        return streebog(data, 64)
    return hashlib.new(name, data).digest()


def verify_timestamp_token(token_der: bytes, original_data: Optional[bytes] = None,
                           nonce: Optional[int] = None,
                           trust_anchor_der: Optional[bytes] = None) -> dict:
    """
    Проверяет метку времени (RFC 3161 TimeStampToken = CMS SignedData с TSTInfo).

    Токен проверяется тем же ядром (verify_cms: подпись TSA + digestSignedAttrs),
    затем сверяются messageImprint (с original_data), nonce и EKU=timeStamping;
    при заданном trust_anchor_der — цепочка сертификата TSA.

    Честность результата: `ok` истинно только по ФАКТИЧЕСКИ выполненным проверкам, а
    `fully_verified` истинно лишь если проверены imprint И nonce И цепочка (с учётом того,
    что для цепочки нужен trust_anchor_der). В `unverified` перечислено, что не проверялось,
    чтобы «ok=True» нельзя было прочитать как «токен полностью подтверждён».
    """
    cms_result = verify_cms(token_der)
    if not cms_result["signers"]:
        raise ValueError("токен метки времени без подписантов (signerInfos пуст)")
    signer = cms_result["signers"][0]

    ci = cms.ContentInfo.load(token_der)
    encap = ci["content"]["encap_content_info"]["content"]
    tst_info = tsp.TSTInfo.load(bytes(encap.contents))

    imprint = tst_info["message_imprint"]
    imprint_alg = imprint["hash_algorithm"]["algorithm"].dotted
    imprint_ok = None
    if original_data is not None:
        imprint_ok = bytes(imprint["hashed_message"].native) == \
            _imprint_digest(original_data, imprint_alg)

    nonce_ok = None
    token_nonce = tst_info["nonce"].native if "nonce" in tst_info.native else None
    if nonce is not None:
        nonce_ok = (token_nonce == nonce)

    signer_certs = ci["content"]["certificates"]
    cert_der = None
    if signer_certs:
        from kalkan_verify import _raw_der, _signer_certificate
        certs = [c.chosen if hasattr(c, "chosen") else c for c in signer_certs]
        matched = _signer_certificate(certs, cms_result["signer_infos"][0]) \
            if cms_result.get("signer_infos") else None
        cert_der = _raw_der(matched if matched is not None else certs[0])

    eku_ok = None
    chain_ok = None
    if cert_der is not None:
        from kalkan_certprop import KC_CERTPROP_EXT_KEY_USAGE, get_cert_info
        eku_ok = "1.3.6.1.5.5.7.3.8" in get_cert_info(cert_der, KC_CERTPROP_EXT_KEY_USAGE)
        if trust_anchor_der is not None:
            chain_result = verify_cms(token_der, trust_anchor_der=trust_anchor_der)
            chain_ok = chain_result["signers"][0]["chain_ok"]

    ok = (signer["state"] == "ok" and imprint_ok is not False
          and nonce_ok is not False and eku_ok is not False and chain_ok is not False)

    unverified = []
    if imprint_ok is None:
        unverified.append("messageImprint не сверен (не переданы original_data)")
    if nonce_ok is None:
        unverified.append("nonce не сверен (не передан nonce)")
    if chain_ok is None:
        unverified.append("цепочка сертификата TSA не проверена (нет trust_anchor_der)")
    if eku_ok is None:
        unverified.append("EKU timeStamping не проверен (нет сертификата в токене)")
    if len(cms_result["signers"]) > 1:                  # враждебный/нештатный токен
        unverified.append(f"в токене {len(cms_result['signers'])} подписантов — проверен первый")

    return {"ok": ok, "fully_verified": ok and not unverified,
            "unverified": unverified,
            "signature_ok": signer["signature_ok"], "digest_ok": signer["digest_ok"],
            "gen_time": tst_info["gen_time"].native, "policy": tst_info["policy"].native,
            "imprint_ok": imprint_ok, "nonce_ok": nonce_ok, "eku_time_stamping": eku_ok,
            "chain_ok": chain_ok, "certificate_der": cert_der}

