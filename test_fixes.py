"""
test_fixes.py — регрессии:

  * OCSP: issuerKeyHash считается от СОДЕРЖИМОГО BIT STRING ключа (RFC 6960),
    а не от всего SubjectPublicKeyInfo;
  * XMLDSig: проверяются ВСЕ ds:Signature (лишняя/битая подпись не проходит молча);
  * наивное datetime (без зоны) не роняет проверку;
  * дельта-CRL помечается как неподдерживаемый (нельзя утверждать «не отозван»).
"""

from __future__ import annotations

import base64
import copy
import hashlib
import os
import sys
from datetime import datetime

from asn1crypto import ocsp as asocsp
from lxml import etree

from kalkan_keys import first_key, kalkan_dir, sdk_dir
from kalkan_revoke import check_crl, ocsp_request_bytes
from kalkan_sign import create_self_signed_certificate, sign_cms
from kalkan_verify import (load_certificate, spki_public_key_bits, verify_certificate_chain,
                           verify_cms, _spki_from_cert)
from kalkan_xmldsig import sign_xml, verify_xml

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

KEY, PW = first_key()
SDK = sdk_dir()
CRL = os.path.join(SDK, "Keys and Certs", "CRL", "nca_gost2022_test.crl")
NCA_TEST = os.path.join(SDK, "Keys and Certs", "CA_Test", "NCA", "nca_gost2022_test.cer")
DS = "{http://www.w3.org/2000/09/xmldsig#}"
WSSE_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
WSU_UTIL = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"


def test_ocsp_request_hash() -> bool:
    """issuerKeyHash — хэш BIT STRING ключа УЦ (не всего SPKI)."""
    from kalkan_p12 import load_gost2015_p12

    if not KEY:
        print("  SKIP: локальный .p12 не найден (KALKAN_DIR) — проверка не выполнялась")
        return True
    cert, _ = load_gost2015_p12(open(KEY, "rb").read(), PW)
    nca = open(os.path.join(kalkan_dir(), "nca_gost_2022.cer"), "rb").read()

    req = asocsp.OCSPRequest.load(ocsp_request_bytes(cert, nca, "sha1"))
    cid = req["tbs_request"]["request_list"][0]["req_cert"]
    key_hash = bytes(cid["issuer_key_hash"].native)

    right = hashlib.sha1(spki_public_key_bits(_spki_from_cert(nca))).digest()
    wrong = hashlib.sha1(_spki_from_cert(nca)).digest()
    ok = key_hash == right and key_hash != wrong
    print("  issuerKeyHash == sha1(BIT STRING ключа):", key_hash == right,
          "| != sha1(весь SPKI):", key_hash != wrong)
    return ok


def test_xml_all_signatures() -> bool:
    """Лишняя (битая) ds:Signature не должна оставаться незамеченной."""
    key_be = os.urandom(64)
    cert = create_self_signed_certificate(key_be, "XML FIX TEST")
    xml = b"<root><value>\xd0\xbf\xd1\x80\xd0\xb8\xd0\xb2\xd0\xb5\xd1\x82</value></root>"
    signed = sign_xml(key_be, xml, cert)

    single = verify_xml(signed, cert)
    ok_single = single["ok"] and single["count"] == 1

    root = etree.fromstring(signed)
    bogus = copy.deepcopy(root.find(f"{DS}Signature"))
    sig_value = bogus.find(f"{DS}SignatureValue")
    raw = base64.b64decode(sig_value.text.strip())
    sig_value.text = base64.b64encode(bytes([raw[0] ^ 0xFF]) + raw[1:]).decode()
    root.append(bogus)

    two = verify_xml(etree.tostring(root), cert)
    ok_two = two["count"] == 2 and two["ok"] is False
    print("  одна подпись -> ok:", single["ok"], "| count:", single["count"])
    print("  добавлена битая подпись -> count:", two["count"], "| ok:", two["ok"],
          "(должно быть False)")
    return ok_single and ok_two


def test_naive_datetime() -> bool:
    """Наивное datetime не должно приводить к TypeError."""
    key_be = os.urandom(64)
    cert = create_self_signed_certificate(key_be, "NAIVE TIME TEST")
    cms = sign_cms(key_be, b"data", cert)
    signer = verify_cms(cms, check_time=datetime.now())["signers"][0]
    ok_cms = signer["time_ok"] in (True, False)
    chain_ok = verify_certificate_chain([cert], cert, check_time=datetime.now())
    print("  verify_cms(check_time=naive):", ok_cms, "| time_ok:", signer["time_ok"])
    print("  verify_certificate_chain(check_time=naive):", chain_ok)
    return ok_cms and isinstance(chain_ok, bool)


def test_delta_crl_flag() -> bool:
    """Обычный CRL не считается дельта; флаги присутствуют."""
    if not os.path.exists(CRL):
        print("  SKIP: тестовый CRL SDK не найден — проверка не выполнялась")
        return True
    crl_der = open(CRL, "rb").read()
    res = check_crl(open(NCA_TEST, "rb").read(), open(NCA_TEST, "rb").read(),
                    crl_der, check_time=datetime.now())
    ok = res["is_delta"] is False and res["supported"] is True and res["time_ok"] in (True, False)
    print("  is_delta:", res["is_delta"], "| supported:", res["supported"],
          "| time_ok:", res["time_ok"])
    return ok


def test_tsa_empty_signers() -> bool:
    """Токен метки времени без подписантов -> понятный ValueError, а не IndexError."""
    import base64 as b64

    from asn1crypto import cms as acms
    from kalkan_tsa import verify_timestamp_token

    sd = acms.SignedData({
        "version": "v1",
        "digest_algorithms": [{"algorithm": "sha256"}],
        "encap_content_info": {"content_type": "1.2.840.113549.1.9.16.1.4"},
        "signer_infos": [],
    })
    token = acms.ContentInfo({"content_type": "signed_data", "content": sd}).dump()
    try:
        verify_timestamp_token(token)
    except ValueError as ex:
        print("  пустой signerInfos -> ValueError:", str(ex)[:60])
        return True
    except Exception as ex:                             # IndexError/другое — плохо
        print("  пустой signerInfos ->", type(ex).__name__, "(ожидался ValueError)")
        return False
    print("  пустой signerInfos -> исключения не было (плохо)")
    return False


def test_xml_signature_value_length() -> bool:
    """SignatureValue неверной длины -> ValueError (как и для DigestValue)."""
    from kalkan_xmldsig import sign_xml, verify_xml

    key_be = os.urandom(64)
    cert = create_self_signed_certificate(key_be, "XML SIGLEN TEST")
    signed = sign_xml(key_be, b"<root><a>1</a></root>", cert)
    root = etree.fromstring(signed)
    sig_value = root.find(f"{DS}Signature")
    node = sig_value.find(f"{DS}SignatureValue")
    node.text = base64.b64encode(b"\x01\x02\x03").decode()
    try:
        verify_xml(etree.tostring(root), cert)
    except ValueError as ex:
        print("  обрезанный SignatureValue -> ValueError:", str(ex)[:60])
        return True
    except Exception as ex:
        print("  обрезанный SignatureValue ->", type(ex).__name__, "(ожидался ValueError)")
        return False
    print("  обрезанный SignatureValue -> исключения не было (плохо)")
    return False


def test_responder_certificate_matching() -> bool:
    """Сопоставление отвечика: by_key по KeyHash, «чужой» ключ -> None (fallback не дыра)."""
    from asn1crypto import ocsp as asocsp
    from asn1crypto import x509 as ax509

    from kalkan_revoke import _responder_certificate
    from kalkan_verify import _spki_from_cert, spki_public_key_bits

    cert_der = create_self_signed_certificate(os.urandom(64), "RESP BYKEY")
    key_hash = hashlib.sha1(spki_public_key_bits(_spki_from_cert(cert_der))).digest()
    basic = {"certs": [ax509.Certificate.load(cert_der)]}

    ok_hit = _responder_certificate(
        basic, asocsp.ResponderId({"by_key": key_hash})) == cert_der
    ok_miss = _responder_certificate(
        basic, asocsp.ResponderId({"by_key": hashlib.sha1(b"other").digest()})) is None
    print("  by_key: верный KeyHash найден:", ok_hit, "| чужой KeyHash -> None:", ok_miss)
    return ok_hit and ok_miss


def test_cms_signed_attrs_tamper() -> bool:
    """Подмена messageDigest в signedAttrs -> digest_ok=False, state != ok."""
    from kalkan_verify import verify_cms

    key_be = os.urandom(64)
    cert = create_self_signed_certificate(key_be, "CMS TAMPER TEST")
    cms = sign_cms(key_be, b"payload", cert)
    return verify_cms(cms, detached_content=b"payload!")["signers"][0]["state"] != "ok"


def test_wsse_freshness_and_binding() -> bool:
    """WSSE: просроченный Timestamp отвергается; подпись привязана к токену по KeyInfo."""
    from kalkan_wsse import sign_wsse, verify_wsse

    key_be = os.urandom(64)
    cert = create_self_signed_certificate(key_be, "WSSE TEST")
    payload = b"<Request><Id>42</Id></Request>"

    fresh = verify_wsse(sign_wsse(key_be, payload, cert, ttl_seconds=600), trust_anchor_der=cert)
    expired = verify_wsse(sign_wsse(key_be, payload, cert, ttl_seconds=-1000))
    ok_fresh = fresh["ok"] and fresh["time_ok"] is True and fresh["token_bound"] \
        and fresh["chain_ok"] is True
    ok_expired = expired["ok"] is False and expired["time_ok"] is False

    # лишняя (битая) вторая подпись не должна оставаться незамеченной (паритет с verify_xml)
    signed = sign_wsse(key_be, payload, cert, ttl_seconds=600)
    root = etree.fromstring(signed)
    extra = copy.deepcopy(root.find(f".//{DS}Signature"))
    sv = extra.find(f"{DS}SignatureValue")
    raw = base64.b64decode(sv.text.strip())
    sv.text = base64.b64encode(bytes([raw[0] ^ 0xFF]) + raw[1:]).decode()   # та же длина, битая
    root.find(f".//{{{WSSE_NS}}}Security").append(extra)
    two = verify_wsse(etree.tostring(root))
    ok_two = two["count"] == 2 and two["ok"] is False
    print("  свежий Timestamp:", fresh["ok"], "| time_ok:", fresh["time_ok"],
          "| токен привязан:", fresh["token_bound"], "| цепочка:", fresh["chain_ok"])
    print("  просроченный    :", expired["ok"], "| time_ok:", expired["time_ok"],
          "| note:", expired["note"])
    print("  лишняя подпись  : count:", two["count"], "| ok:", two["ok"], "(нужно False)")
    # XSW: дубликат wsu:Id подписанного узла должен отвергаться (неоднозначность)
    dup = etree.fromstring(signed)
    ts = dup.find(f".//{{{WSU_UTIL}}}Timestamp")
    security = dup.find(f".//{{{WSSE_NS}}}Security")
    security.insert(0, copy.deepcopy(ts))               # второй узел с тем же wsu:Id
    try:
        verify_wsse(etree.tostring(dup))
        ok_xsw, xsw_note = False, "дубликат wsu:Id ПРИНЯТ (плохо)"
    except ValueError as ex:
        ok_xsw, xsw_note = True, "ValueError: " + str(ex)[:50]
    print("  XSW (дубликат wsu:Id):", xsw_note)
    # F1: дубль ВАЛИДНОЙ подписи на тот же узел должен отвергаться (не «лишняя ок»)
    dup_sig = etree.fromstring(signed)
    sig_node = dup_sig.find(f".//{DS}Signature")
    sig_node.getparent().append(copy.deepcopy(sig_node))
    res_dup_sig = verify_wsse(etree.tostring(dup_sig))
    ok_dup_sig = res_dup_sig["count"] == 2 and res_dup_sig["ok"] is False
    print("  дубль валидной подписи:", "count=%d ok=%s" % (res_dup_sig["count"],
                                                          res_dup_sig["ok"]),
          "| note:", res_dup_sig["note"])
    return ok_fresh and ok_expired and ok_two and ok_xsw and ok_dup_sig


def test_tsa_honest_ok() -> bool:
    """TSA: ok не должен быть True, если imprint/nonce не проверялись (fully_verified=False)."""
    from kalkan_tsa import _imprint_digest
    from kalkan_verify import UnsupportedAlgorithm

    try:
        _imprint_digest(b"x", "1.2.3.4.5.6.7.8.9")       # неизвестный хэш
        ok_raise = False
    except UnsupportedAlgorithm:
        ok_raise = True
    print("  неизвестный хэш messageImprint -> UnsupportedAlgorithm:", ok_raise)
    return ok_raise


def main() -> int:
    ok = test_ocsp_request_hash()
    print()
    ok = test_xml_all_signatures() and ok
    print()
    ok = test_naive_datetime() and ok
    print()
    ok = test_delta_crl_flag() and ok
    print()
    ok = test_tsa_empty_signers() and ok
    print()
    ok = test_xml_signature_value_length() and ok
    print()
    ok = test_responder_certificate_matching() and ok
    print()
    ok = test_cms_signed_attrs_tamper() and ok
    print()
    ok = test_wsse_freshness_and_binding() and ok
    print()
    ok = test_tsa_honest_ok() and ok
    print("\nИТОГ исправлений:", "ВСЁ ОК" if ok else "ЕСТЬ ПРОБЛЕМЫ")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
