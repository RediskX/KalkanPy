"""
cross_check_wsse.py — сверка WSSE с настоящим KalkanCrypt.dll.

У вендора есть только `SignWSSE` (метода VerifyWSSE в интерфейсе нет), поэтому:

  A) DLL SignWSSE (ГОСТ 2015-512) -> наш verify_wsse  — основная сверка;
  A-neg) подделка подписанного узла / подписи -> наш verify_wsse обязан отвергнуть;
  B) наш sign_wsse -> DLL — VerifyWSSE отсутствует; пробуем VerifyXML и фиксируем факт.

Вендор подписывает узел с заданным wsu:Id, канонизация — exc-c14n с
InclusiveNamespaces, сертификат вкладывает в wsse:KeyIdentifier (не в
BinarySecurityToken). Наш верификатор поддерживает оба варианта.
"""

from __future__ import annotations

import base64
import copy
import os

from lxml import etree

try:                                     # консоль Windows бывает cp1251 — не роняем прогон
    import sys as _sys
    _sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from kalkan_dll import KC_CERT_CA, KC_CERT_INTERMEDIATE, KalkanOracle
from kalkan_keys import first_key, kalkan_dir, mask_pii, roots
from kalkan_wsse import sign_wsse, verify_wsse

KEY, PW = first_key()
ROOT, NCA = roots()
DS = "{http://www.w3.org/2000/09/xmldsig#}"

TEMPLATE = b"""<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
 <SOAP-ENV:Header>
  <wsse:Security xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" SOAP-ENV:mustUnderstand="1">
   <wsse:BinarySecurityToken EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509" wsu:Id="x509cert00"></wsse:BinarySecurityToken>
  </wsse:Security>
 </SOAP-ENV:Header>
 <SOAP-ENV:Body xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" wsu:Id="TheBody">
  <getVersion xmlns="http://msgsec.wssecfvt.ws.ibm.com"/>
 </SOAP-ENV:Body>
</SOAP-ENV:Envelope>"""


def _tamper_text(xml: bytes, old: bytes, new: bytes) -> bytes:
    return xml.replace(old, new, 1)


def main() -> int:
    if not KEY:
        print("SKIP: локальный .p12 не найден (задайте KALKAN_DIR) — сверка не выполнялась")
        return 0
    oracle = KalkanOracle()
    oracle.init()
    oracle.load_key_store(PW, KEY, "")
    oracle.load_cert_file(ROOT, KC_CERT_CA)
    oracle.load_cert_file(NCA, KC_CERT_INTERMEDIATE)

    # A) вендор подписывает -> наш верификатор проверяет
    rc_sign, signed = oracle.sign_wsse(TEMPLATE, "TheBody")
    print("A) DLL SignWSSE            : rc=0x%08x, конверт %d байт" % (rc_sign, len(signed)))
    if rc_sign != 0 or not signed:
        print("   SignWSSE не отдал конверт — сверка невозможна")
        oracle.finalize()
        return 1
    signed = signed.rstrip(b"\x00")
    nca_der = open(NCA, "rb").read()
    root_der = open(ROOT, "rb").read()
    res = verify_wsse(signed, trust_anchor_der=nca_der)
    from kalkan_verify import verify_certificate_chain
    full_chain_ok = verify_certificate_chain([res["certificate_der"], nca_der], root_der)
    a_ok = bool(res["ok"] and res["reference_ok"] and res["signature_ok"]
                and res["chain_ok"] is True)
    print("   наш verify_wsse         : ok=%s reference_ok=%s signature_ok=%s chain_ok=%s" %
          (res["ok"], res["reference_ok"], res["signature_ok"], res["chain_ok"]))
    print("   канонизация/сертификат  : c14n=%s | сертификат из %s | привязка к токену=%s" %
          (res["c14n"], res["certificate_source"], res["token_bound"]))
    print("   подписанный узел        : %s (wsu:Id=%s)" % (res["signed_tag"], res["signed_id"]))
    print("   цепочка до корня НУЦ    : %s (cert -> NCA -> root)" % full_chain_ok)

    # A-neg) подделка тела и подписи — должно отвергаться
    tampered_body = _tamper_text(signed, b"getVersion", b"getVersionX")
    res_body = verify_wsse(tampered_body)
    neg_body_ok = (res_body["reference_ok"] is False and res_body["ok"] is False)

    import base64
    from lxml import etree
    root = etree.fromstring(signed)
    sig_node = root.find(f".//{DS}SignatureValue")
    raw = base64.b64decode("".join(sig_node.text.split()))
    sig_node.text = base64.b64encode(bytes([raw[0] ^ 0xFF]) + raw[1:]).decode()
    res_sig = verify_wsse(etree.tostring(root))
    neg_sig_ok = (res_sig["signature_ok"] is False and res_sig["ok"] is False)

    print("A-neg) подделка Body       : reference_ok=%s ok=%s -> %s" %
          (res_body["reference_ok"], res_body["ok"], "отверг" if neg_body_ok else "ПРИНЯЛ (!)"))
    print("A-neg) подделка Signature  : signature_ok=%s ok=%s -> %s" %
          (res_sig["signature_ok"], res_sig["ok"], "отверг" if neg_sig_ok else "ПРИНЯЛ (!)"))

    # A-neg) XML Signature Wrapping: дубликат wsu:Id должен быть отвергнут (неоднозначность)
    dup_root = etree.fromstring(signed)
    body_node = dup_root.find(f".//{{http://schemas.xmlsoap.org/soap/envelope/}}Body")
    decoy = copy.deepcopy(body_node)
    body_node.getparent().insert(0, decoy)              # подсовываем второй узел с тем же Id
    try:
        res_dup = verify_wsse(etree.tostring(dup_root))
        neg_dup_ok = res_dup["ok"] is False
        dup_note = "принял ok=%s (ПЛОХО)" % res_dup["ok"]
    except ValueError as ex:
        neg_dup_ok, dup_note = True, "ValueError: " + str(ex)[:60]
    print("A-neg) дубликат wsu:Id     :", dup_note, "->",
          "отверг" if neg_dup_ok else "ПРИНЯЛ (!)")

    # B) наш конверт -> DLL. VerifyWSSE в интерфейсе DLL отсутствует: пробуем VerifyXML.
    from kalkan_p12 import load_gost2015_p12
    cert, key_be = load_gost2015_p12(open(KEY, "rb").read(), PW)
    mine = sign_wsse(key_be, b"<getVersion/>", cert)
    rc_xml, info = oracle.verify_xml(mine, 0)
    print("B) наш WSSE -> DLL VerifyXML: rc=0x%08x %s" % (rc_xml, mask_pii((info or "").strip()[:60])))
    print("   (в интерфейсе KalkanCrypt нет VerifyWSSE — обратное направление "
          "этой DLL не поддерживается)")
    oracle.finalize()

    ok = a_ok and neg_body_ok and neg_sig_ok and neg_dup_ok
    print("ИТОГ WSSE-сверки:", "ВСЁ ОК (вендорский WSSE проверен: подпись + цепочка; негативы и XSW отвергнуты)"
          if ok else "ЕСТЬ ПРОБЛЕМЫ")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
