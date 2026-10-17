"""
demo_xml_tsa.py — XMLDSig (enveloped) и метка времени (RFC 3161 / TSA).

XML: подписываем тестовый XML реальным ключом НУЦ, проверяем и ломаем.
TSA: строим запрос и (если есть сеть) получаем метку времени с tsp.pki.gov.kz.
"""

from __future__ import annotations

import os
import re

from kalkan_keys import first_key, kalkan_dir, sdk_dir
from kalkan_p12 import load_gost2015_p12
from kalkan_tsa import build_timestamp_request, get_timestamp
from kalkan_xmldsig import sign_xml, verify_xml

KEY, PW = first_key()
SDK = sdk_dir()
XML = os.path.join(SDK, "C", "Linux", "C", "test", "example", "test_xml.txt")


try:                                     # консоль Windows бывает cp1251 — не роняем прогон
    import sys as _sys
    _sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


def main() -> int:
    if not KEY:
        print("SKIP: локальный .p12 не найден (задайте KALKAN_DIR)")
        return 0
    cert, key_be = load_gost2015_p12(open(KEY, "rb").read(), PW)
    xml = open(XML, "rb").read()

    print("=" * 70)
    print("XMLDSig (enveloped, ГОСТ 2015)")
    signed = sign_xml(key_be, xml, cert)
    res = verify_xml(signed)
    tampered = signed.replace(b"770704034", b"770704035")
    if tampered == signed:                              # литерала нет — ломаем текст первого узла
        tampered = re.sub(rb"(<[^/!?][^>]*>)([^<]+)", rb"\1 \2 ", signed, count=1)
    if tampered == signed:
        tampered = signed.replace(b"/>\n", b" />\n", 1)
    print("  подпись        :", res["signature_ok"], "| digest:", res["reference_ok"])
    print("  подделка       :", verify_xml(tampered)["reference_ok"])
    print("  размер signed  :", len(signed), "байт")

    print("=" * 70)
    print("TSA (RFC 3161)")
    data = b"document to timestamp"
    req = build_timestamp_request(data, hash_name="sha256")
    print("  запрос собран   :", len(req), "байт")
    try:
        resp = get_timestamp(data, hash_name="sha256")
        print("  статус          :", resp["status"])
        print("  время (genTime) :", resp["gen_time"])
        print("  токен           :", len(resp.get("token_der") or b""), "байт")
        if resp.get("parse_error"):
            print("  parse_error     :", resp["parse_error"][:100])
        token = resp.get("token_der")
        tsa_ok = resp["status"] in (0, "granted") and resp["gen_time"] is not None
        if token:
            from kalkan_tsa import verify_timestamp_token
            chk = verify_timestamp_token(token, original_data=data,
                                         nonce=resp.get("nonce"))
            print("  верификация токена:", {k: chk[k] for k in
                  ("ok", "signature_ok", "imprint_ok", "nonce_ok", "eku_time_stamping")})
            print("  полностью проверен :", chk["fully_verified"],
                  "| не проверено:", chk["unverified"])
            tsa_ok = tsa_ok and chk["ok"] and chk["imprint_ok"] is True
    except Exception as ex:
        print("  TSA недоступна  :", type(ex).__name__, str(ex)[:80])
        tsa_ok = None

    print("=" * 70)
    xml_ok = res["signature_ok"] and res["reference_ok"] and not verify_xml(tampered)["reference_ok"]
    print("XMLDSig:", "ОК" if xml_ok else "ПРОБЛЕМА",
          "| TSA:", "ОК" if tsa_ok else ("нет сети" if tsa_ok is None else "ПРОБЛЕМА"))
    return 0 if xml_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
