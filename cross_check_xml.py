"""
cross_check_xml.py — сверка SignXML/VerifyXML (мой kalkan_api) с настоящим DLL.

A) мой sign_xml -> Калкан VerifyXML
B) Калкан SignXML -> мой verify_xml
"""

from __future__ import annotations

import os
import sys

from kalkan_api import sign_xml, verify_xml
from kalkan_dll import KalkanOracle, KC_CERT_CA, KC_CERT_INTERMEDIATE
from kalkan_keys import first_key, kalkan_dir, mask_pii, roots, sdk_dir
from kalkan_p12 import load_gost2015_p12

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

KEY, PW = first_key()
ROOT, NCA = roots()
SDK = sdk_dir()
XML = os.path.join(SDK, "C", "Linux", "C", "test", "example", "test_xml.txt")


def main() -> int:
    if not KEY:
        print("SKIP: локальный .p12 не найден (задайте KALKAN_DIR) — сверка не выполнялась")
        return 0
    cert, key_be = load_gost2015_p12(open(KEY, "rb").read(), PW)
    xml = open(XML, "rb").read()

    oracle = KalkanOracle()
    oracle.init()
    oracle.load_key_store(PW, KEY, "")
    oracle.load_cert_file(ROOT, KC_CERT_CA)
    oracle.load_cert_file(NCA, KC_CERT_INTERMEDIATE)

    # A) мой sign -> Калкан VerifyXML (свежий контекст, только проверка)
    mine = sign_xml(xml, key_be, cert)
    rc_a, info = oracle.verify_xml(mine, 0)
    a_ok = (rc_a == 0)
    print("A) мой XML -> Калкан VerifyXML : rc=0x%08x %s" % (rc_a, mask_pii(info.strip()[:60])))

    # A-негатив: подделанный XML Калкан обязан отвергнуть (иначе направление вакуумно)
    tampered = bytearray(mine)
    i = tampered.find(b"<root")
    if i < 0:
        i = len(tampered) // 2
        tampered[i] ^= 0x01
    else:
        j = tampered.find(b">", i) + 1
        tampered[j:j] = b"X"
    rc_a_bad, _ = oracle.verify_xml(bytes(tampered), 0)
    a_negative_ok = (rc_a_bad != 0)
    print("A-негатив: подделанный XML     : rc=0x%08x -> %s" % (
        rc_a_bad, "ОТВЕРГ (проверка осмысленна)" if a_negative_ok else "ПРИНЯЛ (!)"))

    # B) Калкан SignXML -> мой verify
    oracle2 = KalkanOracle()
    oracle2.init()
    oracle2.load_key_store(PW, KEY, "")
    oracle2.load_cert_file(ROOT, KC_CERT_CA)
    oracle2.load_cert_file(NCA, KC_CERT_INTERMEDIATE)
    rc_k, kalk = oracle2.sign_xml(xml, 0)
    b_ok = False
    if rc_k == 0 and kalk:
        res = verify_xml(kalk)
        b_ok = bool(res["ok"])
        print("B) Калкан XML -> мой verify_xml :", res)
    else:
        print("   Калкан SignXML rc=0x%08x (нет подписи)" % rc_k)
    oracle.finalize()
    oracle2.finalize()

    ok = a_ok and a_negative_ok and b_ok
    print("ИТОГ XML-сверки:", "ВСЁ ОК (в обе стороны, с негативным контролем)" if ok
          else "ЕСТЬ ПРОБЛЕМЫ")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
