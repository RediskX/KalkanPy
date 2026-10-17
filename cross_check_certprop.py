"""
cross_check_certprop.py — сверка X509CertificateGetInfo (мой get_cert_info) с настоящим DLL.

Для каждого KC_CERTPROP_* сравнивает значение, которое вернул KalkanCrypt.dll,
и значение моей реализации на том же сертификате.
"""

from __future__ import annotations

import os
import sys

from kalkan_certprop import get_cert_info
from kalkan_keys import first_key, mask_pii, roots
from kalkan_dll import (KalkanOracle, KC_CERT_CA, KC_CERT_INTERMEDIATE, KC_CERT_B64)
from kalkan_p12 import load_gost2015_p12

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

KEY, PW = first_key()                    # путь и пароль берутся локально (не из репозитория)
ROOT, NCA = roots()

PROPS = {
    0x801: "ISSUER_COUNTRYNAME", 0x802: "ISSUER_SOPN", 0x803: "ISSUER_LOCALITYNAME",
    0x804: "ISSUER_ORG_NAME", 0x805: "ISSUER_ORGUNIT_NAME", 0x806: "ISSUER_COMMONNAME",
    0x807: "SUBJECT_COUNTRYNAME", 0x808: "SUBJECT_SOPN", 0x809: "SUBJECT_LOCALITYNAME",
    0x80A: "SUBJECT_COMMONNAME", 0x80B: "SUBJECT_GIVENNAME", 0x80C: "SUBJECT_SURNAME",
    0x80D: "SUBJECT_SERIALNUMBER", 0x80E: "SUBJECT_EMAIL", 0x80F: "SUBJECT_ORG_NAME",
    0x810: "SUBJECT_ORGUNIT_NAME", 0x811: "SUBJECT_BC", 0x812: "SUBJECT_DC",
    0x813: "NOTBEFORE", 0x814: "NOTAFTER", 0x815: "KEY_USAGE", 0x816: "EXT_KEY_USAGE",
    0x817: "AUTH_KEY_ID", 0x818: "SUBJ_KEY_ID", 0x819: "CERT_SN", 0x81A: "ISSUER_DN",
    0x81B: "SUBJECT_DN", 0x81C: "SIGNATURE_ALG", 0x81D: "PUBKEY", 0x81E: "POLICIES_ID",
    0x81F: "OCSP",
}


def main() -> int:
    if not KEY:
        print("SKIP: локальный .p12 не найден (задайте KALKAN_DIR) — сверка не выполнялась")
        return 0
    cert, _ = load_gost2015_p12(open(KEY, "rb").read(), PW)

    oracle = KalkanOracle()
    oracle.init()
    oracle.load_key_store(PW, KEY, "")
    oracle.load_cert_file(ROOT, KC_CERT_CA)
    oracle.load_cert_file(NCA, KC_CERT_INTERMEDIATE)

    rc_exp, cert_text = oracle.export_cert("", KC_CERT_B64)
    if rc_exp != 0 or not cert_text:
        print("export_cert не сработал: rc=0x%08x" % rc_exp)
        oracle.finalize()
        return 2

    verified = absent = differ = 0
    for prop, name in PROPS.items():
        try:
            mine = get_cert_info(cert, prop)
        except Exception as ex:
            mine = f"<err {type(ex).__name__}>"
        rc, theirs = oracle.cert_get_info_from_store(cert_text, prop)
        if rc == 0:
            if mine == theirs:                       # строгое посимвольное сравнение
                verified += 1
                print(f"  OK   {name:22} {mask_pii(str(mine)[:54])!r}")
            else:
                differ += 1
                print(f"  DIFF {name:22}\n       dll ={mask_pii(str(theirs))!r}\n"
                      f"       mine={mask_pii(str(mine))!r}")
        elif mine == "":                             # у Калкана ошибка и у меня пусто = поля нет
            absent += 1
            print(f"  ABS  {name:22} (нет поля у обоих, rc=0x{rc:08x})")
        else:
            differ += 1
            print(f"  DIFF {name:22}\n       dll =<rc=0x{rc:08x}>\n"
                  f"       mine={mask_pii(str(mine))!r}")
    oracle.finalize()

    print(f"ИТОГ certprop: сверено {verified}, отсутствует у обоих {absent}, расхождений {differ}")
    return 0 if differ == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
