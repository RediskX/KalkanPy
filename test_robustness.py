"""
test_robustness.py — регресс на устойчивость парсинга (находки аудита).

Проверяет, что малиформленный ввод даёт КОНКРЕТНУЮ понятную ошибку
(ValueError/UnsupportedKeyStore) или корректный отказ, а не AttributeError/
IndexError/TypeError. Каждый случай проверяет точный тип.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timezone

from asn1crypto import cms

try:                                    # консоль Windows может быть cp1251: не падать на «→»
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from kalkan_api import KC_SIGN_CMS, KC_IN_PEM, verify_data
from kalkan_p12 import UnsupportedKeyStore, load_gost2015_p12, verify_p12_mac
from kalkan_sign import der_utctime
from kalkan_wsse import verify_wsse
from kalkan_keys import first_key
from kalkan_xmldsig import verify_xml

KEY, PW = first_key()
DS = "http://www.w3.org/2000/09/xmldsig#"


def expect(exc_type, fn, label) -> bool:
    try:
        fn()
    except exc_type:
        print(f"  OK   {label}: {exc_type.__name__}")
        return True
    except Exception as ex:
        print(f"  FAIL {label}: получено {type(ex).__name__}, ожидалось {exc_type.__name__}")
        return False
    print(f"  FAIL {label}: исключения не было")
    return False


def check(condition, label) -> bool:
    print(f"  {'OK  ' if condition else 'FAIL'} {label}")
    return bool(condition)


def empty_signers_cms() -> bytes:
    signed_data = cms.SignedData({
        "version": "v1",
        "digest_algorithms": [],
        "encap_content_info": {"content_type": "data"},
        "signer_infos": [],
    })
    return cms.ContentInfo({"content_type": "signed_data", "content": signed_data}).dump()


def main() -> int:
    ok = True

    print("XMLDSig:")
    ok &= expect(ValueError, lambda: verify_xml(b"<a/>"), "нет Signature")
    ok &= expect(ValueError,
                 lambda: verify_xml(f'<a xmlns:ds="{DS}"><ds:Signature/></a>'.encode()),
                 "Signature без SignedInfo")
    ok &= expect(ValueError,
                 lambda: verify_xml(
                     f'<a xmlns:ds="{DS}"><ds:Signature><ds:SignedInfo>'
                     f'<ds:Reference/></ds:SignedInfo></ds:Signature></a>'.encode()),
                 "Reference без DigestValue")

    print("WSSE:")
    ok &= expect(ValueError, lambda: verify_wsse(b"<a/>"), "нет Signature")

    print("CMS (фасад):")
    ok &= expect(ValueError, lambda: verify_data(b"", b"not a cms", KC_SIGN_CMS), "мусор вместо CMS")
    ok &= expect(ValueError, lambda: verify_data(b"", b"key: not pem", KC_SIGN_CMS | KC_IN_PEM),
                 "мусор вместо PEM")

    print("CMS без подписантов:")
    result = verify_data(b"", empty_signers_cms(), KC_SIGN_CMS)
    ok &= check(result["state"] == "no_signers" and result["ok"] is False,
                f"пустые signer_infos -> state={result['state']}")

    print("P12 (малиформ → отказ, без исключений типа IndexError):")
    ok &= check(verify_p12_mac(b"", "x") is False, "verify_p12_mac(b'') == False")
    ok &= check(verify_p12_mac(b"garbage", "x") is False, "verify_p12_mac(garbage) == False")
    ok &= check(verify_p12_mac(b"\x30\x82\xff\xffaa", "x") is False, "битая длина → False")
    ok &= expect(UnsupportedKeyStore, lambda: load_gost2015_p12(b"garbage", "x"),
                 "load_gost2015_p12(garbage)")

    print("P12 (реальный ключ):")
    if os.path.exists(KEY):
        with open(KEY, "rb") as handle:
            blob = handle.read()
        ok &= expect(UnsupportedKeyStore, lambda: load_gost2015_p12(blob, "wrong-password"),
                     "неверный пароль")
        ok &= check(verify_p12_mac(blob, PW) is True, "верный пароль → MAC ok")
    else:
        print("  SKIP: локальный .p12 не найден (задайте KALKAN_DIR)")

    print("DER-время:")
    ok &= check(der_utctime(datetime(2051, 1, 1, tzinfo=timezone.utc))[:1] == b"\x18",
                ">=2050 -> GeneralizedTime")
    ok &= check(der_utctime(datetime(2026, 1, 1, tzinfo=timezone.utc))[:1] == b"\x17",
                "<2050 -> UTCTime")

    print("ИТОГ устойчивости:", "ВСЁ ОК" if ok else "ЕСТЬ ПРОБЛЕМЫ")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
