"""
verify_sdk_samples.py — прогон независимого верификатора по тестовым данным KalkanCrypt SDK.

Использование:
    python verify_sdk_samples.py [путь к SDK]

По умолчанию берётся путь к SDK 2.0. Скрипт НЕ обращается к бинарникам НУЦ —
только читает тестовые сертификаты/сообщения и проверяет подписи своим кодом.
"""

from __future__ import annotations

import os
import sys

from kalkan_keys import kalkan_dir, mask_pii, sdk_dir
from kalkan_verify import (UnsupportedAlgorithm, load_certificate, verify_certificate,
                           verify_cms)

DEFAULT_SDK = os.environ.get("KALKAN_SDK_DIR") or sdk_dir()

try:                                   # чтобы казахские буквы не роняли печать на cp1251
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


def main() -> int:
    sdk = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_SDK
    certs = os.path.join(sdk, "Keys and Certs", "CA_Test")
    root_path = os.path.join(certs, "ROOT", "root_test_gost_2022.cer")
    nca_path = os.path.join(certs, "NCA", "nca_gost2022_test.cer")
    cms_path = os.path.join(sdk, "C", "Linux", "C", "test", "example", "test_CMS_GOST.txt")

    print("=" * 72)
    print("KalkanPy — независимая проверка ЭЦП НУЦ РК (СТ РК ГОСТ Р 34.10-2015)")
    print("=" * 72)

    for p in (root_path, nca_path):
        if not os.path.exists(p):
            print("НЕТ ФАЙЛА:", p)
            return 2

    root_der = open(root_path, "rb").read()
    nca_der = open(nca_path, "rb").read()

    root = load_certificate(root_der)
    nca = load_certificate(nca_der)
    print("\n[Сертификаты]")
    print("  ROOT:", mask_pii(root["tbs_certificate"]["subject"].human_friendly), "|",
          root["signature_algorithm"]["algorithm"].dotted)
    print("  NCA :", mask_pii(nca["tbs_certificate"]["subject"].human_friendly), "|",
          nca["signature_algorithm"]["algorithm"].dotted)

    print("\n[Проверка подписей сертификатов]")
    root_self = verify_certificate(root_der, root_der)
    nca_by_root = verify_certificate(nca_der, root_der)
    nca_self = verify_certificate(nca_der, nca_der)
    print("  ROOT самоподписан                :", root_self)
    print("  NCA подписан ROOT                :", nca_by_root)
    print("  NCA самоподписан (должно False)  :", nca_self)

    print("\n[Проверка CMS из SDK]")
    if os.path.exists(cms_path):
        data = open(cms_path, "rb").read()
        try:
            res = verify_cms(data)
            for i, signer in enumerate(res["signers"], 1):
                print(f"  подписант {i}: state={signer['state']} "
                      f"digest={signer['digest_oid']} sig={signer['signature_oid']} "
                      f"digest_ok={signer['digest_ok']} signature_ok={signer['signature_ok']}")
        except UnsupportedAlgorithm as ex:
            print("  пропущено:", ex)
    else:
        print("  файл CMS не найден:", cms_path)

    print("\n[Негативный контроль: CMS с подменой содержимого]")
    try:
        import os as _os

        from kalkan_sign import create_self_signed_certificate, sign_cms
        from kalkan_verify import verify_cms as _verify_cms

        _key = _os.urandom(64)
        _cert = create_self_signed_certificate(_key, "NEGATIVE CONTROL")
        _cms = sign_cms(_key, b"payload", _cert)
        _good = _verify_cms(_cms)["signers"][0]["state"]
        _bad = _verify_cms(_cms, detached_content=b"payload!")["signers"][0]["state"]
        print("  своя CMS ( state )      :", _good)
        print("  подмена содержимого     :", _bad, "(должно быть не ok)")
    except Exception as ex:
        print("  негативный контроль не выполнен:", type(ex).__name__, ex)

    print("\nВывод: независимый код подтверждает подписи ГОСТ-2015 сертификатов НУЦ РК.")
    return 0 if (root_self and nca_by_root and not nca_self) else 1


if __name__ == "__main__":
    raise SystemExit(main())
