"""
demo_real_key.py — работа с реальными ключами НУЦ РК (.p12) без бинарников НУЦ.

Пути и пароли берутся локально через kalkan_keys (пароль — из имени файла после последнего
«_» либо из KALKAN_P12_PASSWORD); в репозитории секретов нет.

Приватность: по умолчанию вывод МАСКИРУЕТ персональные данные сертификата (ФИО/ИИН) и
пароль; чтобы увидеть их полностью, запустите с `--show-pii`.

Что делает для каждого ключа:
  1) проверяет MAC и извлекает сертификат + приватный ключ GOST 2015;
  2) проверяет подпись сертификата по цепочке НУЦ (NCA -> ROOT);
  3) подписывает данные реальным ключом (RAW и CMS) и проверяет подписи своим кодом.
"""

from __future__ import annotations

import base64
import re
import sys

from kalkan_keys import all_keys, mask_pii, masked, roots
from kalkan_verify import (load_certificate, verify_certificate,
                           verify_certificate_chain, verify_cms)
from kalkan_p12 import UnsupportedKeyStore, load_gost2015_p12, verify_p12_mac
from kalkan_sign import raw_sign, raw_verify, sign_cms

ROOT, NCA = roots()
KEYS = all_keys()
SHOW_PII = "--show-pii" in sys.argv


try:                                     # консоль Windows бывает cp1251 — не роняем прогон
    import sys as _sys
    _sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


def main() -> int:
    if not KEYS:
        print("SKIP: локальные .p12 не найдены (задайте KALKAN_DIR) — демо не выполнялось")
        return 0
    root = open(ROOT, "rb").read()
    nca = open(NCA, "rb").read()
    data = "Договор №1. Проверка ЭЦП ГОСТ 2015.".encode("utf-8")
    all_ok = True

    for path, pw in KEYS:
        raw = open(path, "rb").read()
        print("=" * 70)
        print("ключ :", masked(path))
        print("пароль:", "из имени файла" if not SHOW_PII else pw,
              "| MAC:", verify_p12_mac(raw, pw))

        try:
            cert_der, key_be = load_gost2015_p12(raw, pw)
        except UnsupportedKeyStore as ex:
            print("  ошибка:", ex)
            all_ok = False
            continue
        cert = load_certificate(cert_der)
        print("  сертификат:", mask_pii(cert["tbs_certificate"]["subject"].human_friendly,
                                       show=SHOW_PII))
        print("  размер ключа:", len(key_be) * 8, "бит")

        by_nca = by_root = None
        try:
            by_nca = verify_certificate(cert_der, nca)
        except Exception as ex:
            by_nca = f"err {ex}"
        try:
            chain_ok = verify_certificate_chain([cert_der, nca], root)
        except Exception as ex:
            chain_ok = f"err {ex}"
        print("  подпись NCA :", by_nca, "| цепочка user->NCA->ROOT:", chain_ok)

        sig_raw = raw_sign(key_be, data)
        ok_raw = raw_verify(sig_raw, data, cert_der)
        cms = sign_cms(key_be, data, cert_der)
        ok_cms = verify_cms(cms)["signers"][0]["state"] == "ok"
        print("  RAW подпись/проверка:", ok_raw, "| CMS проверка:", ok_cms)
        print("  RAW base64:", base64.b64encode(sig_raw).decode()[:56], "...")
        print("  CMS base64:", base64.b64encode(cms).decode()[:56], "...")

        all_ok = all_ok and bool(ok_raw and ok_cms)

    print("=" * 70)
    print("ИТОГ:", "ВСЁ ОК" if all_ok else "ЕСТЬ ПРОБЛЕМЫ")
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
