"""
cross_check_formats.py — сверка форматов вход/выход с настоящим KalkanCrypt.dll.

Проверяем, что мой kalkan_api.sign_data/verify_data в кодировках
текст/base64/PEM/DER/файл совпадают с Калканом (в обе стороны).
"""

from __future__ import annotations

import base64
import os

from kalkan_api import (KC_DETACHED_DATA, KC_IN_BASE64, KC_IN_DER, KC_IN_FILE, KC_IN_PEM,
                        KC_OUT_BASE64, KC_OUT_DER, KC_OUT_PEM, KC_SIGN_CMS,
                        KC_SIGN_DRAFT, KC_WITH_CERT, sign_data, verify_data)
from kalkan_dll import KalkanOracle, KC_CERT_CA, KC_CERT_INTERMEDIATE
from kalkan_keys import first_key, kalkan_dir, roots
from kalkan_p12 import load_gost2015_p12

KEY, PW = first_key()
ROOT, NCA = roots()
data = b"Hello World"


def fresh() -> KalkanOracle:
    o = KalkanOracle()
    o.init()
    o.load_key_store(PW, KEY, "")
    o.load_cert_file(ROOT, KC_CERT_CA)
    o.load_cert_file(NCA, KC_CERT_INTERMEDIATE)
    return o


try:                                     # консоль Windows бывает cp1251 — не роняем прогон
    import sys as _sys
    _sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


def main() -> int:
    if not KEY:
        print("SKIP: локальный .p12 не найден (задайте KALKAN_DIR) — сверка не выполнялась")
        return 0
    cert, key_be = load_gost2015_p12(open(KEY, "rb").read(), PW)

    # (подпись: как сформировать у меня, как Калкан проверяет, как формирует Калкан, как проверяю я)
    cases = [
        ("RAW текст  -> BASE64",
         dict(flags=KC_SIGN_DRAFT | KC_OUT_BASE64, inp=data),
         KC_SIGN_DRAFT | KC_IN_BASE64),
        ("RAW base64 -> BASE64",
         dict(flags=KC_SIGN_DRAFT | KC_IN_BASE64 | KC_OUT_BASE64, inp=base64.b64encode(data)),
         KC_SIGN_DRAFT | KC_IN_BASE64),
        ("CMS текст  -> DER",
         dict(flags=KC_SIGN_CMS | KC_WITH_CERT | KC_OUT_DER, inp=data),
         KC_SIGN_CMS | KC_IN_DER),
        ("CMS base64 -> BASE64",
         dict(flags=KC_SIGN_CMS | KC_WITH_CERT | KC_IN_BASE64 | KC_OUT_BASE64,
              inp=base64.b64encode(data)),
         KC_SIGN_CMS | KC_IN_BASE64),
        ("CMS base64 -> PEM",
         dict(flags=KC_SIGN_CMS | KC_WITH_CERT | KC_IN_BASE64 | KC_OUT_PEM,
              inp=base64.b64encode(data)),
         KC_SIGN_CMS | KC_IN_PEM),
        ("CMS detached -> DER",
         dict(flags=KC_SIGN_CMS | KC_WITH_CERT | KC_IN_BASE64 | KC_OUT_DER | KC_DETACHED_DATA,
              inp=base64.b64encode(data)),
         KC_SIGN_CMS | KC_DETACHED_DATA | KC_IN_DER),
    ]

    all_ok = True
    vacuous = []
    verified = []
    mismatch = []
    for title, my_sign, kalkan_flags in cases:
        mine = sign_data(my_sign["inp"], my_sign["flags"], key_be, cert)

        # B) моя подпись -> Калкан, с негативным контролем (иначе направление ничего не доказывает)
        b = fresh()
        in_data = b"" if kalkan_flags & KC_DETACHED_DATA else data
        if kalkan_flags & KC_SIGN_CMS:
            in_data = data if kalkan_flags & KC_DETACHED_DATA else b""
        rc, _ = b.verify_data(in_data, mine, kalkan_flags)
        rc_neg, _ = b.verify_data(in_data + b"X", mine, kalkan_flags)
        b.finalize()

        # A) подпись Калкана -> мой код
        a = fresh()
        kalkan_out = a.sign_data(my_sign["inp"], my_sign["flags"])
        a.finalize()
        res = verify_data(data, kalkan_out, kalkan_flags, certificate_der=cert)

        meaningful = (rc == 0 and rc_neg != 0)
        if rc == 0 and rc_neg == 0:
            vacuous.append(title)
        elif rc != 0:
            mismatch.append(title)                       # DLL отверг нашу корректную подпись
        else:
            verified.append(title)
        ok = res["ok"]
        all_ok = all_ok and ok
        mark = ("OK(DLL проверил)" if meaningful else
                ("ВАКУУМНО(DLL)" if rc == 0 else "РАСХОЖДЕНИЕ"))
        print(f"{title:26} | мой->Калкан rc=0x{rc:08x} neg=0x{rc_neg:08x} "
              f"| Калкан->мой {res['state']:<7} | {mark}")

    # IN_FILE
    path_txt = os.path.join(os.path.dirname(KEY), "_fmt_in.txt")
    open(path_txt, "wb").write(data)
    mine = sign_data(path_txt.encode(), KC_SIGN_DRAFT | KC_IN_FILE | KC_OUT_BASE64, key_be, cert)
    b = fresh()
    rc, _ = b.verify_data(data, mine, KC_SIGN_DRAFT | KC_IN_BASE64)
    rc_neg, _ = b.verify_data(data + b"X", mine, KC_SIGN_DRAFT | KC_IN_BASE64)
    b.finalize()
    ok = rc == 0 and rc_neg != 0
    print(f"{'RAW файл (KC_IN_FILE)':26} | мой->Калкан rc=0x{rc:08x} neg=0x{rc_neg:08x} "
          f"| {'OK' if ok else 'FAIL'}")
    all_ok = all_ok and ok
    os.remove(path_txt)

    if vacuous:
        print("Честно: DLL НЕ проверяет (направление вакуумно) для:", "; ".join(vacuous))
    print("Направление «мой -> Калкан» ДОКАЗАНО (DLL отверг негатив) для:",
          "; ".join(verified) if verified else "(нет)")
    if mismatch:
        print("РАСХОЖДЕНИЕ: DLL отверг нашу корректную подпись в:", "; ".join(mismatch))
        all_ok = False
    print("ИТОГ форматов:", "ВСЁ ОК" if all_ok else "ЕСТЬ ПРОБЛЕМЫ")
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
