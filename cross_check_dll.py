"""
cross_check_dll.py — кросс-проверка моей реализации с настоящим KalkanCrypt.dll.

Проверяются ОБЕ стороны, для RAW и CMS:
  A) Калкан подписывает → мой код проверяет;
  B) мой код подписывает → Калкан проверяет (VerifyData).

Две важные детали, без которых у вендора не строятся цепочки:
  * ПОРЯДОК ИНИЦИАЛИЗАЦИИ: Init → LoadKeyStore → X509LoadCertificateFromFile(root, KC_CERT_CA)
    → X509LoadCertificateFromFile(nca, KC_CERT_INTERMEDIATE). Сертификаты УЦ грузятся ПОСЛЕ ключа
    (как в рабочем коде обёртки); если грузить до ключа — KCR_CACERTNOTFOUND.
  * RAW-ПРОВЕРКА: flags = KC_SIGN_DRAFT | KC_IN_BASE64 (0x11), подпись — base64.
    (KC_IN2_BASE64 даёт BASE64_DECODE_ERROR, а флаг без base64 роняет DLL — не использовать.)
"""

from __future__ import annotations

import base64
import os

from kalkan_dll import (KC_CERT_CA, KC_CERT_INTERMEDIATE, KC_DETACHED_DATA, KC_IN_BASE64,
                        KC_IN_DER, KC_OUT_BASE64, KC_SIGN_CMS, KC_SIGN_DRAFT, KC_WITH_CERT,
                        KalkanOracle)
from kalkan_keys import all_keys, masked, roots
from kalkan_p12 import load_gost2015_p12
from kalkan_sign import raw_sign, raw_verify, sign_cms
from kalkan_verify import verify_cms

ROOT, NCA = roots()
KEYS = all_keys()                                   # локальные контейнеры (пароль из имени файла)


def _tamper(blob: bytes) -> bytes:
    """Портит подпись, сохраняя формат (base64-текст остаётся base64)."""
    alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
    if all(b in alphabet for b in blob):
        text = blob.decode()
        mid = len(text) // 2
        text = text[:mid] + ("A" if text[mid] != "A" else "B") + text[mid + 1:]
        return text.encode()
    data = bytearray(blob)
    data[len(data) // 2] ^= 0x01
    return bytes(data)


try:                                     # консоль Windows бывает cp1251 — не роняем прогон
    import sys as _sys
    _sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


def main() -> int:
    if not KEYS:
        print("SKIP: локальные .p12 не найдены (задайте KALKAN_DIR) — сверка не выполнялась")
        return 0
    data = "Кросс-проверка ГОСТ 2015: RAW и CMS.".encode("utf-8")
    wrong = data + b"!"                                 # данные, которыми НЕ подписывали
    all_ok = True
    vacuous = []

    for path, pw in KEYS:
        cert, key_be = load_gost2015_p12(open(path, "rb").read(), pw)
        print("=" * 70)
        print("ключ:", masked(path))

        # A) Калкан подписывает -> мой код проверяет (отдельный контекст)
        a = KalkanOracle()
        a.init()
        a.load_key_store(pw, path, "")
        a.load_cert_file(ROOT, KC_CERT_CA)
        a.load_cert_file(NCA, KC_CERT_INTERMEDIATE)
        k_raw = base64.b64decode(a.sign_data(
            base64.b64encode(data), KC_SIGN_DRAFT | KC_IN_BASE64 | KC_OUT_BASE64))
        a_raw = raw_verify(k_raw, data, cert)
        k_cms = base64.b64decode(a.sign_data(
            base64.b64encode(data),
            KC_SIGN_CMS | KC_IN_BASE64 | KC_OUT_BASE64 | KC_WITH_CERT))
        a_cms = verify_cms(k_cms)["signers"][0]["state"]
        a.finalize()

        # B) мой код подписывает -> Калкан проверяет, ОБЯЗАТЕЛЬНО с негативным контролем.
        def fresh():
            o = KalkanOracle()
            o.init()
            o.load_key_store(pw, path, "")
            o.load_cert_file(ROOT, KC_CERT_CA)
            o.load_cert_file(NCA, KC_CERT_INTERMEDIATE)
            return o

        def dll(payload, sign_bytes, flags):
            o = fresh()
            rc, _ = o.verify_data(payload, sign_bytes, flags)
            o.finalize()
            return rc

        raw_b64 = base64.b64encode(raw_sign(key_be, data))
        rc_raw_ok = dll(data, raw_b64, KC_SIGN_DRAFT | KC_IN_BASE64)
        rc_raw_wrong = dll(wrong, raw_b64, KC_SIGN_DRAFT | KC_IN_BASE64)
        rc_raw_tampered = dll(data, _tamper(raw_b64), KC_SIGN_DRAFT | KC_IN_BASE64)
        b_raw = rc_raw_ok == 0 and rc_raw_wrong != 0 and rc_raw_tampered != 0

        cms_flags = KC_SIGN_CMS | KC_IN_DER | KC_DETACHED_DATA
        cms_det = sign_cms(key_be, data, cert, detached=True)
        rc_cms_ok = dll(data, cms_det, cms_flags)
        rc_cms_wrong = dll(wrong, cms_det, cms_flags)
        b_cms = rc_cms_ok == 0 and rc_cms_wrong != 0

        # attached-CMS у DLL не проверяется: принимает и подпись от других данных.
        cms_att = sign_cms(key_be, data, cert)
        rc_att_ok = dll(b"", cms_att, KC_SIGN_CMS | KC_IN_DER)
        rc_att_wrong = dll(b"", sign_cms(key_be, wrong, cert), KC_SIGN_CMS | KC_IN_DER)
        if rc_att_ok == 0 and rc_att_wrong == 0:
            vacuous.append("attached CMS (" + masked(path) + ")")

        print("  A) Калкан RAW -> мой raw_verify   :", a_raw)
        print("  A) Калкан CMS -> мой verify_cms   :", a_cms)
        print("  B) мой RAW -> Калкан : ok rc=0x%08x | чужие данные rc=0x%08x | битая подпись rc=0x%08x -> %s"
              % (rc_raw_ok, rc_raw_wrong, rc_raw_tampered,
                 "проверяется" if b_raw else "ВАКУУМНО"))
        print("  B) мой CMS (detached+KC_IN_DER) -> Калкан : ok rc=0x%08x | чужие данные rc=0x%08x -> %s"
              % (rc_cms_ok, rc_cms_wrong, "проверяется" if b_cms else "ВАКУУМНО"))
        print("  B) мой CMS (attached) -> Калкан : ok rc=0x%08x | от других данных rc=0x%08x -> %s"
              % (rc_att_ok, rc_att_wrong,
                 "ВАКУУМНО (DLL принимает любую attached-CMS)" if rc_att_wrong == 0
                 else "проверяется"))

        all_ok = all_ok and a_raw and a_cms == "ok" and b_raw and b_cms

    print("=" * 70)
    if vacuous:
        print("Честно: направление «мой -> Калкан» вакуумно для:", "; ".join(vacuous))
    print("ИТОГ кросс-проверки:", "ВСЁ ОК (RAW и detached-CMS, в обе стороны; с негативным контролем)"
          if all_ok else "ЕСТЬ ПРОБЛЕМЫ")
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
