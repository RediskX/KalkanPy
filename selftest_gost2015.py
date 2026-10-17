"""
selftest_gost2015.py — сквозная проверка ГОСТ 2015: ключ, сертификат, RAW, CMS.

Что делает:
  1) генерирует ключ ГОСТ 2015 (512 и 256 бит);
  2) строит самоподписанный сертификат и проверяет его своей же проверкой;
  3) формирует RAW-подпись и проверяет её (и негативный случай);
  4) формирует CMS с сертификатом и проверяет его (digest + signature);
  5) проверяет реальные корневые сертификаты НУЦ из каталога KALKAN_DIR.

Никакие бинарники НУЦ не используются.
"""

from __future__ import annotations

import base64
import os
import sys

from kalkan_keys import kalkan_dir, roots
from kalkan_verify import UnsupportedAlgorithm, verify_certificate, verify_cms
from kalkan_sign import create_self_signed_certificate, raw_sign, raw_verify, sign_cms


def _gen_private(size: int) -> bytes:
    # держим значение заведомо меньше q (порядка кривой)
    return (int.from_bytes(os.urandom(size), "big") >> 1).to_bytes(size, "big")


def _run_size(size: int) -> bool:
    bits = size * 8
    print(f"\n=== ГОСТ 2015, {bits}-бит ===")
    priv = _gen_private(size)

    cert = create_self_signed_certificate(priv, common_name=f"KALKANPY GOST{bits} TEST")
    print(f"  сертификат: {len(cert)} байт DER")
    self_ok = verify_certificate(cert, cert)
    print("  самоподпись сертификата        :", self_ok)

    data = "Привет, ЭЦП! Hello GOST 2015".encode("utf-8")
    raw = raw_sign(priv, data)
    raw_ok = raw_verify(raw, data, cert)
    raw_bad = raw_verify(raw, data + b"!", cert)
    print("  RAW подпись/проверка           :", raw_ok, "| негатив:", raw_bad)
    print("  RAW base64:", base64.b64encode(raw).decode()[:60], "...")

    cms = sign_cms(priv, data, cert)
    res = verify_cms(cms)
    s = res["signers"][0]
    print("  CMS digest_ok/signature_ok     :", s["digest_ok"], "/", s["signature_ok"],
          "| state:", s["state"])
    print("  CMS base64:", base64.b64encode(cms).decode()[:60], "...")

    # CMS также должен проходить через проверку сертификата внутри
    inner_ok = None
    try:
        from asn1crypto import cms as _cms
        ci = _cms.ContentInfo.load(cms)
        inner = ci["content"]["certificates"][0].chosen.dump()
        inner_ok = verify_certificate(inner, inner)
    except Exception as ex:
        inner_ok = f"ERR {ex}"
    print("  сертификат внутри CMS          :", inner_ok)

    return bool(self_ok and raw_ok and not raw_bad and s["state"] == "ok" and inner_ok)


try:                                     # консоль Windows бывает cp1251 — не роняем прогон
    import sys as _sys
    _sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


def main() -> int:
    ok512 = _run_size(64)
    ok256 = _run_size(32)

    root, nca = roots()
    print(f"\n=== Реальные корневые сертификаты НУЦ ({kalkan_dir()}) ===")
    prod_ok, prod_checked = None, False
    if os.path.exists(root) and os.path.exists(nca):
        rd = open(root, "rb").read()
        nd = open(nca, "rb").read()
        root_self = verify_certificate(rd, rd)
        nca_by_root = verify_certificate(nd, rd)
        print("  root_gost_2022 самоподписан    :", root_self)
        print("  nca_gost_2022 подписан корнем  :", nca_by_root)
        prod_ok = bool(root_self and nca_by_root)
        prod_checked = True
    else:
        print("  SKIP: корни НУЦ не найдены (задайте KALKAN_DIR) — эта часть не проверялась")

    all_ok = ok512 and ok256 and (prod_ok is not False)
    print("\nИТОГ:", "ВСЁ ОК" if all_ok else "ЕСТЬ ПРОБЛЕМЫ",
          "" if prod_checked else "| корни НУЦ: ПРОПУЩЕНО")
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
