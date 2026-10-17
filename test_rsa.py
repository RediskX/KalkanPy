"""
test_rsa.py — проверка RSA-ветки: сертификат, RAW и CMS (sha256WithRSAEncryption).
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import rsa

from kalkan_sign import (create_self_signed_rsa_certificate, raw_sign_rsa, sign_cms_rsa)
from kalkan_verify import verify_certificate, verify_cms, verify_rsa


try:                                     # консоль Windows бывает cp1251 — не роняем прогон
    import sys as _sys
    _sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


def main() -> int:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = create_self_signed_rsa_certificate(key, common_name="KALKANPY RSA SELFTEST")
    data = "RSA ГОСТ-рядом: Hello".encode("utf-8")
    ok = True

    self_ok = verify_certificate(cert, cert)
    print("сертификат самоподписан        :", self_ok)
    ok &= self_ok

    raw = raw_sign_rsa(key, data)
    raw_ok = verify_rsa(cert, data, raw, "sha256")
    raw_bad = verify_rsa(cert, data + b"!", raw, "sha256")
    print("RAW подпись/проверка           :", raw_ok, "| негатив:", raw_bad, "| len:", len(raw))
    ok &= raw_ok and not raw_bad

    cms = sign_cms_rsa(key, data, cert)
    res = verify_cms(cms)["signers"][0]
    print("CMS digest/signature           :", res["digest_ok"], "/", res["signature_ok"],
          "| state:", res["state"])
    ok &= (res["state"] == "ok")

    tampered = sign_cms_rsa(key, data + b"!", cert)
    dst = verify_cms(tampered, detached_content=data)["signers"][0]
    print("CMS c подменой данных          :", dst["state"], "(ожидаем failed)")
    ok &= (dst["state"] != "ok")

    ch = verify_cms(cms, trust_anchor_der=cert)["signers"][0]
    print("CMS цепочка до self-signed     :", ch["chain_ok"])
    ok &= (ch["chain_ok"] is True)

    print("ИТОГ RSA:", "ВСЁ ОК" if ok else "ЕСТЬ ПРОБЛЕМЫ")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
