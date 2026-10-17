"""
test_revoke.py — проверка отзыва: CRL (офлайн, на данных SDK) и OCSP (сеть).
"""

from __future__ import annotations

import os
import sys

from kalkan_keys import first_key, kalkan_dir, sdk_dir
from kalkan_p12 import load_gost2015_p12
from kalkan_revoke import check_crl, crl_is_revoked, crl_revoked_serials, load_crl, ocsp_check
from kalkan_verify import load_certificate

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

KEY, PW = first_key()
SDK = sdk_dir()
# CRL и его издатель — из TEST-набора НУЦ 2022 (парные)
CRL = os.path.join(SDK, "Keys and Certs", "CRL", "nca_gost2022_test.crl")
NCA_TEST = os.path.join(SDK, "Keys and Certs", "CA_Test", "NCA", "nca_gost2022_test.cer")


def main() -> int:
    ok = True
    if not KEY:
        print("SKIP: локальный .p12 не найден (задайте KALKAN_DIR) — проверка не выполнялась")
        return 0
    cert, _ = load_gost2015_p12(open(KEY, "rb").read(), PW)
    nca = open(NCA_TEST, "rb").read()

    print("CRL:", os.path.basename(CRL), "| издатель:", os.path.basename(NCA_TEST))
    crl = load_crl(open(CRL, "rb").read())
    revoked_serials = crl_revoked_serials(crl)
    print("  в списке отозвано:", len(revoked_serials))

    res = check_crl(open(NCA_TEST, "rb").read(), nca, open(CRL, "rb").read())
    print("  подпись списка УЦ :", res["signature_ok"])
    print("  TEST-NCA отозван? :", res["revoked"], "(ожидаем False)")
    ok &= res["signature_ok"] and res["revoked"] is False

    if revoked_serials:
        some = revoked_serials[0]
        print("  отозванный serial :", hex(some), "-> crl_is_revoked:", crl_is_revoked(crl, some))
        ok &= crl_is_revoked(crl, some)

    print("OCSP (http://ocsp.pki.gov.kz):")
    ocsp_state = "ПРОПУЩЕН (сервис недоступен — проверка НЕ выполнялась)"
    try:
        nca_prod = open(os.path.join(kalkan_dir(), "nca_gost_2022.cer"), "rb").read()
        ocsp = ocsp_check(cert, nca_prod, "http://ocsp.pki.gov.kz",
                          verify_signature_response=True)
        print("  ответ на НАШ серт :", ocsp["status"], "| note:", ocsp["note"],
              "| подтверждён (подпись+доверие):", ocsp["status_trusted"])
        print("  this_update:", ocsp["this_update"])
        print("  подпись ответа    :", ocsp["signature_ok"],
              "| подписант:", ocsp["responder"],
              "| доверен УЦ:", ocsp["responder_trusted"],
              "| EKU OCSP Signing:", ocsp["responder_ocsp_eku"],
              "| свежий:", ocsp["fresh"])
        ok &= (ocsp["response_status"] == "successful" and ocsp["note"] is None
               and ocsp["status"] in ("good", "revoked") and ocsp["status_trusted"]
               and ocsp["responder_ocsp_eku"] is True and ocsp["fresh"] is True)
        # негатив: запрос с ЧУЖИМ УЦ не должен давать «good» по нашему сертификату
        other = ocsp_check(cert, open(os.path.join(kalkan_dir(), "root_gost_2022.cer"), "rb").read(),
                           "http://ocsp.pki.gov.kz")
        print("  чужой УЦ          :", other["status"], "| note:", other["note"])
        ok &= other["status"] != "good"
        ocsp_state = "ПРОВЕРЕН (живой сервис)"
    except Exception as ex:
        print("  OCSP недоступен   :", type(ex).__name__, str(ex)[:60])

    print("ИТОГ отзыва:", ("ВСЁ ОК — " + ocsp_state) if ok else "ЕСТЬ ПРОБЛЕМЫ",
          "| OCSP:", ocsp_state)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
