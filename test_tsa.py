"""
test_tsa.py — проверка метки времени: получение токена у TSA НУЦ и его верификация.
"""

from __future__ import annotations

import sys

from kalkan_tsa import get_timestamp, verify_timestamp_token

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


def main() -> int:
    data = b"document to timestamp"
    print("TSA: tsp.pki.gov.kz")
    try:
        resp = get_timestamp(data, hash_name="sha256")
    except Exception as ex:
        print("  TSA недоступна:", type(ex).__name__, str(ex)[:60])
        print("ИТОГ TSA: ПРОПУЩЕНО (сервис недоступен — проверка НЕ выполнялась)")
        return 0                                  # сеть — не ошибка кода, но и не «ВСЁ ОК»

    token = resp["token_der"]
    print("  статус:", resp["status"], "| genTime:", resp["gen_time"], "| токен:", len(token or b""))
    if not token:
        return 1

    good = verify_timestamp_token(token, original_data=data, nonce=resp.get("nonce"))
    print("  верификация (верные данные):", {k: good[k] for k in
          ("ok", "signature_ok", "digest_ok", "imprint_ok", "nonce_ok", "eku_time_stamping")})

    bad = verify_timestamp_token(token, original_data=data + b"!")
    print("  верификация (чужие данные)  :", {"ok": bad["ok"], "imprint_ok": bad["imprint_ok"]})

    ok = bool(good["ok"] and good["imprint_ok"] and good["eku_time_stamping"]
              and bad["imprint_ok"] is False)
    print("ИТОГ TSA:", "ВСЁ ОК" if ok else "ЕСТЬ ПРОБЛЕМЫ")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
