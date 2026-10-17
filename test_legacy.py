"""
test_legacy.py — устаревшие ГОСТ: СТ РК ГОСТ Р 34.311-95 (≈34.11-94) и 34.310-2004 (≈34.10-2001).

Без сети проверяется:
  1. ядро ГОСТ 28147-89 против Magma (gostcrypto) на векторе ГОСТ Р 34.13-2015 и 20 парах;
  2. хэш 34.11-94 против эталонов независимой реализации pygost и промежуточных
     значений RFC 5831 (K1 и KSI шага);
  3. сверка с KalkanCrypt.dll: HashData "Gost34311_95" == KZ-презентация нашего хэша;
  4. реальные legacy-объекты НУЦ РК из SDK: самоподпись корня, выпуск НУЦ корнем,
     негативные проверки и подпись CMS по signedAttrs.

Нет SDK/DLL — соответствующая часть печатает SKIP и не влияет на код возврата.
"""

from __future__ import annotations

import os
import random
import secrets
import sys

from kalkan_keys import kalkan_dir, sdk_dir
from kalkan_legacy import (GOST_28147_SBOX_TC26_Z, GOST_341194_SBOX_CRYPTOPRO,
                           GOST_341194_SBOX_TEST, CURVES_2001, _A, _C2, _P,
                           _hash_step, _is_on_curve, _point_add, _point_mul, _xor,
                           curve_by_oid, gost28147_encrypt, gost341194, gost341194_kz,
                           verify_signature_2001)
from kalkan_verify import load_certificate, verify_certificate, verify_cms

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

SDK = sdk_dir()

# --- эталоны (сверены с pygost 0.15) ---------------------------------------

PYGOST_FOOBAR = "af33c120ea490856eb331106dc28a0ee577c3ee7f9490dfa1d871759a3a3d83b"
#: значение из докстроки pygost — это тот же хэш в обратной (казахстанской) презентации
PYGOST_FOOBAR_REVERSED = "3bd8a3a35917871dfa0d49f9e73e7c57eea028dc061133eb560849ea20c133af"
HASH_TEST = {
    b"": "8d0f49492c91f45a68ff5c05d2c2b4ab78027b9aab5ce3feff5267c49cb985ce",
    b"abc": "1dd5a4067c49703b75bc75c9290f5ecbb5eb85229e7277a2b2b14fc4484313f3",
    b"foobar": PYGOST_FOOBAR,
    bytes(32): "d1d299a314b55b938293d579e13863bc036f8458fe717a1c26b47f8a73886540",
}
HASH_CP_ABC = "2cd42ff986293b167e994381ed59747414dd24953677762d39d718bf6d0585b2"

# --- RFC 5831, §7.3.1, STEP 3 -------------------------------------------------
RFC_H = bytes.fromhex("95BEA0BE88D5AA02FE3C9D45436CE821B8287CB62CBC135B3E339EFEF6576CA9")
RFC_M = bytes.fromhex("00" * 28 + "00000190")
RFC_K1 = bytes.fromhex("95FEB83EBE3C2833A09D7C9EBE45B6FE88432CF6D56CBC57AAE8136D02215B39")
RFC_K2 = bytes.fromhex("8695FEB81BBE3C28E2A09D7C48BE45B6DA88432CEBD56CBC7FABE813F292215B")
RFC_KSI = bytes.fromhex("47E26AFD3E7278A17D47378506140773A3D97E7EA744CB4308AA4C243352C745")


def test_28147_vs_magma() -> bool:
    from gostcrypto import gostcipher
    key = bytes.fromhex("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    plain = bytes.fromhex("fedcba9876543210")
    ok = gost28147_encrypt(key, plain, GOST_28147_SBOX_TC26_Z) == \
        gostcipher.GOST34122015Magma(key).encrypt(plain)
    print("ГОСТ 28147-89 == Magma на векторе ГОСТ Р 34.13-2015:", ok)
    for _ in range(20):
        k = bytes(secrets.randbits(8) for _ in range(32))
        b = bytes(secrets.randbits(8) for _ in range(8))
        if gost28147_encrypt(k, b, GOST_28147_SBOX_TC26_Z) != \
                gostcipher.GOST34122015Magma(k).encrypt(b):
            print("  расхождение с Magma на случайной паре")
            return False
    print("  ещё 20 случайных пар ключ/блок совпали")
    return ok


def test_hash_vectors() -> bool:
    ok = True
    for data, expected in HASH_TEST.items():
        got = gost341194(data, GOST_341194_SBOX_TEST).hex()
        if got != expected:
            print(f"  хэш(test) {len(data)} байт: {got} != {expected}")
            ok = False
    got_cp = gost341194(b"abc", GOST_341194_SBOX_CRYPTOPRO).hex()
    if got_cp != HASH_CP_ABC:
        print(f"  хэш(КриптоПро) 'abc': {got_cp} != {HASH_CP_ABC}")
        ok = False
    #: значение КриптоПро — вывод независимой реализации pygost (его встроенная таблица);
    #: построчная сверка таблиц и 32 сравнения хэшей выполняются в test_pygost_crosscheck
    if gost341194(b"foobar", GOST_341194_SBOX_TEST)[::-1].hex() != PYGOST_FOOBAR_REVERSED:
        print("  KZ-презентация 'foobar' не совпала со значением из докстроки pygost")
        ok = False
    print("хэш 34.11-94 совпал с эталонами (тест-набор: pygost + DLL; КриптоПро: pygost):", ok)
    return ok


def test_rfc5831_step() -> bool:
    """Проверка шаговой функции по промежуточным значениям RFC 5831."""
    k1 = _P(_xor(RFC_H, RFC_M))
    u = _xor(_A(RFC_H), _C2)
    v = _A(_A(RFC_M))
    k2 = _P(_xor(u, v))
    if k1 != RFC_K1:
        print("  подключ K1 не совпал с RFC 5831")
        return False
    if k2 != RFC_K2:
        print("  подключ K2 не совпал с RFC 5831")
        return False
    if _hash_step(RFC_H, RFC_M, GOST_341194_SBOX_TEST) != RFC_KSI:
        print("  результат шага (KSI) не совпал с RFC 5831")
        return False
    print("шаговая функция совпала с RFC 5831 (K1, K2 и KSI): True")
    return True

def test_curve_arithmetic() -> bool:
    """Закон группы кривой: q*G = бесконечность, 2G = G+G, G лежит на кривой."""
    curve = CURVES_2001["id-GostR3410-2001-CryptoPro-A-ParamSet"]
    g = (curve["x"], curve["y"])
    checks = {
        "q*G == бесконечность": _point_mul(curve["q"], g, curve)[0] is None,
        "2G == G+G": _point_mul(2, g, curve) == _point_add(g, g, curve),
        "G на кривой": _is_on_curve(g[0], g[1], curve),
        "G+(-G) == бесконечность": _point_add(
            g, (g[0], (curve["p"] - g[1]) % curve["p"]), curve)[0] is None,
    }
    ok = all(checks.values())
    for name, got in checks.items():
        print(f"  {name}: {got}")
    print("арифметика кривой (ГОСТ Р 34.10-2001, набор A):", ok)
    return ok


def _test_signature(curve, private_key: int, digest: bytes, k: int):
    """Детерминированная подпись ГОСТ Р 34.10-2001 (для офлайн-вектора теста)."""
    q = curve["q"]
    e = int.from_bytes(digest, "little") % q or 1
    r = _point_mul(k, (curve["x"], curve["y"]), curve)[0] % q
    s = (r * private_key + k * e) % q
    pub = _point_mul(private_key, (curve["x"], curve["y"]), curve)
    public_key = pub[0].to_bytes(32, "little") + pub[1].to_bytes(32, "little")
    signature = r.to_bytes(32, "little") + s.to_bytes(32, "little")
    return public_key, signature


def test_self_made_signature() -> bool:
    """
    Офлайн-вектор 34.10-2001 без SDK: ключ и подпись считаются прямо в тесте.

    Плюс негативные регрессы на находки ревью: сценарии, в которых реализация
    без проверки ключа/бесконечности «принимала» подпись.
    """
    curve = CURVES_2001["id-GostR3410-2001-CryptoPro-A-ParamSet"]
    q, p, gx, gy = curve["q"], curve["p"], curve["x"], curve["y"]
    d = 0x00112233445566778899AABBCCDDEEFF0011223344556677889900AABBCCDD01
    digest = gost341194_kz(b"legacy self-test 34.10-2001 vector")
    k = 0x00000000000000000000000000000000000000000000000000000000000C0FFEE1
    public_key, signature = _test_signature(curve, d, digest, k)
    bad_digest = gost341194_kz(b"legacy self-test 34.10-2001 vector!")

    checks = [
        ("своя корректная подпись", verify_signature_2001(public_key, digest, signature,
                                                         curve, "little"), True),
        ("другой хэш", verify_signature_2001(public_key, bad_digest, signature,
                                            curve, "little"), False),
        ("испорченный байт подписи",
         verify_signature_2001(public_key, digest,
                               signature[:5] + bytes([signature[5] ^ 1]) + signature[6:],
                               curve, "little"), False),
    ]
    # негативные регрессы: раньше давали True
    r_neg = (p - 2) % q
    e_neg = (q - r_neg) % q
    pub_neg = gx.to_bytes(32, "little") + ((p - gy) % p).to_bytes(32, "little")
    sig_neg = r_neg.to_bytes(32, "little") + e_neg.to_bytes(32, "little")
    checks += [
        ("ключ = противоположная базовая точка (Q = -G)",
         verify_signature_2001(pub_neg, e_neg.to_bytes(32, "little"), sig_neg,
                               curve, "little"), False),
        ("нулевой «ключ» (точка не на кривой)",
         verify_signature_2001(bytes(64), e_neg.to_bytes(32, "little"),
                               (163).to_bytes(32, "little") + e_neg.to_bytes(32, "little"),
                               curve, "little"), False),
        ("пустой ключ", verify_signature_2001(b"", digest, signature, curve, "little"), False),
        ("подпись 63 байта", verify_signature_2001(public_key, digest, signature[:63],
                                                   curve, "little"), False),
        ("пустой хэш", verify_signature_2001(public_key, b"", signature,
                                             curve, "little"), False),
    ]
    ok = True
    for name, got, want in checks:
        print(f"  {name}: {got} (ожидается {want})")
        ok &= got is want
    print("офлайн-вектор 34.10-2001 и негативные сценарии:", ok)
    return ok


def test_pygost_crosscheck() -> bool:
    """
    Честная сверка с независимой реализацией pygost (если она установлена).

    Важно: НЕ подменяем таблицы в pygost — сравниваем нашу реализацию с его
    встроенными наборами параметров и отдельно сверяем сами таблицы построчно.
    Иначе проверка становится самореферентной (сравнение кода с самим собой).
    """
    try:
        import pygost.gost28147 as g47
        from pygost.gost3411_94 import GOST341194
    except Exception:
        print("ПРОПУЩЕНО: pygost не установлен — независимая сверка хэша не выполнялась")
        return True

    ok = True
    for label, mine, builtin in (
            ("тестовый набор", GOST_341194_SBOX_TEST, "GostR3411_94_TestParamSet"),
            ("набор КриптоПро", GOST_341194_SBOX_CRYPTOPRO,
             "GostR3411_94_CryptoProParamSet")):
        same_table = (mine == g47.SBOXES[builtin])
        print(f"  таблица ({label}) совпала построчно со встроенной у pygost: {same_table}")
        ok &= same_table

    rng = random.Random(20261016)
    cases = [b"", b"a", b"abc", b"foobar", bytes(32), bytes(33), bytes(64)]
    cases += [bytes(rng.randrange(256) for _ in range(rng.randrange(0, 200)))
              for _ in range(25)]
    for label, mine, builtin in (
            ("тестовый набор", GOST_341194_SBOX_TEST, "GostR3411_94_TestParamSet"),
            ("набор КриптоПро", GOST_341194_SBOX_CRYPTOPRO,
             "GostR3411_94_CryptoProParamSet")):
        bad = sum(gost341194(data, mine).hex() != GOST341194(data, sbox=builtin).hexdigest()
                  for data in cases)
        print(f"  сверка хэшей ({label}): {len(cases)} входов, расхождений {bad}")
        ok &= bad == 0
    print("сверка с pygost (встроенные наборы, без подмены таблиц):", ok)
    return ok


def test_kz_presentation() -> bool:
    """Хэш в казахстанской презентации должен совпадать с HashData "Gost34311_95"."""
    try:
        from kalkan_dll import KalkanOracle
        oracle = KalkanOracle()
        oracle.init()
    except Exception as ex:
        print(f"SKIP: KalkanCrypt.dll недоступен ({type(ex).__name__}) — сверка не выполнялась")
        return True
    ok = True
    for data in (b"", b"a", b"abc", bytes(32), b"1234567890", bytes(range(200))):
        rc, ref = oracle.hash_data("Gost34311_95", data)
        mine = gost341194_kz(data).hex()
        if rc != 0 or mine != ref.hex():
            ok = False
            print(f"  {len(data)} байт: {mine[:24]} != {ref.hex()[:24]}")
    oracle.finalize()
    print('KZ-презентация == HashData "Gost34311_95":', ok)
    return ok


def _load_der(path):
    import base64
    raw = open(path, "rb").read()
    if b"-----BEGIN" in raw:
        body = b"".join(l for l in raw.splitlines() if not l.startswith(b"-----"))
        return base64.b64decode(body)
    return raw


def test_legacy_objects() -> bool:
    base = os.path.join(SDK, "Keys and Certs", "CA_Test")
    old_root = os.path.join(base, "ROOT", "old", "root_gost_test_old.crt")
    old_nca = os.path.join(base, "NCA", "old", "nca_gost_test_old.crt")
    cms_path = os.path.join(SDK, "C", "Linux", "C", "test", "example", "test_CMS_GOST.txt")
    if not (os.path.exists(old_root) and os.path.exists(old_nca)):
        print("SKIP: legacy-объекты НУЦ не найдены (задайте KALKAN_DIR) — проверка не выполнялась")
        return True

    root, nca = _load_der(old_root), _load_der(old_nca)
    cert = load_certificate(root)
    print("legacy-сертификат: подпись", cert["signature_algorithm"]["algorithm"].dotted)

    from kalkan_verify import _spki_from_cert, _tbs_from_cert, public_key_from_spki
    curve = curve_by_oid("1.2.398.3.10.1.1.1.1.1")      # OID из KeyParams сертификата НУЦ
    _, pk = public_key_from_spki(_spki_from_cert(root))
    digest = gost341194_kz(_tbs_from_cert(root))
    sig = bytes(cert["signature_value"].native)
    wrong = bytearray(sig)
    wrong[5] ^= 0xFF

    checks = [
        ("самоподпись корня (34.10-2001)", verify_certificate(root, root), True),
        ("сертификат НУЦ под корнем", verify_certificate(nca, root), True),
        ("НУЦ «сам за себя»", verify_certificate(nca, nca), False),
        ("подпись с испорченным байтом",
         verify_signature_2001(pk, digest, bytes(wrong), curve, "little"), False),
    ]
    broken = bytearray(nca)
    broken[-1] ^= 0x01
    checks.append(("сертификат НУЦ с испорченной подписью",
                   verify_certificate(bytes(broken), root), False))

    ok = True
    for name, got, want in checks:
        print(f"  {name}: {got} (ожидается {want})")
        ok &= got is want

    if os.path.exists(cms_path):
        res = verify_cms(open(cms_path, "rb").read())
        if not res["signers"]:
            print("  CMS: подписантов не найдено — проверка не состоялась")
            ok = False
        for signer in res["signers"]:
            print("  CMS:", signer["digest_oid"], signer["signature_oid"],
                  "| digest_ok =", signer["digest_ok"],
                  "| signature_ok =", signer["signature_ok"], "| state =", signer["state"])
            ok &= (signer["state"] == "ok" and bool(signer["digest_ok"])
                   and bool(signer["signature_ok"]))
    else:
        print("ПРОПУЩЕНО: тестовый legacy-CMS не найден — проверка CMS не выполнялась")
    return ok


def main() -> int:
    print("=== устаревшие ГОСТ (34.11-94 / 34.10-2001) ===")
    ok = True
    for test in (test_28147_vs_magma, test_hash_vectors, test_pygost_crosscheck,
                 test_rfc5831_step, test_curve_arithmetic, test_self_made_signature,
                 test_kz_presentation, test_legacy_objects):
        ok &= test()
    print("\nИТОГ:", "OK" if ok else "ЕСТЬ ОШИБКИ")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
