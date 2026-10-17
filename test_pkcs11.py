"""
test_pkcs11.py — проверка обёртки PKCS#11 (kalkan_pkcs11.py).

Часть 1 (всегда): end-to-end на мок-модуле PKCS#11 без железа. Мок отдаёт
    сертификат и приватный ключ, а C_Sign возвращает подпись ГОСТ в конвенции
    токена (r||s, little-endian по половине). Подпись проверяем нашим
    верификатором по сертификату — контракт «токен -> проверка».

Часть 2 (если есть модуль): проба загрузки реального модуля PKCS#11
    (по умолчанию knca_pkcs11.dll из SDK; можно задать KNCA_PKCS11, напр. SoftHSM2).
"""

from __future__ import annotations

import ctypes
import os
import sys

from kalkan_pkcs11 import (CKA_CLASS, CKA_ID, CKA_LABEL, CKA_VALUE, CKM_GOSTR3410,
                           CKM_GOSTR3410_WITH_GOSTR3411, CKO_CERTIFICATE,
                           CKO_PRIVATE_KEY, CKR_ATTRIBUTE_TYPE_INVALID, CKR_BUFFER_TOO_SMALL,
                           CKR_OK, CK_UNAVAILABLE_INFORMATION, Pkcs11Error, Pkcs11Token, UL)

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from kalkan_keys import kalkan_dir, sdk_dir

DEFAULT_MODULE = os.environ.get("KNCA_PKCS11") or os.path.join(
    sdk_dir(), "C", "Windows", "pkcs11_module",
    "x64", "knca_pkcs11.dll")


class MockPkcs11Module:
    """Мок PKCS#11: один токен, один сертификат и один приватный ключ ГОСТ."""

    def __init__(self, cert_der: bytes, key_be: bytes, cert_id: bytes = b"\x2a\x2b"):
        self.cert_der = cert_der
        self.key_be = key_be
        self.objects = [
            {"handle": 0x1001, "class": CKO_CERTIFICATE, "id": cert_id,
             "label": b"TOKEN CERT", "value": cert_der},
            {"handle": 0x1002, "class": CKO_PRIVATE_KEY, "id": cert_id,
             "label": b"TOKEN KEY", "value": b""},
        ]
        self._found: list = []
        self._mechanism = None
        self.inaccessible: set = set()          # атрибуты, которые носитель не отдаёт
        self.oversize_on_value_pass: set = set()  # атрибуты, «не влезающие» в буфер
        self.last_pin = None
        self.last_pin_len = None
        self.session_opened = False

    def _obj(self, handle):
        return next((o for o in self.objects if o["handle"] == handle), None)

    def C_Initialize(self, p): return CKR_OK
    def C_Finalize(self, p): return CKR_OK
    def C_GetInfo(self, info): return CKR_OK

    def C_GetSlotList(self, present, arr, count):
        if not arr:
            count.value = 1
        else:
            arr[0] = 7
        return CKR_OK

    def C_GetTokenInfo(self, slot, info):
        info.label[:5] = b"SOFT "
        info.manufacturerID[:5] = b"MOCK "
        return CKR_OK

    def C_OpenSession(self, slot, flags, app, notify, out):
        out.value = 0x2222
        self.session_opened = True
        return CKR_OK

    def C_CloseSession(self, session):
        self.session_opened = False
        return CKR_OK

    def C_Login(self, session, user, pin, plen):
        self.last_pin = ctypes.string_at(pin, plen) if pin else b""
        self.last_pin_len = plen
        return CKR_OK

    def C_Logout(self, session): return CKR_OK

    def C_FindObjectsInit(self, session, template, n):
        wanted = ctypes.cast(template[0].pValue, ctypes.POINTER(UL)).contents.value
        self._found = [o["handle"] for o in self.objects if o["class"] == wanted]
        return CKR_OK

    def C_FindObjects(self, session, buf, max_count, count):
        chunk, self._found = self._found[:max_count], self._found[max_count:]
        for i, h in enumerate(chunk):
            buf[i] = h
        count.value = len(chunk)
        return CKR_OK

    def C_FindObjectsFinal(self, session):
        self._found = []
        return CKR_OK

    def C_GetAttributeValue(self, session, handle, template, n):
        obj = self._obj(handle)
        if obj is None:
            return 0x000000A0  # CKR_OBJECT_HANDLE_INVALID
        values = {CKA_CLASS: obj["class"].to_bytes(ctypes.sizeof(UL), "little"),
                  CKA_ID: obj["id"], CKA_LABEL: obj["label"], CKA_VALUE: obj["value"]}
        rc = CKR_OK
        for i in range(n):
            if template[i].type in self.inaccessible:   # как ведёт себя реальный носитель
                template[i].ulValueLen = CK_UNAVAILABLE_INFORMATION
                rc = CKR_ATTRIBUTE_TYPE_INVALID
                continue
            if template[i].pValue and template[i].type in self.oversize_on_value_pass:
                template[i].ulValueLen = template[i].ulValueLen + 100  # «не влезло»
                rc = CKR_BUFFER_TOO_SMALL
                continue
            data = values.get(template[i].type, b"")
            if not template[i].pValue:
                template[i].ulValueLen = len(data)      # запрос размера
            else:
                if data:
                    ctypes.memmove(template[i].pValue, data, len(data))
                template[i].ulValueLen = len(data)
        return rc

    def C_GetMechanismList(self, slot, arr, count):
        mechanisms = [0x00001201, 0x00001202, 0x00001210]
        if not arr:
            count.value = len(mechanisms)
        else:
            for i, m in enumerate(mechanisms):
                arr[i] = m
        return CKR_OK

    def C_SignInit(self, session, mech, key):
        self._mechanism = getattr(mech, "mechanism", None)
        return CKR_OK

    def C_Sign(self, session, data, dlen, out, outlen):
        """Как настоящий токен: WITH_GOSTR3411 хэширует сам, CKM_GOSTR3410 подписывает готовый хэш."""
        from kalkan_sign import _sign_der, raw_sign
        payload = ctypes.string_at(data, dlen)
        if self._mechanism == CKM_GOSTR3410_WITH_GOSTR3411:
            signature = raw_sign(self.key_be, payload)
        else:
            signature = _sign_der(self.key_be, payload)
        if not out:
            outlen.value = len(signature)               # запрос размера
        else:
            ctypes.memmove(out, signature, len(signature))
            outlen.value = len(signature)
        return CKR_OK


def test_mock_end_to_end() -> bool:
    """Полный цикл PKCS#11 (init -> slots -> login -> find -> sign) без железа."""
    from kalkan_sign import create_self_signed_certificate, raw_verify
    from kalkan_verify import verify_cms

    key_be = os.urandom(64)
    cert_der = create_self_signed_certificate(key_be, "TOKEN TEST")
    token = Pkcs11Token(module=MockPkcs11Module(cert_der, key_be))

    token.initialize()
    slots = token.slots(token_present=True)
    token.open_session(slots[0])
    token.login("123456")

    certs = token.find_certificates()
    keys = token.find_private_keys()
    data = "проверка подписи на токене".encode("utf-8")
    key_id = certs[0]["id"]

    # RAW: токен хэширует сам (CKM_GOSTR3410_WITH_GOSTR3411)
    signature = token.sign(data, mechanism=CKM_GOSTR3410_WITH_GOSTR3411, key_id=key_id)
    # RAW: хэш считаем сами, токен подписывает готовый дайджест (CKM_GOSTR3410)
    signature2 = token.sign_raw(data, size=64, key_id=key_id)
    # CMS: токен подписывает signedAttributes, контейнер собираем сами
    cms_bytes = token.sign_cms(data, cert_der, key_id=key_id)
    token.finalize()

    ok_cert = len(certs) == 1 and certs[0]["certificate_der"] == cert_der
    ok_key = len(keys) == 1 and keys[0]["id"] == certs[0]["id"]
    ok_sig = raw_verify(signature, data, cert_der)
    ok_sig2 = raw_verify(signature2, data, cert_der)
    signer = verify_cms(cms_bytes)["signers"][0]
    ok_cms = signer["state"] == "ok"
    tampered = verify_cms(cms_bytes, detached_content=data + b"!")["signers"][0]
    ok_neg = tampered["state"] == "failed"

    print("  слоты:", slots, "| сертификатов:", len(certs), "| ключей:", len(keys))
    print("  сертификат совпал:", ok_cert, "| ключ найден по CKA_ID:", ok_key)
    print("  RAW (токен хэширует):", ok_sig, "| RAW (готовый дайджест):", ok_sig2,
          "| len:", len(signature), "/", len(signature2))
    print("  CMS с токена -> verify_cms:", ok_cms, "| state:", signer["state"],
          "| подмена данных отвергнута:", ok_neg)
    return all([ok_cert, ok_key, ok_sig, ok_sig2, ok_cms, ok_neg])


def test_tolerant_attributes() -> bool:
    """Носитель не отдаёт часть атрибутов (CK_UNAVAILABLE_INFORMATION) — поиск не должен падать."""
    from kalkan_sign import create_self_signed_certificate, raw_verify

    key_be = os.urandom(64)
    cert_der = create_self_signed_certificate(key_be, "ATTR TEST")
    module = MockPkcs11Module(cert_der, key_be)
    module.inaccessible = {CKA_LABEL}                   # у объектов нет метки

    token = Pkcs11Token(module=module)
    token.initialize()
    try:
        with token.session(7, pin="123456"):            # контекст: сессия закрывается сама
            mechanisms = token.mechanisms()
            certs = token.find_certificates()
            keys = token.find_private_keys()
            signature = token.sign_raw(b"data", size=64, key_id=certs[0]["id"])
    finally:
        token.finalize()

    ok_cert = len(certs) == 1 and certs[0]["certificate_der"] == cert_der
    ok_label = certs[0]["label"] == ""                  # недоступный атрибут пропущен, не упал
    ok_mech = mechanisms[:2] == [0x00001201, 0x00001202]
    ok_sign = len(keys) == 1 and raw_verify(signature, b"data", cert_der)
    ok_closed = not token._logged and token._session is None
    print("  недоступные атрибуты: поиск выжил:", ok_cert and ok_label and ok_sign,
          "| метки нет, но объекты найдены:", len(certs), "/", len(keys))
    print("  C_GetMechanismList:", [hex(m) for m in mechanisms], "->", ok_mech)
    print("  сессия закрыта контекстом:", ok_closed)
    return all([ok_cert, ok_label, ok_mech, ok_sign, ok_closed])


def test_pin_and_oversize() -> bool:
    """PIN уходит в байтах (не символах); атрибут, не влезший в буфер, не отдаётся обрезком."""
    from kalkan_sign import create_self_signed_certificate

    key_be = os.urandom(64)
    cert_der = create_self_signed_certificate(key_be, "PIN TEST")
    module = MockPkcs11Module(cert_der, key_be)
    module.oversize_on_value_pass = {CKA_LABEL}

    token = Pkcs11Token(module=module)
    token.initialize()
    try:
        with token.session(7, pin="пароль"):            # не-ASCII PIN: 6 символов / 12 байт
            certs = token.find_certificates()
    finally:
        token.finalize()

    pin_bytes = "пароль".encode("utf-8")
    ok_pin = module.last_pin_len == len(pin_bytes) and module.last_pin == pin_bytes
    ok_guard = certs[0]["certificate_der"] == cert_der and certs[0]["label"] == ""
    print("  PIN ушёл байтами:", ok_pin, f"(передано {module.last_pin_len} байт,",
          f"ожидалось {len(pin_bytes)})")
    print("  обрезанный атрибут пропущен, сертификат цел:", ok_guard)
    return ok_pin and ok_guard


def _nss_bootstrap(module: str):
    """Для NSS softokn3.dll: инициализирует NSS (NoDB) через nss3.dll из той же папки."""
    if os.path.basename(module).lower() != "softokn3.dll":
        return None
    nss_dir = os.path.dirname(module)
    if not os.path.exists(os.path.join(nss_dir, "nss3.dll")):
        return None
    os.add_dll_directory(nss_dir)
    nss3 = ctypes.WinDLL(os.path.join(nss_dir, "nss3.dll"))
    nss3.NSS_NoDB_Init.argtypes = [ctypes.c_char_p]
    nss3.NSS_NoDB_Init.restype = ctypes.c_int
    print("  NSS_NoDB_Init rc:", nss3.NSS_NoDB_Init(b""))
    return nss3


def probe_real_module(module: str) -> None:
    """Проба реального модуля PKCS#11 (если доступен)."""
    print("модуль PKCS#11:", module)
    if not os.path.exists(module):
        print("  не найден — пропуск")
        return
    nss3 = _nss_bootstrap(module)
    try:
        token = Pkcs11Token(module)
    except (Pkcs11Error, OSError) as ex:
        print("  не удалось загрузить:", ex)
        return
    try:
        token.initialize()
    except (Pkcs11Error, OSError) as ex:
        print("  C_GetFunctionList получен, но C_Initialize не прошёл:",
              type(ex).__name__, ex)
        return
    print("  библиотека :", token.library_info())
    slots = token.slots(token_present=True)
    print("  с токеном  :", len(slots), "| всего слотов:", len(token.slots(False)))
    for slot in slots:
        try:
            info = token.token_info(slot)
            print("   слот", info)
        except Pkcs11Error as ex:
            print(f"   слот {slot}: нет токена ({ex})")
    token.finalize()
    if nss3 is not None:
        try:
            nss3.NSS_Shutdown()
        except Exception:
            pass


def main() -> int:
    print("== Часть 1: end-to-end на мок-модуле (без железа) ==")
    ok1 = test_mock_end_to_end()
    print("\n== Часть 1b: устойчивость к недоступным атрибутам ==")
    ok2 = test_tolerant_attributes()
    print("\n== Часть 1c: PIN в байтах и обрезанные атрибуты ==")
    ok3 = test_pin_and_oversize()
    print("\n== Часть 2: проба реального модуля ==")
    probe_real_module(os.environ.get("KNCA_PKCS11", DEFAULT_MODULE))
    ok = ok1 and ok2 and ok3
    print("\nИТОГ PKCS#11:", "ВСЁ ОК" if ok else "ЕСТЬ ПРОБЛЕМЫ")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

