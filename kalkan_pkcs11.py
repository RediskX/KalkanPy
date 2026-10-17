"""
kalkan_pkcs11.py — доступ к токенам (Kaztoken/eToken/JaCarta/aKey) через PKCS#11.

Приватный ключ НЕ извлекается: подпись выполняется на токене (C_Sign). Математика
подписи та же (ГОСТ 2015 / RSA), поэтому функция даёт r||s в конвенции НУЦ.

Модуль PKCS#11 берётся у производителя носителя:
    * Kaztoken      : knca_pkcs11.dll (из SDK НУЦ);
    * eToken/JaCarta/aKey : PKCS#11-модуль соответствующего вендора;
    * без железа для тестов годится программный HSM (SoftHSM2).

Examples:
    token = Pkcs11Token(r"...\\knca_pkcs11.dll")
    token.open(pin="123456")
    token.sign(data, mechanism=Pkcs11Token.CKM_GOSTR3410_WITH_GOSTR3411)
"""

from __future__ import annotations

import contextlib
import ctypes
import os
from typing import Optional

__all__ = ["Pkcs11Token", "Pkcs11Error"]

# --- CK_* константы --------------------------------------------------------
CKR_OK = 0x00000000
CKR_ATTRIBUTE_SENSITIVE = 0x00000011
CKR_ATTRIBUTE_TYPE_INVALID = 0x00000012
CKR_BUFFER_TOO_SMALL = 0x00000150
CKR_CRYPTOKI_ALREADY_INITIALIZED = 0x00000191
CK_UNAVAILABLE_INFORMATION = 0xFFFFFFFF
CKF_RW_SESSION = 0x00000002
CKF_SERIAL_SESSION = 0x00000004
CKU_USER = 0x00000001

#: атрибут не отдан модулем (нет/недоступен) — не фатально для остальных
_TOLERATED_ATTR_ERRORS = (CKR_ATTRIBUTE_SENSITIVE, CKR_ATTRIBUTE_TYPE_INVALID,
                          CKR_BUFFER_TOO_SMALL)
#: разумный потолок значения атрибута (защита от CK_UNAVAILABLE_INFORMATION/мусора)
_MAX_ATTR_SIZE = 1 << 20

CKA_CLASS = 0x00000000
CKA_LABEL = 0x00000003
CKA_VALUE = 0x00000011
CKA_ID = 0x00000102
CKA_KEY_TYPE = 0x00000100

CKO_CERTIFICATE = 0x00000001
CKO_PRIVATE_KEY = 0x00000003

# механизмы ГОСТ (TC26/КриптоПро)
CKM_GOSTR3410 = 0x00001201
CKM_GOSTR3410_WITH_GOSTR3411 = 0x00001202


class Pkcs11Error(Exception):
    """Ошибка PKCS#11 (CKR_*) либо загрузки модуля."""


# --- структуры PKCS#11 -----------------------------------------------------
# ВАЖНО: структуры PKCS#11 объявлены как УПАКОВАННЫЕ (#pragma pack(1) в эталонных
# pkcs11.h/pkcs11t.h). На win64 без _pack_ смещения полей не совпадают с модулем,
# и вызов функции по адресу из CK_FUNCTION_LIST роняет процесс. Проверено на
# реальном softokn3.dll: без упаковки — крах, с _pack_=1 — C_GetInfo даёт Cryptoki 2.40.

class CK_VERSION(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("major", ctypes.c_ubyte), ("minor", ctypes.c_ubyte)]


class CK_INFO(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("cryptokiVersion", CK_VERSION),
        ("manufacturerID", ctypes.c_ubyte * 32),
        ("flags", ctypes.c_ulong),
        ("libraryDescription", ctypes.c_ubyte * 32),
        ("libraryVersion", CK_VERSION),
    ]


class CK_SLOT_INFO(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("slotDescription", ctypes.c_ubyte * 64),
        ("manufacturerID", ctypes.c_ubyte * 32),
        ("flags", ctypes.c_ulong),
        ("hardwareVersion", CK_VERSION),
        ("firmwareVersion", CK_VERSION),
    ]


class CK_TOKEN_INFO(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("label", ctypes.c_ubyte * 32),
        ("manufacturerID", ctypes.c_ubyte * 32),
        ("model", ctypes.c_ubyte * 16),
        ("serialNumber", ctypes.c_ubyte * 16),
        ("flags", ctypes.c_ulong),
        ("ulMaxSessionCount", ctypes.c_ulong),
        ("ulSessionCount", ctypes.c_ulong),
        ("ulMaxRwSessionCount", ctypes.c_ulong),
        ("ulRwSessionCount", ctypes.c_ulong),
        ("ulMaxPinLen", ctypes.c_ulong),
        ("ulMinPinLen", ctypes.c_ulong),
        ("ulTotalPublicMemory", ctypes.c_ulong),
        ("ulFreePublicMemory", ctypes.c_ulong),
        ("ulTotalPrivateMemory", ctypes.c_ulong),
        ("ulFreePrivateMemory", ctypes.c_ulong),
        ("hardwareVersion", CK_VERSION),
        ("firmwareVersion", CK_VERSION),
        ("utcTime", ctypes.c_ubyte * 16),
    ]


class CK_ATTRIBUTE(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("type", ctypes.c_ulong),
                ("pValue", ctypes.c_void_p),
                ("ulValueLen", ctypes.c_ulong)]


class CK_MECHANISM(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("mechanism", ctypes.c_ulong),
                ("pParameter", ctypes.c_void_p),
                ("ulParameterLen", ctypes.c_ulong)]


# Порядок функций по PKCS#11 v2.40 (до C_Sign включительно). Поля — просто адреса.
_FUNC_NAMES = [
    "C_Initialize", "C_Finalize", "C_GetInfo", "C_GetFunctionList",
    "C_GetSlotList", "C_GetSlotInfo", "C_GetTokenInfo", "C_GetMechanismList",
    "C_GetMechanismInfo", "C_InitToken", "C_InitPIN", "C_SetPIN",
    "C_OpenSession", "C_CloseSession", "C_CloseAllSessions", "C_GetSessionInfo",
    "C_GetOperationState", "C_SetOperationState", "C_Login", "C_Logout",
    "C_CreateObject", "C_CopyObject", "C_DestroyObject", "C_GetObjectSize",
    "C_GetAttributeValue", "C_SetAttributeValue", "C_FindObjectsInit",
    "C_FindObjects", "C_FindObjectsFinal", "C_EncryptInit", "C_Encrypt",
    "C_EncryptUpdate", "C_EncryptFinal", "C_DecryptInit", "C_Decrypt",
    "C_DecryptUpdate", "C_DecryptFinal", "C_DigestInit", "C_Digest",
    "C_DigestUpdate", "C_DigestKey", "C_DigestFinal", "C_SignInit", "C_Sign",
]


class CK_FUNCTION_LIST(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("version", CK_VERSION)] + [(n, ctypes.c_void_p) for n in _FUNC_NAMES]


UL = ctypes.c_ulong
WIN = ctypes.WINFUNCTYPE
SIG = {
    "C_Initialize": WIN(UL, ctypes.c_void_p),
    "C_Finalize": WIN(UL, ctypes.c_void_p),
    "C_GetInfo": WIN(UL, ctypes.POINTER(CK_INFO)),
    "C_GetSlotList": WIN(UL, ctypes.c_ubyte, ctypes.POINTER(UL), ctypes.POINTER(UL)),
    "C_GetTokenInfo": WIN(UL, UL, ctypes.POINTER(CK_TOKEN_INFO)),
    "C_GetMechanismList": WIN(UL, UL, ctypes.POINTER(UL), ctypes.POINTER(UL)),
    "C_OpenSession": WIN(UL, UL, UL, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(UL)),
    "C_CloseSession": WIN(UL, UL),
    "C_Login": WIN(UL, UL, UL, ctypes.c_char_p, UL),
    "C_Logout": WIN(UL, UL),
    "C_FindObjectsInit": WIN(UL, UL, ctypes.POINTER(CK_ATTRIBUTE), UL),
    "C_FindObjects": WIN(UL, UL, ctypes.POINTER(UL), UL, ctypes.POINTER(UL)),
    "C_FindObjectsFinal": WIN(UL, UL),
    "C_GetAttributeValue": WIN(UL, UL, UL, ctypes.POINTER(CK_ATTRIBUTE), UL),
    "C_SignInit": WIN(UL, UL, ctypes.POINTER(CK_MECHANISM), UL),
    "C_Sign": WIN(UL, UL, ctypes.c_char_p, UL, ctypes.c_char_p, ctypes.POINTER(UL)),
}


class Pkcs11Token:
    """Обёртка над PKCS#11-модулем: слоты, сессия, поиск объектов, подпись."""

    CKM_GOSTR3410 = CKM_GOSTR3410
    CKM_GOSTR3410_WITH_GOSTR3411 = CKM_GOSTR3410_WITH_GOSTR3411

    def __init__(self, module_path: Optional[str] = None, *, module=None):
        """
        module_path — путь к .dll PKCS#11; либо module — объект-заглушка с методами C_*
        (для тестов без железа).
        """
        self._session: Optional[int] = None
        self._slot: Optional[int] = None
        self._logged = False
        if module is not None:
            self._lib = None
            self._funcs = module
            return
        if not os.path.exists(module_path):
            raise Pkcs11Error(f"модуль PKCS#11 не найден: {module_path}")
        os.add_dll_directory(os.path.dirname(module_path))
        self._lib = ctypes.WinDLL(module_path)
        try:
            get_list = self._lib.C_GetFunctionList
        except AttributeError:
            raise Pkcs11Error(
                f"DLL не экспортирует C_GetFunctionList — это не модуль PKCS#11: "
                f"{module_path}") from None
        get_list.argtypes = [ctypes.POINTER(ctypes.POINTER(CK_FUNCTION_LIST))]
        get_list.restype = UL
        ptr = ctypes.POINTER(CK_FUNCTION_LIST)()
        rc = get_list(ctypes.byref(ptr))
        if rc != CKR_OK:
            raise Pkcs11Error(f"C_GetFunctionList -> 0x{rc:08x}")
        self._funcs = ptr.contents

    # --- низкоуровневые вызовы ---
    def _call(self, name: str, *args):
        target = getattr(self._funcs, name)
        if isinstance(target, int):                 # адрес из реальной структуры
            return ctypes.cast(target, SIG[name])(*args)
        return target(*args)                        # уже вызываемый объект (мок)

    def _check(self, rc: int, where: str) -> None:
        if rc != CKR_OK:
            raise Pkcs11Error(f"{where} -> CKR=0x{rc:08x}")

    # --- инфо/слоты ---
    def initialize(self) -> None:
        rc = self._call("C_Initialize", None)
        # модуль мог быть инициализирован извне (например, NSS softokn) — это не ошибка
        if rc not in (CKR_OK, CKR_CRYPTOKI_ALREADY_INITIALIZED):
            self._check(rc, "C_Initialize")

    def finalize(self) -> None:
        self.close_session()
        self._call("C_Finalize", None)

    def library_info(self) -> dict:
        info = CK_INFO()
        self._check(self._call("C_GetInfo", info), "C_GetInfo")
        return {"version": f"{info.cryptokiVersion.major}.{info.cryptokiVersion.minor}",
                "manufacturer": bytes(info.manufacturerID).decode("latin1").strip(),
                "description": bytes(info.libraryDescription).decode("latin1").strip()}

    def slots(self, token_present: bool = True) -> list:
        count = UL()
        self._check(self._call("C_GetSlotList", 1 if token_present else 0, None,
                               count), "C_GetSlotList(count)")
        if count.value == 0:
            return []
        arr = (UL * count.value)()
        self._check(self._call("C_GetSlotList", 1 if token_present else 0, arr,
                               count), "C_GetSlotList(list)")
        return list(arr[:count.value])

    def token_info(self, slot: int) -> dict:
        info = CK_TOKEN_INFO()
        self._check(self._call("C_GetTokenInfo", slot, info), "C_GetTokenInfo")
        return {"slot": slot,
                "label": bytes(info.label).decode("latin1").strip(),
                "manufacturer": bytes(info.manufacturerID).decode("latin1").strip(),
                "model": bytes(info.model).decode("latin1").strip(),
                "serial": bytes(info.serialNumber).decode("latin1").strip()}

    # --- сессия ---
    def open_session(self, slot: int, read_write: bool = True) -> int:
        flags = CKF_SERIAL_SESSION | (CKF_RW_SESSION if read_write else 0)
        session = UL()
        self._check(self._call("C_OpenSession", slot, flags, None, None,
                               session), "C_OpenSession")
        self._session = session.value
        self._slot = slot
        return self._session

    def close_session(self) -> None:
        if self._session is not None:
            self._call("C_CloseSession", self._session)
            self._session = None
            self._logged = False

    def login(self, pin: str) -> None:
        # ulPinLen по стандарту PKCS#11 — число БАЙТ (не символов)
        pin_bytes = pin.encode("utf-8")
        rc = self._call("C_Login", self._session, CKU_USER, pin_bytes, len(pin_bytes))
        self._check(rc, "C_Login")
        self._logged = True

    def logout(self) -> None:
        if self._logged:
            self._call("C_Logout", self._session)
            self._logged = False

    @contextlib.contextmanager
    def session(self, slot: int, pin: Optional[str] = None, read_write: bool = True):
        """Контекст: сессия (+ логин) закрывается даже при исключении."""
        self.open_session(slot, read_write)
        try:
            if pin is not None:
                self.login(pin)
            yield self
        finally:
            try:
                self.logout()
            finally:
                self.close_session()

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self.finalize()
        return False

    def mechanisms(self) -> list:
        """Список механизмов текущего токена (C_GetMechanismList)."""
        count = UL()
        self._check(self._call("C_GetMechanismList", self._slot, None, count),
                    "C_GetMechanismList(count)")
        if count.value == 0:
            return []
        arr = (UL * count.value)()
        self._check(self._call("C_GetMechanismList", self._slot, arr, count),
                    "C_GetMechanismList(list)")
        return list(arr[:count.value])

    # --- объекты ---
    def _find(self, obj_class: int) -> list:
        template = (CK_ATTRIBUTE * 1)()
        template[0].type = CKA_CLASS
        class_value = UL(obj_class)
        template[0].pValue = ctypes.cast(ctypes.byref(class_value), ctypes.c_void_p)
        template[0].ulValueLen = ctypes.sizeof(UL)

        self._check(self._call("C_FindObjectsInit", self._session, template, 1),
                    "C_FindObjectsInit")
        handles = []
        buf = (UL * 16)()
        count = UL()
        try:
            while True:
                self._check(self._call("C_FindObjects", self._session, buf, 16,
                                       count), "C_FindObjects")
                if count.value == 0:
                    break
                handles.extend(buf[:count.value])
        finally:
            # операция поиска обязана быть завершена, иначе следующий Init даст CKR_OPERATION_ACTIVE
            self._call("C_FindObjectsFinal", self._session)
        return handles

    def get_attributes(self, handle: int, types: list, strict: bool = True) -> dict:
        """
        Читает атрибуты объекта. Возвращает {type: bytes}.

        Атрибуты, которых у объекта нет или которые модуль не отдал
        (CKR_ATTRIBUTE_TYPE_INVALID/SENSITIVE/BUFFER_TOO_SMALL,
        CK_UNAVAILABLE_INFORMATION), в словарь не попадают и не роняют чтение
        остальных. strict=True — фатальным считается только прочий CKR.
        """
        template = (CK_ATTRIBUTE * len(types))()
        for i, t in enumerate(types):
            template[i].type = t
            template[i].pValue = None
            template[i].ulValueLen = 0

        rc = self._call("C_GetAttributeValue", self._session, handle, template, len(types))
        if strict and rc != CKR_OK and rc not in _TOLERATED_ATTR_ERRORS:
            self._check(rc, "C_GetAttributeValue(size)")

        sizes = []
        for i in range(len(types)):
            size = template[i].ulValueLen
            sizes.append(None if size > _MAX_ATTR_SIZE else size)

        buffers = []
        allocated = []
        for i, size in enumerate(sizes):
            if size is None:                            # недоступно/мусорная длина
                buffers.append(None)
                allocated.append(0)
                template[i].pValue = None
                template[i].ulValueLen = 0
                continue
            buf = (ctypes.c_ubyte * max(size, 1))()
            buffers.append(buf)
            allocated.append(size)
            template[i].pValue = ctypes.cast(buf, ctypes.c_void_p)
            template[i].ulValueLen = size

        if any(buf is not None for buf in buffers):
            rc = self._call("C_GetAttributeValue", self._session, handle, template,
                            len(types))
            if strict and rc != CKR_OK and rc not in _TOLERATED_ATTR_ERRORS:
                self._check(rc, "C_GetAttributeValue(value)")

        result = {}
        for i, t in enumerate(types):
            if buffers[i] is None:
                continue
            size = template[i].ulValueLen
            # атрибут не влез в буфер (значение удлинилось) — не отдаём обрезок
            if size > _MAX_ATTR_SIZE or size > allocated[i]:
                continue
            result[t] = bytes(bytearray(buffers[i][:size]))
        return result

    def find_certificates(self) -> list:
        out = []
        for handle in self._find(CKO_CERTIFICATE):
            attrs = self.get_attributes(handle, [CKA_ID, CKA_VALUE, CKA_LABEL],
                                        strict=False)
            out.append({"handle": handle,
                        "id": attrs.get(CKA_ID, b"").hex().upper(),
                        "label": attrs.get(CKA_LABEL, b"").decode("utf-8", "replace"),
                        "certificate_der": attrs.get(CKA_VALUE, b"")})
        return out

    def find_private_keys(self) -> list:
        out = []
        for handle in self._find(CKO_PRIVATE_KEY):
            attrs = self.get_attributes(handle, [CKA_ID, CKA_LABEL], strict=False)
            out.append({"handle": handle,
                        "id": attrs.get(CKA_ID, b"").hex().upper(),
                        "label": attrs.get(CKA_LABEL, b"").decode("utf-8", "replace")})
        return out

    # --- подпись ---
    def sign(self, data: bytes, mechanism: int = CKM_GOSTR3410_WITH_GOSTR3411,
             key_handle: Optional[int] = None, key_id: Optional[bytes] = None) -> bytes:
        """C_Sign на токене. key_handle либо key_id (hex-строка/bytes) для поиска ключа."""
        if key_handle is None:
            keys = self.find_private_keys()
            if not keys:
                raise Pkcs11Error("на токене не найдено приватных ключей")
            if key_id is not None:
                wanted = key_id.hex().upper() if isinstance(key_id, (bytes, bytearray)) \
                    else str(key_id).upper()
                key_handle = next((k["handle"] for k in keys if k["id"] == wanted), None)
                if key_handle is None:
                    raise Pkcs11Error(f"ключ с CKA_ID={wanted} не найден")
            else:
                key_handle = keys[0]["handle"]

        mech = CK_MECHANISM(mechanism, None, 0)
        self._check(self._call("C_SignInit", self._session, mech, key_handle),
                    "C_SignInit")
        out_len = UL()
        rc = self._call("C_Sign", self._session, data, len(data), None, out_len)
        if rc != CKR_OK:
            raise Pkcs11Error(f"C_Sign(size) -> CKR=0x{rc:08x}")
        buf = ctypes.create_string_buffer(out_len.value)
        self._check(self._call("C_Sign", self._session, data, len(data), buf,
                               out_len), "C_Sign")
        return buf.raw[:out_len.value]

    # --- подписи высокого уровня -------------------------------------------
    def sign_raw(self, data: bytes, *, size: int = 64, key_handle: Optional[int] = None,
                 key_id=None, mechanism: int = CKM_GOSTR3410) -> bytes:
        """
        RAW-подпись: Стрибог-хэш данных уходит в C_Sign, результат — r||s (конвенция НУЦ).

        size — 64 для ГОСТ-512 (ключи НУЦ), 32 для ГОСТ-256.
        """
        from kalkan_verify import streebog

        return self.sign(streebog(data, size), mechanism=mechanism,
                         key_handle=key_handle, key_id=key_id)

    def sign_cms(self, data: bytes, certificate_der: bytes, *, detached: bool = False,
                 key_handle: Optional[int] = None, key_id=None,
                 mechanism: int = CKM_GOSTR3410, signing_time=None,
                 extra_certs=None) -> bytes:
        """
        CMS SignedData (CAdES-BES), подписанный на токене.

        Приватный ключ не покидает носитель: наружу отдаётся только подпись
        signedAttributes. Размер ключа (256/512) определяется по сертификату.
        extra_certs — дополнительные DER-сертификаты цепочки для вложения в CMS.
        """
        from kalkan_sign import cms_sign
        from kalkan_verify import load_certificate, public_key_from_spki

        cert = load_certificate(certificate_der)
        spki = cert["tbs_certificate"]["subject_public_key_info"].dump()
        size, _ = public_key_from_spki(spki)
        return cms_sign(lambda digest: self.sign(digest, mechanism=mechanism,
                                                 key_handle=key_handle, key_id=key_id),
                        size, data, certificate_der, detached, signing_time, extra_certs)


