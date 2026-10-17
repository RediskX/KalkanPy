"""
kalkan_dll.py — эталон-оракул: доступ к настоящему KalkanCrypt.dll через ctypes.

НЕ часть независимого движка: используется только для кросс-проверки — сравнить
результаты моей реализации с вендорской библиотекой («Калкан подписал → мой код
проверил», «мой код подписал → Калкан проверил»).

DLL: C\\Windows\\KalkanCrypt_С\\lib\\x64\\KalkanCrypt.dll (SDK 2.0).
"""

from __future__ import annotations

import ctypes
import os

from kalkan_keys import kalkan_dir, sdk_dir

DEFAULT_DLL = os.environ.get("KALKAN_DLL") or os.path.join(
    sdk_dir(), "C", "Windows", "KalkanCrypt_С",
    "lib", "x64", "KalkanCrypt.dll")

UL = ctypes.c_ulong
API = ctypes.WINFUNCTYPE

FIELDS = [
    ("KC_Init", ()),
    ("KC_GetTokens", (UL, ctypes.c_void_p, ctypes.POINTER(UL))),
    ("KC_GetCertificatesList", (ctypes.c_void_p, ctypes.POINTER(UL))),
    ("KC_LoadKeyStore", (ctypes.c_int, ctypes.c_void_p, ctypes.c_int,
                         ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p)),
    ("X509LoadCertificateFromFile", (ctypes.c_void_p, ctypes.c_int)),
    ("X509LoadCertificateFromBuffer", (ctypes.c_void_p, ctypes.c_int, ctypes.c_int)),
    ("X509ExportCertificateFromStore", (ctypes.c_void_p, ctypes.c_int,
                                        ctypes.c_void_p, ctypes.POINTER(ctypes.c_int))),
    ("X509CertificateGetInfo", (ctypes.c_void_p, ctypes.c_int, ctypes.c_int,
                                ctypes.c_void_p, ctypes.POINTER(ctypes.c_int))),
    ("X509ValidateCertificate", (ctypes.c_void_p, ctypes.c_int, ctypes.c_int,
                                 ctypes.c_void_p, ctypes.c_longlong, ctypes.c_void_p,
                                 ctypes.POINTER(ctypes.c_int), ctypes.c_int,
                                 ctypes.c_void_p, ctypes.POINTER(ctypes.c_int))),
    ("HashData", (ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_int,
                  ctypes.c_void_p, ctypes.POINTER(ctypes.c_int))),
    ("SignHash", (ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_int,
                  ctypes.c_void_p, ctypes.POINTER(ctypes.c_int))),
    ("SignData", (ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_int,
                  ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p,
                  ctypes.POINTER(ctypes.c_int))),
    ("SignXML", (ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_int,
                 ctypes.c_void_p, ctypes.POINTER(ctypes.c_int),
                 ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)),
    ("VerifyData", (ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_int,
                    ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p,
                    ctypes.POINTER(ctypes.c_int), ctypes.c_void_p,
                    ctypes.POINTER(ctypes.c_int), ctypes.c_int, ctypes.c_void_p,
                    ctypes.POINTER(ctypes.c_int))),
    ("VerifyXML", (ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_int,
                   ctypes.c_void_p, ctypes.POINTER(ctypes.c_int))),
    ("KC_getCertFromXML", (ctypes.c_void_p, ctypes.c_int, ctypes.c_int,
                           ctypes.c_void_p, ctypes.POINTER(ctypes.c_int))),
    ("KC_getSigAlgFromXML", (ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p,
                             ctypes.POINTER(ctypes.c_int))),
    ("KC_GetLastError", ()),
    ("KC_GetLastErrorString", (ctypes.c_void_p, ctypes.POINTER(ctypes.c_int))),
    ("KC_XMLFinalize", ()),
    ("KC_Finalize", ()),
    ("KC_TSASetUrl", (ctypes.c_void_p,)),
    ("KC_GetTimeFromSig", (ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                           ctypes.POINTER(ctypes.c_longlong))),
    ("KC_SetProxy", (ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p,
                     ctypes.c_void_p, ctypes.c_void_p)),
    ("KC_GetCertFromCMS", (ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                           ctypes.c_void_p, ctypes.POINTER(ctypes.c_int))),
    ("SignWSSE", (ctypes.c_void_p, UL, ctypes.c_void_p, ctypes.c_int,
                  ctypes.c_void_p, ctypes.POINTER(ctypes.c_int), ctypes.c_void_p)),
    ("ZipConVerify", (ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p,
                      ctypes.POINTER(ctypes.c_int))),
    ("ZipConSign", (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                    ctypes.c_void_p, ctypes.c_int)),
    ("KC_getCertFromZipFile", (ctypes.c_void_p, ctypes.c_int, ctypes.c_int,
                               ctypes.c_void_p, ctypes.POINTER(ctypes.c_int))),
]


class KCFuncs(ctypes.Structure):
    _fields_ = [
        (name, API(None if name in ("KC_XMLFinalize", "KC_Finalize") else UL, *sig))
        for name, sig in FIELDS
    ]


# флаги / константы (KalkanCrypt.h)
KCST_PKCS12 = 0x1
KC_CERT_CA = 0x201
KC_CERT_INTERMEDIATE = 0x202
KC_CERT_USER = 0x204
KC_CERT_DER = 0x101
KC_CERT_PEM = 0x102
KC_CERT_B64 = 0x104
KC_SIGN_DRAFT = 0x1
KC_SIGN_CMS = 0x2
KC_IN_PEM = 0x4
KC_IN_DER = 0x8
KC_IN_BASE64 = 0x10
KC_IN2_BASE64 = 0x20
KC_DETACHED_DATA = 0x40
KC_WITH_CERT = 0x80
KC_WITH_TIMESTAMP = 0x100
KC_OUT_PEM = 0x200
KC_OUT_DER = 0x400
KC_OUT_BASE64 = 0x800
KC_IN_FILE = 0x8000
KC_USE_NOTHING = 0x401
KC_USE_CRL = 0x402
KC_USE_OCSP = 0x404
KC_NOCHECKCERTTIME = 0x10000


class KalkanOracle:
    """Тонкая обёртка над KalkanCrypt.dll (только для сверки)."""

    def __init__(self, dll_path: str = DEFAULT_DLL):
        os.add_dll_directory(os.path.dirname(dll_path))
        self._lib = ctypes.WinDLL(dll_path)
        get_list = self._lib.KC_GetFunctionList
        get_list.argtypes = [ctypes.POINTER(ctypes.POINTER(KCFuncs))]
        get_list.restype = ctypes.c_int
        ptr = ctypes.POINTER(KCFuncs)()
        get_list(ctypes.byref(ptr))
        self.kc = ptr.contents

    def last_error(self) -> str:
        buf = ctypes.create_string_buffer(8192)
        ln = ctypes.c_int(8192)
        self.kc.KC_GetLastErrorString(buf, ctypes.byref(ln))
        return buf.value.decode("cp1251", "replace")

    def init(self) -> int:
        return self.kc.KC_Init()

    def finalize(self) -> None:
        self.kc.KC_Finalize()

    def load_cert_file(self, path: str, cert_type: int) -> int:
        return self.kc.X509LoadCertificateFromFile(path.encode("ascii"), cert_type)

    def load_key_store(self, password: str, path: str, alias: str = "") -> int:
        pw = password.encode("ascii")
        path_b = path.encode("ascii")
        buf_pw = ctypes.create_string_buffer(pw, len(pw) + 1)
        buf_path = ctypes.create_string_buffer(path_b, len(path_b) + 1)
        buf_alias = ctypes.create_string_buffer(alias.encode("ascii"), 256)
        return self.kc.KC_LoadKeyStore(KCST_PKCS12, buf_pw, len(pw),
                                       buf_path, len(path_b), buf_alias)

    def sign_data(self, data: bytes, flags: int, alias: str = "") -> bytes:
        in_buf = ctypes.create_string_buffer(data, len(data) + 1)
        empty = ctypes.create_string_buffer(b"", 1)
        out = ctypes.create_string_buffer(200000)
        out_len = ctypes.c_int(200000)
        alias_b = ctypes.create_string_buffer(alias.encode("ascii"), 256)
        rc = self.kc.SignData(alias_b, flags, in_buf, len(data), empty, 0,
                              out, ctypes.byref(out_len))
        if rc != 0:
            raise RuntimeError(f"SignData rc=0x{rc:08x}: {self.last_error()}")
        return out.raw[:out_len.value]

    def cert_get_info(self, cert_der: bytes, prop_id: int):
        """X509CertificateGetInfo(cert, propId). Возвращает (rc, text)."""
        cert_buf = ctypes.create_string_buffer(cert_der, len(cert_der) + 1)
        out = ctypes.create_string_buffer(65536)
        out_len = ctypes.c_int(65536)
        rc = self.kc.X509CertificateGetInfo(cert_buf, len(cert_der), prop_id,
                                            out, ctypes.byref(out_len))
        text = out.raw[:max(out_len.value, 0)].decode("utf-8", "replace").rstrip("\x00")
        return rc, text

    def export_cert(self, alias: str = "", flag: int = KC_CERT_B64):
        """X509ExportCertificateFromStore(alias, flag). Возвращает (rc, bytes)."""
        out = ctypes.create_string_buffer(65536)
        out_len = ctypes.c_int(65536)
        rc = self.kc.X509ExportCertificateFromStore(alias.encode("ascii"), flag,
                                                    out, ctypes.byref(out_len))
        return rc, out.raw[:max(out_len.value, 0)]

    def cert_get_info_from_store(self, cert_text: bytes, prop_id: int):
        """X509CertificateGetInfo по сертификату, полученному из хранилища (PEM/Base64)."""
        buf = ctypes.create_string_buffer(cert_text, len(cert_text) + 1)
        out = ctypes.create_string_buffer(65536)
        out_len = ctypes.c_int(65536)
        rc = self.kc.X509CertificateGetInfo(buf, len(cert_text), prop_id,
                                            out, ctypes.byref(out_len))
        text = out.raw[:max(out_len.value, 0)].decode("utf-8", "replace").rstrip("\x00")
        return rc, text

    def sign_xml(self, xml_text: bytes, flags: int = 0, alias: str = ""):
        """SignXML(alias, flags, inData, ..., outSign). Возвращает (rc, out)."""
        in_buf = ctypes.create_string_buffer(xml_text, len(xml_text) + 1)
        out = ctypes.create_string_buffer(400000)
        out_len = ctypes.c_int(400000)
        empty = ctypes.create_string_buffer(b"", 1)
        rc = self.kc.SignXML(alias.encode("ascii"), flags, in_buf, len(xml_text),
                             out, ctypes.byref(out_len), empty, empty, empty)
        return rc, out.raw[:max(out_len.value, 0)]

    def verify_xml(self, xml_text: bytes, flags: int = 0, alias: str = ""):
        """VerifyXML(alias, flags, inData, ..., outVerifyInfo). Возвращает (rc, info)."""
        in_buf = ctypes.create_string_buffer(xml_text, len(xml_text) + 1)
        info = ctypes.create_string_buffer(65536)
        info_len = ctypes.c_int(65536)
        rc = self.kc.VerifyXML(alias.encode("ascii"), flags, in_buf, len(xml_text),
                               info, ctypes.byref(info_len))
        text = info.raw[:max(info_len.value, 0)].decode("utf-8", "replace").rstrip("\x00")
        return rc, text

    def sign_wsse(self, envelope: bytes, sign_node_id: str, flags: int = 0,
                  alias: str = ""):
        """
        SignWSSE(alias, flags, inData, len, outSign, &outLen, signNodeId).

        signNodeId — wsu:Id узла с BinarySecurityToken в шаблоне конверта.
        Возвращает (rc, подписанный XML | b"").
        """
        in_buf = ctypes.create_string_buffer(envelope, len(envelope) + 1)
        out = ctypes.create_string_buffer(400000)
        out_len = ctypes.c_int(400000)
        rc = self.kc.SignWSSE(alias.encode("ascii"), flags, in_buf, len(envelope),
                              out, ctypes.byref(out_len),
                              sign_node_id.encode("ascii"))
        return rc, out.raw[:max(out_len.value, 0)]

    def hash_data(self, algorithm: str, data: bytes, flags: int = 0):
        """HashData(algorithm, flags, inData, len, outData, &outLen). Возвращает (rc, bytes)."""
        in_buf = ctypes.create_string_buffer(data, len(data) + 1)
        out = ctypes.create_string_buffer(256)
        out_len = ctypes.c_int(256)
        rc = self.kc.HashData(algorithm.encode("ascii"), flags, in_buf, len(data),
                              out, ctypes.byref(out_len))
        return rc, out.raw[:max(out_len.value, 0)]

    def zipcon_verify(self, zip_path: str):
        """ZipConVerify(path, flags, outInfo, &len) -> (rc, текст отчёта)."""
        out = ctypes.create_string_buffer(16384)
        out_len = ctypes.c_int(16384)
        rc = self.kc.ZipConVerify(str(zip_path).encode(), 0, out, ctypes.byref(out_len))
        text = out.raw[:max(out_len.value, 0)].decode("utf-8", "replace")
        return rc, text

    def zipcon_sign(self, files: list, name: str, out_dir: str, alias: str = "") -> int:
        """ZipConSign(alias, "файл1|файл2|" или папка или готовый .zip|, name, outDir, flags)."""
        paths = "|".join(str(f) for f in files)
        if paths and not paths.endswith("|"):
            paths += "|"
        return self.kc.ZipConSign(alias.encode(), paths.encode(), name.encode(),
                                  str(out_dir).encode(), 0)

    def verify_data(self, data: bytes, sign: bytes, flags: int, alias: str = ""):
        in_buf = ctypes.create_string_buffer(data, len(data) + 1)
        sign_buf = ctypes.create_string_buffer(sign, len(sign) + 1)
        out_data = ctypes.create_string_buffer(200000)
        out_data_len = ctypes.c_int(200000)
        info = ctypes.create_string_buffer(65536)
        info_len = ctypes.c_int(65536)
        cert = ctypes.create_string_buffer(65536)
        cert_len = ctypes.c_int(65536)
        alias_b = ctypes.create_string_buffer(alias.encode("ascii"), 256)
        rc = self.kc.VerifyData(alias_b, flags, in_buf, len(data), sign_buf, len(sign),
                                out_data, ctypes.byref(out_data_len),
                                info, ctypes.byref(info_len), 0, cert,
                                ctypes.byref(cert_len))
        return rc, info.raw[:info_len.value].decode("cp1251", "replace")
