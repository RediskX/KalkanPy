"""
kalkan_p12.py — чтение приватного ключа и сертификата из .p12 НУЦ РК (ГОСТ 2015).

Зачем свой ридер:
    * .p12 НУЦ использует BER с НЕОПРЕДЕЛЁННОЙ длиной внутри — asn1crypto/cryptography
      его не разбирают;
    * ключ завёрнут в pkcs8ShroudedKeyBag (PBE SHA1 + 3DES), сертификат — в
      encryptedData (pbeWithSHAAnd40BitRC2-CBC).

Реализовано независимо: BER-парсер, PKCS#12 KDF (RFC 7292), HMAC-проверка MAC,
3DES-CBC и RC2-CBC (через cryptography, decrepit).

MAC-конвенция (откалибрована на OpenSSL-эталоне):
    key = PKCS12_KDF(id=3, salt=macSalt, iters, len=hash_size)
    MAC = HMAC(hash, key, authSafe_content)
Пароль кодируется как BMPString (UTF-16BE) + терминатор 0x0000.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Optional, Tuple

try:
    from cryptography.hazmat.decrepit.ciphers.algorithms import RC2, TripleDES
except Exception:  # старые версии cryptography
    from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES
    from cryptography.hazmat.primitives.ciphers.algorithms import RC2  # noqa
from cryptography.hazmat.primitives.ciphers import Cipher, modes

__all__ = ["load_gost2015_p12", "p12_extract_certificate", "UnsupportedKeyStore"]

#: потолок итераций KDF из контейнера (защита от «зависания» на враждебном файле)
MAX_KDF_ITERS = 10 ** 7

#: алгоритмы хэша для MAC контейнера (неизвестный OID — не угадываем)
_MAC_HASHES = {"1.3.14.3.2.26": "sha1", "2.16.840.1.101.3.4.2.1": "sha256",
               "2.16.840.1.101.3.4.2.2": "sha384", "2.16.840.1.101.3.4.2.3": "sha512"}

OID_SHROUDED_KEY = "1.2.840.113549.1.12.10.1.2"
OID_CERT_BAG = "1.2.840.113549.1.12.10.1.3"
OID_PBE_3DES = "1.2.840.113549.1.12.1.3"
OID_PBE_RC2_40 = "1.2.840.113549.1.12.1.6"


class UnsupportedKeyStore(Exception):
    pass


# --- BER-парсер (неопределённая и определённая длина) ----------------------

def _parse(buf: bytes, i: int, end: int):
    nodes = []
    while i < end:
        if buf[i] == 0 and i + 1 < end and buf[i + 1] == 0:
            return nodes, i + 2
        tag = buf[i]
        i += 1
        if tag & 0x1F == 0x1F:                      # многобайтовый тег
            while i < end and buf[i] & 0x80:
                i += 1
            i += 1
        if i >= end:
            raise ValueError("обрыв BER: нет длины")
        length = buf[i]
        i += 1
        if length == 0x80:                          # неопределённая длина
            children, i = _parse(buf, i, end)
            nodes.append((tag, children, None))
            continue
        if length & 0x80:
            n = length & 0x7F
            if n == 0 or i + n > end:
                raise ValueError("обрыв BER: некорректная длина")
            ln = int.from_bytes(buf[i:i + n], "big")
            i += n
        else:
            ln = length
        seg = i + ln
        if seg > end:
            raise ValueError("обрыв BER: значение за границей")
        if tag & 0x20:                              # constructed
            children, _ = _parse(buf, i, seg)
            nodes.append((tag, children, None))
        else:
            nodes.append((tag, None, buf[i:seg]))
        i = seg
    return nodes, i


def _oid(value: bytes) -> str:
    first = value[0]
    parts = [first // 40, first % 40]
    acc = 0
    for byte in value[1:]:
        acc = (acc << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(acc)
            acc = 0
    return ".".join(map(str, parts))


def _child(node, tag):
    return next((n for n in node[1] if n[0] == tag), None)


def _encrypted_content(eci) -> bytes:
    """
    Возвращает шифртекст из EncryptedContentInfo.

    Учитывает оба варианта тега encryptedContent: constructed [0] (0xA0) с одним или
    несколькими OCTET STRING и primitive [0] (0x80) — тогда значение это сам шифртекст.
    """
    node = next((n for n in eci[1] if n[0] in (0xA0, 0x80)), None)
    if node is None:
        raise UnsupportedKeyStore("нет encryptedContent")
    if node[0] == 0x80:
        return node[2] or b""
    return b"".join(c[2] for c in (node[1] or []) if c[0] == 0x04 and c[2])


def _bmp(password: str) -> bytes:
    return password.encode("utf-16-be") + b"\x00\x00"


# --- PKCS#12 KDF (RFC 7292 B.2) -------------------------------------------

def _kdf(password_bmp: bytes, salt: bytes, iters: int, n: int,
         id_byte: int, hash_name: str = "sha1") -> bytes:
    u = hashlib.new(hash_name).digest_size
    v = hashlib.new(hash_name).block_size
    D = bytes([id_byte]) * v

    def _pad(x: bytes) -> bytes:
        if not x:
            return b""
        length = ((len(x) + v - 1) // v) * v
        return (x * ((length // len(x)) + 1))[:length]

    I = bytearray(_pad(salt) + _pad(password_bmp))
    c = (len(I) + v - 1) // v if I else 0
    out = b""
    for _ in range(1, c + 1):
        A = hashlib.new(hash_name, D + bytes(I)).digest()
        for _ in range(iters - 1):
            A = hashlib.new(hash_name, A).digest()
        out += A
        B = (A * ((v + u - 1) // u))[:v]
        for j in range(c):
            block = I[j * v:(j + 1) * v]
            carry = 1
            res = bytearray(v)
            for k in range(v - 1, -1, -1):
                t = block[k] + B[k] + carry
                res[k] = t & 0xFF
                carry = t >> 8
            I[j * v:(j + 1) * v] = res
    return out[:n]


def _cbc_decrypt(cipher, iv: bytes, data: bytes) -> bytes:
    decryptor = Cipher(cipher, modes.CBC(iv)).decryptor()
    plain = decryptor.update(data) + decryptor.finalize()
    pad = plain[-1] if plain else 0
    if 1 <= pad <= 8:
        plain = plain[:-pad]
    return plain


def _decrypt_pbe(alg_oid: str, params, ctext: bytes, password_bmp: bytes) -> bytes:
    salt = _child(params, 0x04)[2]
    iters = int.from_bytes(_child(params, 0x02)[2], "big")
    if not 1 <= iters <= MAX_KDF_ITERS:
        raise UnsupportedKeyStore(f"недопустимое число итераций KDF: {iters}")
    if alg_oid == OID_PBE_3DES:
        key = _kdf(password_bmp, salt, iters, 24, 1)
        iv = _kdf(password_bmp, salt, iters, 8, 2)
        return _cbc_decrypt(TripleDES(key), iv, ctext)
    if alg_oid == OID_PBE_RC2_40:
        key5 = _kdf(password_bmp, salt, iters, 5, 1)
        iv = _kdf(password_bmp, salt, iters, 8, 2)
        try:
            from Crypto.Cipher import ARC2              # pycryptodome: корректный RC2-40
            plain = ARC2.new(key5, ARC2.MODE_CBC, iv,
                             effective_keylen=40).decrypt(ctext)
        except Exception:
            key16 = key5 + b"\x00" * 11
            try:
                cipher = RC2(key16, effective_key_bits=40)
            except TypeError:
                cipher = RC2(key16)
            return _cbc_decrypt(cipher, iv, ctext)
        pad = plain[-1] if plain else 0
        if 1 <= pad <= 8:
            plain = plain[:-pad]
        return plain
    raise UnsupportedKeyStore(f"неподдержанный PBE: {alg_oid}")


# --- разбор Pfx -----------------------------------------------------------

def _auth_safe_content(pfx):
    a0 = _child(pfx[1], 0xA0)                      # authSafe ContentInfo -> [0]
    return _child(a0, 0x04)[2]


def verify_p12_mac(data: bytes, password: str) -> bool:
    """Проверяет MAC контейнера — подтверждает корректность пароля. Малиформ → False."""
    try:
        nodes, _ = _parse(data, 0, len(data))
        pfx = nodes[0][1]
        if len(pfx) < 3:
            return False
        mac_node = pfx[2]
        digest_info = mac_node[1][0]
        alg_oid = _oid(_child(_child(digest_info, 0x30), 0x06)[2])
        if alg_oid not in _MAC_HASHES:
            return False                                # неизвестный алгоритм MAC — не угадываем
        hash_name = _MAC_HASHES[alg_oid]
        mac_value = _child(digest_info, 0x04)[2]
        salt = _child(mac_node, 0x04)[2]
        iters = int.from_bytes(_child(mac_node, 0x02)[2], "big")
        if not 1 <= iters <= MAX_KDF_ITERS:
            return False                                # защита от «зависания» KDF
        key = _kdf(_bmp(password), salt, iters,
                   hashlib.new(hash_name).digest_size, 3, hash_name)
        return hmac.compare_digest(
            hmac.new(key, _auth_safe_content(pfx), hash_name).digest(), mac_value)
    except (IndexError, ValueError, TypeError, KeyError, AttributeError, RecursionError):
        return False


def _extract_gost_private_key(plain: bytes) -> bytes:
    """Из PrivateKeyInfo достаёт сырой ключ ГОСТ (32/64 байта)."""
    nodes, _ = _parse(plain, 0, len(plain))

    def walk(node):
        tag, children, value = node
        if children is not None:
            for child in children:
                got = walk(child)
                if got:
                    return got
        elif tag == 0x04 and value:
            if len(value) in (32, 64):
                return value
            try:                                    # вложенная обёртка 04 40 <key>
                inner, _ = _parse(value, 0, len(value))
                for t2, _, v2 in inner:
                    if t2 == 0x04 and v2 and len(v2) in (32, 64):
                        return v2
            except Exception:
                pass
        return None

    key = walk(nodes[0])
    if key is None:
        raise UnsupportedKeyStore("в PrivateKeyInfo не найден ключ ГОСТ")
    return key


def _load_gost2015_p12_impl(data: bytes, password: str) -> Tuple[bytes, bytes]:
    """
    Читает .p12 НУЦ (ГОСТ 2015): возвращает (certificate_der, private_key_be).

    private_key_be — 32 или 64 байта big-endian (порядок gostcrypto).
    """
    if not verify_p12_mac(data, password):
        raise UnsupportedKeyStore("неверный пароль или повреждённый контейнер")

    nodes, _ = _parse(data, 0, len(data))
    pfx = nodes[0][1]
    auth = _auth_safe_content(pfx)
    inner, _ = _parse(auth, 0, len(auth))
    password_bmp = _bmp(password)

    cert_der = None
    key_be = None
    for ci in inner[0][1]:
        oid = _oid(_child(ci, 0x06)[2])
        a0 = _child(ci, 0xA0)
        if oid == "1.2.840.113549.1.7.1":                     # data: shrouded key bag
            sc_octets = _child(a0, 0x04)[2]
            safe, _ = _parse(sc_octets, 0, len(sc_octets))
            for bag in safe[0][1]:
                if _oid(bag[1][0][2]) != OID_SHROUDED_KEY:
                    continue
                epki = _child(bag, 0xA0)[1][0]
                alg = _child(epki, 0x30)
                alg_oid = _oid(_child(alg, 0x06)[2])
                clear = _decrypt_pbe(alg_oid, _child(alg, 0x30),
                                     _child(epki, 0x04)[2], password_bmp)
                key_be = _extract_gost_private_key(clear)
        elif oid == "1.2.840.113549.1.7.6":                   # encryptedData: certificate
            enc_data = _child(a0, 0x30)
            eci = _child(enc_data, 0x30)
            alg = _child(eci, 0x30)
            alg_oid = _oid(_child(alg, 0x06)[2])
            ctext = _encrypted_content(eci)
            clear = _decrypt_pbe(alg_oid, _child(alg, 0x30), ctext, password_bmp)
            safe, _ = _parse(clear, 0, len(clear))
            for bag in safe[0][1]:
                if _oid(bag[1][0][2]) == OID_CERT_BAG:
                    certbag = _child(bag, 0xA0)[1][0]
                    cert_der = _child(certbag, 0xA0)[1][0][2]

    if key_be is None or cert_der is None:
        raise UnsupportedKeyStore("в контейнере не найдены ключ и/или сертификат")

    # авто-определение порядка байт приватного ключа по открытому ключу сертификата
    from asn1crypto import x509 as _x509
    from gostcrypto import gostsignature as _gs
    from kalkan_verify import _curve_name, _le_each, public_key_from_spki

    cert = _x509.Certificate.load(cert_der)
    _, cert_pk_be = public_key_from_spki(
        cert["tbs_certificate"]["subject_public_key_info"].dump())
    size = len(key_be)
    curve = _gs.CURVES_R_1323565_1_024_2019[_curve_name(size)]
    mode = _gs.MODE_256 if size == 32 else _gs.MODE_512
    obj = _gs.new(mode, curve)
    if bytes(obj.public_key_generate(bytearray(key_be))) != _le_each(cert_pk_be, size):
        key_be = key_be[::-1]
        if bytes(obj.public_key_generate(bytearray(key_be))) != _le_each(cert_pk_be, size):
            # ни один порядок байт не даёт ключ из сертификата — контейнер не наш
            raise UnsupportedKeyStore(
                "приватный ключ не соответствует открытому ключу сертификата")

    return cert_der, key_be


def load_gost2015_p12(data: bytes, password: str) -> Tuple[bytes, bytes]:
    """
    Читает .p12 НУЦ (ГОСТ 2015): (certificate_der, private_key_be).

    Повреждённый/не-PKCS12 ввод → UnsupportedKeyStore (а не IndexError/TypeError).
    """
    try:
        return _load_gost2015_p12_impl(data, password)
    except UnsupportedKeyStore:
        raise
    except (IndexError, ValueError, TypeError, KeyError, AttributeError,
            RecursionError) as ex:                      # RecursionError — глубоко вложенный BER
        raise UnsupportedKeyStore(f"повреждённый .p12: {ex}") from ex


def p12_extract_certificate(data: bytes, password: str) -> bytes:
    """DER сертификата из .p12."""
    return load_gost2015_p12(data, password)[0]
