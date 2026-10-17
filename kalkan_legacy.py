"""
kalkan_legacy.py — устаревшие ГОСТ: СТ РК ГОСТ Р 34.311-95 (≈ ГОСТ Р 34.11-94)
и СТ РК ГОСТ Р 34.310-2004 (≈ ГОСТ Р 34.10-2001).

Реализовано самостоятельно, без внешних ГОСТ-94/2001 библиотек:
  * ГОСТ 28147-89 — блочный шифр (подстановки, функция g, расписание подключей);
  * ГОСТ Р 34.11-94 — хэш 256 бит на базе 28147-89 (преобразования A, P, χ, 61 цикл);
  * ГОСТ Р 34.10-2001 — проверка подписи на эллиптической кривой (наборы A/B/C).

Эталоны и результаты сверки (всё воспроизводится через test_legacy.py):
  * ГОСТ 28147-89: вектор ГОСТ Р 34.13-2015 и случайные пары — совпадение с «Магмой»
    из gostcrypto; блок в тесте, отдельная сверка дала 50 пар без расхождений;
  * ГОСТ Р 34.11-94: промежуточные значения (K1, K2, KSI) RFC 5831 и честная сверка
    с независимой реализацией pygost — таблицы обоих наборов параметров сверяются
    построчно с его встроенными, затем 32 входа × 2 набора (подмены таблиц нет,
    иначе проверка самореферентна);
  * в казахстанской презентации (gost341194_kz) хэш побайтово равен HashData
    "Gost34311_95" из KalkanCrypt.dll (при отсутствии DLL тест печатает ПРОПУЩЕНО);
  * ГОСТ Р 34.10-2001: закон группы (q*G = ∞), офлайн-вектор «свой ключ → своя
    подпись → проверка» и реальные объекты НУЦ РК — самоподпись корневого
    сертификата, сертификат НУЦ под корнем и подпись CMS (по signedAttrs).

При проверке подписи неверные входы — это отказ (False), а не исключение, и открытый
ключ обязательно проверяется как точка кривой (иначе подпись «принимается» для объекта,
не являющегося ключом).
"""

from __future__ import annotations

__all__ = [
    "gost28147_encrypt", "gost341194", "gost341194_kz",
    "GOST_28147_SBOX_TC26_Z", "GOST_341194_SBOX_TEST", "GOST_341194_SBOX_CRYPTOPRO",
    "CURVES_2001", "CURVE_OIDS_2001", "curve_by_oid", "verify_signature_2001",
]

MASK32 = 0xFFFFFFFF

# --- S-box (8 узлов по 16 значений по 4 бита) ------------------------------

#: id-tc26-gost-28147-param-Z (ГОСТ Р 34.12-2015 «Магма»), RFC 7836
GOST_28147_SBOX_TC26_Z = (
    (0xC, 0x4, 0x6, 0x2, 0xA, 0x5, 0xB, 0x9, 0xE, 0x8, 0xD, 0x7, 0x0, 0x3, 0xF, 0x1),
    (0x6, 0x8, 0x2, 0x3, 0x9, 0xA, 0x5, 0xC, 0x1, 0xE, 0x4, 0x7, 0xB, 0xD, 0x0, 0xF),
    (0xB, 0x3, 0x5, 0x8, 0x2, 0xF, 0xA, 0xD, 0xE, 0x1, 0x7, 0x4, 0xC, 0x9, 0x6, 0x0),
    (0xC, 0x8, 0x2, 0x1, 0xD, 0x4, 0xF, 0x6, 0x7, 0x0, 0xA, 0x5, 0x3, 0xE, 0x9, 0xB),
    (0x7, 0xF, 0x5, 0xA, 0x8, 0x1, 0x6, 0xD, 0x0, 0x9, 0x3, 0xE, 0xB, 0x4, 0x2, 0xC),
    (0x5, 0xD, 0xF, 0x6, 0x9, 0x2, 0xC, 0xA, 0xB, 0x7, 0x8, 0x1, 0x4, 0x3, 0xE, 0x0),
    (0x8, 0xE, 0x2, 0x5, 0x6, 0x9, 0x1, 0xC, 0xF, 0x4, 0xB, 0x0, 0xD, 0xA, 0x3, 0x7),
    (0x1, 0x7, 0xE, 0xD, 0x0, 0x5, 0x8, 0x3, 0x4, 0xF, 0xA, 0x6, 0x9, 0xC, 0xB, 0x2),
)

#: id-GOST28147-89-TestParamSet / id-GostR3411-94-TestParamSet (тестовый набор)
GOST_341194_SBOX_TEST = (
    (4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3),
    (14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9),
    (5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11),
    (7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3),
    (6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2),
    (4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14),
    (13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12),
    (1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12),
)

#: id-GostR3411-94-CryptoProParamSet — набор параметров хэширования КриптоПро.
#: Ориентация та же, что у тестового набора (сверяется с таблицей pygost построчно).
GOST_341194_SBOX_CRYPTOPRO = (
    (10, 4, 5, 6, 8, 1, 3, 7, 13, 12, 14, 0, 9, 2, 11, 15),
    (5, 15, 4, 0, 2, 13, 11, 9, 1, 7, 6, 3, 12, 14, 10, 8),
    (7, 15, 12, 14, 9, 4, 1, 0, 3, 11, 5, 2, 6, 10, 8, 13),
    (4, 10, 7, 12, 0, 15, 2, 8, 14, 1, 6, 5, 13, 11, 9, 3),
    (7, 6, 4, 11, 9, 12, 2, 10, 1, 8, 0, 14, 15, 13, 3, 5),
    (7, 6, 2, 4, 13, 9, 15, 0, 10, 1, 5, 11, 8, 14, 12, 3),
    (13, 14, 4, 1, 7, 0, 5, 10, 3, 12, 8, 15, 6, 2, 9, 11),
    (1, 3, 10, 9, 5, 11, 4, 15, 8, 6, 7, 14, 13, 0, 2, 12),
)


# --- ГОСТ 28147-89 ---------------------------------------------------------

def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _substitute(word: bytes, sbox) -> bytes:
    """Замена полубайтов; младший полубайт последнего байта идёт через sbox[0]/[1]."""
    out = bytearray(4)
    for i in range(4):
        low = sbox[(3 - i) * 2][word[i] & 0xF]
        high = sbox[(3 - i) * 2 + 1][(word[i] >> 4) & 0xF]
        out[i] = (high << 4) | low
    return bytes(out)


def _round_g(subkey: bytes, word: bytes, sbox) -> bytes:
    """Функция g: (k + a) mod 2^32, подстановка, циклический сдвиг влево на 11."""
    total = (int.from_bytes(subkey, "big") + int.from_bytes(word, "big")) & MASK32
    value = int.from_bytes(_substitute(total.to_bytes(4, "big"), sbox), "big")
    value = ((value << 11) | (value >> 21)) & MASK32
    return value.to_bytes(4, "big")


def gost28147_encrypt(key: bytes, block: bytes, sbox=GOST_341194_SBOX_TEST) -> bytes:
    """
    Режим простой замены ГОСТ 28147-89 для одного 64-битного блока.

    Соглашения (big-endian, совпадают с ГОСТ Р 34.12-2015 «Магма»): ключ — 8
    подключей по 4 байта; блок — N1||N2 (N1 — старшие 4 байта); последний раунд
    выполняется без перестановки половин.
    """
    if len(block) != 8 or len(key) != 32:
        raise ValueError("28147-89: блок 8 байт, ключ 32 байта")
    subkeys = [key[i * 4:i * 4 + 4] for i in range(8)]
    order = list(range(8)) * 3 + list(range(7, -1, -1))
    n1, n2 = block[:4], block[4:]
    for i, idx in enumerate(order):
        g = _round_g(subkeys[idx], n2, sbox)
        if i == 31:
            n1 = _xor(n1, g)
        else:
            n1, n2 = n2, _xor(n1, g)
    return n1 + n2


# --- ГОСТ Р 34.11-94 -------------------------------------------------------

#: константы C2..C4 расписания ключей шага (C1 — нулевая, поэтому не хранится)
_C2 = bytes(32)
_C3 = bytes.fromhex("ff00ffff000000ffff0000ff00ffff0000ff00ff00ff00ffff00ff00ff00ff00")
_C4 = bytes(32)


def _A(x: bytes) -> bytes:
    """Преобразование A: A(Y) = (y1 ^ y2) || y4 || y3 || y2 (y1 — старшие 8 байт)."""
    x4, x3, x2, x1 = x[0:8], x[8:16], x[16:24], x[24:32]
    return _xor(x1, x2) + x4 + x3 + x2


#: байтовая перестановка P (транспонирование матрицы 4x8)
_P_TABLE = (0, 8, 16, 24, 1, 9, 17, 25, 2, 10, 18, 26, 3, 11, 19, 27,
            4, 12, 20, 28, 5, 13, 21, 29, 6, 14, 22, 30, 7, 15, 23, 31)


def _P(x: bytes) -> bytes:
    return bytes(x[i] for i in _P_TABLE)


def _chi(y: bytes) -> bytes:
    """Регистр сдвига χ: (y1^y2^y3^y4^y13^y16) || y16 || y15 || ... || y2."""
    y1, y2, y3, y4, y13, y16 = y[30:32], y[28:30], y[26:28], y[24:26], y[6:8], y[0:2]
    head = bytes(a ^ b ^ c ^ d ^ e ^ f for a, b, c, d, e, f in
                 zip(y1, y2, y3, y4, y13, y16))
    return head + y[0:30]


def _reverse_words(value: bytes) -> bytes:
    """Обратный порядок 4-байтовых слов (соглашение 34.11-94 для подключей шага)."""
    words = [value[i:i + 4] for i in range(0, len(value), 4)]
    return b"".join(reversed(words))


def _hash_step(h_in: bytes, m: bytes, sbox) -> bytes:
    """Шаговая функция сжатия f(H, M) ГОСТ Р 34.11-94."""
    u, v = h_in, m
    k1 = _P(_xor(u, v))
    u = _xor(_A(u), _C2)
    v = _A(_A(v))
    k2 = _P(_xor(u, v))
    u = _xor(_A(u), _C3)
    v = _A(_A(v))
    k3 = _P(_xor(u, v))
    u = _xor(_A(u), _C4)
    v = _A(_A(v))
    k4 = _P(_xor(u, v))

    h4, h3, h2, h1 = h_in[0:8], h_in[8:16], h_in[16:24], h_in[24:32]
    s = (gost28147_encrypt(_reverse_words(k4), h4, sbox)
         + gost28147_encrypt(_reverse_words(k3), h3, sbox)
         + gost28147_encrypt(_reverse_words(k2), h2, sbox)
         + gost28147_encrypt(_reverse_words(k1), h1, sbox))

    # перемешивание: H_out = χ^61(H_in ⊕ χ(m ⊕ χ^12(S)))
    x = s
    for _ in range(12):
        x = _chi(x)
    x = _xor(x, m)
    x = _chi(x)
    x = _xor(h_in, x)
    for _ in range(61):
        x = _chi(x)
    return x


def gost341194(data: bytes, sbox=GOST_341194_SBOX_TEST) -> bytes:
    """
    Хэш ГОСТ Р 34.11-94 / СТ РК 34.311-95, 32 байта (академический порядок байт).

    Сверено с независимой реализацией pygost (68 входов, оба набора S-box) и с
    промежуточными значениями RFC 5831. Для совместимости с KalkanCrypt берите
    gost341194_kz (обратный порядок байт результата).
    """
    mask = (1 << 256) - 1
    length = 0
    checksum = 0
    h = bytes(32)
    for i in range(0, len(data), 32):
        part = data[i:i + 32][::-1]
        length += len(part) * 8
        checksum = (checksum + int.from_bytes(part, "big")) & mask
        if len(part) < 32:
            part = bytes(32 - len(part)) + part
        h = _hash_step(h, part, sbox)
    h = _hash_step(h, bytes(24) + length.to_bytes(8, "big"), sbox)
    h = _hash_step(h, checksum.to_bytes(32, "big"), sbox)
    return h


def gost341194_kz(data: bytes, sbox=GOST_341194_SBOX_TEST) -> bytes:
    """
    Хэш 34.11-94 в казахстанской презентации (совместимость с KalkanCrypt).

    Отличия от академического варианта:
      * результат возвращается в обратном порядке байт (как HashData "Gost34311_95");
      * для пустого ввода всегда обрабатывается хотя бы один нулевой блок
        (поведение KalkanCrypt; подтверждено на DLL).
    """
    if not data:
        h = _hash_step(bytes(32), bytes(32), sbox)
        h = _hash_step(h, bytes(32), sbox)
        return _hash_step(h, bytes(32), sbox)[::-1]
    return gost341194(data, sbox)[::-1]


# --- ГОСТ Р 34.10-2001 -----------------------------------------------------

def _curve(p, a, b, q, x, y):
    return {"p": p, "a": a, "b": b, "q": q, "x": x, "y": y}


#: Наборы параметров эллиптических кривых 2001 года (256 бит, RFC 4357)
CURVES_2001 = {
    "id-GostR3410-2001-CryptoPro-A-ParamSet": _curve(
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97,
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94,
        0xA6,
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893,
        0x1,
        0x8D91E471E0989CDA27DF505A453F2B7635294F2DDF23E3B122ACC99C9E9F1E14),
    "id-GostR3410-2001-CryptoPro-B-ParamSet": _curve(
        0x8000000000000000000000000000000000000000000000000000000000000C99,
        0x8000000000000000000000000000000000000000000000000000000000000C96,
        0x3E1AF419A269A5F866A7D3C25C3DF80AE979259373FF2B182F49D4CE7E1BBC8B,
        0x800000000000000000000000000000015F700CFFF1A624E5E497161BCC8A198F,
        0x1,
        0x3FA8124359F96680B83D1C3EB2C070E5C545C9858D03ECFB744BF8D717717EFC),
    "id-GostR3410-2001-CryptoPro-C-ParamSet": _curve(
        0x9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D759B,
        0x9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D7598,
        0x805A,
        0x9B9F605F5A858107AB1EC85E6B41C8AA582CA3511EDDFB74F02F3A6598980BB9,
        0x0,
        0x41ECE55743711A8C3CBF3783CD08C0EE4D4DC440D4641A8F366E550DFDB3BB67),
}

#: OID наборов параметров кривой (legacy КЗ и «родные» КриптоПро)
CURVE_OIDS_2001 = {
    "1.2.398.3.10.1.1.1.1.1": "id-GostR3410-2001-CryptoPro-A-ParamSet",
    "1.2.398.3.10.1.1.1.1.2": "id-GostR3410-2001-CryptoPro-B-ParamSet",
    "1.2.398.3.10.1.1.1.1.3": "id-GostR3410-2001-CryptoPro-C-ParamSet",
    "1.2.643.2.2.35.1": "id-GostR3410-2001-CryptoPro-A-ParamSet",
    "1.2.643.2.2.35.2": "id-GostR3410-2001-CryptoPro-B-ParamSet",
    "1.2.643.2.2.35.3": "id-GostR3410-2001-CryptoPro-C-ParamSet",
    "1.2.643.2.2.36.0": "id-GostR3410-2001-CryptoPro-A-ParamSet",
    "1.2.643.2.2.36.1": "id-GostR3410-2001-CryptoPro-C-ParamSet",
}


def curve_by_oid(oid: str) -> dict:
    """Параметры кривой 2001 по OID набора параметров (KeyParams в SPKI)."""
    name = CURVE_OIDS_2001.get(oid)
    if name is None:
        raise ValueError(f"неизвестный набор параметров кривой 2001: {oid}")
    return CURVES_2001[name]


def _point_add(a, b, curve):
    """
    Сложение точек кривой. Точка на бесконечности кодируется парой (None, None).

    Разбираются все случаи («Руководство» RFC 5832, §5.1): бесконечность,
    совпадающие точки (удвоение), противоположные точки (результат — бесконечность).
    """
    p, ac = curve["p"], curve["a"]
    if a[0] is None:
        return b
    if b[0] is None:
        return a
    x1, y1 = a
    x2, y2 = b
    if x1 == x2:
        if (y1 + y2) % p == 0:                  # противоположные точки
            return None, None
        lam = (3 * x1 * x1 + ac) * pow(2 * y1, p - 2, p) % p        # удвоение
    else:
        lam = (y2 - y1) * pow(x2 - x1, p - 2, p) % p
    x3 = (lam * lam - x1 - x2) % p
    return x3, (lam * (x1 - x3) - y1) % p


def _point_mul(k: int, point, curve):
    """
    Умножение точки кривой на скаляр: двоичный «double-and-add» слева направо.

    Удвоение идёт ПЕРЕД добавлением: для k = 0b10 результат — именно 2P,
    а не P (перепутанный порядок даёт неверный скаляр и «тихо» ломает проверку).
    """
    result = (None, None)
    for bit in bin(k)[2:]:
        result = _point_add(result, result, curve)
        if bit == "1":
            result = _point_add(result, point, curve)
    return result


def _is_on_curve(x: int, y: int, curve) -> bool:
    """Проверка, что (x, y) — точка кривой: y^2 = x^3 + ax + b (mod p)."""
    p, a, b = curve["p"], curve["a"], curve["b"]
    if not (0 <= x < p and 0 <= y < p):
        return False
    return (y * y - (x * x * x + a * x + b)) % p == 0


def verify_signature_2001(public_key: bytes, digest: bytes, signature: bytes, curve: dict,
                          byte_order: str = "little") -> bool:
    """
    Проверка подписи ГОСТ Р 34.10-2001.

    public_key : X||Y, каждая половина по 32 байта (как выдаёт public_key_from_spki)
    digest     : хэш 34.11-94 (32 байта; для объектов НУЦ — в KZ-презентации)
    signature  : r||s, каждая половина по 32 байта (как в сертификате/CMS)
    byte_order : порядок интерпретации чисел (объекты НУЦ РК — little-endian)

    Неверные входы — это отказ (False), а не исключение: проверка обязана отвергать
    мусор, а не падать. Дополнительно проверяется, что открытый ключ — действительно
    точка кривой (RFC 5832, §5.2), иначе подпись может быть «принята» для объекта,
    не являющегося ключом.
    """
    q, p = curve["q"], curve["p"]
    if len(signature) != 64 or len(digest) != 32 or len(public_key) != 64:
        return False
    r = int.from_bytes(signature[:32], byte_order)
    s = int.from_bytes(signature[32:], byte_order)
    if not (0 < r < q and 0 < s < q):
        return False
    px = int.from_bytes(public_key[:32], "little")
    py = int.from_bytes(public_key[32:], "little")
    if not _is_on_curve(px, py, curve):
        return False
    e = int.from_bytes(digest, byte_order) % q
    if e == 0:
        e = 1
    v = pow(e, q - 2, q)
    z1 = s * v % q
    z2 = (-r * v) % q
    c = _point_add(_point_mul(z1, (curve["x"], curve["y"]), curve),
                   _point_mul(z2, (px, py), curve), curve)
    if c[0] is None:                            # C — точка на бесконечности: подпись неверна
        return False
    return c[0] % q == r

