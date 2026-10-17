"""
kalkan_keys.py — доступ к ЛОКАЛЬНЫМ тестовым ключам НУЦ.

В репозитории нет ни паролей, ни имён контейнеров: путь к каталогу ключей берётся из
переменной окружения `KALKAN_DIR` (либо файла `local_keys.py`, он в .gitignore), файлы
`GOST512_*.p12` находятся автоматически, а пароль контейнера выводится из имени файла
(соглашение проекта: часть после последнего `_`) либо берётся из `KALKAN_P12_PASSWORD`.

Если ключей нет — скрипты печатают SKIP и не падают: библиотека от них не зависит.
"""

from __future__ import annotations

import glob
import os
import re

try:                                  # необязательный локальный файл с путями (не коммитится)
    import local_keys as _local
except ImportError:
    _local = None


def kalkan_dir() -> str:
    """Каталог с ключами/корнями НУЦ: KALKAN_DIR, затем local_keys.DIR, иначе несуществующий каталог (проверки пропускаются)."""
    return (os.environ.get("KALKAN_DIR") or getattr(_local, "DIR", None)
            or os.path.join(os.getcwd(), "kalkan_local"))


def sdk_dir() -> str:
    """Каталог данных SDK НУЦ РК («SDK 2.0»): KALKAN_SDK_DIR, затем local_keys.SDK_DIR, иначе несуществующий каталог."""
    return (os.environ.get("KALKAN_SDK_DIR") or getattr(_local, "SDK_DIR", None)
            or os.path.join(kalkan_dir(), "SDK"))


def password_from_name(path: str) -> str:
    """Пароль контейнера: KALKAN_P12_PASSWORD либо часть имени после последнего `_`."""
    env = os.environ.get("KALKAN_P12_PASSWORD")
    if env:
        return env
    base = os.path.splitext(os.path.basename(path))[0]
    return base.rsplit("_", 1)[1] if "_" in base else ""


def all_keys() -> list:
    """[(path, password)] — все найденные ГОСТ-контейнеры (пароль из имени файла)."""
    found = sorted(glob.glob(os.path.join(kalkan_dir(), "GOST512_*.p12")))
    return [(path, password_from_name(path)) for path in found]


def first_key() -> tuple:
    """(path, password) первого контейнера либо (None, "") — тогда проверка пропускается."""
    found = all_keys()
    return found[0] if found else (None, "")


def roots() -> tuple:
    """(путь к корневому сертификату НУЦ, путь к промежуточному NCA)."""
    directory = kalkan_dir()
    return (os.path.join(directory, "root_gost_2022.cer"),
            os.path.join(directory, "nca_gost_2022.cer"))


def masked(path) -> str:
    """Имя файла без пароля (пароль в имени контейнера — не показываем)."""
    if not path:
        return "(нет ключа)"
    base = os.path.basename(path)
    return base.split("_")[0] + "_…<пароль скрыт>.p12"


# --- маскирование персональных данных в выводе -----------------------------

#: буквы казахского + русского + латинского алфавитов (ФИО/наименования/значения)
_PII_WORD = re.compile(r"[А-Яа-яЁёӘәҒғҚқҢңӨөҰұҮүҺһІіA-Za-z]{3,}")
_PII_DIGITS = re.compile(r"\d{6,}")
_PII_HEX = re.compile(r"\b[0-9A-Fa-f]{12,}\b")


def show_pii() -> bool:
    """Показывать ПДн полностью (переменная окружения KALKAN_SHOW_PII=1 или --show-pii)."""
    return os.environ.get("KALKAN_SHOW_PII", "").lower() in ("1", "true", "yes")


def mask_pii(text: str, show: bool = False) -> str:
    """
    Маскирует персональные данные в строке вывода: слова из 4+ букв (ФИО, наименования),
    числа от 6 знаков (ИИН/БИН) и длинные hex (серийники). Первая буква слова остаётся.
    """
    if not text or show or show_pii():
        return text
    text = _PII_DIGITS.sub(lambda m: m.group(0)[:2] + "*" * (len(m.group(0)) - 2), text)
    text = _PII_HEX.sub(lambda m: m.group(0)[:2] + "*" * (len(m.group(0)) - 2), text)
    return _PII_WORD.sub(lambda m: m.group(0)[0] + "***", text)
