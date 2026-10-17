"""
test_zipcon.py — контейнеры ZipCon: наш верификатор и наша сборка.

Проверяется (без сети):
  1. манифест: сборка/разбор, формат как у вендора;
  2. цикл на реальном ключе: наша сборка → наша проверка → проверка самой DLL
     (`ZipConVerify`, ожидается rc=0 «CMS Verify - OK»);
  3. обратное направление: контейнер, собранный DLL, проверяется нашим кодом;
  4. образцы SDK: дайджесты файлов совпадают, а подписи НЕ проходят — образцы
     устаревшие (то же говорит и DLL), тест фиксирует именно это;
  5. негативы: подмена файла, отсутствие манифеста.

Нет ключа/SDK/DLL — соответствующая часть печатает ПРОПУЩЕНО.
"""

from __future__ import annotations

import ctypes
import os
import sys
import zipfile

from kalkan_keys import first_key, kalkan_dir, roots, sdk_dir
from kalkan_p12 import load_gost2015_p12
from kalkan_verify import streebog
from kalkan_zipcon import (MANIFEST_NAME, build_manifest, parse_manifest, sign_zipcon,
                           verify_zipcon)

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

WORK = os.path.join(os.environ.get("TEMP") or __import__("tempfile").gettempdir(), "zipcon_test")
SDK = sdk_dir()
SDK_ZIP = os.path.join(SDK, "PHP_Linux", "example", "example 1", "zip", "zip_multiply.zip")
DIGEST_512 = "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34112015-512"


def _make_files() -> list:
    os.makedirs(WORK, exist_ok=True)
    paths = []
    for name, data in (("alpha.txt", b"Hello, ZipCon from KalkanPy!"),
                       ("beta.bin", bytes(range(64)))):
        path = os.path.join(WORK, name)
        with open(path, "wb") as fh:
            fh.write(data)
        paths.append(path)
    return paths


def _verdict(text: str) -> str:
    lines = [ln.strip() for ln in text.splitlines() if "Verify" in ln or "FAILED" in ln]
    return lines[-1] if lines else ""


def test_manifest_build() -> bool:
    """Сборка и разбор манифеста; формат совпадает с вендорским шаблоном."""
    objects = [{"uri": "alpha.txt", "algorithm": DIGEST_512, "digest": streebog(b"data", 64)}]
    manifest = build_manifest(objects, ["META-INF/signature-abcd1234.cms"])
    parsed = parse_manifest(manifest)
    ok = (parsed["signatures"] == ["META-INF/signature-abcd1234.cms"]
          and len(parsed["objects"]) == 1
          and parsed["objects"][0]["uri"] == "alpha.txt"
          and parsed["objects"][0]["digest"] == objects[0]["digest"])
    ok &= manifest.startswith(
        b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?> \r\n<NCAManifest>\r\n')
    ok &= manifest.endswith(b"\t</DataObjectReference>\r\n</NCAManifest>")
    print("манифест: сборка/разбор и формат вендора:", ok)
    return ok



def _dll_verify(path: str, oracle):
    """Проверка контейнера самой DLL: (rc, текст отчёта)."""
    return oracle.zipcon_verify(path)


def test_roundtrip() -> bool:
    """Наша сборка → наша проверка → проверка DLL; контейнер DLL → наша проверка."""
    key_path, password = first_key()
    if not key_path:
        print("ПРОПУЩЕНО: локального .p12 нет — цикл сборки/проверки не выполнялся")
        return True
    cert, key_be = load_gost2015_p12(open(key_path, "rb").read(), password)
    files = _make_files()
    ours = os.path.join(WORK, "ours.zip")
    sign_zipcon(files, key_be, cert, ours)

    ok = True
    report = verify_zipcon(ours)
    print("наша сборка → наша проверка:", report["ok"], "| problems:", report["problems"])
    ok &= report["ok"]

    try:
        from kalkan_dll import KC_CERT_CA, KC_CERT_INTERMEDIATE, KalkanOracle
        oracle = KalkanOracle()
        oracle.init()
        oracle.load_key_store(password, key_path, "")
        root, nca = roots()
        oracle.load_cert_file(root, KC_CERT_CA)
        oracle.load_cert_file(nca, KC_CERT_INTERMEDIATE)
    except Exception as ex:
        print(f"ПРОПУЩЕНО: DLL недоступна ({type(ex).__name__}) — сверка с вендором не выполнялась")
        return ok

    rc, text = _dll_verify(ours, oracle)
    good = rc == 0 and "CMS Verify - OK" in text
    print(f"наша сборка → DLL ZipConVerify: rc=0x{rc:08x} «{_verdict(text)}» -> {good}")
    ok &= good

    dll_zip = os.path.join(WORK, "from_dll.zip")
    rc2 = oracle.kc.ZipConSign(b"", f"{files[0]}|{files[1]}|".encode(),
                               b"from_dll", WORK.encode(), 0)
    if rc2 == 0 and os.path.exists(dll_zip):
        report2 = verify_zipcon(dll_zip)
        print("контейнер DLL → наша проверка:", report2["ok"],
              "| problems:", report2["problems"])
        ok &= report2["ok"]
    else:
        print(f"ПРОПУЩЕНО: DLL не собрала контейнер (rc=0x{rc2:08x})")
    oracle.finalize()
    return ok


def test_sdk_sample() -> bool:
    """Образец SDK: дайджесты совпадают, подписи — нет (образцы устарели)."""
    if not os.path.exists(SDK_ZIP):
        print("ПРОПУЩЕНО: образец ZipCon из SDK не найден — проверка не выполнялась")
        return True
    report = verify_zipcon(SDK_ZIP)
    hashes_ok = [f for f in report["files"] if f["digest_ok"] is True]
    print(f"образец SDK: дайджестов совпало {len(hashes_ok)} из {len(report['files'])}, "
          f"подписи ok={[s['ok'] for s in report['signatures']]}, итог ok={report['ok']}")
    return (len(report["files"]) > 0 and len(hashes_ok) == len(report["files"])
            and report["ok"] is False)


def test_negative() -> bool:
    """Подмена файла и отсутствие манифеста должны отвергаться."""
    ok = True
    key_path, password = first_key()
    if key_path:
        cert, key_be = load_gost2015_p12(open(key_path, "rb").read(), password)
        files = _make_files()
        original = os.path.join(WORK, "neg.zip")
        sign_zipcon(files, key_be, cert, original)
        tampered = os.path.join(WORK, "neg_tampered.zip")
        with zipfile.ZipFile(original) as src, \
                zipfile.ZipFile(tampered, "w", zipfile.ZIP_DEFLATED) as dst:
            for item in src.infolist():
                data = src.read(item.filename)
                if item.filename == "alpha.txt":
                    data += b"!"
                dst.writestr(item, data)
        report = verify_zipcon(tampered)
        ok &= report["ok"] is False
        print("подмена файла:", report["ok"], "| problems:", report["problems"])

    no_manifest = os.path.join(WORK, "no_manifest.zip")
    with zipfile.ZipFile(no_manifest, "w") as zf:
        zf.writestr("alpha.txt", b"data")
    report2 = verify_zipcon(no_manifest)
    ok &= report2["ok"] is False and any("NCAManifest" in p for p in report2["problems"])
    print("архив без манифеста:", report2["ok"], "| problems:", report2["problems"])

    broken = os.path.join(WORK, "broken_manifest.zip")
    with zipfile.ZipFile(broken, "w") as zf:
        zf.writestr("alpha.txt", b"data")
        zf.writestr(MANIFEST_NAME, b"<NCAManifest><broken")
    report3 = verify_zipcon(broken)
    ok &= report3["ok"] is False and any("не разобран" in p for p in report3["problems"])
    print("битый манифест:", report3["ok"], "| problems:", report3["problems"])
    return ok


class _RawNameInfo(zipfile.ZipInfo):
    """ZipInfo, который кладёт в архив «сырые» байты имени (ANSI, без флага UTF-8)."""

    def _encodeFilenameFlags(self):
        return self._raw_name, 0


def test_cp1251_container() -> bool:
    """
    Не-ASCII имена: имя записи в архиве в ANSI (cp1251) без флага UTF-8, манифест —
    в UTF-8 и (второй вариант) в cp1251 при объявленном `encoding="UTF-8"`.
    Файл должен находиться, а дайджест — совпадать.
    """
    name = "документ.txt"
    data = "Кириллица в контейнере".encode("utf-8")
    objects = [{"uri": name, "algorithm": DIGEST_512, "digest": streebog(data, 64)}]
    base = build_manifest(objects, ["META-INF/signature-cp1251.cms"])
    os.makedirs(WORK, exist_ok=True)
    ok = True
    for label, manifest in (("манифест UTF-8", base),
                            ("манифест cp1251", base.replace(name.encode("utf-8"),
                                                             name.encode("cp1251")))):
        path = os.path.join(WORK, f"cp1251_{'utf8' if 'UTF-8' in label else 'ansi'}.zip")
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
            info = _RawNameInfo(name)
            info._raw_name = name.encode("cp1251")
            zf.writestr(info, data)
            zf.writestr(MANIFEST_NAME, manifest)
        report = verify_zipcon(path)
        good = (report["encoding"] is not None and bool(report["files"])
                and report["files"][0]["digest_ok"] is True)
        ok &= good
        print(f"ANSI-имя в ZIP, {label}: найден и дайджест совпал: {good}"
              f" (encoding={report['encoding']})")
    return ok


def main() -> int:
    print("=== ZipCon (контейнеры ZipConSign/ZipConVerify) ===")
    ok = True
    for test in (test_manifest_build, test_cp1251_container, test_roundtrip,
                 test_sdk_sample, test_negative):
        ok &= test()
    print("\nИТОГ:", "OK" if ok else "ЕСТЬ ОШИБКИ")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
