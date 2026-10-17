"""
kalkan_zipcon.py — контейнеры ZipCon (аналоги ZipConSign/ZipConVerify из KalkanCrypt).

Формат разобран на реальных контейнерах НУЦ и на контейнере, собранном самой DLL:

    ZIP:
        <подписанные файлы>
        META-INF/NCAManifest.xml       — манифест: SigReference + DataObjectReference
        META-INF/signature-<id>.cms    — CMS-подпись (detached) по БАЙТАМ манифеста

Манифест (байт-в-байт как у вендора):

    <?xml version="1.0" encoding="UTF-8" standalone="yes"?> \r\n
    <NCAManifest>\r\n
    \t<SigReference URI="META-INF/signature-<id>.cms"/>\r\n
    \t<DataObjectReference URI="файл">\r\n
    \t\t<DigestMethod Algorithm="<uri>"/>\r\n
    \t\t<DigestValue><base64></DigestValue>\r\n
    \t</DataObjectReference>\r\n
    </NCAManifest>

URI дайджеста: `…#gost34311` — ГОСТ 34.11-94 (наша `gost341194_kz`);
`…pkigovkz…gostr34112015-256/512` — Стрибог (наш `streebog`).

Подпись — обычный CMS с `eContentType = id-data` и пустым содержимым; подписанные
байты — манифест, поэтому проверка: `verify_cms(cms, detached_content=manifest)`.

Замечено на вендорских контейнерах (важно для совместимости):
  * DLL кладёт `NULL` в параметры `digestAlgorithm` — без этого её `ZipConVerify`
    отвечает «CMS Verify - FAILED» (наши подписи печатают `NULL`);
  * не-ASCII имена файлов DLL хранит как ANSI (cp1251) без флага UTF-8, а манифест
    помечает как `UTF-8` — читаем оба варианта (см. `parse_manifest`/`_resolve_entry`).
"""

from __future__ import annotations

import base64
import io
import os
import secrets
import zipfile
import xml.etree.ElementTree as ET

from kalkan_legacy import gost341194_kz
from kalkan_sign import sign_cms
from kalkan_verify import streebog, verify_cms

__all__ = [
    "MANIFEST_NAME", "SIG_PREFIX", "DIGEST_GOST34311", "DIGEST_GOST2015",
    "parse_manifest", "build_manifest", "verify_zipcon", "sign_zipcon",
]

MANIFEST_NAME = "META-INF/NCAManifest.xml"
SIG_PREFIX = "META-INF/signature-"
DIGEST_GOST34311 = "http://www.w3.org/2001/04/xmldsig-more#gost34311"
DIGEST_GOST2015 = {
    32: "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34112015-256",
    64: "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34112015-512",
}
_OBJECT_TAG = "DataObjectReference"
_SIG_TAG = "SigReference"


def _digest_by_uri(uri: str):
    """Функция дайджеста по URI из манифеста (None — алгоритм неизвестен)."""
    if uri == DIGEST_GOST34311:
        return gost341194_kz
    for size, known in DIGEST_GOST2015.items():
        if uri == known:
            return lambda data, _s=size: streebog(data, _s)
    return None


def parse_manifest(manifest: bytes) -> dict:
    """
    Разбор NCAManifest.xml: ссылки на подписи и объекты с дайджестами.

    Возвращает {"signatures": [uri, …], "encoding": "utf-8"|"cp1251",
                "objects": [{"uri", "algorithm", "digest"}, …]}.

    Вендор печатает `encoding="UTF-8"`, но в Windows-версии встречаются манифесты с
    именами в cp1251 (однобайтовый ANSI) — такие тоже разбираем (см. verify_zipcon).
    Малиформленный XML → ValueError (в verify_zipcon это превращается в отказ).
    """
    try:
        root = ET.fromstring(manifest)
        encoding = "utf-8"
    except ET.ParseError:
        root = ET.fromstring(manifest.decode("cp1251"))
        encoding = "cp1251"
    if not root.tag.endswith("NCAManifest"):
        raise ValueError(f"ожидался корень NCAManifest, получен {root.tag}")
    signatures, objects = [], []
    for child in root:
        if child.tag.endswith(_SIG_TAG):
            signatures.append(child.attrib.get("URI", ""))
        elif child.tag.endswith(_OBJECT_TAG):
            algorithm, digest = None, None
            for sub in child:
                if sub.tag.endswith("DigestMethod"):
                    algorithm = sub.attrib.get("Algorithm", "")
                elif sub.tag.endswith("DigestValue"):
                    digest = (sub.text or "").strip()
            if algorithm is None or digest is None:
                raise ValueError(f"у объекта {child.attrib.get('URI')} нет дайджеста")
            objects.append({"uri": child.attrib.get("URI", ""), "algorithm": algorithm,
                            "digest": base64.b64decode(digest)})
    return {"signatures": signatures, "encoding": encoding, "objects": objects}


def build_manifest(objects: list, signature_uris: list, newline: str = "\r\n") -> bytes:
    """Сборка NCAManifest.xml в формате вендора (objects: uri/algorithm/digest(bytes))."""
    parts = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?> ', newline,
             "<NCAManifest>", newline]
    for uri in signature_uris:
        parts.append(f'\t<SigReference URI="{uri}"/>' + newline)
    for obj in objects:
        parts.append(f'\t<DataObjectReference URI="{obj["uri"]}">' + newline)
        parts.append(f'\t\t<DigestMethod Algorithm="{obj["algorithm"]}"/>' + newline)
        parts.append("\t\t<DigestValue>"
                     + base64.b64encode(obj["digest"]).decode() + "</DigestValue>" + newline)
        parts.append("\t</DataObjectReference>" + newline)
    parts.append("</NCAManifest>")
    return "".join(parts).encode("utf-8")


def _raw_name(info: "zipfile.ZipInfo") -> bytes:
    """Байты имени записи внутри ZIP: UTF-8 при флаге 0x800, иначе как есть (cp437-декод)."""
    return info.filename.encode("utf-8") if info.flag_bits & 0x800 \
        else info.filename.encode("cp437")


def _resolve_entry(uri: str, names, raw_index, manifest_encoding: str = "utf-8"):
    """
    Имя записи в архиве, соответствующее URI из манифеста.

    Обычно совпадает буквально; для не-ASCII имён вендор пишет в ZIP байты ANSI (cp1251)
    без флага UTF-8, поэтому дополнительно сверяем «сырые» байты имени.
    """
    if uri in names:
        return uri
    for encoding in (manifest_encoding, "utf-8", "cp1251"):
        try:
            raw = uri.encode(encoding)
        except (UnicodeEncodeError, LookupError):
            continue
        if raw in raw_index:
            return raw_index[raw]
    return None


def _open_zip(source):
    """Открывает ZIP по пути или по байтам; возвращает (ZipFile, имена записей)."""
    if isinstance(source, (bytes, bytearray)):
        zf = zipfile.ZipFile(io.BytesIO(source))
    else:
        zf = zipfile.ZipFile(source)
    return zf, zf.namelist()


def verify_zipcon(source, trust_anchor_der: bytes = None, check_time=None) -> dict:
    """
    Проверка контейнера ZipCon: дайджесты файлов по манифесту + подписи по манифесту.

    source — путь к .zip или его байты. Отчёт:
        {"ok", "manifest", "files": [{"uri", "digest_ok", "algorithm", "reason"}],
         "signatures": [{"name", "signers", "ok", "reason"}], "problems": [...]}

    `ok` — истина только если манифест разобран, все файлы на месте и их дайджесты
    совпали, и каждая ссылка на подпись проверена успешно (цепочка/сроки — по
    параметрам `trust_anchor_der`/`check_time`, как в verify_cms).
    """
    report = {"ok": False, "manifest": None, "encoding": None,
              "files": [], "signatures": [], "problems": []}
    zf, names = _open_zip(source)
    try:
        raw_index = {_raw_name(info): info.filename for info in zf.infolist()}
        manifest_name = next((n for n in names if n.lower() == MANIFEST_NAME.lower()), None)
        if manifest_name is None:
            report["problems"].append("в архиве нет META-INF/NCAManifest.xml")
            return report
        report["manifest"] = manifest_name
        manifest = zf.read(manifest_name)
        try:
            parsed = parse_manifest(manifest)
        except (ValueError, ET.ParseError) as ex:
            report["problems"].append(f"манифест не разобран: {ex}")
            return report
        report["encoding"] = parsed["encoding"]

        for obj in parsed["objects"]:
            entry = {"uri": obj["uri"], "algorithm": obj["algorithm"],
                     "digest_ok": None, "reason": None}
            digest_func = _digest_by_uri(obj["algorithm"])
            resolved = _resolve_entry(obj["uri"], names, raw_index, parsed["encoding"])
            if digest_func is None:
                entry["reason"] = "неизвестный алгоритм дайджеста"
            elif resolved is None:
                entry["reason"] = "файла нет в архиве"
            else:
                entry["digest_ok"] = digest_func(zf.read(resolved)) == obj["digest"]
                if not entry["digest_ok"]:
                    entry["reason"] = "дайджест не совпал"
            report["files"].append(entry)
            if entry["digest_ok"] is not True:
                report["problems"].append(f"{obj['uri']}: {entry['reason']}")

        for sig_uri in parsed["signatures"]:
            entry = {"name": sig_uri, "signers": [], "ok": False, "reason": None}
            resolved = _resolve_entry(sig_uri, names, raw_index, parsed["encoding"])
            if resolved is None:
                entry["reason"] = "файла подписи нет в архиве"
            else:
                result = verify_cms(zf.read(resolved), detached_content=manifest,
                                    trust_anchor_der=trust_anchor_der,
                                    check_time=check_time)
                entry["signers"] = result["signers"]
                entry["ok"] = bool(result["signers"]) and all(
                    s["state"] == "ok" for s in result["signers"])
                if not entry["ok"]:
                    entry["reason"] = ", ".join(s["state"] for s in result["signers"]) \
                        or "подписантов нет"
            report["signatures"].append(entry)
            if not entry["ok"]:
                report["problems"].append(f"{sig_uri}: {entry['reason']}")
    finally:
        zf.close()

    report["ok"] = (not report["problems"]
                    and bool(report["signatures"])
                    and all(f["digest_ok"] is True for f in report["files"])
                    and all(s["ok"] for s in report["signatures"]))
    return report


def sign_zipcon(files: list, private_key_be: bytes, certificate_der: bytes, out_path: str,
                signature_id: str = None, digest_size: int = 64, signing_time=None,
                extra_certs: list = None, entry_names: dict = None) -> dict:
    """
    Сборка контейнера ZipCon: манифест + detached CMS по байтам манифеста.

    files        — пути к подписываемым файлам;
    signature_id — идентификатор в имени `signature-<id>.cms` (по умолчанию случайный,
                   как у DLL: 10 hex-символов; значение на проверку не влияет — имя
                   берётся из манифеста);
    digest_size  — 32 (Стрибог-256) или 64 (Стрибог-512, как у ключей НУЦ 512);
    entry_names  — соответствие «путь → имя внутри архива» (по умолчанию basename).
    """
    entry_names = entry_names or {}
    names = [entry_names.get(path, os.path.basename(path)) for path in files]
    algorithm = DIGEST_GOST2015[32 if digest_size == 32 else 64]
    objects = [{"uri": name, "algorithm": algorithm,
                "digest": streebog(open(path, "rb").read(), digest_size)}
               for path, name in zip(files, names)]

    sig_name = f"{SIG_PREFIX}{signature_id or secrets.token_hex(5)}.cms"
    manifest = build_manifest(objects, [sig_name])
    cms = sign_cms(private_key_be, manifest, certificate_der, detached=True,
                   signing_time=signing_time, extra_certs=extra_certs)

    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, name in zip(files, names):
            zf.write(path, name)
        zf.writestr(MANIFEST_NAME, manifest)
        zf.writestr(sig_name, cms)
    return {"ok": True, "manifest": MANIFEST_NAME, "signature": sig_name,
            "objects": [o["uri"] for o in objects]}

