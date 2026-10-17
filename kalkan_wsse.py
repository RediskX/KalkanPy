"""
kalkan_wsse.py — WS-Security (WSSE) с ГОСТ 2015, независимо.

Строит SOAP-конверт с заголовком wsse:Security:
  * wsu:Timestamp (Id="TS-1") — подписываемый элемент;
  * wsse:BinarySecurityToken — сертификат (base64 DER);
  * ds:Signature с Reference URI="#TS-1" (C14N + ГОСТ-подпись).

Проверка: пересчёт digest по элементу с указанным wsu:Id и проверка подписи
открытым ключом сертификата из BinarySecurityToken.
"""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone

from lxml import etree

from kalkan_sign import _sign_der
from kalkan_verify import (load_certificate, public_key_from_spki, streebog,
                           verify_signature)

SOAP = "http://schemas.xmlsoap.org/soap/envelope/"
WSSE = ("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd")
WSU = ("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd")
DS = "http://www.w3.org/2000/09/xmldsig#"
C14N_URI = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
C14N_COMMENTS_URI = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"
EXC_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#"
HASH_URI = "http://www.w3.org/2001/04/xmldsig-more#gost34311"
SIG_URI = "http://www.w3.org/2001/04/xmldsig-more#gost34310-gost34311"
B64_TYPE = ("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-"
            "security-1.0#Base64Binary")
X509_TYPE = ("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-"
             "profile-1.0#X509v3")

__all__ = ["sign_wsse", "verify_wsse"]


def _q(ns: str, name: str) -> str:
    return f"{{{ns}}}{name}"


def sign_wsse(private_key_be: bytes, payload_xml: bytes, certificate_der: bytes,
              ttl_seconds: int = 600, digest_size: int = 32) -> bytes:
    """Возвращает SOAP-конверт с подписанным WSSE-Timestamp."""
    size = len(private_key_be)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    expires = now + timedelta(seconds=ttl_seconds)

    nsmap = {"soap": SOAP, "wsse": WSSE, "wsu": WSU, "ds": DS}
    envelope = etree.Element(_q(SOAP, "Envelope"), nsmap=nsmap)
    header = etree.SubElement(envelope, _q(SOAP, "Header"))
    security = etree.SubElement(header, _q(WSSE, "Security"))
    security.set(_q(SOAP, "mustUnderstand"), "1")

    timestamp = etree.SubElement(security, _q(WSU, "Timestamp"))
    timestamp.set(_q(WSU, "Id"), "TS-1")
    etree.SubElement(timestamp, _q(WSU, "Created")).text = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    etree.SubElement(timestamp, _q(WSU, "Expires")).text = expires.strftime("%Y-%m-%dT%H:%M:%SZ")

    token = etree.SubElement(security, _q(WSSE, "BinarySecurityToken"))
    token.set("EncodingType", B64_TYPE)
    token.set("ValueType", X509_TYPE)
    token.set(_q(WSU, "Id"), "X509-1")
    token.text = base64.b64encode(certificate_der).decode("ascii")

    body = etree.SubElement(envelope, _q(SOAP, "Body"))
    body.append(etree.fromstring(payload_xml))

    signature = etree.SubElement(security, _q(DS, "Signature"))
    signed_info = etree.SubElement(signature, _q(DS, "SignedInfo"))
    etree.SubElement(signed_info, _q(DS, "CanonicalizationMethod")).set("Algorithm", C14N_URI)
    etree.SubElement(signed_info, _q(DS, "SignatureMethod")).set("Algorithm", SIG_URI)
    ref = etree.SubElement(signed_info, _q(DS, "Reference"))
    ref.set("URI", "#TS-1")
    transforms = etree.SubElement(ref, _q(DS, "Transforms"))
    etree.SubElement(transforms, _q(DS, "Transform")).set("Algorithm", C14N_URI)
    etree.SubElement(ref, _q(DS, "DigestMethod")).set("Algorithm", HASH_URI)
    digest_like = etree.SubElement(ref, _q(DS, "DigestValue"))
    signature_value = etree.SubElement(signature, _q(DS, "SignatureValue"))
    key_info = etree.SubElement(signature, _q(DS, "KeyInfo"))
    ref_node = etree.SubElement(key_info, _q(WSSE, "SecurityTokenReference"))
    token_ref = etree.SubElement(ref_node, _q(WSSE, "Reference"))
    token_ref.set("URI", "#X509-1")                     # привязка подписи к токену
    token_ref.set("ValueType", X509_TYPE)

    digest = streebog(_c14n(timestamp), digest_size)
    digest_like.text = base64.b64encode(digest).decode("ascii")
    signature_value.text = base64.b64encode(
        _sign_der(private_key_be, streebog(_c14n(signed_info), size))).decode("ascii")

    return etree.tostring(envelope, xml_declaration=True, encoding="UTF-8")


def _c14n(el, algorithm: str = C14N_URI, inclusive_prefixes=None) -> bytes:
    """
    Канонизация так, как указано в документе: inclusive/exclusive + комментарии.

    Вендор (SignWSSE) использует exc-c14n с InclusiveNamespaces, наш sign_wsse — inclusive
    C14N 1.0; один верификатор должен понимать оба.
    """
    exclusive = "exc-c14n" in (algorithm or "")
    with_comments = "WithComments" in (algorithm or "")
    kwargs = {"method": "c14n", "exclusive": exclusive, "with_comments": with_comments}
    if exclusive and inclusive_prefixes:
        kwargs["inclusive_ns_prefixes"] = list(inclusive_prefixes)
    return etree.tostring(el, **kwargs)


def _inclusive_prefixes(node) -> list:
    """PrefixList из c14n:InclusiveNamespaces (пусто, если узла нет)."""
    found = node.find(f"{{{EXC_C14N}}}InclusiveNamespaces") if node is not None else None
    if found is None:
        return []
    return (found.get("PrefixList") or "").split()


def _reference_c14n(reference) -> tuple:
    """Алгоритм канонизации Reference (последний C14N-трансформ) и его префиксы."""
    algorithm, prefixes = C14N_URI, []
    for transform in reference.findall(f"{{{DS}}}Transforms/{{{DS}}}Transform"):
        algo = transform.get("Algorithm") or ""
        if "c14n" in algo:
            algorithm = algo
            prefixes = _inclusive_prefixes(transform)
    return algorithm, prefixes


def _certificate_of_signature(root, signature) -> tuple:
    """
    Сертификат подписи и признак привязки к токену.

    Источники (в порядке приоритета): ds:X509Certificate, wsse:KeyIdentifier
    (так делает вендор в SignWSSE), wsse:BinarySecurityToken (наш sign_wsse).
    """
    x509 = signature.findtext(f".//{{{DS}}}X509Certificate")
    if x509 and x509.strip():
        return base64.b64decode("".join(x509.split())), "X509Certificate", True

    key_id = signature.find(f".//{{{WSSE}}}KeyIdentifier")
    if key_id is not None and (key_id.text or "").strip():
        return base64.b64decode("".join(key_id.text.split())), "KeyIdentifier", True

    token, bound = _find_token(root, signature)
    if token is None or not (token.text or "").strip():
        return None, "нет сертификата в KeyInfo", False
    return base64.b64decode("".join(token.text.split())), "BinarySecurityToken", bound


def _find_token(root, signature):
    """
    BinarySecurityToken, на который указывает ds:KeyInfo/wsse:SecurityTokenReference.

    Возвращает (token, bound): bound=True, только если токен найден по ссылке KeyInfo
    (иначе подпись формально не связана с токеном).
    """
    refs = signature.findall(f".//{{{WSSE}}}SecurityTokenReference/{{{WSSE}}}Reference")
    ids = [r.get("URI", "")[1:] for r in refs if r.get("URI", "").startswith("#")]
    tokens = root.findall(f".//{{{WSSE}}}BinarySecurityToken")
    for wanted in ids:
        for token in tokens:
            if token.get(f"{{{WSU}}}Id") == wanted:
                return token, True
    if len(tokens) == 1:                                # единственный токен — берём его
        return tokens[0], False
    return None, False


def _parse_utc(text) -> datetime:
    return datetime.strptime(text.strip(), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _timestamp_freshness(target) -> tuple:
    """Свежесть подписанного wsu:Timestamp: Created <= now <= Expires (допуск 60 с)."""
    created_text = target.findtext(f"{{{WSU}}}Created")
    expires_text = target.findtext(f"{{{WSU}}}Expires")
    if created_text is None and expires_text is None:
        return None, "подписан не Timestamp — свежесть не проверялась"
    now = datetime.now(timezone.utc)
    skew = timedelta(seconds=60)
    for text in (created_text, expires_text):
        if text is not None:
            try:
                _parse_utc(text)
            except ValueError:
                return False, "неверный формат времени в wsu:Timestamp"
    created = _parse_utc(created_text) if created_text else None
    expires = _parse_utc(expires_text) if expires_text else None
    if created is not None and now < created - skew:
        return False, "wsu:Timestamp ещё не действителен (Created в будущем)"
    if expires is not None and now > expires + skew:
        return False, "wsu:Timestamp просрочен (Expires в прошлом)"
    return True, None


def _verify_one_signature(root, signature) -> dict:
    """Проверяет одну ds:Signature в конверте (целостность, подпись, привязка, свежесть)."""
    signed_info = signature.find(f"{{{DS}}}SignedInfo")
    ref = signature.find(f"{{{DS}}}SignedInfo/{{{DS}}}Reference")
    if signed_info is None or ref is None:
        raise ValueError("малиформленный WSSE: нет Signature/SignedInfo/Reference")
    uri = ref.get("URI")
    if not uri:
        raise ValueError("малиформленный WSSE: у Reference нет URI")
    ref_id = uri[1:] if uri.startswith("#") else uri

    matches = root.findall(f".//*[@{{{WSU}}}Id='{ref_id}']")
    if not matches:
        raise ValueError(f"не найден элемент с wsu:Id={ref_id}")
    if len(matches) > 1:
        # дубликат Id = попытка XML Signature Wrapping: какой из узлов подписан — неоднозначно
        raise ValueError(f"wsu:Id={ref_id} встречается {len(matches)} раз — подпись неоднозначна")
    target = matches[0]

    digest_text = ref.findtext(f"{{{DS}}}DigestValue")
    if digest_text is None:
        raise ValueError("малиформленный WSSE: нет DigestValue")
    digest_value = base64.b64decode("".join(digest_text.split()))
    digest_size = len(digest_value)
    if digest_size not in (32, 64):
        raise ValueError(f"неподдерживаемый размер DigestValue: {digest_size}")

    ref_algo, ref_prefixes = _reference_c14n(ref)       # канонизация по документу
    reference_ok = streebog(_c14n(target, ref_algo, ref_prefixes), digest_size) == digest_value

    certificate_der, cert_source, token_bound = _certificate_of_signature(root, signature)
    if certificate_der is None:
        raise ValueError("малиформленный WSSE: нет сертификата в KeyInfo/SecurityTokenReference")
    from kalkan_verify import _spki_from_cert
    _, pk = public_key_from_spki(_spki_from_cert(certificate_der))

    sig_text = signature.findtext(f"{{{DS}}}SignatureValue")
    if sig_text is None:
        raise ValueError("малиформленный WSSE: нет SignatureValue")
    sig = base64.b64decode("".join(sig_text.split()))
    if len(sig) not in (64, 128):
        raise ValueError(f"неподдерживаемая длина SignatureValue: {len(sig)}")
    size = len(sig) // 2

    c14n_node = signed_info.find(f"{{{DS}}}CanonicalizationMethod")
    si_algo = (c14n_node.get("Algorithm") if c14n_node is not None else C14N_URI) or C14N_URI
    si_prefixes = _inclusive_prefixes(c14n_node)
    signature_ok = verify_signature(pk, streebog(_c14n(signed_info, si_algo, si_prefixes), size),
                                    sig, size)

    time_ok, fresh_note = _timestamp_freshness(target)
    reasons = []
    if not reference_ok:
        reasons.append("digest подписанного элемента не сходится")
    if not signature_ok:
        reasons.append("подпись не сходится")
    if not token_bound:
        reasons.append("подпись не привязана к токену (KeyInfo/SecurityTokenReference)")
    if time_ok is False:
        reasons.append(fresh_note)

    return {"ok": not reasons and reference_ok and signature_ok,
            "token_bound": token_bound, "reference_ok": reference_ok,
            "signature_ok": signature_ok, "time_ok": time_ok,
            "certificate_der": certificate_der, "certificate_source": cert_source,
            "c14n": "exclusive" if "exc-c14n" in si_algo else "inclusive",
            "signed_id": ref_id, "signed_tag": etree.QName(target).localname,
            "note": "; ".join(reasons) if reasons else None}


def verify_wsse(envelope_bytes: bytes, trust_anchor_der: bytes = None) -> dict:
    """
    Проверяет ВСЕ ds:Signature конверта и свежесть подписанного Timestamp.

    Правило агрегата — как в `verify_xml`: `ok=True`, если подписи есть и КАЖДАЯ из них
    валидна (целостность + подпись + привязка к токену + свежесть подписанного Timestamp).
    Дополнительно отвергаются ДУБЛИРУЮЩИЕ подписи одного и того же узла (`wsu:Id`):
    несколько разных валидных подписей (например, на Timestamp и на тело) допустимы.
    Любая битая/поддельная подпись делает `ok=False`.

    Доверие сертификата — обязанность вызывающего: передайте `trust_anchor_der`, чтобы
    дополнительно проверить цепочку (поле `chain_ok`; `None` если якорь не передан).
    Если подписан элемент без Created/Expires, `time_ok=None` — решение о свежести
    принимает вызывающий.
    """
    root = etree.fromstring(envelope_bytes)
    signatures = root.findall(f".//{{{DS}}}Signature")
    if not signatures:
        raise ValueError("малиформленный WSSE: нет ds:Signature")

    results = [_verify_one_signature(root, sig) for sig in signatures]
    first = results[0]
    chain_ok = None
    if trust_anchor_der is not None:
        from kalkan_verify import verify_certificate_chain
        try:
            chain_ok = verify_certificate_chain([first["certificate_der"]],
                                                trust_anchor_der)
        except Exception:
            chain_ok = False

    signed_ids = [r["signed_id"] for r in results]
    duplicated = sorted({i for i in signed_ids if signed_ids.count(i) > 1})
    ok = all(r["ok"] for r in results) and not duplicated and chain_ok is not False

    note = first["note"] if len(results) == 1 else \
        (f"подписей в конверте: {len(results)}; "
         + ("все валидны" if ok else "есть невалидные"))
    if duplicated:
        note = f"подпись узла(ов) {', '.join(duplicated)} продублирована — отклонено"

    return {"ok": ok, "count": len(results), "signatures": results,
            "token_bound": first["token_bound"],
            "reference_ok": first["reference_ok"], "signature_ok": first["signature_ok"],
            "time_ok": first["time_ok"], "chain_ok": chain_ok,
            "certificate_der": first["certificate_der"],
            "certificate_source": first["certificate_source"], "c14n": first["c14n"],
            "signed_id": first["signed_id"], "signed_tag": first["signed_tag"],
            "note": note}
