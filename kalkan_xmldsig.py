"""
kalkan_xmldsig.py — XMLDSig (enveloped) с ГОСТ 2015, независимо.

URI алгоритмов взяты из самого KalkanCrypt.dll (встроенный xmlsec):
    хэш      : http://www.w3.org/2001/04/xmldsig-more#gost34311
    подпись  : http://www.w3.org/2001/04/xmldsig-more#gost34310-gost34311
    C14N     : http://www.w3.org/TR/2001/REC-xml-c14n-20010315
    enveloped: http://www.w3.org/2000/09/xmldsig#enveloped-signature

Схема: enveloped-подпись документа. DigestValue = Стрибог(C14N документа без
элемента Signature); SignatureValue = ГОСТ-подпись над Стрибог(SignedInfo C14N).
"""

from __future__ import annotations

import base64
import copy

from lxml import etree

from kalkan_sign import _sign_der
from kalkan_verify import (load_certificate, public_key_from_spki, streebog,
                           verify_signature)

DS = "http://www.w3.org/2000/09/xmldsig#"
C14N_URI = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
C14N_COMMENTS_URI = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"
ENVELOPED_URI = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"

# URI алгоритмов КZ (взяты из вывода настоящего KalkanCrypt.dll)
_SIG_URI = {
    32: "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34102015-gostr34112015-256",
    64: "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34102015-gostr34112015-512",
}
_HASH_URI = {
    32: "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34112015-256",
    64: "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34112015-512",
}
# обратная совместимость (старые URI)
HASH_URI = "http://www.w3.org/2001/04/xmldsig-more#gost34311"
SIG_URI = "http://www.w3.org/2001/04/xmldsig-more#gost34310-gost34311"

__all__ = ["sign_xml", "verify_xml", "C14N_URI", "HASH_URI", "SIG_URI"]


def _c14n(element, with_comments: bool = False) -> bytes:
    return etree.tostring(element, method="c14n", with_comments=with_comments)


def _c14n_without_signature(root, with_comments: bool = False) -> bytes:
    clone = copy.deepcopy(root)
    for sig in clone.findall(f".//{{{DS}}}Signature"):
        sig.getparent().remove(sig)
    return _c14n(clone, with_comments=with_comments)


def _wrap_b64(value: bytes) -> str:
    b64 = base64.b64encode(value).decode("ascii")
    return "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))


def _tag(name: str) -> str:
    return f"{{{DS}}}{name}"


def sign_xml(private_key_be: bytes, xml_bytes: bytes, certificate_der: bytes) -> bytes:
    """Строит XML с enveloped-подписью ГОСТ 2015 в формате Калкана. Возвращает bytes."""
    root = etree.fromstring(xml_bytes)
    size = len(private_key_be)
    sig_uri = _SIG_URI[size]
    hash_uri = _HASH_URI[size]

    sig = etree.SubElement(root, _tag("Signature"))
    signed_info = etree.SubElement(sig, _tag("SignedInfo"))
    etree.SubElement(signed_info, _tag("CanonicalizationMethod")).set("Algorithm", C14N_URI)
    etree.SubElement(signed_info, _tag("SignatureMethod")).set("Algorithm", sig_uri)

    ref = etree.SubElement(signed_info, _tag("Reference"))
    ref.set("URI", "")
    transforms = etree.SubElement(ref, _tag("Transforms"))
    etree.SubElement(transforms, _tag("Transform")).set("Algorithm", ENVELOPED_URI)
    etree.SubElement(transforms, _tag("Transform")).set("Algorithm", C14N_COMMENTS_URI)
    etree.SubElement(ref, _tag("DigestMethod")).set("Algorithm", hash_uri)
    digest_value = etree.SubElement(ref, _tag("DigestValue"))

    signature_value = etree.SubElement(sig, _tag("SignatureValue"))
    key_info = etree.SubElement(sig, _tag("KeyInfo"))
    x509_data = etree.SubElement(key_info, _tag("X509Data"))
    x509_cert = etree.SubElement(x509_data, _tag("X509Certificate"))
    x509_cert.text = _wrap_b64(certificate_der)

    digest = streebog(_c14n_without_signature(root, with_comments=True), size)
    digest_value.text = _wrap_b64(digest)

    signed_info_c14n = _c14n(signed_info)
    signature = _sign_der(private_key_be, streebog(signed_info_c14n, size))
    signature_value.text = _wrap_b64(signature)

    return etree.tostring(root, xml_declaration=True, encoding="UTF-8")


def _verify_one(root, sig, certificate_der):
    """Проверяет одну подпись ds:Signature (целостность + подпись)."""
    signed_info = sig.find(f"{{{DS}}}SignedInfo")
    ref = sig.find(f"{{{DS}}}SignedInfo/{{{DS}}}Reference")
    if signed_info is None or ref is None:
        raise ValueError("малиформленный XMLDSig: нет SignedInfo/Reference")
    digest_node = ref.find(f"{{{DS}}}DigestValue")
    if digest_node is None or digest_node.text is None:
        raise ValueError("малиформленный XMLDSig: нет DigestValue")
    digest_value = base64.b64decode(digest_node.text.strip())
    digest_size = len(digest_value)
    if digest_size not in (32, 64):
        raise ValueError(f"неподдерживаемый размер DigestValue: {digest_size}")

    with_comments = any(
        t.get("Algorithm") == C14N_COMMENTS_URI
        for t in ref.findall(f"{{{DS}}}Transforms/{{{DS}}}Transform"))
    recomputed = streebog(_c14n_without_signature(root, with_comments=with_comments),
                          digest_size)
    reference_ok = recomputed == digest_value

    cert_der = certificate_der
    if cert_der is None:
        x509_b64 = sig.findtext(
            f"{{{DS}}}KeyInfo/{{{DS}}}X509Data/{{{DS}}}X509Certificate")
        if x509_b64 is None:
            raise ValueError("малиформленный XMLDSig: нет X509Certificate")
        cert_der = base64.b64decode(x509_b64.strip())

    from kalkan_verify import _spki_from_cert
    _, pk = public_key_from_spki(_spki_from_cert(cert_der))

    sig_value = sig.findtext(f"{{{DS}}}SignatureValue")
    if sig_value is None:
        raise ValueError("малиформленный XMLDSig: нет SignatureValue")
    signature = base64.b64decode(sig_value.strip())
    if len(signature) not in (64, 128):
        raise ValueError(f"неподдерживаемая длина SignatureValue: {len(signature)}")
    size = len(signature) // 2
    signature_ok = verify_signature(pk, streebog(_c14n(signed_info), size), signature, size)
    return {"reference_ok": reference_ok, "signature_ok": signature_ok,
            "certificate_der": cert_der}


def verify_xml(xml_bytes: bytes, certificate_der: bytes = None) -> dict:
    """
    Проверяет ВСЕ enveloped-подписи документа, а не только первую.

    Возвращает {'count', 'ok', 'signatures': [...]}, а также совместимые ключи
    reference_ok/signature_ok/certificate_der (от первой подписи). ok=True только если
    подписи есть и КАЖДАЯ одновременно целостна и валидна — лишняя или битая подпись в
    документе не остаётся незамеченной (как у KalkanCrypt VerifyXML).

    Проверяется ЦЕЛОСТНОСТЬ (digest) и ПОДПИСЬ; цепочка/сроки сертификата — отдельно
    через kalkan_verify. certificate_der — если задан, доверяем только ему.

    Оговорка: при вычислении digest удаляются ВСЕ элементы ds:Signature (в т.ч.
    «чужие» подписи) — как в реализации вендора для enveloped-трансформации.
    """
    root = etree.fromstring(xml_bytes)
    sigs = root.findall(f".//{{{DS}}}Signature")
    if not sigs:
        raise ValueError("в XML нет ds:Signature")

    # малиформленная подпись (нет SignedInfo/DigestValue/...) — понятный ValueError
    # (конвенция проекта), а криптографически неверная — это ok=False в signatures[].
    results = []
    for sig in sigs:
        results.append(_verify_one(root, sig, certificate_der))
    first = results[0]
    return {"count": len(results),
            "ok": all(r["reference_ok"] and r["signature_ok"] for r in results),
            "signatures": results,
            "reference_ok": first["reference_ok"],
            "signature_ok": first["signature_ok"],
            "certificate_der": first["certificate_der"]}

