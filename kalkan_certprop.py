"""
kalkan_certprop.py — аналог X509CertificateGetInfo (KC_CERTPROP_*) на чистом Python.

Возвращает по числовому идентификатору поля/расширения сертификата текстовое значение,
как это делает KalkanCryptCOM.X509CertificateGetInfo. Сверяется с настоящим DLL
(см. cross_check_certprop.py).
"""

from __future__ import annotations

import base64

from asn1crypto import x509

from kalkan_verify import load_certificate

# идентификаторы (KalkanCryptCOM / KalkanCrypt.h)
KC_CERTPROP_ISSUER_COUNTRYNAME = 0x801
KC_CERTPROP_ISSUER_SOPN = 0x802
KC_CERTPROP_ISSUER_LOCALITYNAME = 0x803
KC_CERTPROP_ISSUER_ORG_NAME = 0x804
KC_CERTPROP_ISSUER_ORGUNIT_NAME = 0x805
KC_CERTPROP_ISSUER_COMMONNAME = 0x806
KC_CERTPROP_SUBJECT_COUNTRYNAME = 0x807
KC_CERTPROP_SUBJECT_SOPN = 0x808
KC_CERTPROP_SUBJECT_LOCALITYNAME = 0x809
KC_CERTPROP_SUBJECT_COMMONNAME = 0x80A
KC_CERTPROP_SUBJECT_GIVENNAME = 0x80B
KC_CERTPROP_SUBJECT_SURNAME = 0x80C
KC_CERTPROP_SUBJECT_SERIALNUMBER = 0x80D
KC_CERTPROP_SUBJECT_EMAIL = 0x80E
KC_CERTPROP_SUBJECT_ORG_NAME = 0x80F
KC_CERTPROP_SUBJECT_ORGUNIT_NAME = 0x810
KC_CERTPROP_SUBJECT_BC = 0x811
KC_CERTPROP_SUBJECT_DC = 0x812
KC_CERTPROP_NOTBEFORE = 0x813
KC_CERTPROP_NOTAFTER = 0x814
KC_CERTPROP_KEY_USAGE = 0x815
KC_CERTPROP_EXT_KEY_USAGE = 0x816
KC_CERTPROP_AUTH_KEY_ID = 0x817
KC_CERTPROP_SUBJ_KEY_ID = 0x818
KC_CERTPROP_CERT_SN = 0x819
KC_CERTPROP_ISSUER_DN = 0x81A
KC_CERTPROP_SUBJECT_DN = 0x81B
KC_CERTPROP_SIGNATURE_ALG = 0x81C
KC_CERTPROP_PUBKEY = 0x81D
KC_CERTPROP_POLICIES_ID = 0x81E
KC_CERTPROP_OCSP = 0x81F

__all__ = ["get_cert_info"]

# OID атрибутов имени
_OID = {
    "C": "2.5.4.6", "ST": "2.5.4.8", "L": "2.5.4.7", "O": "2.5.4.10", "OU": "2.5.4.11",
    "CN": "2.5.4.3", "GN": "2.5.4.42", "SN": "2.5.4.4", "SERIALNUMBER": "2.5.4.5",
    "EMAIL": "1.2.840.113549.1.9.1", "BC": "2.5.4.15", "DC": "0.9.2342.19200300.100.1.25",
}

_ISSUER_PROPS = {
    KC_CERTPROP_ISSUER_COUNTRYNAME: _OID["C"],
    KC_CERTPROP_ISSUER_SOPN: _OID["ST"],
    KC_CERTPROP_ISSUER_LOCALITYNAME: _OID["L"],
    KC_CERTPROP_ISSUER_ORG_NAME: _OID["O"],
    KC_CERTPROP_ISSUER_ORGUNIT_NAME: _OID["OU"],
    KC_CERTPROP_ISSUER_COMMONNAME: _OID["CN"],
}
_SUBJECT_PROPS = {
    KC_CERTPROP_SUBJECT_COUNTRYNAME: _OID["C"],
    KC_CERTPROP_SUBJECT_SOPN: _OID["ST"],
    KC_CERTPROP_SUBJECT_LOCALITYNAME: _OID["L"],
    KC_CERTPROP_SUBJECT_COMMONNAME: _OID["CN"],
    KC_CERTPROP_SUBJECT_GIVENNAME: _OID["GN"],
    KC_CERTPROP_SUBJECT_SURNAME: _OID["SN"],
    KC_CERTPROP_SUBJECT_SERIALNUMBER: _OID["SERIALNUMBER"],
    KC_CERTPROP_SUBJECT_EMAIL: _OID["EMAIL"],
    KC_CERTPROP_SUBJECT_ORG_NAME: _OID["O"],
    KC_CERTPROP_SUBJECT_ORGUNIT_NAME: _OID["OU"],
    KC_CERTPROP_SUBJECT_BC: _OID["BC"],
    KC_CERTPROP_SUBJECT_DC: _OID["DC"],
}


def _rdn(name: x509.Name, oid: str) -> str:
    for rdn in name.chosen:
        for attribute in rdn:
            if attribute["type"].dotted == oid:
                value = attribute["value"].native
                return value if isinstance(value, str) else str(value)
    return ""


# префиксы имён — как в X509CertificateGetInfo Калкана
_NAME_PREFIX = {
    "2.5.4.6": "C", "2.5.4.8": "ST", "2.5.4.7": "L", "2.5.4.10": "O", "2.5.4.11": "OU",
    "2.5.4.3": "CN", "2.5.4.42": "GN", "2.5.4.4": "SN", "2.5.4.5": "serialNumber",
    "1.2.840.113549.1.9.1": "E", "2.5.4.15": "businessCategory",
    "0.9.2342.19200300.100.1.25": "DC",
}
_KEY_USAGE = {
    "digital_signature": "digitalSignature", "non_repudiation": "nonRepudiation",
    "key_encipherment": "keyEncipherment", "data_encipherment": "dataEncipherment",
    "key_agreement": "keyAgreement", "key_cert_sign": "keyCertSign",
    "crl_sign": "cRLSign", "encipher_only": "encipherOnly",
    "decipher_only": "decipherOnly",
}
_KEY_USAGE_ORDER = list(_KEY_USAGE.keys())
_EKU_NAME = {
    "server_auth": ("1.3.6.1.5.5.7.3.1", "TLS Web Server Authentication"),
    "client_auth": ("1.3.6.1.5.5.7.3.2", "TLS Web Client Authentication"),
    "code_signing": ("1.3.6.1.5.5.7.3.3", "Code Signing"),
    "email_protection": ("1.3.6.1.5.5.7.3.4", "E-mail Protection"),
    "time_stamping": ("1.3.6.1.5.5.7.3.8", "Time Stamping"),
    "ocsp_signing": ("1.3.6.1.5.5.7.3.9", "OCSP Signing"),
}
_SIG_ALG_NAME = {
    "1.2.398.3.10.1.1.2.3.2": "GOST R 34.10-2015 with GOST R 34.11-2015 (512 bit)",
    "1.2.398.3.10.1.1.1.1": "GOST R 34.10-2001 with GOST R 34.11-94",
    "1.2.643.7.1.1.3.2": "GOST R 34.10-2012 with GOST R 34.11-2012 (256 bit)",
    "1.2.643.7.1.1.3.3": "GOST R 34.10-2012 with GOST R 34.11-2012 (512 bit)",
}


def _named(name: x509.Name, oid: str) -> str:
    value = _rdn(name, oid)
    prefix = _NAME_PREFIX.get(oid, oid)
    return f"{prefix}={value}" if value else ""


def _dn(name: x509.Name) -> str:
    parts = []
    for rdn in name.chosen:
        for attribute in rdn:
            oid = attribute["type"].dotted
            value = attribute["value"].native
            if not isinstance(value, str):
                value = str(value)
            parts.append(f"{_NAME_PREFIX.get(oid, oid)}={value}")
    return "/" + "/".join(parts) if parts else ""


def _local(value) -> str:
    return value.astimezone().strftime("%d.%m.%Y %H:%M:%S")


def _extension(tbs, oid: str):
    """native-значение расширения по OID (или None)."""
    exts = tbs["extensions"]
    if exts is None:
        return None
    for ext in exts:
        if ext["extn_id"].dotted == oid:
            try:
                return ext["extn_value"].parsed.native
            except (KeyError, ValueError, TypeError):
                return None
    return None


def _aia_location(entry) -> str:
    loc = entry.get("access_location")
    if isinstance(loc, dict):
        return loc.get("uniform_resource_identifier") or str(loc)
    return str(loc) if loc is not None else ""


def get_cert_info(certificate, prop_id: int) -> str:
    """Значение поля/расширения по KC_CERTPROP_* в формате X509CertificateGetInfo (Kalkan)."""
    cert = certificate if isinstance(certificate, x509.Certificate) else load_certificate(certificate)
    tbs = cert["tbs_certificate"]

    if prop_id in _ISSUER_PROPS:
        return _named(tbs["issuer"], _ISSUER_PROPS[prop_id])
    if prop_id in _SUBJECT_PROPS:
        return _named(tbs["subject"], _SUBJECT_PROPS[prop_id])

    if prop_id == KC_CERTPROP_NOTBEFORE:
        return f"notBefore={_local(tbs['validity']['not_before'].native)} "
    if prop_id == KC_CERTPROP_NOTAFTER:
        return f"notAfter={_local(tbs['validity']['not_after'].native)} "
    if prop_id == KC_CERTPROP_CERT_SN:
        return f"certificateSerialNumber={tbs['serial_number'].native:X}"
    if prop_id == KC_CERTPROP_ISSUER_DN:
        return _dn(tbs["issuer"])
    if prop_id == KC_CERTPROP_SUBJECT_DN:
        return _dn(tbs["subject"])
    if prop_id == KC_CERTPROP_SIGNATURE_ALG:
        oid = cert["signature_algorithm"]["algorithm"].dotted
        return f"signatureAlgorithm={_SIG_ALG_NAME.get(oid, '')}({oid})"
    if prop_id == KC_CERTPROP_PUBKEY:
        b64 = base64.b64encode(tbs["subject_public_key_info"].dump()).decode("ascii")
        return "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))

    if prop_id == KC_CERTPROP_KEY_USAGE:
        usage = set(_extension(tbs, "2.5.29.15") or [])
        ordered = [u for u in _KEY_USAGE_ORDER if u in usage]
        return f"keyUsage={' '.join(_KEY_USAGE[u] for u in ordered)} " if ordered else ""
    if prop_id == KC_CERTPROP_EXT_KEY_USAGE:
        eku = _extension(tbs, "2.5.29.37") or []
        parts = []
        for item in eku:
            oid, name = _EKU_NAME.get(str(item), (str(item), str(item)))
            parts.append(f"{name} ({oid})")
        return "extendedKeyUsage=" + "; ".join(parts) + "; " if parts else ""
    if prop_id == KC_CERTPROP_AUTH_KEY_ID:
        aki = _extension(tbs, "2.5.29.35")
        if aki and aki.get("key_identifier"):
            return "authorityKeyIdentifier=" + aki["key_identifier"].hex().upper()
        return ""
    if prop_id == KC_CERTPROP_SUBJ_KEY_ID:
        ski = _extension(tbs, "2.5.29.14")
        return "subjectKeyIdentifier=" + ski.hex().upper() if isinstance(ski, (bytes, bytearray)) else ""
    if prop_id == KC_CERTPROP_POLICIES_ID:
        policies = _extension(tbs, "2.5.29.32")
        return "certificatePolicies=" + ", ".join(p["policy_identifier"] for p in policies) \
            if policies else ""
    if prop_id == KC_CERTPROP_OCSP:
        aia = _extension(tbs, "1.3.6.1.5.5.7.1.1")
        urls = [_aia_location(e) for e in (aia or []) if e.get("access_method") == "ocsp"]
        return "OCSP=" + ", ".join(filter(None, urls)) if urls else ""

    raise ValueError(f"неизвестный KC_CERTPROP: 0x{prop_id:x}")
