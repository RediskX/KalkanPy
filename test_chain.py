"""
test_chain.py — проверка ДОВЕРИЯ цепочки: признак УЦ, сроки, path len, подписи.

Ключевой сценарий (подделка): конечный сертификат выдан ОБЫЧНЫМ пользовательским
сертификатом (BasicConstraints CA=FALSE) — такая «цепочка» не должна приниматься.
Проверяются оба пути: verify_certificate_chain() и verify_cms(trust_anchor_der=...).
"""

from __future__ import annotations

import os
import secrets
import sys
from datetime import datetime, timedelta, timezone

from kalkan_keys import first_key, roots
from kalkan_sign import (_ctx, _name, _sig_algorithm_id, _sign_der, _signer,
                         _subject_public_key_info, der_bit_string, der_integer,
                         der_octet_string, der_oid, der_sequence, der_utctime,
                         sign_cms, _tlv)
from kalkan_verify import streebog, verify_certificate_chain, verify_cms

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

KEY, PW = first_key()
ROOT, NCA = roots()
BOOL_TRUE = _tlv(0x01, b"\xff")


def _bc_extension(ca: bool, path_len=None) -> bytes:
    """basicConstraints: SEQUENCE{OID, critical, OCTET STRING{SEQ{BOOLEAN[,INT]}}}."""
    items = [_tlv(0x01, b"\xff" if ca else b"\x00")]
    if path_len is not None:
        items.append(der_integer(path_len))
    return der_sequence(der_oid("2.5.29.19"), BOOL_TRUE,
                        der_octet_string(der_sequence(*items)))


def make_cert(subject_key_be: bytes, issuer_key_be: bytes, issuer_name_der: bytes,
              cn: str, ca: bool, path_len=None, days: int = 3650):
    """Сертификат ГОСТ 2015, подписанный issuer_key_be -> (der, subject_name_der)."""
    size = len(subject_key_be)
    public_key_be = bytes(_signer(size).public_key_generate(bytearray(subject_key_be)))
    serial = secrets.randbits(size * 8 - 1) or 1
    now = datetime.now(timezone.utc).replace(microsecond=0)
    subject = _name(cn, "KZ")
    tbs = der_sequence(
        _ctx(0, der_integer(2)),
        der_integer(serial),
        _sig_algorithm_id(),
        issuer_name_der,
        der_sequence(der_utctime(now), der_utctime(now + timedelta(days=days))),
        subject,
        _subject_public_key_info(public_key_be),
        _tlv(0xA3, der_sequence(_bc_extension(ca, path_len))),
    )
    der = der_sequence(tbs, _sig_algorithm_id(),
                       der_bit_string(_sign_der(issuer_key_be, streebog(tbs, size))))
    return der, subject


class Pki:
    """Одна PKI: root(CA) → [mid_ca(CA) | mid_user(НЕ CA)] → leaf'ы."""

    def __init__(self, root_path_len=None):
        self.root_key = os.urandom(64)
        self.root, self.root_name = make_cert(self.root_key, self.root_key,
                                              _name("TEST ROOT", "KZ"), "TEST ROOT",
                                              ca=True, path_len=root_path_len)
        self.mid_ca_key = os.urandom(64)
        self.mid_ca, self.mid_ca_name = make_cert(self.mid_ca_key, self.root_key,
                                                  self.root_name, "TEST MIDCA", ca=True)
        self.mid_user_key = os.urandom(64)
        self.mid_user, self.mid_user_name = make_cert(self.mid_user_key, self.root_key,
                                                      self.root_name, "TEST MIDUSER",
                                                      ca=False)
        self.leaf_ca_key = os.urandom(64)
        self.leaf_ca, _ = make_cert(self.leaf_ca_key, self.mid_ca_key, self.mid_ca_name,
                                    "TEST LEAF-CA", ca=False)
        self.leaf_user_key = os.urandom(64)
        self.leaf_user, _ = make_cert(self.leaf_user_key, self.mid_user_key,
                                      self.mid_user_name, "TEST LEAF-USER", ca=False)


def test_chain_rules() -> bool:
    pki = Pki()
    ok_valid = verify_certificate_chain([pki.leaf_ca, pki.mid_ca], pki.root) is True
    ok_fake = verify_certificate_chain([pki.leaf_user, pki.mid_user], pki.root) is False
    ok_direct = verify_certificate_chain([pki.leaf_ca], pki.root) is False

    pki0 = Pki(root_path_len=0)
    ok_pathlen = verify_certificate_chain([pki0.leaf_ca, pki0.mid_ca], pki0.root) is False

    root_key = os.urandom(64)
    root, root_name = make_cert(root_key, root_key, _name("EXP ROOT", "KZ"), "EXP ROOT",
                                ca=True)
    expired, _ = make_cert(os.urandom(64), root_key, root_name, "EXPIRED", ca=False,
                           days=-1)
    ok_expired = verify_certificate_chain([expired], root) is False

    print("  валидная цепочка (в середине настоящий УЦ) :", ok_valid, "(нужно True)")
    print("  ПОДДЕЛКА: издатель — обычный пользователь  :", ok_fake, "(нужно True)")
    print("  leaf напрямую от root (без посредника)     :", ok_direct, "(нужно True)")
    print("  path len = 0, но есть промежуточный УЦ     :", ok_pathlen, "(нужно True)")
    print("  просроченный сертификат                    :", ok_expired, "(нужно True)")
    return all([ok_valid, ok_fake, ok_direct, ok_pathlen, ok_expired])


def test_cms_trust() -> bool:
    pki = Pki()
    data = b"trust chain test"
    forged = verify_cms(sign_cms(pki.leaf_user_key, data, pki.leaf_user,
                                 extra_certs=[pki.mid_user]),
                        trust_anchor_der=pki.root)["signers"][0]
    valid = verify_cms(sign_cms(pki.leaf_ca_key, data, pki.leaf_ca,
                                extra_certs=[pki.mid_ca]),
                       trust_anchor_der=pki.root)["signers"][0]
    print("  CMS, в цепочке не-УЦ : chain_ok =", forged["chain_ok"], "(ожидалось False)",
          "| state:", forged["state"])
    print("  CMS, в цепочке УЦ    : chain_ok =", valid["chain_ok"], "(ожидалось True)",
          "| state:", valid["state"])
    return forged["chain_ok"] is False and valid["chain_ok"] is True


def test_real_chain() -> bool:
    """Реальные сертификаты НУЦ: user → NCA → root не ломается новыми правилами."""
    from kalkan_p12 import load_gost2015_p12

    cert, _ = load_gost2015_p12(open(KEY, "rb").read(), PW)
    ok = verify_certificate_chain([cert, open(NCA, "rb").read()],
                                  open(ROOT, "rb").read()) is True
    print("  реальная цепочка user → NCA → root :", ok)
    return ok


def test_dll_chain() -> bool:
    """Сверка с KalkanCrypt.dll: подделка (не-УЦ в цепочке) должна отвергаться и им."""
    try:
        from kalkan_dll import (KC_CERT_CA, KC_DETACHED_DATA, KC_IN_DER, KC_SIGN_CMS,
                                KalkanOracle)
    except Exception as ex:                                 # нет DLL — не считаем провалом
        print("  DLL недоступна, сверка пропущена:", ex)
        return True
    import tempfile

    try:
        probe = KalkanOracle()
        probe.init()
        probe.finalize()
    except Exception as ex:                                 # DLL нет/не грузится — пропуск
        print("  DLL недоступна, сверка пропущена:", type(ex).__name__, ex)
        return True

    pki = Pki()
    data = b"trust chain test"
    forged = sign_cms(pki.leaf_user_key, data, pki.leaf_user,
                      detached=True, extra_certs=[pki.mid_user])
    valid = sign_cms(pki.leaf_ca_key, data, pki.leaf_ca,
                     detached=True, extra_certs=[pki.mid_ca])

    root_path = os.path.join(tempfile.gettempdir(), "_chain_root.cer")
    open(root_path, "wb").write(pki.root)

    def dll_rc(cms_bytes):
        o = KalkanOracle()
        o.init()
        o.load_cert_file(root_path, KC_CERT_CA)
        rc, _ = o.verify_data(data, cms_bytes,
                              KC_SIGN_CMS | KC_IN_DER | KC_DETACHED_DATA)
        o.finalize()
        return rc

    rc_forged = dll_rc(forged)
    rc_valid = dll_rc(valid)
    print("  DLL: подделка (не-УЦ) rc=0x%08x -> %s" % (rc_forged,
                                                     "ОТВЕРГ (как и мы)"
                                                     if rc_forged else "ПРИНЯЛ (!)"))
    print("  DLL: валидная цепочка rc=0x%08x -> %s" % (rc_valid,
                                                     "принял" if rc_valid == 0
                                                     else "отверг (синтетический УЦ "
                                                          "не устраивает DLL)"))
    # обязательный контроль: подделку DLL принимать НЕ должен
    return rc_forged != 0


def main() -> int:
    ok = test_chain_rules()
    print()
    ok = test_cms_trust() and ok
    print()
    ok = test_real_chain() and ok
    print()
    test_dll_chain_ok = test_dll_chain()
    print()
    ok = test_dll_chain_ok and ok
    print("\nИТОГ цепочки доверия:", "ВСЁ ОК" if ok else "ЕСТЬ ПРОБЛЕМЫ")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
