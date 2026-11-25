#!/usr/bin/env python3
"""Sign an MT6990 Android v2 boot.img using MediaTek cert1 + RSA-PSS cert2."""
import argparse
import hashlib
import os
import struct
import subprocess
import tempfile
from pathlib import Path

BOOT_MAGIC = b"ANDROID!"
MKIMG_MAGIC = 0x58881688
MKIMG_EXT_MAGIC = 0x58891689
MKIMG_HDR_SIZE = 512

# Version=2, serial=8dcc21f6bcc0525c, sha256WithRSAEncryption,
# issuer/subject C=AU/ST=Some-State/O=Mediatek, validity 2015-06-04..2035-06-04.
CERT2_TBS_PREFIX = bytes.fromhex(
    "a003020102"
    "0209008dcc21f6bcc0525c"
    "300d06092a864886f70d01010b0500"
    "3035310b30090603550406130241553113301106035504080c0a536f6d652d5374617465"
    "3111300f060355040a0c084d6564696174656b"
    "301e170d3135303630343033313434345a170d3335303630343033313434345a"
    "3035310b30090603550406130241553113301106035504080c0a536f6d652d5374617465"
    "3111300f060355040a0c084d6564696174656b"
)

# RSASSA-PSS with SHA-256, MGF1-SHA-256, saltLen=32, trailerField=1.
RSASSA_PSS_ALGO_ID = bytes.fromhex(
    "304606092a864886f70d01010a3039"
    "a00f300d06096086480165030402010500"
    "a11c301a06092a864886f70d010108300d06096086480165030402010500"
    "a203020120"
    "a303020101"
)


def der_tlv(tag: int, body: bytes) -> bytes:
    """Encode an ASN.1 DER TLV element."""
    n = len(body)
    if n < 0x80:
        len_bytes = bytes([n])
    else:
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        len_bytes = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + len_bytes + body


def parse_der_tlv(buf: bytes, offset: int) -> tuple[int, int, int, int]:
    """Return (tag, hdr_len, content_len, total_len) at offset."""
    tag = buf[offset]
    b0 = buf[offset + 1]
    if b0 < 0x80:
        hdr_len = 2
        content_len = b0
    else:
        num = b0 & 0x7F
        hdr_len = 2 + num
        content_len = int.from_bytes(buf[offset + 2 : offset + hdr_len], "big")
    return tag, hdr_len, content_len, hdr_len + content_len


def extract_pubkey_der(prvk_path: Path) -> bytes:
    """Extract SubjectPublicKeyInfo DER from an RSA private key PEM."""
    return subprocess.check_output(
        ["openssl", "pkey", "-in", str(prvk_path), "-pubout", "-outform", "DER"],
        stderr=subprocess.PIPE,
    )


def sign_pss_sha256(prvk_path: Path, data: bytes) -> bytes:
    """Sign SHA-256 digest of data with RSA-PSS (saltlen=32)."""
    digest = hashlib.sha256(data).digest()
    with tempfile.NamedTemporaryFile(delete=False) as hf, tempfile.NamedTemporaryFile(
        delete=False
    ) as sf:
        hf.write(digest)
        hname, sname = hf.name, sf.name
    try:
        subprocess.check_call(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-inkey",
                str(prvk_path),
                "-in",
                hname,
                "-out",
                sname,
                "-pkeyopt",
                "digest:sha256",
                "-pkeyopt",
                "rsa_padding_mode:pss",
                "-pkeyopt",
                "rsa_pss_saltlen:32",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        return Path(sname).read_bytes()
    finally:
        for p in (hname, sname):
            if os.path.exists(p):
                os.unlink(p)


def verify_cert_der(label: str, cert_der: bytes, pub_der: bytes) -> None:
    """Verify an X.509-like MTK cert's RSASSA-PSS SHA-256 signature."""
    tag, hdr_len, _, total_len = parse_der_tlv(cert_der, 0)
    if tag != 0x30 or total_len != len(cert_der):
        raise SystemExit(f"{label}: invalid outer DER SEQUENCE")
    _, _, _, tbs_len = parse_der_tlv(cert_der, hdr_len)
    tbs = cert_der[hdr_len : hdr_len + tbs_len]
    _, _, _, alg_len = parse_der_tlv(cert_der, hdr_len + tbs_len)
    sig_off = hdr_len + tbs_len + alg_len
    sig_tag, sig_hdr, sig_clen, _ = parse_der_tlv(cert_der, sig_off)
    if sig_tag != 0x03 or cert_der[sig_off + sig_hdr] != 0:
        raise SystemExit(f"{label}: invalid signature BIT STRING")
    sig = cert_der[sig_off + sig_hdr + 1 : sig_off + sig_hdr + sig_clen]

    with (
        tempfile.NamedTemporaryFile(delete=False) as tf,
        tempfile.NamedTemporaryFile(delete=False) as sf,
        tempfile.NamedTemporaryFile(delete=False) as pf,
    ):
        tf.write(tbs)
        sf.write(sig)
        pf.write(pub_der)
        tn, sn, pn = tf.name, sf.name, pf.name
    try:
        r = subprocess.run(
            [
                "openssl",
                "dgst",
                "-sha256",
                "-verify",
                pn,
                "-keyform",
                "DER",
                "-sigopt",
                "rsa_padding_mode:pss",
                "-sigopt",
                "rsa_pss_saltlen:32",
                "-signature",
                sn,
                tn,
            ],
            capture_output=True,
            text=True,
        )
        if r.returncode != 0:
            raise SystemExit(f"{label}: signature verification failed: {r.stderr.strip()}")
    finally:
        for p in (tn, sn, pn):
            if os.path.exists(p):
                os.unlink(p)


def mkimg_header(name: bytes, dsize: int, img_type: int, img_list_end: int) -> bytes:
    """Build a 512-byte MediaTek v2 MKIMG header."""
    hdr = struct.pack(
        "<II32sIIIIIIIIII",
        MKIMG_MAGIC,
        dsize,
        name,
        0x12345678,
        0xFFFFFFFF,
        MKIMG_EXT_MAGIC,
        MKIMG_HDR_SIZE,
        1,
        img_type,
        img_list_end,
        16,
        0,
        0x22345678,
    )
    return hdr.ljust(MKIMG_HDR_SIZE, b"\xff")


def align16(data: bytes) -> bytes:
    rem = len(data) % 16
    return data if rem == 0 else data + b"\0" * (16 - rem)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", required=True)
    ap.add_argument("--cert1", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--pad-size", type=int, default=33554432)
    ap.add_argument("--verify-root", default=None)
    args = ap.parse_args()

    boot_raw = Path(args.inp).read_bytes()
    if boot_raw[:8] != BOOT_MAGIC:
        raise SystemExit(f"{args.inp}: missing ANDROID! magic")
    page_size = struct.unpack_from("<I", boot_raw, 36)[0]
    if page_size < 2048 or len(boot_raw) <= page_size or len(boot_raw) % page_size != 0:
        raise SystemExit(f"{args.inp}: unexpected size={len(boot_raw)} page_size={page_size}")

    cert1_bytes = Path(args.cert1).read_bytes()
    c1_magic, c1_dsize = struct.unpack_from("<II", cert1_bytes, 0)
    if c1_magic != MKIMG_MAGIC or cert1_bytes[8:14] != b"cert1\0":
        raise SystemExit(f"{args.cert1}: invalid MTK cert1 header")
    if args.verify_root:
        root_pub = extract_pubkey_der(Path(args.verify_root))
        verify_cert_der("cert1", cert1_bytes[MKIMG_HDR_SIZE : MKIMG_HDR_SIZE + c1_dsize], root_pub)

    key_path = Path(args.key)
    img_pub = extract_pubkey_der(key_path)
    img_hdr_hash = hashlib.sha256(boot_raw[:page_size]).digest()
    img_hash = hashlib.sha256(boot_raw[page_size:]).digest()

    # MTK cert2 proprietary OID attributes matching x509_template/cert2.cfg
    ext = (
        bytes.fromhex("060760867693160301020100")
        + bytes.fromhex("060760867693160201032100")
        + img_hash
        + bytes.fromhex("060760867693160202020100")
        + bytes.fromhex("060760867693160204032100")
        + img_hdr_hash
        + bytes.fromhex("06076086769316020603020000")
        + bytes.fromhex("060760867693160302020101")
        + bytes.fromhex("060760867693160207130130")
        + bytes.fromhex("060760867693160208020100")
        + bytes.fromhex("060760867693160209020100")
    )
    tbs = der_tlv(0x30, CERT2_TBS_PREFIX + img_pub + ext)
    sig = sign_pss_sha256(key_path, tbs)
    cert2_der = der_tlv(0x30, tbs + RSASSA_PSS_ALGO_ID + der_tlv(0x03, b"\x00" + sig))
    verify_cert_der("cert2", cert2_der, img_pub)

    cert2_block = align16(mkimg_header(b"cert2", len(cert2_der), 0x02000002, 1) + cert2_der)
    signed = boot_raw + cert1_bytes + cert2_block

    if args.pad_size > 0:
        if len(signed) > args.pad_size:
            raise SystemExit(
                f"signed boot image ({len(signed)} bytes) exceeds pad_size ({args.pad_size})"
            )
        signed = signed + b"\0" * (args.pad_size - len(signed))

    Path(args.out).write_bytes(signed)
    print(
        f"signed {args.out}: raw=0x{len(boot_raw):x} cert1=0x{len(cert1_bytes):x} "
        f"cert2=0x{len(cert2_block):x} total=0x{len(signed):x}"
    )


if __name__ == "__main__":
    main()
