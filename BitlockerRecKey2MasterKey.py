#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""BitlockerRecKey2MasterKey - derive a BitLocker volume's VMK and FVEK from a protector secret.

Supported protectors: recovery password, user password, startup/recovery key (.BEK),
clear key (suspended protection). Both key-derivation schemes are supported for
password-based protectors: the legacy SHA-256 chain hash and PBKDF2-HMAC-SHA256
(protectors flagged 0x0040 / "PBKDF2_HMAC_SHA256"). Every candidate is accepted only
when the AES-CCM MAC verifies, and the FVEK is checked by decrypting the relocated boot
sector. Volumes: Vista, Windows 7+ and BitLocker To Go; raw images, partitions, block
devices, or E01 when pyewf is installed. Source data is opened read-only.
"""
import argparse
import getpass
import hashlib
import json
import os
import re
import struct
import sys

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESCCM
except ImportError:
    sys.exit("python3-cryptography is required (apt install python3-cryptography)")

VERSION = "0.1"

FVE_SIG = b"-FVE-FS-"
TOGO_SIG = b"MSWIN4.1"
EWF_SIG = b"EVF\x09\x0d\x0a\xff\x00"

EXIT_OK, EXIT_USAGE, EXIT_NO_VOLUME, EXIT_NO_UNLOCK, EXIT_UNSUPPORTED, EXIT_VALIDATION = 0, 1, 2, 3, 4, 5

# encryption method -> (name, mode, AES key length in bytes)
METHODS = {
    0x8000: ("AES-128-CBC + Elephant diffuser", "cbc-diffuser", 16),
    0x8001: ("AES-256-CBC + Elephant diffuser", "cbc-diffuser", 32),
    0x8002: ("AES-128-CBC", "cbc", 16),
    0x8003: ("AES-256-CBC", "cbc", 32),
    0x8004: ("XTS-AES-128", "xts", 16),
    0x8005: ("XTS-AES-256", "xts", 32),
}

# datum value type -> header size; types with nested datums
V_KEY, V_UNICODE, V_STRETCH, V_AES_CCM, V_TPM, V_VMK, V_EXTERNAL = 1, 2, 3, 5, 6, 8, 9
HDR_SIZE = [8, 0xC, 8, 0x1C, 0xC, 0x24, 0xC, 8, 0x24, 0x20, 0x2C, 0x34, 8, 8, 8, 0x18, 0xC, 0xC, 0x1C, 0xC]
NESTED = {3, 4, 8, 9, 10}
E_VMK, E_FVEK = 2, 3

PROTECTOR_NAMES = {
    0x0000: "clear key (protection suspended)",
    0x0100: "TPM",
    0x0200: "startup key",
    0x0500: "TPM + PIN",
    0x0800: "recovery password",
    0x2000: "password",
}

LEGACY_ROUNDS = 0x100000
DEFAULT_PBKDF2_ITERATIONS = 0x100000
FS_SIGNATURES = {b"NTFS    ": "NTFS", b"EXFAT   ": "exFAT", b"ReFS\0\0\0\0": "ReFS"}

VERBOSE = False


def log(msg):
    print(f"[+] {msg}", file=sys.stderr)


def dbg(msg):
    if VERBOSE:
        print(f"[D] {msg}", file=sys.stderr)


def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def fmt_guid(b):
    d1, d2, d3 = struct.unpack_from("<IHH", b, 0)
    return f"{d1:08X}-{d2:04X}-{d3:04X}-{b[8:10].hex().upper()}-{b[10:16].hex().upper()}"


def fingerprint(key):
    return hashlib.sha256(key).hexdigest()[:16]


# Sources

class RawSource:
    def __init__(self, path):
        self.path = path
        self.f = open(path, "rb")

    def read(self, off, n):
        self.f.seek(off)
        return self.f.read(n)


class EwfSource:
    def __init__(self, path):
        try:
            import pyewf
        except ImportError:
            raise SystemExit(
                f"{path} is an E01 image but pyewf is not installed.\n"
                f"Either: apt install python3-libewf\n"
                f"    or: ewfmount {path} /mnt/ewf  and pass /mnt/ewf/ewf1")
        self.path = path
        self.h = pyewf.handle()
        self.h.open(pyewf.glob(path))

    def read(self, off, n):
        if hasattr(self.h, "read_buffer_at_offset"):
            return self.h.read_buffer_at_offset(n, off)
        self.h.seek(off)
        return self.h.read(n)


def open_source(path):
    with open(path, "rb") as f:
        head = f.read(8)
    return EwfSource(path) if head == EWF_SIG else RawSource(path)


# Volume discovery

def bitlocker_kind(src, off):
    vh = src.read(off, 512)
    if len(vh) < 512:
        return None
    sig = vh[3:11]
    if sig == FVE_SIG:
        return "vista" if u64(vh, 0x38) else "win7+"
    if sig == TOGO_SIG:
        o = u64(vh, 0x1B8)
        if o and src.read(off + o, 8) == FVE_SIG:
            return "togo"
    return None


def partition_offsets(src):
    mbr = src.read(0, 512)
    if len(mbr) < 512 or mbr[510:512] != b"\x55\xaa":
        return []
    offs = []
    entries = [mbr[0x1BE + 16 * i:0x1BE + 16 * (i + 1)] for i in range(4)]
    if any(e[4] == 0xEE for e in entries):
        for ss in (512, 4096):
            gpt = src.read(ss, 92)
            if gpt[:8] != b"EFI PART":
                continue
            lba, count, esize = u64(gpt, 72), u32(gpt, 80), u32(gpt, 84)
            if esize < 128:
                continue
            table = src.read(lba * ss, min(count, 1024) * esize)
            for i in range(len(table) // esize):
                e = table[i * esize:(i + 1) * esize]
                if e[:16] != b"\0" * 16:
                    offs.append(u64(e, 32) * ss)
            return offs
    for e in entries:
        ptype, start = e[4], u32(e, 8)
        if ptype in (0x05, 0x0F, 0x85):
            ebr_base = cur = start
            for _ in range(128):
                ebr = src.read(cur * 512, 512)
                if ebr[510:512] != b"\x55\xaa":
                    break
                e1, e2 = ebr[0x1BE:0x1CE], ebr[0x1CE:0x1DE]
                if e1[4]:
                    offs.append((cur + u32(e1, 8)) * 512)
                if not e2[4]:
                    break
                cur = ebr_base + u32(e2, 8)
        elif ptype and start:
            offs.append(start * 512)
    return offs


def find_volumes(src, offset=None):
    if offset is not None:
        kind = bitlocker_kind(src, offset)
        return [(offset, kind)] if kind else []
    kind = bitlocker_kind(src, 0)
    if kind:
        return [(0, kind)]
    return [(o, k) for o in partition_offsets(src) for k in [bitlocker_kind(src, o)] if k]


# Metadata parsing

class Datum:
    def __init__(self, buf, off):
        self.buf, self.off = buf, off
        self.size, self.etype, self.vtype, self.status = struct.unpack_from("<4H", buf, off)
        self.hdr = HDR_SIZE[self.vtype] if self.vtype < len(HDR_SIZE) else 8
        self.children = []
        if self.vtype in NESTED and self.size > self.hdr:
            self.children = parse_datums(buf, off + self.hdr, off + self.size)

    @property
    def raw(self):
        return self.buf[self.off:self.off + self.size]

    @property
    def payload(self):
        return self.buf[self.off + self.hdr:self.off + self.size]

    def walk(self):
        for c in self.children:
            yield c
            yield from c.walk()


def parse_datums(buf, start, end):
    out, p = [], start
    while p + 8 <= end:
        size = u16(buf, p)
        if size < 8 or p + size > end:
            break
        out.append(Datum(buf, p))
        p += size
    return out


class Metadata:
    """One FVE metadata (information) block."""

    def __init__(self, src, voff, moff):
        info = src.read(voff + moff, 0x70)
        if len(info) < 0x70 or info[:8] != FVE_SIG:
            raise ValueError(f"no FVE metadata at volume offset {moff:#x}")
        self.offset = moff
        self.version = u16(info, 0xA)
        self.encrypted_size = u64(info, 0x10)
        self.nb_backup_sectors = u32(info, 0x1C)
        self.offsets = [u64(info, 0x20 + 8 * i) for i in range(3)]
        self.boot_backup = u64(info, 0x38)
        dsize = u32(info, 0x40)
        if not 0x30 < dsize < 0x100000:
            raise ValueError(f"implausible dataset size {dsize}")
        self.dataset = src.read(voff + moff + 0x40, dsize)
        self.method = u16(self.dataset, 0x24)
        self.datums = parse_datums(self.dataset, 0x30, dsize)

    def description(self):
        for d in self.datums:
            if d.vtype == V_UNICODE and d.etype == 7:
                return d.payload.decode("utf-16-le", "replace").rstrip("\0")
        return ""


def metadata_blocks(src, voff, kind):
    vh = src.read(voff, 512)
    if kind == "win7+":
        offs = [u64(vh, 0xB0 + 8 * i) for i in range(3)]
    elif kind == "togo":
        offs = [u64(vh, 0x1B8 + 8 * i) for i in range(3)]
    else:
        first = u64(vh, 0x38) * vh[0xD] * u16(vh, 0xB)
        offs = [first] + Metadata(src, voff, first).offsets[1:]
    blocks, seen = [], set()
    for o in offs:
        try:
            m = Metadata(src, voff, o)
        except ValueError as e:
            dbg(str(e))
            continue
        if m.dataset not in seen:
            seen.add(m.dataset)
            blocks.append(m)
    return blocks


class Protector:
    def __init__(self, d):
        self.datum = d
        self.guid = d.buf[d.off + 8:d.off + 24]
        self.priority = u16(d.buf, d.off + 34)   # protection type
        self.stretch = next((c for c in d.children if c.vtype == V_STRETCH), None)
        self.clear_key = next((c for c in d.children if c.vtype == V_KEY), None)
        self.has_tpm = any(c.vtype == V_TPM for c in d.walk())
        self.ccm = [c for c in d.walk() if c.vtype == V_AES_CCM]

    @property
    def type(self):
        p = self.priority
        if p in PROTECTOR_NAMES:
            return PROTECTOR_NAMES[p]
        if 0x0800 <= p <= 0x0FFF:
            return "recovery password"
        if self.has_tpm:
            return f"TPM variant (0x{p:04x})"
        return f"unknown (0x{p:04x})"

    @property
    def is_recovery(self):
        return 0x0800 <= self.priority <= 0x0FFF and self.stretch is not None

    @property
    def is_password(self):
        return self.priority == 0x2000 and self.stretch is not None

    @property
    def salt(self):
        s = self.stretch
        return s.buf[s.off + 12:s.off + 28]

    @property
    def kdf(self):
        if not self.stretch:
            return None
        s = self.stretch
        for c in s.children:
            if c.vtype == V_UNICODE:
                name = c.payload.decode("utf-16-le", "replace").rstrip("\0")
                if name:
                    return name
        return "PBKDF2 (flag 0x0040)" if u16(s.buf, s.off + 10) & 0x0040 else "legacy SHA-256 chain"

    @property
    def wants_pbkdf2(self):
        return self.kdf is not None and "PBKDF2" in self.kdf.upper()

    def describe(self):
        d = {"guid": fmt_guid(self.guid), "type": self.type, "priority": f"0x{self.priority:04x}"}
        if self.stretch:
            d["kdf"] = self.kdf
        return d


def protectors(meta):
    return [Protector(d) for d in meta.datums if d.etype == E_VMK and d.vtype == V_VMK]


# Crypto

def ccm_unwrap(key, d):
    b, o = d.buf, d.off
    nonce, mac, ct = b[o + 8:o + 20], b[o + 20:o + 36], b[o + 36:o + d.size]
    try:
        return AESCCM(key, tag_length=16).decrypt(nonce, ct + mac, None)
    except (InvalidTag, ValueError):
        return None


def key_from_datum(pt):
    """Plaintext of a wrapped key is a KEY datum: size, entry, value type 1, status, algo, pad, key."""
    if not pt or len(pt) < 12:
        return None, None
    size, _, vtype, _ = struct.unpack_from("<4H", pt, 0)
    if vtype != V_KEY or not 12 < size <= len(pt):
        return None, None
    return u16(pt, 8), pt[12:size]


def legacy_stretch(password_hash, salt):
    last = b"\0" * 32
    fixed = password_hash + salt
    sha = hashlib.sha256
    for i in range(LEGACY_ROUNDS):
        last = sha(last + fixed + i.to_bytes(8, "little")).digest()
    return last


def pbkdf2(password, salt, iterations):
    return hashlib.pbkdf2_hmac("sha256", password, salt, iterations, 32)


def distil_recovery_password(rp):
    s = re.sub(r"[\s\-]", "", rp)
    if not re.fullmatch(r"\d{48}", s):
        raise ValueError("a recovery password is 48 digits (8 groups of 6)")
    out = b""
    for i in range(8):
        blk = s[6 * i:6 * i + 6]
        v, d = int(blk), [int(c) for c in blk]
        if v % 11 or v >= 720896:
            raise ValueError(f"group {i + 1} ({blk}) is not a valid recovery-password group")
        if (d[0] - d[1] + d[2] - d[3] + d[4]) % 11 != d[5]:
            raise ValueError(f"group {i + 1} ({blk}) has an invalid check digit")
        out += struct.pack("<H", v // 11)
    return out


def rp_candidates(distilled, prot, iterations):
    legacy = ("legacy SHA-256 chain", lambda: legacy_stretch(hashlib.sha256(distilled).digest(), prot.salt))
    pb = [
        (f"PBKDF2-HMAC-SHA256 ({iterations} it.)", lambda: pbkdf2(distilled, prot.salt, iterations)),
        (f"PBKDF2-HMAC-SHA256 over SHA256 ({iterations} it.)",
         lambda: pbkdf2(hashlib.sha256(distilled).digest(), prot.salt, iterations)),
    ]
    return pb + [legacy] if prot.wants_pbkdf2 else [legacy] + pb


def password_candidates(password, prot, iterations):
    utf16 = password.encode("utf-16-le")
    h1 = hashlib.sha256(utf16).digest()
    h2 = hashlib.sha256(h1).digest()
    legacy = ("legacy SHA-256 chain", lambda: legacy_stretch(h2, prot.salt))
    pb = [(f"PBKDF2-HMAC-SHA256 [{label}] ({iterations} it.)", (lambda p=p: pbkdf2(p, prot.salt, iterations)))
          for label, p in (("SHA256(SHA256(UTF-16))", h2), ("SHA256(UTF-16)", h1), ("UTF-16", utf16))]
    return pb + [legacy] if prot.wants_pbkdf2 else [legacy] + pb


def try_vmk(prot, key):
    for d in prot.ccm:
        _, vmk = key_from_datum(ccm_unwrap(key, d))
        if vmk and len(vmk) == 32:
            return vmk
    return None


def parse_bek(path):
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < 0x30 or not 0x30 < u32(data, 0) <= len(data):
        raise ValueError(f"{path} is not a BEK file")
    for d in parse_datums(data, 0x30, u32(data, 0)):
        if d.vtype == V_EXTERNAL:
            guid = data[d.off + 8:d.off + 24]
            for c in d.children:
                if c.vtype == V_KEY and len(c.payload) >= 32:
                    return guid, c.payload[:32]
    raise ValueError(f"no external key found in {path}")


def unlock_vmk(meta, secret_kind, secret, iterations):
    """Return (vmk, protector, method) or (None, None, None)."""
    prots = protectors(meta)
    for p in prots:
        if p.clear_key is not None:
            vmk = try_vmk(p, p.clear_key.payload)
            if vmk:
                return vmk, p, "clear key"
    if secret_kind == "vmk":
        return secret, None, "supplied VMK"
    if secret_kind == "bek":
        guid, key = secret
        ordered = sorted(prots, key=lambda p: p.guid != guid)
        for p in ordered:
            vmk = try_vmk(p, key)
            if vmk:
                return vmk, p, "startup key (BEK)"
        return None, None, None
    if secret_kind in ("recovery", "password"):
        targets = [p for p in prots if (p.is_recovery if secret_kind == "recovery" else p.is_password)]
        targets += [p for p in prots if p.stretch is not None and p not in targets]
        for p in targets:
            cands = (rp_candidates(secret, p, iterations) if secret_kind == "recovery"
                     else password_candidates(secret, p, iterations))
            for label, derive in cands:
                dbg(f"protector {fmt_guid(p.guid)}: trying {label}")
                vmk = try_vmk(p, derive())
                if vmk:
                    return vmk, p, label
    return None, None, None


def unlock_fvek(meta, vmk):
    for d in meta.datums:
        if d.vtype == V_AES_CCM:
            algo, key = key_from_datum(ccm_unwrap(vmk, d))
            if key and algo in METHODS:
                return algo, key
    return None, None


# Sector decryption (validation)

M32 = 0xFFFFFFFF


def _rotl(x, r):
    return ((x << r) | (x >> (32 - r))) & M32 if r else x


def diffuser_a_decrypt(buf):
    n = len(buf) // 4
    d = list(struct.unpack(f"<{n}I", buf))
    ra = (9, 0, 13, 0)
    for _ in range(5):
        for i in range(n):
            d[i] = (d[i] + (d[(i - 2) % n] ^ _rotl(d[(i - 5) % n], ra[i % 4]))) & M32
    return struct.pack(f"<{n}I", *d)


def diffuser_b_decrypt(buf):
    n = len(buf) // 4
    d = list(struct.unpack(f"<{n}I", buf))
    rb = (0, 10, 0, 25)
    for _ in range(3):
        for i in range(n):
            d[i] = (d[i] + (d[(i + 2) % n] ^ _rotl(d[(i + 5) % n], rb[i % 4]))) & M32
    return struct.pack(f"<{n}I", *d)


def _ecb(key, block):
    return Cipher(algorithms.AES(key), modes.ECB()).encryptor().update(block)


def decrypt_sector(method, fvek, data, address, sector_size):
    _, mode, kl = METHODS[method]
    if mode == "xts":
        tweak = (address // sector_size).to_bytes(16, "little")
        return Cipher(algorithms.AES(fvek[:2 * kl]), modes.XTS(tweak)).decryptor().update(data)
    key = fvek[:kl]
    base = address.to_bytes(16, "little")
    out = Cipher(algorithms.AES(key), modes.CBC(_ecb(key, base))).decryptor().update(data)
    if mode == "cbc-diffuser":
        tkey = fvek[0x20:0x20 + kl]
        sector_key = _ecb(tkey, base) + _ecb(tkey, base[:15] + b"\x80")
        out = diffuser_a_decrypt(diffuser_b_decrypt(out))
        out = bytes(b ^ sector_key[i % 32] for i, b in enumerate(out))
    return out


def validate_fvek(src, voff, kind, meta, method, fvek):
    """Decrypt the relocated boot sector and look for a filesystem signature."""
    if kind == "vista":
        return None, "skipped (Vista volumes keep the boot sector in place)"
    ss = u16(src.read(voff, 512), 0xB) or 512
    addr = meta.boot_backup
    if not addr:
        return None, "skipped (no boot-sector backup recorded)"
    raw = src.read(voff + addr, ss)
    plain = raw if meta.encrypted_size and addr >= meta.encrypted_size else decrypt_sector(method, fvek, raw, addr, ss)
    fs = FS_SIGNATURES.get(plain[3:11])
    if fs:
        return True, f"boot sector decrypts to {fs}"
    # FAT is identified by its BPB, not the OEM id: that is whatever the formatter wrote
    # ("MSDOS5.0", "mkfs.fat", "BSD  4.4", ...).
    if plain[510:512] == b"\x55\xaa" and plain[0] in (0xEB, 0xE9) and u16(plain, 0xB) in (512, 1024, 2048, 4096):
        if plain[0x52:0x57] == b"FAT32" or plain[0x36:0x39] == b"FAT":
            return True, "boot sector decrypts to FAT"
        oem = plain[3:11].decode("ascii", "replace").strip()
        return True, f"boot sector decrypts to a valid boot sector (OEM id {oem!r})"
    return False, "boot sector did not decrypt to a known filesystem"


# CLI

def read_secret_file(path):
    with open(path, encoding="utf-8-sig") as f:
        return f.read().strip("\r\n")


def get_secret(args):
    if args.recovery_password or args.recovery_password_file:
        rp = (read_secret_file(args.recovery_password_file) if args.recovery_password_file
              else getpass.getpass("Recovery password: ") if sys.stdin.isatty() else sys.stdin.readline())
        return "recovery", distil_recovery_password(rp)
    if args.password or args.password_file:
        pw = (read_secret_file(args.password_file) if args.password_file
              else getpass.getpass("BitLocker password: ") if sys.stdin.isatty() else sys.stdin.readline().rstrip("\r\n"))
        return "password", pw
    if args.bek:
        return "bek", parse_bek(args.bek)
    if args.vmk:
        with open(args.vmk, "rb") as f:
            vmk = f.read()
        if len(vmk) != 32:
            raise ValueError("a VMK file must contain exactly 32 bytes")
        return "vmk", vmk
    return None, None


def write_key(path, data, force):
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | (0 if force else os.O_EXCL)
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, data)
        try:
            os.fchmod(fd, 0o600)
        except OSError:
            pass
    finally:
        os.close(fd)
    if os.stat(path).st_mode & 0o077:
        print(f"[!] {path} is readable by others (filesystem ignores permissions) - move it somewhere safe",
              file=sys.stderr)


def process_volume(src, voff, kind, secret_kind, secret, args):
    res = {"offset": voff, "layout": kind, "unlocked": False}
    blocks = metadata_blocks(src, voff, kind)
    if not blocks:
        res["error"] = "no readable FVE metadata"
        return res
    first = blocks[0]
    res["encryption"] = METHODS.get(first.method, (f"unknown (0x{first.method:04x})",))[0]
    res["metadata_version"] = first.version
    res["description"] = first.description()
    res["protectors"] = [p.describe() for p in protectors(first)]
    if args.list:
        return res
    for meta in blocks:
        vmk, prot, how = unlock_vmk(meta, secret_kind, secret, args.pbkdf2_iterations)
        if not vmk:
            continue
        method, fvek = unlock_fvek(meta, vmk)
        if not fvek:
            res["error"] = "VMK obtained but the FVEK did not unwrap with it"
            return res
        ok, note = validate_fvek(src, voff, kind, meta, method, fvek)
        res.update(unlocked=True, metadata_offset=meta.offset, unlocked_by=how,
                   protector=prot.describe() if prot else None,
                   fvek_method=METHODS[method][0], fvek_method_id=f"0x{method:04x}",
                   vmk_fingerprint=fingerprint(vmk), fvek_fingerprint=fingerprint(fvek),
                   validation=note, validated=ok)
        if args.show_keys:
            res["vmk"], res["fvek"] = vmk.hex(), fvek.hex()
        res["_vmk"], res["_fvek"], res["_method"] = vmk, fvek, method
        return res
    usable = [p for p in protectors(first)
              if p.stretch is not None or p.clear_key is not None or p.priority == 0x0200]
    if not usable and secret_kind != "vmk":
        res["error"] = "only TPM-based protectors present - a recovery password, password or BEK is required"
    elif not secret_kind:
        res["error"] = "no secret supplied and the volume has no clear key"
    else:
        res["error"] = "no protector unlocked with the supplied secret (wrong key or unsupported scheme)"
    return res


def main(argv=None):
    global VERBOSE
    ap = argparse.ArgumentParser(
        description="Derive a BitLocker VMK/FVEK from a recovery password, password, BEK or clear key.",
        epilog="Secrets are never accepted on the command line. Exit codes: 0 ok, 1 usage, 2 no BitLocker "
               "volume, 3 not unlocked, 4 only unsupported protectors, 5 FVEK validation failed.")
    ap.add_argument("source", help="raw image, partition, block device, or E01 (needs pyewf)")
    ap.add_argument("-O", "--offset", type=lambda s: int(s, 0), help="volume offset in bytes (default: auto-detect)")
    ap.add_argument("-l", "--list", action="store_true", help="list BitLocker volumes and protectors only")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("-r", "--recovery-password", action="store_true", help="prompt for the 48-digit recovery password")
    g.add_argument("--recovery-password-file", metavar="FILE")
    g.add_argument("-p", "--password", action="store_true", help="prompt for the user password")
    g.add_argument("--password-file", metavar="FILE")
    g.add_argument("-b", "--bek", metavar="FILE", help="startup/recovery key file (.BEK)")
    g.add_argument("--vmk", metavar="FILE", help="known 32-byte VMK (derive and check the FVEK only)")
    ap.add_argument("-o", "--out-dir", help="write <prefix>vmk.bin, fvek_dislocker.bin and fvek_raw.bin here (mode 600)")
    ap.add_argument("--prefix", default="", help="filename prefix for written keys")
    ap.add_argument("-f", "--force", action="store_true", help="overwrite existing key files")
    ap.add_argument("--pbkdf2-iterations", type=int, default=DEFAULT_PBKDF2_ITERATIONS)
    ap.add_argument("--show-keys", action="store_true", help="print VMK/FVEK hex (default: fingerprints only)")
    ap.add_argument("--json", action="store_true", help="JSON output on stdout")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("-V", "--version", action="version", version=f"%(prog)s {VERSION}")
    args = ap.parse_args(argv)
    VERBOSE = args.verbose

    try:
        secret_kind, secret = (None, None) if args.list else get_secret(args)
    except (ValueError, OSError) as e:
        print(f"[!] {e}", file=sys.stderr)
        return EXIT_USAGE

    try:
        src = open_source(args.source)
        vols = find_volumes(src, args.offset)
    except (OSError, struct.error) as e:
        print(f"[!] cannot read {args.source}: {e}", file=sys.stderr)
        return EXIT_USAGE
    if not vols:
        print("[!] no BitLocker volume found", file=sys.stderr)
        return EXIT_NO_VOLUME

    results = []
    for voff, kind in vols:
        log(f"BitLocker volume at offset {voff} ({kind})")
        try:
            res = process_volume(src, voff, kind, secret_kind, secret, args)
        except (ValueError, IndexError, struct.error) as e:   # truncated or damaged metadata
            res = {"offset": voff, "layout": kind, "unlocked": False, "error": f"unreadable FVE metadata ({e})"}
        results.append(res)
        if res.get("unlocked") and args.out_dir:
            pre = os.path.join(args.out_dir, f"{args.prefix}vol{voff}_" if len(vols) > 1 else args.prefix)
            files = {"vmk": (pre + "vmk.bin", res["_vmk"]),
                     "fvek_dislocker": (pre + "fvek_dislocker.bin",
                                        struct.pack("<H", res["_method"]) + res["_fvek"][:64].ljust(64, b"\0")),
                     "fvek_raw": (pre + "fvek_raw.bin", res["_fvek"])}
            try:
                os.makedirs(args.out_dir, exist_ok=True)
                for path, data in files.values():
                    write_key(path, data, args.force)
            except FileExistsError as e:
                print(f"[!] {e.filename} already exists (use --force to overwrite)", file=sys.stderr)
                return EXIT_USAGE
            except OSError as e:
                print(f"[!] cannot write key files: {e}", file=sys.stderr)
                return EXIT_USAGE
            res["files"] = {k: v[0] for k, v in files.items()}

    clean = [{k: v for k, v in r.items() if not k.startswith("_")} for r in results]
    if args.json:
        print(json.dumps(clean, indent=2))
    else:
        for r in clean:
            print(f"\nVolume @ {r['offset']} ({r['layout']}), metadata v{r.get('metadata_version', '?')}")
            for k in ("description", "encryption"):
                if r.get(k):
                    print(f"  {k:<13} {r[k]}")
            for p in r.get("protectors", []):
                print(f"  protector     {p['guid']}  {p['type']}" + (f"  [{p['kdf']}]" if p.get("kdf") else ""))
            if args.list:
                continue
            if not r["unlocked"]:
                print(f"  RESULT        not unlocked - {r.get('error')}")
                continue
            print(f"  RESULT        unlocked via {r['unlocked_by']}"
                  + (f" ({r['protector']['guid']})" if r.get("protector") else ""))
            print(f"  FVEK method   {r['fvek_method']} ({r['fvek_method_id']})")
            print(f"  validation    {r['validation']}")
            print(f"  VMK  sha256   {r['vmk_fingerprint']}..." + (f"  {r['vmk']}" if r.get("vmk") else ""))
            print(f"  FVEK sha256   {r['fvek_fingerprint']}..." + (f"  {r['fvek']}" if r.get("fvek") else ""))
            if r.get("files"):
                print(f"  wrote         {r['files']['vmk']} (dislocker -K)")
                print(f"                {r['files']['fvek_dislocker']} (dislocker -k)")
                print(f"                {r['files']['fvek_raw']} (raw FVEK)")
                print(f"  mount         dislocker -V {args.source} -O {r['offset']} -K {r['files']['vmk']} -r -- /mnt/bde")

    if args.list:
        return EXIT_OK
    unlocked = [r for r in results if r.get("unlocked")]
    if not unlocked:
        if all("TPM-based" in (r.get("error") or "") for r in results):
            return EXIT_UNSUPPORTED
        return EXIT_NO_UNLOCK
    if any(r.get("validated") is False for r in unlocked):
        return EXIT_VALIDATION
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
