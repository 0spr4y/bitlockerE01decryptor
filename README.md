# BitlockerE01Decryptor

Decrypts BitLocker volumes inside E01 (EWF) evidence images and produces a decrypted raw (`.dd`)
or E01 image. It records MD5/SHA1/SHA256 hashes, verifies the output, and writes a
chain-of-custody report.

The E01 is mounted read-only (`ewfmount`) and the BitLocker volume is unlocked read-only.

It ships with `BitlockerRecKey2MasterKey.py`, a standalone BitLocker key-derivation tool. It
handles recovery-password protectors that use the newer **PBKDF2-HMAC-SHA256**, which current versions
of dislocker, libbde/bdemount, dissect.fve and cryptsetup cannot unlock, even when the key is
correct (dislocker, for example, reports `The MACs don't match`).

This is a work in progress. If you find a problem, please open an issue or a pull request.

## How it works

```
E01 ──ewfmount (ro)──▶ raw disk ──partition scan──▶ BitLocker volume(s)
                                                        │
        BitlockerRecKey2MasterKey.py (VMK derivation, MAC + boot-sector validation)
                                                        │
                       dislocker-fuse -K vmk.bin (ro) ──▶ decrypted volume
                                                        │
             dd / ewfacquirestream + MD5/SHA1/SHA256 ──▶ output image ──▶ re-hash ──▶ report
```

If the key tool is unavailable or cannot unlock the volume, the script falls back to unlocking
directly with `dislocker-fuse`, then `bdemount`. The fallback uses only the first line of a key
file, and it passes the recovery password or password on the decryptor's command line, so the
secret is visible in the process list while the volume is being unlocked.

## Install

Debian/Ubuntu/Kali:

```bash
sudo apt install ewf-tools sleuthkit dislocker libbde-utils python3-cryptography
```

Optional: `sudo apt install python3-libewf` lets `BitlockerRecKey2MasterKey.py` open an E01 directly.

Check dependencies and versions:

```bash
./BitlockerE01Decryptor.sh --check-deps
```

FUSE must be available. In Docker, run the container with `--device /dev/fuse --cap-add SYS_ADMIN`.

## Usage

```
BitlockerE01Decryptor.sh -i IMAGE.E01 -o OUTDIR [key option] [options]
```

### Key options (exactly one)

| Flag | Description |
|------|-------------|
| `--recovery-password` | Prompt for the 48-digit recovery password |
| `--password` | Prompt for the user password |
| `--startup-key FILE` | `.BEK` startup/recovery key file |
| `--key-file FILE` | File (mode 600) with one recovery password or password per line. Each volume is tried with every line, so one file can cover disks whose volumes have different keys. A line in recovery-password format is used as a recovery password; any other line is used as a password |

### Target selection

| Flag | Description |
|------|-------------|
| `--partition N` | Partition slot number (from `--list`) |
| `--offset BYTES` | Byte offset of the volume. No partition table is needed |
| `--all` | Decrypt every BitLocker volume found |
| `--list` | List partitions with BitLocker detection, then exit |

If there is only one BitLocker volume it is selected automatically. If there are several, pass
`--partition`, `--offset` or `--all`; otherwise the script asks on a terminal and exits with
code 4 when it is not run interactively.

### Output options

| Flag | Description |
|------|-------------|
| `-f, --format raw\|e01` | Output format (default `raw`) |
| `--full-disk` | Also build a full-disk image with every decrypted volume spliced in place |
| `--segment-size SIZE` | E01 segment size (default `2GiB`) |
| `--compression none\|fast\|best` | E01 compression (default `fast`) |

### Case metadata

Written to the report, and into the E01 header when the output format is `e01`.

| Flag | Description |
|------|-------------|
| `--case-number STR` | Case number |
| `--evidence-number STR` | Evidence number |
| `--examiner STR` | Examiner name |
| `--description STR` | Description |
| `--notes STR` | Notes |

### Other options

| Flag | Description |
|------|-------------|
| `--verify-source` | Run `ewfverify` on the source E01 first. The result is recorded in the report; a failure is a warning and does not stop the run |
| `--workdir DIR` | Directory for the FUSE mount points (default: a temporary directory) |
| `--force` | Overwrite existing outputs |
| `--keep-partial` | Keep partial outputs when a run fails |
| `--check-deps` | Check dependencies and print tool versions |
| `-v, --verbose` | Verbose output |

### Examples

```bash
# list partitions and detect BitLocker
./BitlockerE01Decryptor.sh -i evidence.E01 --list

# decrypt with an interactive recovery-password prompt
./BitlockerE01Decryptor.sh -i evidence.E01 -o ./output --recovery-password

# key file, E01 output, case metadata
./BitlockerE01Decryptor.sh -i evidence.E01 -o ./output \
    --key-file ./recovery.txt --format e01 \
    --case-number "CASE-0001" --examiner "J. Doe" --verify-source

# all BitLocker volumes (keys.txt lists each volume's recovery password) plus a full-disk image
./BitlockerE01Decryptor.sh -i evidence.E01 -o ./output \
    --key-file ./keys.txt --all --full-disk
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Usage error, or an output already exists and `--force` was not given |
| 2 | Missing dependency or no FUSE |
| 3 | No BitLocker volume found |
| 4 | Several BitLocker volumes and none selected |
| 5 | Unlock failed |
| 6 | I/O or mount error |
| 7 | Output verification failed |
| 130 | Interrupted |

## Output

`<image>` is the E01 name without its extension, so `PC1.exhibit2.E01` gives `PC1.exhibit2`.

| File | Description |
|------|-------------|
| `<image>_p<slot>_decrypted.dd` / `.E01` | Decrypted volume image |
| `<image>_p<slot>_decrypted.md5` / `.sha1` / `.sha256` | Hash sidecars (`md5sum -c` style) |
| `<image>_fulldisk_decrypted.dd` (+ sidecars) | With `--full-disk` |
| `<image>_report.txt` / `.json` | Report: source hashes and EWF metadata, case metadata, tool versions, and per volume the protector, KDF, cipher, VMK fingerprint, output hashes and verification |
| `<image>_run.log` | Run log (appended to on every run) |

After imaging, the output is re-read and re-hashed (MD5, SHA1, SHA256) and its size is checked
against the decrypted volume. For E01 output, `ewfverify` must pass and report the same MD5.
Any mismatch exits with code 7. A read error aborts the run instead of zero-filling.

If a run fails, the image it was writing is removed (unless `--keep-partial`). Images that were
already verified, and any output that existed before the run, are left alone.

## BitlockerRecKey2MasterKey.py

Standalone tool that derives the VMK and FVEK from a protector secret and writes them for use
with dislocker (`-K vmk.bin` or `-k fvek_dislocker.bin`).

| Supported | |
|---|---|
| Protectors | Recovery password, user password, startup/recovery key (`.BEK`), clear key (suspended volume), known VMK (`--vmk`). TPM-only volumes are reported as unsupported |
| KDFs | Legacy SHA-256 chain (0x100000 rounds) and PBKDF2-HMAC-SHA256 (`--pbkdf2-iterations`, default 1048576). The KDF is detected per protector |
| Ciphers | AES-128/256-CBC with and without Elephant diffuser, XTS-AES-128/256 |
| Layouts | Windows 7+, BitLocker To Go, Vista. MBR, extended and GPT partitions are detected automatically |
| Input | Raw image, partition, block device, or E01 (E01 needs `python3-libewf`; otherwise `ewfmount` first) |

A candidate key is accepted only when its AES-CCM MAC verifies. The FVEK is then checked by decrypting
the relocated boot sector (not possible on Vista volumes) and looking for an NTFS, FAT, exFAT or ReFS
boot sector. If that check fails the tool exits with code 5; `BitlockerE01Decryptor.sh` then warns
and images anyway, because the MAC has already proved the keys. Secrets come from a prompt,
stdin or a file, never argv. Keys are printed as SHA-256 fingerprints unless `--show-keys` is given,
and key files are written mode 600.

```bash
# list volumes and protectors (shows the KDF each protector uses)
./BitlockerRecKey2MasterKey.py /mnt/ewf/ewf1 --list

# derive keys, then mount read-only with dislocker
./BitlockerRecKey2MasterKey.py /mnt/ewf/ewf1 --recovery-password-file rp.txt -o ./keys
dislocker -V /mnt/ewf/ewf1 -O <offset> -K ./keys/vmk.bin -r -- /mnt/bde
```

Exit codes: 0 ok, 1 usage, 2 no BitLocker volume, 3 not unlocked, 4 only unsupported
protectors, 5 unlocked but the decrypted boot sector was not recognised.

## Limitations

- Input to `BitlockerE01Decryptor.sh` is E01 only. For raw images or devices, use the key tool plus dislocker directly.
- Linux only, and FUSE is required. Speed is limited by dislocker over FUSE (about 20 MB/s seen), plus a second full read for verification.
- No brute force, and no key extraction from memory, hiberfil or TPM.
- Dynamic disks (LDM) and Storage Spaces are not parsed. Pass `--offset` for a volume on them.
- BitLocker only: no VeraCrypt, LUKS, APFS, etc.
- dislocker is mounted single-threaded (FUSE `-s`), because some dislocker 0.7.x builds are not
  safe with concurrent FUSE threads.


## License

[MIT](LICENSE). Dependencies keep their own licences: dislocker is GPL-2.0+, libewf/libbde are LGPL-3.0+,
and Sleuth Kit is mixed (CPL/IPL/GPL). Those three are run as separate programs.
