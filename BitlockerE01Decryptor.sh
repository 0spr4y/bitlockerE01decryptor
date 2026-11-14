#!/usr/bin/env bash
# BitlockerE01Decryptor.sh: decrypt BitLocker volumes inside an E01 image to a raw or E01
# image, hashed with MD5, SHA1 and SHA256.
# SPDX-License-Identifier: MIT
set -Eeuo pipefail
set +x               # secrets pass through variables, so never trace
export LC_ALL=C      # tool output (ewfinfo, df, dd) is parsed; never localise it

readonly SCRIPT_VERSION="0.1"
readonly SCRIPT_NAME="${0##*/}"
START_TIME_UTC=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
readonly START_TIME_UTC
START_EPOCH=$(date +%s)
readonly START_EPOCH

# Globals
IMAGE=""
OUTDIR=""
KEY_MODE=""          # recovery-password | password | startup-key | key-file
KEY_VALUE=""         # path for startup-key/key-file; empty for interactive
PARTITION_SEL=""     # N | offset:BYTES | all | ""
LIST_ONLY=0
OUTPUT_FORMAT="raw"
FULL_DISK=0
SEGMENT_SIZE="2GiB"
COMPRESSION="fast"
CASE_NUMBER="" EVIDENCE_NUMBER="" EXAMINER="" DESCRIPTION="" NOTES=""
VERIFY_SOURCE=0
WORKDIR=""
WORKDIR_CREATED=0
FORCE=0
KEEP_PARTIAL=0
VERBOSE=0
DECRYPTOR=""         # dislocker | bdemount (auto-detected)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEYTOOL="${SCRIPT_DIR}/BitlockerRecKey2MasterKey.py"
DEC_FILE=""          # decrypted volume exposed by unlock_volume
KEY_DERIVATION="" UNLOCK_PROTECTOR="" FVEK_METHOD="" FVEK_VALIDATION="" VMK_FINGERPRINT=""
declare -a T_DEC=() T_RESULT=()   # per target: decrypted file, report fields (k=v lines)
SECTOR_SIZE=512
MEDIA_SIZE=0
RAW=""               # path to raw image exposed by ewfmount
STORED_MD5="" STORED_SHA1=""
EWF_CASE="" EWF_EXAMINER="" EWF_ACQ_DATE=""
declare -a MOUNT_STACK=()
declare -a PARTIAL_OUTPUTS=()
declare -a TARGET_OFFSETS=()
declare -a TARGET_SLOTS=()
LOG_FILE=""
BITLOCKER_META="" VERIFY_SOURCE_RESULT="" VERIFY_RESULT=""
FULL_DISK_VERIFY="" FULL_DISK_HASHES=""
IMG_MD5="" IMG_SHA1="" IMG_SHA256="" DEC_SIZE=""

# Colours (disabled if not a terminal)
if [[ -t 2 ]]; then
    RED=$'\033[1;31m' YEL=$'\033[1;33m' GRN=$'\033[1;32m'
    CYN=$'\033[1;36m' RST=$'\033[0m'
else
    RED="" YEL="" GRN="" CYN="" RST=""
fi

# Logging
msg()  { printf '%s\n' "$*" >&2; }
info() { msg "${GRN}[+]${RST} $*"; }
warn() { msg "${YEL}[!]${RST} $*"; }
err()  { msg "${RED}[-]${RST} $*"; }
dbg()  { (( VERBOSE )) && msg "${CYN}[D]${RST} $*" || true; }
die()  { local rc=$1; shift; err "$*"; exit "$rc"; }

# Usage
usage() {
    cat <<'USAGE'
Usage: BitlockerE01Decryptor.sh -i IMAGE.E01 -o OUTDIR [key option] [options]

Key (exactly one required):
  --recovery-password        prompt for 48-digit recovery key
  --password                 prompt for user password
  --startup-key FILE         .BEK file
  --key-file FILE            recovery passwords and/or passwords, one per line (mode 600);
                             each volume is tried with every line

Target selection:
  --partition N              partition slot number
  --offset BYTES             byte offset of the volume
  --all                      decrypt every BitLocker volume found
  --list                     list partitions + BitLocker detection, then exit

Output:
  -f, --format raw|e01       output format (default: raw)
  --full-disk                build a full-disk image with decrypted partition
  --segment-size SIZE        E01 segment size (default 2GiB)
  --compression none|fast|best  E01 compression (default fast)

Case metadata:
  --case-number STR          --evidence-number STR
  --examiner STR             --description STR
  --notes STR

Misc:
  --verify-source            ewfverify the source E01 before decrypting
  --workdir DIR              FUSE mount-point directory (default: mktemp -d)
  --force                    overwrite existing outputs
  --keep-partial             don't delete partial outputs on failure
  --check-deps               check and print tool versions
  -v, --verbose              verbose output
  -h, --help                 this help

Exit codes:
  0  success         1  usage error        2  missing dependency / no FUSE
  3  no BitLocker    4  selection needed    5  unlock failed
  6  I/O / mount     7  verify failed      130  interrupted
USAGE
    exit 0
}

# Argument parsing
parse_args() {
    [[ $# -eq 0 ]] && usage
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -i|-o|--startup-key|--key-file|--partition|--offset|-f|--format|--segment-size|--compression|\
            --case-number|--evidence-number|--examiner|--description|--notes|--workdir)
                [[ $# -ge 2 && -n "$2" ]] || die 1 "$1 requires an argument" ;;
        esac
        case "$1" in
            -i)                   IMAGE="$2"; shift 2 ;;
            -o)                   OUTDIR="$2"; shift 2 ;;
            --recovery-password)  set_key_mode recovery-password; shift ;;
            --password)           set_key_mode password; shift ;;
            --startup-key)        set_key_mode startup-key "$2"; shift 2 ;;
            --key-file)           set_key_mode key-file "$2"; shift 2 ;;
            --partition)          PARTITION_SEL="$2"; shift 2 ;;
            --offset)             PARTITION_SEL="offset:$2"; shift 2 ;;
            --all)                PARTITION_SEL="all"; shift ;;
            --list)               LIST_ONLY=1; shift ;;
            -f|--format)          OUTPUT_FORMAT="$2"; shift 2 ;;
            --full-disk)          FULL_DISK=1; shift ;;
            --segment-size)       SEGMENT_SIZE="$2"; shift 2 ;;
            --compression)        COMPRESSION="$2"; shift 2 ;;
            --case-number)        CASE_NUMBER="$2"; shift 2 ;;
            --evidence-number)    EVIDENCE_NUMBER="$2"; shift 2 ;;
            --examiner)           EXAMINER="$2"; shift 2 ;;
            --description)        DESCRIPTION="$2"; shift 2 ;;
            --notes)              NOTES="$2"; shift 2 ;;
            --verify-source)      VERIFY_SOURCE=1; shift ;;
            --workdir)            WORKDIR="$2"; shift 2 ;;
            --force)              FORCE=1; shift ;;
            --keep-partial)       KEEP_PARTIAL=1; shift ;;
            --check-deps)         check_deps; exit $? ;;
            -v|--verbose)         VERBOSE=1; shift ;;
            -h|--help)            usage ;;
            -*)                   die 1 "Unknown option: $1" ;;
            *)                    die 1 "Unexpected argument: $1" ;;
        esac
    done
    validate_args
}

set_key_mode() {
    [[ -z "$KEY_MODE" ]] || die 1 "Only one key option may be given (--$KEY_MODE and --$1)"
    KEY_MODE=$1
    KEY_VALUE=${2:-}
}

validate_args() {
    if (( ! LIST_ONLY )); then
        [[ -z "$IMAGE" ]] && die 1 "-i IMAGE.E01 is required"
        [[ -z "$OUTDIR" ]] && die 1 "-o OUTDIR is required"
        [[ -z "$KEY_MODE" ]] && die 1 "A key option is required (--recovery-password, --password, --startup-key, --key-file)"
    else
        [[ -z "$IMAGE" ]] && die 1 "-i IMAGE.E01 is required"
    fi

    [[ -n "$IMAGE" && ! -f "$IMAGE" ]] && die 1 "Image not found: $IMAGE"

    case "$OUTPUT_FORMAT" in
        raw|e01) ;;
        *) die 1 "Invalid --format: $OUTPUT_FORMAT (must be raw or e01)" ;;
    esac

    case "$COMPRESSION" in
        none|fast|best) ;;
        *) die 1 "Invalid --compression: $COMPRESSION (must be none, fast or best)" ;;
    esac

    if [[ "$KEY_MODE" == "startup-key" ]]; then
        [[ ! -f "$KEY_VALUE" ]] && die 1 "Startup key not found: $KEY_VALUE"
    fi

    if [[ "$KEY_MODE" == "key-file" ]]; then
        [[ ! -f "$KEY_VALUE" ]] && die 1 "Key file not found: $KEY_VALUE"
        local perms
        perms=$(stat -c '%a' "$KEY_VALUE")
        if [[ "$perms" != "600" && "$perms" != "400" ]]; then
            warn "Key file permissions are $perms - should be 600 or 400"
        fi
    fi

    if [[ -n "$PARTITION_SEL" && "$PARTITION_SEL" != "all" ]]; then
        if [[ "$PARTITION_SEL" == offset:* ]]; then
            local off="${PARTITION_SEL#offset:}"
            [[ ! "$off" =~ ^[0-9]+$ ]] && die 1 "Invalid --offset: must be a number"
        else
            [[ ! "$PARTITION_SEL" =~ ^[0-9]+$ ]] && die 1 "Invalid --partition: must be a number"
        fi
    fi
    return 0    # the tests above end in a false [[ ]] on valid input; under set -e that must not be the status
}

# Dependency check
tool_version() {
    local tool=$1
    case "$tool" in
        dislocker-fuse|dislocker-metadata)
            "$tool" -h 2>&1 | grep -m1 -o 'v[0-9][0-9.]*' || echo "unknown" ;;
        dd|python3)
            "$tool" --version 2>&1 | head -1 || echo "unknown" ;;
        *)  "$tool" -V 2>&1 | head -1 || echo "unknown" ;;
    esac 2>/dev/null
}

check_deps() {
    local missing=0
    local -A packages=(
        [ewfmount]="ewf-tools" [ewfinfo]="ewf-tools"
        [ewfverify]="ewf-tools" [ewfacquirestream]="ewf-tools"
        [mmls]="sleuthkit"
        [dislocker-fuse]="dislocker" [dislocker-metadata]="dislocker"
        [bdemount]="libbde-utils" [fusermount]="fuse3" [dd]="coreutils" [python3]="python3"
    )
    local -a required=(ewfmount ewfinfo ewfverify mmls dd python3)
    local -a optional=(ewfacquirestream dislocker-fuse dislocker-metadata bdemount fusermount)

    msg ""
    msg "=== Required tools ==="
    for tool in "${required[@]}"; do
        if command -v "$tool" &>/dev/null; then
            msg "  ok       $tool  $(tool_version "$tool")"
        else
            msg "  MISSING  $tool  - apt install ${packages[$tool]:-$tool}"
            missing=1
        fi
    done

    msg ""
    msg "=== Optional / fallback tools ==="
    for tool in "${optional[@]}"; do
        if command -v "$tool" &>/dev/null; then
            msg "  ok       $tool  $(tool_version "$tool")"
        else
            msg "  absent   $tool  - apt install ${packages[$tool]:-$tool}"
        fi
    done

    if keytool_available; then
        msg "  ok       BitlockerRecKey2MasterKey.py  $(python3 -I "$KEYTOOL" --version 2>&1)"
    else
        msg "  absent   BitlockerRecKey2MasterKey.py  unavailable (needs python3 + python3-cryptography) - PBKDF2 protectors will not unlock"
    fi

    msg ""
    if ! command -v dislocker-fuse &>/dev/null && ! command -v bdemount &>/dev/null; then
        msg "  MISSING  Need at least one BitLocker decryptor: dislocker or libbde-utils"
        missing=1
    fi

    if ! check_fuse_status; then
        msg "  MISSING  FUSE (see the warning above)"
        missing=1
    fi

    msg ""
    if (( missing )); then
        msg "Install missing tools: sudo apt install ewf-tools sleuthkit dislocker libbde-utils python3-cryptography"
        return 2
    else
        msg "All required tools present."
        return 0
    fi
}

check_fuse_status() {
    if [[ ! -e /dev/fuse ]]; then
        warn "/dev/fuse not found. In Docker, use: --device /dev/fuse --cap-add SYS_ADMIN"
        return 2
    fi
    if [[ ! -w /dev/fuse ]] && (( EUID != 0 )); then
        warn "/dev/fuse is not writable. Run as root or add user to the 'fuse' group."
        return 2
    fi
    return 0
}

# Cleanup trap
cleanup() {
    local rc=$?
    set +e

    # Unmount in reverse order
    local i
    for (( i=${#MOUNT_STACK[@]}-1; i>=0; i-- )); do
        local mp="${MOUNT_STACK[$i]}"
        if mountpoint -q "$mp" 2>/dev/null || mount | grep -qF "$mp" 2>/dev/null; then
            dbg "Unmounting: $mp"
            if ! fusermount -u "$mp" 2>/dev/null; then
                warn "fusermount -u failed on $mp, trying umount -l"
                umount -l "$mp" 2>/dev/null || warn "Could not unmount $mp"
            fi
        fi
    done

    # Remove partial outputs unless --keep-partial
    if (( rc != 0 && ! KEEP_PARTIAL )); then
        for f in "${PARTIAL_OUTPUTS[@]}"; do
            dbg "Removing partial output: $f"
            rm -f "$f"
            [[ "$f" == *.E01 ]] && rm -f "${f%01}"??    # further segments (.E02 ...)
        done
    fi

    # Key material never outlives the run, even on failure or with a user-supplied --workdir
    [[ -n "$WORKDIR" ]] && find "$WORKDIR" -path '*/keys_*' -type f -exec shred -u {} + 2>/dev/null

    # Remove workdir if we created it
    if (( WORKDIR_CREATED )) && [[ -d "$WORKDIR" ]]; then
        rm -rf "$WORKDIR"
    fi

    exit "$rc"
}

setup_workdir() {
    if [[ -z "$WORKDIR" ]]; then
        WORKDIR=$(mktemp -d -t bitlockere01_XXXXXX)
        WORKDIR_CREATED=1
    else
        mkdir -p "$WORKDIR" || die 6 "Cannot create workdir: $WORKDIR"
    fi
    chmod 700 "$WORKDIR"
    dbg "Workdir: $WORKDIR"
}

# Logging to file
start_logging() {
    local base
    base=$(basename_noext "$IMAGE")
    LOG_FILE="${OUTDIR}/${base}_run.log"
    # The terminal keeps colours and live dd progress; the log gets plain text.
    exec > >(tee >(sed -u -e 's/\x1b\[[0-9;]*m//g' -e 's/^.*\r//' >> "$LOG_FILE")) 2>&1
    dbg "Logging to $LOG_FILE"
}

basename_noext() {
    local name
    name=$(basename "$1")
    echo "${name%.*}"    # strip only the segment extension (.E01/.Ex01); keep dots in exhibit names
}

# Source E01 info
source_info() {
    info "Reading source E01 metadata..."
    local ewf_out
    ewf_out=$(ewfinfo "$IMAGE" 2>&1) || die 6 "ewfinfo failed on $IMAGE"

    SECTOR_SIZE=$(echo "$ewf_out" | grep -iE 'bytes per sector' | grep -oE '[0-9]+' | tail -1 || true)
    [[ -z "$SECTOR_SIZE" ]] && SECTOR_SIZE=512
    dbg "Sector size: $SECTOR_SIZE"

    # Extract byte count from "Media size: 100 MiB (104857600 bytes)" - grab number inside parens
    MEDIA_SIZE=$(echo "$ewf_out" | grep -iE 'media size' | grep -oP '\((\d+) bytes\)' | grep -oE '[0-9]+' | head -1 || true)
    if [[ -z "$MEDIA_SIZE" ]]; then
        # Fallback: try "number of bytes" line or last number on media size line
        MEDIA_SIZE=$(echo "$ewf_out" | grep -iE 'media size' | grep -oE '[0-9]+' | sort -rn | head -1 || true)
    fi
    if [[ -z "$MEDIA_SIZE" ]]; then
        MEDIA_SIZE=$(echo "$ewf_out" | grep -iE 'number of sectors' | grep -oE '[0-9]+' | head -1 || true)
        if [[ -n "$MEDIA_SIZE" ]]; then
            MEDIA_SIZE=$(( MEDIA_SIZE * SECTOR_SIZE ))
        fi
    fi
    [[ -z "$MEDIA_SIZE" ]] && MEDIA_SIZE=0
    dbg "Media size: $MEDIA_SIZE"

    # ewfinfo may say "MD5:" or "MD5 hash:" depending on version
    STORED_MD5=$(echo "$ewf_out" | grep -iE '^\s*MD5' | awk -F: '{gsub(/^[ \t]+/,"",$NF); print $NF}' | head -1 || true)
    STORED_SHA1=$(echo "$ewf_out" | grep -iE '^\s*SHA1' | awk -F: '{gsub(/^[ \t]+/,"",$NF); print $NF}' | head -1 || true)
    dbg "Stored MD5:  ${STORED_MD5:-none}"
    dbg "Stored SHA1: ${STORED_SHA1:-none}"

    # value after the first colon, intact (dates and notes contain colons)
    ewf_field() { grep -iE -m1 "^[[:space:]]*$1" <<<"$ewf_out" | sed 's/^[^:]*:[[:space:]]*//' || true; }
    EWF_CASE=$(ewf_field 'case number')
    EWF_EXAMINER=$(ewf_field 'examiner')
    EWF_ACQ_DATE=$(ewf_field 'acquisition date')

    info "Source: sectors=${SECTOR_SIZE}B, media=${MEDIA_SIZE} bytes"
}

# Verify source
verify_source() {
    if (( ! VERIFY_SOURCE )); then return 0; fi
    info "Verifying source E01 integrity (ewfverify)..."
    local vout rc=0
    vout=$(ewfverify -d sha1 "$IMAGE" 2>&1) || rc=$?
    if (( rc != 0 )); then
        warn "ewfverify returned $rc"
    fi
    if echo "$vout" | grep -qi 'SUCCESS'; then
        info "Source verification: PASSED"
        VERIFY_SOURCE_RESULT="PASSED"
    elif echo "$vout" | grep -qi 'FAIL'; then
        warn "Source verification: FAILED"
        VERIFY_SOURCE_RESULT="FAILED"
    else
        VERIFY_SOURCE_RESULT="UNKNOWN (no stored hash?)"
        warn "Source verification: $VERIFY_SOURCE_RESULT"
    fi
}

# Mount EWF
mount_ewf() {
    local ewf_dir="${WORKDIR}/ewf"
    mkdir -p "$ewf_dir"

    info "Mounting E01 via ewfmount..."
    if ! ewfmount "$IMAGE" "$ewf_dir" &>/dev/null; then
        # Try with allow_root for multi-user scenarios
        if ! ewfmount -X allow_root "$IMAGE" "$ewf_dir" &>/dev/null; then
            die 6 "ewfmount failed. Check ewf-tools and FUSE."
        fi
    fi
    MOUNT_STACK+=("$ewf_dir")

    # Find the raw device
    if [[ -e "${ewf_dir}/ewf1" ]]; then
        RAW="${ewf_dir}/ewf1"
    elif [[ -e "${ewf_dir}/ewf2" ]]; then
        RAW="${ewf_dir}/ewf2"
    else
        die 6 "ewfmount succeeded but no ewf1/ewf2 found in $ewf_dir"
    fi

    local raw_size
    raw_size=$(stat -c %s "$RAW")
    info "EWF mounted: $RAW ($raw_size bytes)"
}

# Signature reading
sig_at() {
    local offset=$1
    local skip=$(( offset + 3 ))
    dd if="$RAW" bs=1 skip="$skip" count=8 iflag=skip_bytes,count_bytes status=none 2>/dev/null | tr -d '\0' || true
}

# Prints "fve" (Vista / Windows 7+ volume) or "togo" (BitLocker To Go) if a BitLocker volume
# starts at the byte offset, nothing otherwise. A To Go volume has a FAT-style header with the
# BitLocker identifier GUID at 0x1A8.
readonly BDE_GUID="3bd66749292ed84a8399f6a339e3d001"
bitlocker_at() {
    local off=$1 sig guid
    sig=$(sig_at "$off")
    if [[ "$sig" == "-FVE-FS-" ]]; then
        echo fve
    elif [[ "$sig" == "MSWIN4.1" ]]; then
        guid=$(dd if="$RAW" bs=1 skip=$(( off + 424 )) count=16 iflag=skip_bytes,count_bytes status=none 2>/dev/null \
            | od -An -tx1 | tr -d ' \n' || true)
        [[ "$guid" == "$BDE_GUID" ]] && echo togo
    fi
    return 0
}

# Layout detection
detect_layout() {
    info "Detecting image layout..."
    local kind

    # --offset names the volume directly, so no partition table is needed (LDM, Storage Spaces)
    if [[ "$PARTITION_SEL" == offset:* ]] && (( ! LIST_ONLY )); then
        local off="${PARTITION_SEL#offset:}"
        [[ -n "$(bitlocker_at "$off")" ]] || warn "No BitLocker signature at offset $off, trying anyway"
        TARGET_OFFSETS=("$off")
        TARGET_SLOTS=("custom")
        return 0
    fi

    kind=$(bitlocker_at 0)
    if [[ -n "$kind" ]]; then
        if [[ "$kind" == togo ]]; then
            info "Image is a BitLocker To Go volume (no partition table)"
        else
            info "Image is a BitLocker volume (no partition table)"
        fi
        TARGET_OFFSETS=(0)
        TARGET_SLOTS=("vol")
        return 0
    fi

    # Try partition table
    list_partitions
}

# Partition listing
declare -a PT_SLOTS=() PT_STARTS=() PT_LENGTHS=() PT_DESCS=() PT_BITLOCKER=()

list_partitions() {
    info "Reading partition table..."
    PT_SLOTS=() PT_STARTS=() PT_LENGTHS=() PT_DESCS=() PT_BITLOCKER=()

    command -v mmls &>/dev/null || die 2 "mmls not found (apt install sleuthkit)"
    list_partitions_mmls && return 0
    die 3 "No partition table found and no BitLocker volume at offset 0 (use --offset if you know where it is)"
}

list_partitions_mmls() {
    local mmls_out rc=0
    mmls_out=$(mmls -b "$SECTOR_SIZE" "$RAW" 2>&1) || rc=$?
    if (( rc != 0 )); then
        dbg "mmls failed (rc=$rc): $mmls_out"
        return 1
    fi

    local slot start length desc
    while IFS= read -r line; do
        # Only parse lines that start with a partition entry (NNN: at start)
        [[ ! "$line" =~ ^[[:space:]]*[0-9]+: ]] && continue
        # Skip Meta and Unallocated rows
        [[ "$line" =~ Meta ]] && continue
        [[ "$line" =~ Unallocated ]] && continue

        # Parse: "002:  000:000   0000002048   0000204799   0000202752   NTFS / exFAT (0x07)"
        slot=$(echo "$line" | awk '{print $1}' | tr -d ':')
        start=$(echo "$line" | awk '{print $3}')
        length=$(echo "$line" | awk '{print $5}')
        desc=$(echo "$line" | awk '{for(i=6;i<=NF;i++) printf "%s ", $i; print ""}' | sed 's/[[:space:]]*$//')

        [[ -z "$start" || -z "$length" ]] && continue

        # Strip leading zeros (mmls prints 002) so they are not read as octal
        slot=$((10#$slot))
        start=$((10#$start))
        length=$((10#$length))

        PT_SLOTS+=("$slot")
        PT_STARTS+=("$start")
        PT_LENGTHS+=("$length")
        PT_DESCS+=("$desc")
    done <<< "$mmls_out"

    find_bitlocker
    return 0
}

# BitLocker signature check per partition
find_bitlocker() {
    info "Checking partitions for BitLocker signatures..."
    PT_BITLOCKER=()
    local i offset
    for (( i=0; i<${#PT_SLOTS[@]}; i++ )); do
        offset=$(( ${PT_STARTS[$i]} * SECTOR_SIZE ))
        if [[ -n "$(bitlocker_at "$offset")" ]]; then
            PT_BITLOCKER+=("yes")
            dbg "Partition ${PT_SLOTS[$i]} at offset $offset: BitLocker"
        else
            PT_BITLOCKER+=("no")
        fi
    done
}

# Print partition table
print_partition_table() {
    printf '\n%-6s %-14s %-16s %-14s %-10s %s\n' \
        "Slot" "Start Sector" "Byte Offset" "Size" "BitLocker" "Description"
    printf '%-6s %-14s %-16s %-14s %-10s %s\n' \
        "----" "------------" "-----------" "----" "---------" "-----------"
    local i offset size_hr
    for (( i=0; i<${#PT_SLOTS[@]}; i++ )); do
        offset=$(( PT_STARTS[i] * SECTOR_SIZE ))
        size_hr=$(numfmt --to=iec-i --suffix=B $(( PT_LENGTHS[i] * SECTOR_SIZE )) 2>/dev/null || echo "${PT_LENGTHS[$i]}s")
        printf '%-6s %-14s %-16s %-14s %-10s %s\n' \
            "${PT_SLOTS[$i]}" "${PT_STARTS[$i]}" "$offset" "$size_hr" \
            "${PT_BITLOCKER[$i]:-n/a}" "${PT_DESCS[$i]}"
    done
    echo ""
}

# Target selection
select_targets() {
    # If already set (volume image), return
    if (( ${#TARGET_OFFSETS[@]} > 0 )); then return 0; fi

    # Find BitLocker partitions
    local -a bl_indices=()
    local i
    for (( i=0; i<${#PT_BITLOCKER[@]}; i++ )); do
        [[ "${PT_BITLOCKER[$i]}" == "yes" ]] && bl_indices+=("$i")
    done

    if (( ${#bl_indices[@]} == 0 )); then
        print_partition_table
        die 3 "No BitLocker volumes found in partition table"
    fi

    # --list: just print and exit
    if (( LIST_ONLY )); then
        print_partition_table
        exit 0
    fi

    # Explicit selection
    if [[ "$PARTITION_SEL" == "all" ]]; then
        for i in "${bl_indices[@]}"; do
            TARGET_OFFSETS+=("$(( PT_STARTS[i] * SECTOR_SIZE ))")
            TARGET_SLOTS+=("${PT_SLOTS[$i]}")
        done
        return 0
    fi

    if [[ -n "$PARTITION_SEL" ]]; then
        for (( i=0; i<${#PT_SLOTS[@]}; i++ )); do
            if (( PT_SLOTS[i] == 10#$PARTITION_SEL )); then
                TARGET_OFFSETS+=("$(( PT_STARTS[i] * SECTOR_SIZE ))")
                TARGET_SLOTS+=("${PT_SLOTS[$i]}")
                return 0
            fi
        done
        die 1 "Partition slot $PARTITION_SEL not found"
    fi

    # Auto: exactly one BitLocker partition
    if (( ${#bl_indices[@]} == 1 )); then
        local idx="${bl_indices[0]}"
        TARGET_OFFSETS+=("$(( PT_STARTS[idx] * SECTOR_SIZE ))")
        TARGET_SLOTS+=("${PT_SLOTS[$idx]}")
        info "Auto-selected partition ${PT_SLOTS[$idx]} (only BitLocker volume)"
        return 0
    fi

    # Multiple: interactive or error
    print_partition_table
    if [[ -t 0 ]]; then
        msg "Multiple BitLocker volumes found. Select one:"
        local n=1
        for i in "${bl_indices[@]}"; do
            local off=$(( PT_STARTS[i] * SECTOR_SIZE ))
            msg "  $n) Slot ${PT_SLOTS[$i]} at offset $off - ${PT_DESCS[$i]}"
            (( n++ ))
        done
        local choice
        read -rp "Choice [1-$((n-1))]: " choice
        if [[ ! "$choice" =~ ^[0-9]+$ ]] || (( choice < 1 || choice >= n )); then
            die 4 "Invalid choice"
        fi
        local idx="${bl_indices[$((choice-1))]}"
        TARGET_OFFSETS+=("$(( PT_STARTS[idx] * SECTOR_SIZE ))")
        TARGET_SLOTS+=("${PT_SLOTS[$idx]}")
    else
        die 4 "Multiple BitLocker volumes found. Use --partition, --offset, or --all."
    fi
}

# Read key (secure)
read_key() {
    local key=""
    case "$KEY_MODE" in
        recovery-password)
            if [[ -t 0 ]]; then
                msg "Enter 48-digit BitLocker recovery password:"
                read -rs key
            else
                die 1 "Cannot read recovery password - stdin is not a terminal"
            fi
            ;;
        password)
            if [[ -t 0 ]]; then
                msg "Enter BitLocker user password:"
                read -rs key
            else
                die 1 "Cannot read password - stdin is not a terminal"
            fi
            ;;
        key-file)
            # One secret per line (several lines: tried in turn on each volume). Strip CR and
            # surrounding whitespace only - passwords may contain inner spaces.
            key=$(sed -e 's/\r$//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e '/^$/d' "$KEY_VALUE")
            [[ -n "$key" ]] || die 1 "Key file is empty: $KEY_VALUE"
            ;;
        startup-key)
            # Startup key is a file path, used directly
            key="$KEY_VALUE"
            ;;
    esac
    # Recovery passwords are often pasted with stray spaces or without hyphens: rewrite any
    # line that is 48 digits once spaces and hyphens are removed into the canonical form.
    local line digits out=""
    while IFS= read -r line; do
        digits=${line//[[:space:]-]/}
        if [[ "$KEY_MODE" != "password" && "$digits" =~ ^[0-9]{48}$ ]]; then
            line=$(sed -E 's/[0-9]{6}/&-/g; s/-$//' <<<"$digits")
        fi
        out+="${out:+$'\n'}$line"
    done <<< "$key"
    echo "$out"
}

# Unlock BitLocker volume
keytool_available() {
    [[ -f "$KEYTOOL" ]] && command -v python3 &>/dev/null && python3 -I -c 'import cryptography' 2>/dev/null
}

is_recovery_password() { [[ "$1" =~ ^[0-9]{6}(-?[0-9]{6}){7}$ ]]; }

# How one secret is used: recovery-password | password | startup-key. A key-file line in
# recovery-password format is a recovery password, anything else a password.
secret_kind() {
    if [[ "$KEY_MODE" != "key-file" ]]; then
        echo "$KEY_MODE"
    elif is_recovery_password "$1"; then
        echo recovery-password
    else
        echo password
    fi
}

# Derive the VMK with BitlockerRecKey2MasterKey.py (legacy and PBKDF2 protectors), trying each
# secret line in turn. Returns the tool's exit code; on success the VMK is in ${WORKDIR}/keys_<slot>/.
derive_vmk() {
    local offset=$1 slot=$2 key=$3
    local kdir="${WORKDIR}/keys_${slot}"
    local -a secret_args=()
    local rc=0 json="" secret line n=0
    mkdir -p "$kdir"
    chmod 700 "$kdir"

    info "Deriving VMK with BitlockerRecKey2MasterKey.py (offset=$offset)..."
    while IFS= read -r secret; do
        n=$((n + 1)); rc=0
        if [[ "$KEY_MODE" == "startup-key" ]]; then
            secret_args=(--bek "$secret")
        else
            ( umask 077; printf '%s' "$secret" > "${kdir}/secret" )
            secret_args=("--$(secret_kind "$secret")-file" "${kdir}/secret")
        fi
        json=$(python3 -I "$KEYTOOL" "$RAW" -O "$offset" "${secret_args[@]}" -o "$kdir" --force --json \
            </dev/null 2>"${kdir}/keytool.log") || rc=$?
        [[ -f "${kdir}/secret" ]] && { shred -u "${kdir}/secret" 2>/dev/null || rm -f "${kdir}/secret"; }
        while IFS= read -r line; do dbg "keytool[$n]: $line"; done < "${kdir}/keytool.log"
        # 3 = this secret did not unlock, 1 = it is malformed: try the next line. Anything else is final.
        (( rc == 3 || rc == 1 )) || break
    done <<< "$key"
    secret=""

    local -a f=()
    mapfile -t f < <(python3 -I -c '
import json, sys
try:
    r = json.load(sys.stdin)[0]
except Exception:
    r = {}
p = r.get("protector") or {}
for v in (r.get("unlocked_by"), p.get("guid"), p.get("type"), r.get("fvek_method"),
          r.get("validation"), r.get("vmk_fingerprint"), r.get("error")):
    print(v or "")
' <<<"$json")
    KEY_DERIVATION="${f[0]:-}"
    UNLOCK_PROTECTOR="${f[1]:-}${f[2]:+ (${f[2]})}"
    FVEK_METHOD="${f[3]:-}"
    FVEK_VALIDATION="${f[4]:-}"
    VMK_FINGERPRINT="${f[5]:-}"

    if (( rc == 0 || rc == 5 )); then
        info "  Protector:  $UNLOCK_PROTECTOR"
        info "  KDF:        $KEY_DERIVATION"
        info "  Cipher:     $FVEK_METHOD"
        info "  Validation: $FVEK_VALIDATION"
    else
        local why="${f[6]:-}"
        [[ -n "$why" ]] || why=$(tail -n 1 "${kdir}/keytool.log" 2>/dev/null | sed 's/^\[!\] //' || true)
        warn "BitlockerRecKey2MasterKey.py did not unlock the volume (rc=$rc): ${why:-no detail}"
    fi
    return "$rc"
}

unlock_volume() {
    local offset=$1
    local slot=$2
    local key=$3
    local bde_dir="${WORKDIR}/bde_${slot}"
    mkdir -p "$bde_dir"

    local dec_file=""
    DEC_FILE=""
    KEY_DERIVATION="" UNLOCK_PROTECTOR="" FVEK_METHOD="" FVEK_VALIDATION="" VMK_FINGERPRINT=""

    # Collect metadata if available
    if command -v dislocker-metadata &>/dev/null; then
        local meta_out=""
        meta_out=$(dislocker-metadata -V "$RAW" -o "$offset" 2>&1) || true
        dbg "BitLocker metadata: ${meta_out:0:500}"
        BITLOCKER_META="$meta_out"
    fi

    # Preferred: derive the VMK ourselves, then mount with dislocker -K (no secret in argv)
    # dislocker is mounted single-threaded (FUSE -s): imaging is one sequential read, and some
    # dislocker builds are not safe with concurrent FUSE threads.
    if keytool_available && command -v dislocker-fuse &>/dev/null; then
        local krc=0
        derive_vmk "$offset" "$slot" "$key" || krc=$?
        if (( krc == 0 || krc == 5 )); then
            # The VMK and FVEK unwrapped with a valid AES-CCM MAC, so the keys are right even
            # if the boot sector is not a filesystem this tool recognises.
            (( krc == 5 )) && warn "Keys are MAC-verified but the decrypted boot sector is not a recognised filesystem - imaging anyway, check the output"
            local kdir="${WORKDIR}/keys_${slot}"
            DECRYPTOR="dislocker -K (VMK from BitlockerRecKey2MasterKey.py)"
            info "Unlocking partition $slot with dislocker-fuse -K (offset=$offset)..."
            local dl_rc=0
            dislocker-fuse -V "$RAW" -O "$offset" -K "${kdir}/vmk.bin" -r -- -s "$bde_dir" </dev/null &>/dev/null || dl_rc=$?
            if (( dl_rc != 0 )); then
                err "dislocker-fuse -K failed (rc=$dl_rc)"
                return 5
            fi
            MOUNT_STACK+=("$bde_dir")
            dec_file="${bde_dir}/dislocker-file"
            shred -u "${kdir}"/*.bin 2>/dev/null || rm -f "${kdir}"/*.bin
        elif (( krc == 4 )); then
            err "Only TPM protectors on this volume - a recovery password, password or BEK is required"
            return 5
        else
            warn "Falling back to direct dislocker/bdemount unlock"
        fi
    else
        warn "BitlockerRecKey2MasterKey.py unavailable (must sit next to this script; needs python3-cryptography) - PBKDF2 protectors will not unlock"
    fi

    if [[ -n "$dec_file" ]]; then
        :
    elif command -v dislocker-fuse &>/dev/null; then
        DECRYPTOR="dislocker"
        info "Unlocking partition $slot with dislocker-fuse (offset=$offset)..."
        [[ "$KEY_MODE" == "startup-key" ]] || warn "Fallback path: the secret is passed on the decryptor's command line"

        local dl_rc=0
        key="${key%%$'\n'*}"    # direct tools take a single secret: use the first line
        case "$(secret_kind "$key")" in
            recovery-password)
                dbg "Running: dislocker-fuse -V $RAW -O $offset -pxx -r -- $bde_dir"
                dislocker-fuse -V "$RAW" -O "$offset" -p"$key" -r -- -s "$bde_dir" </dev/null &>/dev/null || dl_rc=$?
                ;;
            password)
                dbg "Running: dislocker-fuse -V $RAW -O $offset -uxx -r -- $bde_dir"
                dislocker-fuse -V "$RAW" -O "$offset" -u"$key" -r -- -s "$bde_dir" </dev/null &>/dev/null || dl_rc=$?
                ;;
            startup-key)
                dbg "Running: dislocker-fuse -V $RAW -O $offset -f $key -r -- $bde_dir"
                dislocker-fuse -V "$RAW" -O "$offset" -f "$key" -r -- -s "$bde_dir" </dev/null &>/dev/null || dl_rc=$?
                ;;
        esac

        if (( dl_rc != 0 )); then
            warn "dislocker-fuse failed (rc=$dl_rc)"
            # Try bdemount fallback
            if command -v bdemount &>/dev/null; then
                unlock_volume_bdemount "$offset" "$slot" "$key" "$bde_dir" || return $?
            else
                err "Unlock failed: wrong key, unsupported protector or damaged metadata"
                return 5
            fi
        else
            dec_file="${bde_dir}/dislocker-file"
            MOUNT_STACK+=("$bde_dir")
        fi

    elif command -v bdemount &>/dev/null; then
        unlock_volume_bdemount "$offset" "$slot" "${key%%$'\n'*}" "$bde_dir" || return $?
    else
        die 2 "No BitLocker decryptor found (need dislocker or libbde-utils)"
    fi

    # Determine the decrypted file path
    if [[ -z "$dec_file" ]]; then
        if [[ -e "${bde_dir}/bde1" ]]; then
            dec_file="${bde_dir}/bde1"
        elif [[ -e "${bde_dir}/dislocker-file" ]]; then
            dec_file="${bde_dir}/dislocker-file"
        else
            die 6 "Decrypted volume file not found in $bde_dir"
        fi
    fi

    # Sanity check for the fallback path (the key tool has already validated the boot sector)
    if [[ -z "$FVEK_VALIDATION" ]]; then
        local dec_sig boot_end
        dec_sig=$(dd if="$dec_file" bs=1 skip=3 count=8 status=none 2>/dev/null | tr -d '\0' || true)
        boot_end=$(dd if="$dec_file" bs=1 skip=510 count=2 status=none 2>/dev/null | od -An -tx1 | tr -d ' \n' || true)
        if [[ "$dec_sig" != NTFS* && "$dec_sig" != EXFAT* && "$dec_sig" != ReFS* && "$boot_end" != "55aa" ]]; then
            warn "The decrypted volume does not start with a recognised boot sector - check the output"
        fi
    fi

    DEC_FILE="$dec_file"
}

unlock_volume_bdemount() {
    local offset=$1 slot=$2 key=$3 bde_dir=$4
    DECRYPTOR="bdemount"
    info "Unlocking partition $slot with bdemount (offset=$offset)..."

    local bde_rc=0

    case "$(secret_kind "$key")" in
        recovery-password)
            dbg "Running: bdemount -o $offset -r xx $RAW $bde_dir"
            bdemount -o "$offset" -r "$key" "$RAW" "$bde_dir" </dev/null &>/dev/null || bde_rc=$?
            ;;
        password)
            dbg "Running: bdemount -o $offset -p xx $RAW $bde_dir"
            bdemount -o "$offset" -p "$key" "$RAW" "$bde_dir" </dev/null &>/dev/null || bde_rc=$?
            ;;
        startup-key)
            dbg "Running: bdemount -o $offset -s $key $RAW $bde_dir"
            bdemount -o "$offset" -s "$key" "$RAW" "$bde_dir" </dev/null &>/dev/null || bde_rc=$?
            ;;
    esac

    if (( bde_rc != 0 )); then
        err "Unlock failed (bdemount rc=$bde_rc): wrong key, unsupported protector or damaged metadata"
        return 5
    fi

    MOUNT_STACK+=("$bde_dir")
    return 0
}

# Stream hashing: hash_begin, then tee into "${HASH_FIFOS[@]}", then hash_end sets H_MD5/H_SHA1/H_SHA256.
declare -a HASH_FIFOS=() HASH_PIDS=()
H_MD5="" H_SHA1="" H_SHA256=""
hash_begin() {
    local d a
    d=$(mktemp -d "${WORKDIR}/hash.XXXXXX")
    HASH_FIFOS=() HASH_PIDS=()
    for a in md5 sha1 sha256; do
        mkfifo "$d/$a"
        "${a}sum" < "$d/$a" > "$d/$a.out" &
        HASH_PIDS+=($!) HASH_FIFOS+=("$d/$a")
    done
}
hash_end() {
    local d=${HASH_FIFOS[0]%/*}
    wait "${HASH_PIDS[@]}"
    H_MD5=$(cut -d' ' -f1 "$d/md5.out") H_SHA1=$(cut -d' ' -f1 "$d/sha1.out") H_SHA256=$(cut -d' ' -f1 "$d/sha256.out")
    rm -rf "$d"
}
hash_file() { hash_begin; tee "${HASH_FIFOS[@]}" < "$1" > /dev/null; hash_end; }
write_sidecars() {  # out_file base
    echo "$H_MD5  ${1##*/}" > "$2.md5"
    echo "$H_SHA1  ${1##*/}" > "$2.sha1"
    echo "$H_SHA256  ${1##*/}" > "$2.sha256"
}

# Imaging + hashing
image_volume() {
    local dec_file=$1
    local out_base=$2

    local dec_size
    dec_size=$(stat -c %s "$dec_file")
    DEC_SIZE=$dec_size
    info "Decrypted volume size: $dec_size bytes ($(numfmt --to=iec-i --suffix=B "$dec_size" 2>/dev/null || echo "${dec_size}B"))"

    # Check free space
    check_free_space "$dec_size"

    case "$OUTPUT_FORMAT" in
        raw)  image_volume_raw "$dec_file" "$out_base" ;;
        e01)  image_volume_e01 "$dec_file" "$out_base" ;;
    esac
}

check_free_space() {
    local needed=$1
    local avail
    avail=$(df --output=avail -B1 "$OUTDIR" 2>/dev/null | tail -1 | tr -d ' ')
    if [[ -n "$avail" && "$avail" =~ ^[0-9]+$ ]]; then
        if [[ "$OUTPUT_FORMAT" == "raw" ]] && (( avail < needed )); then
            warn "Low disk space: need ~$(numfmt --to=iec-i "$needed"), available $(numfmt --to=iec-i "$avail")"
        elif [[ "$OUTPUT_FORMAT" == "e01" ]] && (( avail < needed / 2 )); then
            warn "Low disk space: need ~$(numfmt --to=iec-i $((needed/2))), available $(numfmt --to=iec-i "$avail")"
        fi
    fi
}

image_volume_raw() {
    local dec_file=$1 out_base=$2
    local out_file="${out_base}.dd"

    if [[ -e "$out_file" ]] && (( ! FORCE )); then
        die 1 "Output exists: $out_file (use --force to overwrite)"
    fi
    PARTIAL_OUTPUTS+=("$out_file")    # only after the check: cleanup deletes these on failure

    info "Imaging with dd (raw + MD5 + SHA1 + SHA256)..."
    # A read error aborts the run (pipefail) rather than silently zero-filling evidence.
    # dd stderr must never join the data stream.
    hash_begin
    dd if="$dec_file" bs=4M status=progress | tee "${HASH_FIFOS[@]}" > "$out_file"
    hash_end
    IMG_MD5=$H_MD5 IMG_SHA1=$H_SHA1 IMG_SHA256=$H_SHA256

    info "Imaging complete: $out_file"
    info "  MD5:    $IMG_MD5"
    info "  SHA1:   $IMG_SHA1"
    info "  SHA256: $IMG_SHA256"
    write_sidecars "$out_file" "$out_base"
}

image_volume_e01() {
    local dec_file=$1 out_base=$2
    local out_file="${out_base}.E01"

    if [[ -e "$out_file" ]] && (( ! FORCE )); then
        die 1 "Output exists: $out_file (use --force to overwrite)"
    fi

    PARTIAL_OUTPUTS+=("$out_file")
    rm -f "$out_file" "${out_base}".E??    # --force: no stale segments from an earlier, larger image

    info "Imaging with ewfacquirestream (E01 + MD5 + SHA1 + SHA256)..."
    local ewf_args=(-q -d sha1 -c "$COMPRESSION" -S "$SEGMENT_SIZE" -t "$out_base")
    [[ -n "$CASE_NUMBER" ]]    && ewf_args+=(-C "$CASE_NUMBER")
    [[ -n "$DESCRIPTION" ]]    && ewf_args+=(-D "$DESCRIPTION")
    [[ -n "$EVIDENCE_NUMBER" ]] && ewf_args+=(-E "$EVIDENCE_NUMBER")
    [[ -n "$EXAMINER" ]]       && ewf_args+=(-e "$EXAMINER")
    [[ -n "$NOTES" ]]          && ewf_args+=(-N "$NOTES")

    local ewf_log="${WORKDIR}/ewfacquirestream.log" rc=0
    hash_begin
    dd if="$dec_file" bs=4M status=progress | tee "${HASH_FIFOS[@]}" | \
        ewfacquirestream "${ewf_args[@]}" > "$ewf_log" 2>&1 || rc=$?
    hash_end
    while IFS= read -r line; do dbg "ewfacquire: $line"; done < "$ewf_log"
    (( rc == 0 )) || die 6 "E01 imaging failed (rc=$rc): $(tail -1 "$ewf_log")"
    IMG_MD5=$H_MD5 IMG_SHA1=$H_SHA1 IMG_SHA256=$H_SHA256

    info "Imaging complete: $out_file"
    info "  MD5:    $IMG_MD5"
    info "  SHA1:   $IMG_SHA1"
    info "  SHA256: $IMG_SHA256"
    write_sidecars "$out_file" "$out_base"
}

# Verify output
verify_output() {
    local out_base=$1

    if [[ "$OUTPUT_FORMAT" == "raw" ]]; then
        local out_file="${out_base}.dd"
        info "Verifying raw output..."
        local out_size
        out_size=$(stat -c %s "$out_file")
        if [[ -n "${DEC_SIZE:-}" && "$out_size" != "$DEC_SIZE" ]]; then
            err "SIZE MISMATCH - decrypted volume: $DEC_SIZE, output: $out_size"
            VERIFY_RESULT="FAILED"
            return 7
        fi
        hash_file "$out_file"    # one read, all three digests
        if [[ "$H_MD5 $H_SHA1 $H_SHA256" != "$IMG_MD5 $IMG_SHA1 $IMG_SHA256" ]]; then
            err "HASH MISMATCH - imaging: $IMG_MD5 $IMG_SHA1 $IMG_SHA256, verify: $H_MD5 $H_SHA1 $H_SHA256"
            VERIFY_RESULT="FAILED"
            return 7
        fi
        VERIFY_RESULT="PASSED"
        info "Verification PASSED (MD5 + SHA1 + SHA256 match)"

    elif [[ "$OUTPUT_FORMAT" == "e01" ]]; then
        local out_file="${out_base}.E01"
        info "Verifying E01 output (ewfverify)..."
        local vout rc=0
        vout=$(ewfverify -d sha1 "$out_file" 2>&1) || rc=$?
        local e01_size
        e01_size=$(ewfinfo "$out_file" 2>/dev/null | grep -iE 'media size' | grep -oP '\(\K[0-9]+(?= bytes\))' | head -1 || true)
        if [[ -n "${DEC_SIZE:-}" && -n "$e01_size" && "$e01_size" != "$DEC_SIZE" ]]; then
            err "SIZE MISMATCH - decrypted volume: $DEC_SIZE, E01 media: $e01_size"
            VERIFY_RESULT="FAILED"
            return 7
        fi
        # ewfverify must succeed AND report the MD5 we computed on the stream
        if (( rc == 0 )) && grep -qi 'SUCCESS' <<<"$vout" && grep -qi "$IMG_MD5" <<<"$vout"; then
            VERIFY_RESULT="PASSED"
            info "Verification PASSED (ewfverify, stream MD5 matches)"
        else
            VERIFY_RESULT="FAILED"
            err "ewfverify FAILED on $out_file"
            return 7
        fi
    fi
    return 0
}

# Full-disk image
# Splices every decrypted volume (T_DEC: "offset:file", all still mounted) into the raw disk.
build_full_disk() {
    local out_base=$1
    (( ! FULL_DISK )) && return 0

    info "Building full-disk decrypted image (${#T_DEC[@]} decrypted volume(s))..."
    local full_file="${out_base}_fulldisk_decrypted.dd" pos=0 raw_size off dec t
    raw_size=$(stat -c %s "$RAW")
    [[ -e "$full_file" ]] && (( ! FORCE )) && die 1 "Output exists: $full_file (use --force)"
    PARTIAL_OUTPUTS+=("$full_file")

    hash_begin
    {
        while IFS= read -r t; do
            off=${t%%:*} dec=${t#*:}
            (( off > pos )) && dd if="$RAW" bs=4M iflag=skip_bytes,count_bytes skip="$pos" count=$(( off - pos )) status=none
            cat "$dec"
            pos=$(( off + $(stat -c %s "$dec") ))
        done < <(printf '%s\n' "${T_DEC[@]}" | sort -n -t: -k1,1)
        (( pos < raw_size )) && dd if="$RAW" bs=4M iflag=skip_bytes skip="$pos" status=none
        true
    } | tee "${HASH_FIFOS[@]}" > "$full_file"
    hash_end
    local f_md5=$H_MD5 f_sha1=$H_SHA1 f_sha256=$H_SHA256
    write_sidecars "$full_file" "${out_base}_fulldisk_decrypted"
    info "Full-disk image: $full_file"
    info "  MD5:    $f_md5"
    info "  SHA1:   $f_sha1"
    info "  SHA256: $f_sha256"

    info "Verifying full-disk image..."
    if [[ $(stat -c %s "$full_file") == "$raw_size" ]] && hash_file "$full_file" \
        && [[ "$H_MD5 $H_SHA1 $H_SHA256" == "$f_md5 $f_sha1 $f_sha256" ]]; then
        FULL_DISK_VERIFY="PASSED"
        info "Full-disk verification PASSED"
    else
        FULL_DISK_VERIFY="FAILED"
        die 7 "Full-disk verification FAILED"
    fi
    FULL_DISK_HASHES="$f_md5 $f_sha1 $f_sha256"
}

# Report
# Report fields for the target just processed, as k=v lines (one T_RESULT entry per target)
target_result() {
    printf '%s\n' "slot=$1" "offset=$2" "output=$3" "decrypted_size=$DEC_SIZE" \
        "decryptor=${DECRYPTOR:-}" "protector=${UNLOCK_PROTECTOR:-}" "key_derivation=${KEY_DERIVATION:-}" \
        "fvek_method=${FVEK_METHOD:-}" "fvek_validation=${FVEK_VALIDATION:-}" \
        "vmk_sha256_fingerprint=${VMK_FINGERPRINT:-}" \
        "md5=$IMG_MD5" "sha1=$IMG_SHA1" "sha256=$IMG_SHA256" "verification=${VERIFY_RESULT:-}"
}

write_report() {
    local base report_txt report_json end_time_utc duration
    base=$(basename_noext "$IMAGE")
    report_txt="${OUTDIR}/${base}_report.txt" report_json="${OUTDIR}/${base}_report.json"
    end_time_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
    duration=$(( $(date +%s) - START_EPOCH ))

    # Sanitised command line (key file paths redacted; secrets are never on our argv)
    local safe_cmd="$SCRIPT_NAME" skip_next=0 arg
    for arg in "$@"; do
        if (( skip_next )); then safe_cmd+=" [REDACTED]"; skip_next=0; continue; fi
        [[ "$arg" == --startup-key || "$arg" == --key-file ]] && skip_next=1
        safe_cmd+=" $arg"
    done

    local versions="" t
    for t in ewfinfo dislocker-fuse bdemount dd python3; do
        command -v "$t" &>/dev/null && versions+="tools.$t=$(tool_version "$t")"$'\n'
    done
    keytool_available && versions+="tools.BitlockerRecKey2MasterKey.py=$(python3 -I "$KEYTOOL" --version 2>&1)"$'\n'

    local top
    top=$(printf '%s\n' "script_version=$SCRIPT_VERSION" "start_time_utc=$START_TIME_UTC" \
        "end_time_utc=$end_time_utc" "duration_seconds=$duration" "hostname=$(hostname)" "user=$(whoami)" \
        "command=$safe_cmd" "key_type=$KEY_MODE" "output_format=$OUTPUT_FORMAT" \
        "source.image=$IMAGE" "source.media_size=$MEDIA_SIZE" "source.sector_size=$SECTOR_SIZE" \
        "source.stored_md5=${STORED_MD5:-}" "source.stored_sha1=${STORED_SHA1:-}" \
        "source.verify=${VERIFY_SOURCE_RESULT:-not performed}" "source.ewf_case=${EWF_CASE:-}" \
        "source.ewf_examiner=${EWF_EXAMINER:-}" "source.ewf_acquisition_date=${EWF_ACQ_DATE:-}" \
        "case.case_number=$CASE_NUMBER" "case.evidence_number=$EVIDENCE_NUMBER" "case.examiner=$EXAMINER" \
        "case.description=$DESCRIPTION" "case.notes=$NOTES")
    (( FULL_DISK )) && top+=$'\n'"full_disk.hashes=$FULL_DISK_HASHES"$'\n'"full_disk.verification=$FULL_DISK_VERIFY"
    top+=$'\n'"${versions%$'\n'}"

    info "Writing report: $report_txt"
    python3 -I - "$report_txt" "$report_json" "$top" "${T_RESULT[@]}" <<'PY'
import json, sys
txt, js, top, targets = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4:]
INTS = {"duration_seconds", "media_size", "sector_size", "offset", "decrypted_size"}
def kv(s):
    d = dict(l.split("=", 1) for l in s.splitlines() if "=" in l)
    return {k: int(v) if k.rsplit(".", 1)[-1] in INTS and v.isdigit() else v for k, v in d.items()}
flat = kv(top)
doc = {k: v for k, v in flat.items() if "." not in k}
for k, v in flat.items():
    if "." in k:
        g, f = k.split(".", 1)
        doc.setdefault(g, {})[f] = v
doc["targets"] = [kv(t) for t in targets]
with open(js, "w") as f:
    json.dump(doc, f, indent=2)
    f.write("\n")
with open(txt, "w") as f:
    w = lambda k, v, ind="": f.write(f"{ind}{k + ':':<32}{v}\n")
    f.write("=" * 60 + "\n  BitLocker E01 Decryptor Report\n" + "=" * 60 + "\n\n")
    for k, v in doc.items():
        if not isinstance(v, (dict, list)):
            w(k, v)
    for g in ("source", "case", "tools", "full_disk"):
        if any(v != "" for v in doc.get(g, {}).values()):
            f.write(f"\n--- {g.replace('_', ' ').title()} ---\n")
            for k, v in doc[g].items():
                if v != "":
                    w(k, v, "  ")
    for i, t in enumerate(doc["targets"], 1):
        f.write(f"\n--- Target {i}/{len(doc['targets'])} ---\n")
        for k, v in t.items():
            w(k, v, "  ")
    f.write("\n" + "=" * 60 + "\n")
PY
    info "Writing JSON report: $report_json"
    if [[ -n "$BITLOCKER_META" ]]; then
        printf '\n--- dislocker-metadata (last volume) ---\n%s\n' "$BITLOCKER_META" >> "$report_txt"
    fi
}

# Main
main() {
    parse_args "$@"

    check_fuse_status || die 2 "FUSE is not available"
    local -a need=(ewfinfo ewfmount mmls python3)
    (( VERIFY_SOURCE )) && need+=(ewfverify)
    [[ "$OUTPUT_FORMAT" == "e01" ]] && (( ! LIST_ONLY )) && need+=(ewfverify ewfacquirestream)
    local t
    for t in "${need[@]}"; do
        command -v "$t" &>/dev/null || die 2 "$t not found - run '$SCRIPT_NAME --check-deps'"
    done
    if (( ! LIST_ONLY )) && ! command -v dislocker-fuse &>/dev/null && ! command -v bdemount &>/dev/null; then
        die 2 "No BitLocker decryptor found (need dislocker or libbde-utils)"
    fi

    setup_workdir
    trap cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    if (( ! LIST_ONLY )); then
        mkdir -p "$OUTDIR" || die 6 "Cannot create output directory: $OUTDIR"
        start_logging
        info "$SCRIPT_NAME $SCRIPT_VERSION started at $START_TIME_UTC"
    fi

    source_info
    verify_source
    mount_ewf
    detect_layout

    if (( LIST_ONLY )); then
        (( ${#PT_SLOTS[@]} > 0 )) && print_partition_table
        exit 0
    fi

    select_targets
    info "Processing ${#TARGET_OFFSETS[@]} target(s)..."

    local key
    key=$(read_key)

    local base i
    base=$(basename_noext "$IMAGE")
    for (( i=0; i<${#TARGET_OFFSETS[@]}; i++ )); do
        local offset="${TARGET_OFFSETS[$i]}" slot="${TARGET_SLOTS[$i]}"
        local out_base="${OUTDIR}/${base}_p${slot}_decrypted" urc=0
        info "=== Target $((i+1))/${#TARGET_OFFSETS[@]}: slot=$slot offset=$offset ==="

        # Runs in this shell so DECRYPTOR/MOUNT_STACK/report fields persist. Volumes stay
        # mounted until cleanup so --full-disk can splice all of them.
        unlock_volume "$offset" "$slot" "$key" || urc=$?
        (( urc != 0 )) && die 5 "Unlock failed for slot $slot"

        image_volume "$DEC_FILE" "$out_base"
        verify_output "$out_base" || die 7 "VERIFICATION FAILED for slot $slot"
        PARTIAL_OUTPUTS=()    # verified: a later failure must not delete this image

        T_DEC+=("$offset:$DEC_FILE")
        T_RESULT+=("$(target_result "$slot" "$offset" "${out_base}.$([[ $OUTPUT_FORMAT == raw ]] && echo dd || echo E01)")")
    done

    key=""
    unset key

    build_full_disk "${OUTDIR}/${base}"
    write_report "$@"

    info "Completed successfully at $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    info "Output: $OUTDIR"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
