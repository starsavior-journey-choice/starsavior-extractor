"""
Decrypt templet .bytes files directly from decrypted Unity bundles.
Bypasses UnityPy which corrupts binary TextAsset data during extraction.
Uses the correct magic constant 0x2B21DE00 and K4os-compatible LZ4 framing.
"""

import os
import sys
import io
import json
import struct
import hashlib
import lz4.frame
import lz4.block
from pathlib import Path

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

TEMPLET_MAGIC = 0x2B21DE00  # Correct magic: 0x2B21DE00 (723639808 & 0xFFFFFF00)
DECRYPTED_BUNDLES_DIR = Path(r"./output/decrypted")
OUTPUT_DIR = Path(r"./output/decrypted_templets")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def compute_mask(filename: str) -> bytes:
    if not filename.endswith(".bytes"):
        filename += ".bytes"
    return hashlib.md5(filename.encode("utf-8")).digest()


def apply_mask(data: bytes, mask: bytes, offset: int = 0) -> bytes:
    result = bytearray(data)
    mask_len = len(mask)
    for i in range(len(result)):
        result[i] ^= mask[(offset + i) % mask_len]
    return bytes(result)


# LZ4 의 이론적 최대 압축비는 255:1 이다(같은 바이트가 반복될 때). 그래서
# 압축 크기 x255 + 여유는 어떤 블록에도 충분한 출력 버퍼 크기다.
LZ4_MAX_RATIO = 255
LZ4_MIN_CAPACITY = 1 << 16


def _decompress_block(block: bytes, actual: int) -> bytes | None:
    """블록 하나를 푼다. 실패하면 None.

    lz4.block.decompress 의 uncompressed_size 는 "정확한 크기" 가 아니라
    **출력 버퍼 용량**이다. 실제보다 크게 줘도 되고, 실제 길이를 돌려준다.
    그래서 넉넉하게 몇 번만 시도하면 된다.

    예전에는 `range(actual, max(actual*4, 65536))` 로 1바이트씩 올려 가며
    찾았다. 두 가지가 틀렸다.
      · 상한이 압축 크기의 4배 — 다국어 JSON 문자열 테이블은 42:1 로 압축된다.
        그래서 STRING_COMMON / KEY_STRING_DIALOG 같은 **큰 파일만** 실패했다.
      · 1바이트씩 올리면 큰 블록에서 수백만 번 시도한다.
    """
    cap = max(actual * 8, LZ4_MIN_CAPACITY)
    ceiling = actual * LZ4_MAX_RATIO + LZ4_MIN_CAPACITY
    while True:
        try:
            return lz4.block.decompress(block, uncompressed_size=cap)
        except lz4.block.LZ4BlockError:
            if cap >= ceiling:
                return None
            cap = min(cap * 4, ceiling)


# 마지막으로 쓴 압축 해제 경로. "어제는 됐는데 오늘은 안 된다" 를 판별하려면
# frame 경로였는지 수동 블록 경로였는지가 유일한 단서다(수동 경로만 버그가 있었다).
last_path = "?"


def decompress_lz4(data: bytes) -> bytes:
    global last_path
    try:
        out = lz4.frame.decompress(data)
        last_path = "frame"
        return out
    except Exception:
        pass

    last_path = "blocks"
    # Manual block parsing as fallback
    try:
        offset = 7  # skip frame header
        all_dec = b""
        n_blocks = 0
        while offset < len(data):
            if offset + 4 > len(data):
                break
            bs = struct.unpack_from("<I", data, offset)[0]
            offset += 4
            if bs == 0:
                break
            uncomp = bool(bs & 0x80000000)
            actual = bs & 0x7FFFFFFF
            if actual > len(data) - offset:
                break
            block = data[offset : offset + actual]
            offset += actual
            n_blocks += 1
            if uncomp:
                all_dec += block
            else:
                result = _decompress_block(block, actual)
                if result is None:
                    last_path = f"blocks x{n_blocks} (block {actual:,}B failed)"
                    return None
                all_dec += result
        last_path = f"blocks x{n_blocks}"
        return all_dec if all_dec else None
    except Exception:
        return None


def extract_textasset_bytes_from_bundle(bundle_data: bytes) -> list[tuple[str, bytes]]:
    """
    Extract raw TextAsset name+bytes pairs from a decrypted Unity bundle.
    Uses UnityPy for parsing but reads raw bytes directly.
    """
    import UnityPy

    UnityPy.config.FALLBACK_UNITY_VERSION = "6000.0.61f1"

    results = []
    try:
        env = UnityPy.load(io.BytesIO(bundle_data))
    except Exception:
        return results

    for obj in env.objects:
        if obj.type.name == "TextAsset":
            try:
                data = obj.read()
                name = data.m_Name
                raw = obj.get_raw_data()

                if not raw or len(raw) < 8:
                    continue

                # Parse raw data structure:
                # [4 bytes: name_len LE] [name string] [padding to 4-byte align]
                # [4 bytes: script_len LE] [script bytes]
                name_len = struct.unpack_from("<I", raw, 0)[0]
                name_end = 4 + name_len
                # Align to 4 bytes
                name_end_aligned = (name_end + 3) & ~3
                if name_end_aligned + 4 > len(raw):
                    continue
                script_len = struct.unpack_from("<I", raw, name_end_aligned)[0]
                script_start = name_end_aligned + 4
                script_data = raw[script_start : script_start + script_len]

                if len(script_data) >= 4:
                    results.append((name, script_data))
            except Exception as e:
                continue

    return results


# 번들에는 templet 이 아닌 TextAsset 도 잔뜩 들어 있다(설정, 셰이더 텍스트 등).
# 그건 실패가 아니라 "대상이 아님" 이다. 둘을 섞으면 실패 목록이 수천 줄이 되어
# 정작 STRING_COMMON 이 안 보인다. 이 접두로 구분한다.
NOT_TEMPLET = "not a templet: "


def decrypt_templet(data: bytes, filename: str) -> tuple[str | None, str]:
    if len(data) <= 4:
        return None, NOT_TEMPLET + "too short"

    magic = struct.unpack_from("<i", data, 0)[0]

    if (magic & 0xFFFFFF00) != TEMPLET_MAGIC:
        version = magic & 0xFF
        return None, NOT_TEMPLET + f"unknown magic {magic:#010x} (version {version})"

    version_byte = magic & 0xFF
    stripped = data[4:]

    # 실패는 None 으로 돌려준다. 예전에는 hex 덤프를 돌려줬는데, 그러면
    # 호출부가 "성공" 으로 보고 STRING_COMMON.txt 같은 400바이트 쓰레기 파일을
    # 남긴다. 변환기는 .json 만 읽으므로 그 templet 이 조용히 통째로 빠진다 —
    # 문자열 테이블이 그렇게 되면 모든 이름이 빈 값이 된다. 실제로 그랬다.
    if version_byte == 0 or version_byte == 1:
        result = decompress_lz4(stripped)
        if result is None:
            return None, f"v{version_byte}: lz4[{last_path}] failed"
        try:
            return result.decode("utf-8-sig"), f"v{version_byte}: lz4[{last_path}] + json"
        except UnicodeDecodeError:
            return None, f"v{version_byte}: lz4[{last_path}] ok but not utf8"

    elif version_byte == 2:
        mask = compute_mask(filename)
        unmasked = apply_mask(stripped, mask)
        result = decompress_lz4(unmasked)
        if result is None:
            return None, f"v2: bitblend + lz4[{last_path}] failed"
        try:
            return result.decode("utf-8-sig"), f"v2: bitblend + lz4[{last_path}] + json"
        except UnicodeDecodeError:
            return None, f"v2: bitblend + lz4[{last_path}] ok but not utf8"

    else:
        return None, f"unknown version byte: {version_byte}"


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Decrypt TEMPLET .bytes files from bundles"
    )
    parser.add_argument(
        "--limit", type=int, default=0, help="Max bundles to process (0=all)"
    )
    parser.add_argument(
        "--name", type=str, default="", help="Process specific bundle by hash"
    )
    parser.add_argument("--output", type=str, default="", help="Output directory")
    parser.add_argument(
        "--force", action="store_true", help="Re-process existing files"
    )
    parser.add_argument(
        "--allow-failures", action="store_true",
        help="Report failed templets but exit 0. Use only when you have "
             "confirmed the failing files are not needed (e.g. one cutscene). "
             "A failing STRING_COMMON must never be allowed through — every "
             "name in the site becomes an empty string.",
    )
    args = parser.parse_args()

    out_dir = Path(args.output) if args.output else OUTPUT_DIR

    if args.name:
        bundle_files = [DECRYPTED_BUNDLES_DIR / f"{args.name}.bundle"]
    else:
        bundle_files = sorted(DECRYPTED_BUNDLES_DIR.glob("*.bundle"))

    if args.limit > 0:
        bundle_files = bundle_files[: args.limit]

    print(f"Found {len(bundle_files)} decrypted bundles")

    success = 0
    failed = 0
    skipped_files = 0
    results = []
    failures = []          # (에셋 이름, 이유) — 마지막에 반드시 보여 준다

    for i, bundle_path in enumerate(bundle_files):
        bundle_data = bundle_path.read_bytes()
        assets = extract_textasset_bytes_from_bundle(bundle_data)

        for name, script_data in assets:
            ext = ".json"
            out_path = out_dir / f"{name}{ext}"

            if not args.force and out_path.exists():
                skipped_files += 1
                continue

            text, method = decrypt_templet(script_data, name)

            if text is not None:
                is_json = text.strip().startswith("{") or text.strip().startswith("[")
                # Also check for UTF-8 BOM
                if text.startswith("\ufeff"):
                    text = text[1:]
                    is_json = text.strip().startswith("{") or text.strip().startswith(
                        "["
                    )

                ext = ".json" if is_json else ".txt"
                out_path = out_dir / f"{name}{ext}"
                out_path.write_text(text, encoding="utf-8")
                results.append((name, method, len(text), is_json, str(out_path)))
                success += 1
            elif method.startswith(NOT_TEMPLET):
                skipped_files += 1          # templet 이 아닌 에셋 — 정상
            else:
                # 매직이 맞았으니 templet 인데 복호화가 실패했다. 이건 사고다.
                failures.append((name, method))
                failed += 1

        if (i + 1) % 20 == 0 or i + 1 == len(bundle_files):
            print(
                f"  {i + 1}/{len(bundle_files)} bundles ({success} ok, {skipped_files} skipped)"
            )

    print(f"\nDone: {success} decrypted, {skipped_files} skipped, {failed} FAILED")
    print(f"Output: {out_dir}")

    if results:
        json_files = [(n, m, sz, p) for n, m, sz, is_j, p in results if is_j]
        print(f"\nJSON files: {len(json_files)}")
        print("\nLargest JSON files:")
        json_files.sort(key=lambda x: -x[2])
        for name, method, size, path in json_files[:30]:
            print(f"  {method:30s} {size:>10,} bytes  {name}")

        txt_files = [(n, m, sz, p) for n, m, sz, is_j, p in results if not is_j]
        if txt_files:
            print(f"\nNon-JSON files: {len(txt_files)}")
            for name, method, size, path in txt_files[:10]:
                print(f"  {method:30s} {size:>10,} bytes  {name}")

    # 실패 보고는 **마지막**에 둔다. 위 요약보다 앞에서 return 하면 어떤 파일이
    # 잘 나왔는지를 못 보게 된다.
    if failures:
        # 여기서 성공으로 끝내면 변환기가 그 templet 을 통째로 못 읽은 채로
        # 돌아간다. STRING_COMMON 이 그렇게 빠지면 모든 이름이 빈 값이 되고,
        # 그래도 파이프라인은 통과한다. 실제로 그렇게 하루를 잃었다.
        # 그래서 종료 코드 1 로 멈춘다 — 루트 run.sh 가 여기서 중단한다.
        print(f"\n{'=' * 70}")
        print(f"  FAILED {len(failures)} templet(s) — DO NOT convert with this output")
        print(f"{'=' * 70}")
        reasons = {}
        for name, reason in failures:
            reasons.setdefault(reason, []).append(name)
        for reason, names in sorted(reasons.items(), key=lambda kv: -len(kv[1])):
            print(f"  {reason}  ({len(names)})")
            for n in sorted(names)[:15]:
                print(f"      {n}")
            if len(names) > 15:
                print(f"      ... and {len(names) - 15} more")
        print(f"{'=' * 70}")
        print("  These templets are absent from the output. The converter reads")
        print("  only *.json, so they would silently be empty.")
        if args.allow_failures:
            print("  --allow-failures given: exiting 0 anyway.")
            return 0
        print("  Aborting with exit code 1.  (--allow-failures to override)")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
