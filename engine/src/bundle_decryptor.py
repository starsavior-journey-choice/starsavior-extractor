import hashlib
import json
import numpy as np
import os
import shutil
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import Optional

from . import asset_extractor
from .asset_extractor import AssetExtractor

KNOWN_PLAINTEXT = bytes(
    [
        0x55,
        0x6E,
        0x69,
        0x74,
        0x79,
        0x46,
        0x53,
        0x00,
        0x00,
        0x00,
        0x00,
        0x08,
        0x35,
        0x2E,
        0x78,
        0x2E,
    ]
)

KEY_SIZE = 16
ENCRYPTION_LIMIT = 102400
TYPE1_KEY = bytes([0xFF, 0xBB, 0xCC, 0x21])


def derive_key_from_filename(bundle_name: str) -> bytes:
    name32 = bundle_name[:32]
    return hashlib.md5((name32 + ".bytes").encode("utf-8")).digest()


def derive_key(encrypted_first_16: bytes) -> bytes:
    return bytes(e ^ p for e, p in zip(encrypted_first_16[:KEY_SIZE], KNOWN_PLAINTEXT))


def is_type1(encrypted_first_16: bytes) -> bool:
    derived = derive_key(encrypted_first_16)
    return derived == TYPE1_KEY * 4


def apply_bitblend(data: bytearray, mask: bytes, start_pos: int = 0) -> bytearray:
    mask_len = len(mask)
    if mask_len == 0:
        return data
    for i in range(len(data)):
        data[i] ^= mask[(start_pos + i) % mask_len]
    return data


def reverse_bitblend_block(data: bytes, mask: bytes, block_file_offset: int) -> bytes:
    result = bytearray(data)
    apply_bitblend(result, mask, block_file_offset)
    return bytes(result)


def load_mask_map(output_dir: str) -> dict:
    mask_path = Path(output_dir) / "mask_map.json"
    if not mask_path.exists():
        return {}
    with open(mask_path) as f:
        return json.load(f)


def parse_blocks_info(
    data: bytes,
    blocks_info_offset: int,
    blocks_info_size: int,
    blocks_info_compressed: int,
) -> list:
    blocks = []
    if blocks_info_compressed:
        import lz4.block

        try:
            bi_data = lz4.block.decompress(
                data[blocks_info_offset : blocks_info_offset + blocks_info_size]
            )
            data = bi_data
        except Exception:
            return blocks
        blocks_info_offset = 0
        blocks_info_size = len(bi_data)

    pos = blocks_info_offset
    end = blocks_info_offset + blocks_info_size
    archive_version = int.from_bytes(data[8:12], "big")

    storage_count = int.from_bytes(data[pos : pos + 4], "big")
    pos += 4

    if archive_version >= 7:
        _ = int.from_bytes(data[pos : pos + 4], "big")
        pos += 4

    for _ in range(storage_count):
        uncompressed_size = int.from_bytes(data[pos : pos + 4], "big")
        compressed_size = int.from_bytes(data[pos + 4 : pos + 8], "big")
        flags = int.from_bytes(data[pos + 8 : pos + 12], "big")
        pos += 12

        if archive_version >= 7:
            _ = int.from_bytes(data[pos : pos + 4], "big")
            pos += 4

        blocks.append(
            {
                "uncompressed_size": uncompressed_size,
                "compressed_size": compressed_size,
                "flags": flags,
            }
        )
    return blocks


def get_bundle_block_info(data: bytes) -> tuple:
    if len(data) < 64:
        return None, []

    if data[:8] != b"UnityFS\x00":
        return None, []

    archive_version = int.from_bytes(data[8:12], "big")
    pos = 12

    version_str = b""
    while data[pos] != 0:
        pos += 1
    pos += 1  # null terminator for player version
    while data[pos] != 0:
        pos += 1
    pos += 1  # null terminator for engine version

    file_size = int.from_bytes(data[pos : pos + 8], "big")
    pos += 8
    compressed_blocks_size = int.from_bytes(data[pos : pos + 4], "big")
    uncompressed_blocks_size = int.from_bytes(data[pos + 4 : pos + 8], "big")
    flags = int.from_bytes(data[pos + 8 : pos + 12], "big")
    pos += 12

    if archive_version >= 8:
        pos += 16  # align to 16 bytes

    is_compressed = (flags & 0x3) != 0
    return pos, parse_blocks_info(data, pos, compressed_blocks_size, is_compressed)


def decrypt_bundle(
    data: bytes, bundle_name: str = "", mask: Optional[bytes] = None
) -> bytes:
    if len(data) < KEY_SIZE:
        return data
    if data[:7] == b"UnityFS":
        return data
    first16 = data[:KEY_SIZE]
    if is_type1(first16):
        key = TYPE1_KEY * (128 // 4)
        limit = 128
    else:
        if bundle_name:
            key = derive_key_from_filename(bundle_name)
        else:
            key = derive_key(first16)
        limit = ENCRYPTION_LIMIT
    result = bytearray(data)
    end = min(len(result), limit)
    for i in range(end):
        result[i] ^= key[i % len(key)]
    return bytes(result)


def parse_mask_hex(mask_hex: str) -> bytes:
    return bytes(int(x, 16) for x in mask_hex.strip().split())


def decrypt_file(src: str, dst: str, mask: Optional[bytes] = None) -> int:
    with open(src, "rb") as f:
        data = f.read()
    if len(data) < KEY_SIZE or data[:7] == b"UnityFS":
        return 0
    bundle_name = Path(src).stem
    dec = decrypt_bundle(data, bundle_name, mask)
    with open(dst, "wb") as f:
        f.write(dec)
    return len(dec)


def verify_decrypted_header(data: bytes) -> bool:
    return len(data) >= 32 and data[:7] == b"UnityFS" and data[7] == 0


def find_unityfs_offset(data: bytes, max_scan: int = 64) -> int:
    if not data:
        return -1
    limit = min(len(data), max_scan)
    return data[:limit].find(b"UnityFS")


class ExtractCache:
    """소스 파일의 size+mtime 을 기록해 '바뀐 것만 다시 하게' 하는 매니페스트.

    --force(=skip_existing=False) 없이도 항상 최신을 보장하는 게 목적이다.
    과거 skip_existing 의 문제는 변경 여부를 모르는 채 건너뛰어 STRING_COMMON 이
    옛 것으로 남는 것이었는데, 소스 해시가 바뀐 번들만 재처리하므로 그 버그가
    원천 제거된다. 복호화/추출 코드 자체가 바뀌었을 때도 전체 재빌드하도록
    tool 파일들의 stat 을 매니페스트 헤더에 넣었다.
    """

    def __init__(self, path, tool_paths=()):
        self.path = Path(path)
        self.tool_keys = {str(p): self._stat_key(p) for p in tool_paths}
        self.data = self._load()
        self.dirty = False

    @staticmethod
    def _stat_key(p) -> Optional[str]:
        try:
            st = Path(p).stat()
            return f"{st.st_size}:{st.st_mtime_ns}"
        except OSError:
            return None

    def _load(self) -> dict:
        if self.path.exists():
            try:
                with open(self.path, encoding="utf-8") as f:
                    d = json.load(f)
                if d.get("tools") == self.tool_keys:
                    return d
            except Exception:
                pass
        # 없거나(첫 실행) 도구 코드가 바뀌었으면 전부 다시 한다.
        return {"tools": self.tool_keys, "entries": {}}

    def valid(self, src, outputs) -> bool:
        """src 가 매니페스트 키와 일치하고, 산출물이 실제로 존재할 때만 True."""
        e = self.data["entries"].get(str(src))
        if not e:
            return False
        if e.get("key") != self._stat_key(Path(src)):
            return False
        return all(Path(o).exists() for o in e.get("out", []))

    def record(self, src, outputs):
        key = self._stat_key(Path(src))
        if key is None:
            return
        self.data["entries"][str(src)] = {
            "key": key,
            "out": [str(o) for o in outputs],
        }
        self.dirty = True

    def prune(self, live_sources):
        """더 이상 존재하지 않는 소스의 항목과 산출물을 지운다."""
        live = {str(s) for s in live_sources}
        stale = [s for s in self.data["entries"] if s not in live]
        for s in stale:
            for o in self.data["entries"][s].get("out", []):
                p = Path(o)
                if p.is_dir():
                    shutil.rmtree(p, ignore_errors=True)
                elif p.exists():
                    p.unlink(missing_ok=True)
            del self.data["entries"][s]
        if stale:
            self.dirty = True
        return stale

    def save(self):
        if not self.dirty:
            return
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=1)
        self.dirty = False


def _extract_out_dirs(output_dir: Path, stem: str) -> list[Path]:
    """번들 하나의 산출 디렉토리 전부. AssetExtractor 가 쓰는 것과 정확히 일치해야
    한다 — 캐시 valid() 가 이 디렉토리들의 존재를 검사하고, wipe/기록도 이 기준이다.
    """
    return [
        output_dir / "textures" / stem,
        output_dir / "sprites" / stem,
        output_dir / "text_assets" / stem,
        output_dir / "audio" / stem,
    ]


def _extract_bundle_worker(args):
    """extract_all_decrypted 의 워커. 번들 단위라 산출 디렉토리(textures/<stem>/ 등)가
    서로 겹치지 않으므로 프로세스별로 써도 안전하다. 진행 출력은 메인이 모아서 한다.
    """
    src, normalized_dir, output_dir, wipe_existing = args
    src = Path(src)
    normalized_dir = Path(normalized_dir)
    output_dir = Path(output_dir)
    out_dirs = _extract_out_dirs(output_dir, src.stem)
    try:
        # 옛 산출물을 먼저 지운다(패치로 이름이 사라진 PNG 등이 남지 않게). 그 뒤
        # 빈 디렉토리를 만들어 둔다 — 캐시 valid() 가 세 디렉토리의 존재를 요구하는데
        # AssetExtractor 는 에셋이 있을 때만 디렉토리를 만드므로, 순서가 반대면
        # 에셋 종류가 하나라도 없는 번들이 매 실행 다시 추출된다.
        if wipe_existing:
            for d in out_dirs:
                if d.is_dir():
                    shutil.rmtree(d, ignore_errors=True)
        for d in out_dirs:
            d.mkdir(parents=True, exist_ok=True)
        with open(src, "rb") as f:
            data = f.read()
        offset = find_unityfs_offset(data)
        if offset < 0:
            return (src.name, "failed", {}, "UnityFS header not found near start")
        normalized = data[offset:]
        if not verify_decrypted_header(normalized):
            return (src.name, "failed", {}, "bad UnityFS header after trim")
        dst = normalized_dir / f"{src.stem}.bundle"
        if not dst.exists() or dst.stat().st_size != len(normalized):
            with open(dst, "wb") as f:
                f.write(normalized)

        import warnings

        from UnityPy.exceptions import UnityVersionFallbackWarning

        # 순차 버전과 마찬가지로 버전 폴백 경고는 잡는다. 안 잡으면 워커마다
        # stderr 로 쏟아져 진행 출력만 방해된다. raise_on_error — 파싱 실패를
        # '빈 번들' 로 캐시하지 않고 실패로 세려고 예외로 받는다.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UnityVersionFallbackWarning)
            assets = AssetExtractor(str(output_dir)).extract_from_file(
                str(dst), raise_on_error=True
            )
        counts = {}
        for a in assets:
            counts[a.asset_type] = counts.get(a.asset_type, 0) + 1
        status = "extracted" if assets else "empty"
        return (src.name, status, counts, "")
    except Exception as e:
        return (src.name, "failed", {}, str(e))


class BundleDecryptor:
    def __init__(
        self, bundle_dir: str, output_dir: str, decrypted_dir: Optional[str] = None
    ):
        self.bundle_dir = Path(bundle_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.decrypted_dir = (
            Path(decrypted_dir) if decrypted_dir else self.output_dir / "decrypted"
        )
        self.decrypted_dir.mkdir(parents=True, exist_ok=True)
        self.asset_extractor = AssetExtractor(str(self.output_dir))
        self.normalized_dir = self.output_dir / "normalized_bundles"
        self.normalized_dir.mkdir(parents=True, exist_ok=True)
        self.mask_map = load_mask_map(str(self.output_dir))

    def resolve_captured_dir(self) -> Path:
        if self.decrypted_dir.exists():
            has_files = any(self.decrypted_dir.glob("*.bundle")) or any(
                self.decrypted_dir.glob("*.decrypted")
            )
            if has_files:
                return self.decrypted_dir

        captured_dir = self.output_dir / "decrypted_bundles"
        if captured_dir.exists():
            has_files = any(captured_dir.glob("*.bundle")) or any(
                captured_dir.glob("*.decrypted")
            )
            if has_files:
                return captured_dir

        return self.decrypted_dir

    def iter_decrypted_files(self) -> list[Path]:
        source_dir = self.resolve_captured_dir()
        files = list(source_dir.glob("*.bundle"))
        files.extend(source_dir.glob("*.decrypted"))
        files.sort()
        return files

    def prepare_bundle_for_extraction(self, src: Path) -> tuple[Optional[Path], int]:
        with open(src, "rb") as f:
            data = f.read()

        if len(data) < 16:
            return None, -1

        offset = find_unityfs_offset(data)
        if offset < 0:
            return None, -1

        normalized = data[offset:]
        if not verify_decrypted_header(normalized):
            return None, offset

        dst = self.normalized_dir / f"{src.stem}.bundle"
        if not dst.exists() or dst.stat().st_size != len(normalized):
            with open(dst, "wb") as f:
                f.write(normalized)

        return dst, offset

    def decrypt_all(self, skip_existing: bool = True, progress_cb=None) -> dict:
        files = sorted(self.bundle_dir.glob("*.bundle"))
        total = len(files)
        r = {"decrypted": 0, "skipped": 0, "failed": 0, "bitblended": 0, "total": total}
        has_masks = len(self.mask_map) > 0
        # skip_existing=True 는 '캐시로 스킵'(소스가 안 바뀌었고 산출물이 있으면).
        # False(--force) 는 매니페스트를 무시하고 전부 재처리한다.
        cache = ExtractCache(
            self.output_dir / ".decrypt_cache.json",
            tool_paths=[Path(__file__).resolve()],
        )
        for i, p in enumerate(files):
            if progress_cb:
                progress_cb(i, total, p.name)
            dst = self.decrypted_dir / p.name
            if skip_existing and cache.valid(p, [dst]):
                r["skipped"] += 1
                continue
            try:
                mask = None
                if has_masks and p.name in self.mask_map:
                    mask = parse_mask_hex(self.mask_map[p.name])
                    r["bitblended"] += 1
                decrypt_file(str(p), str(dst), mask)
                # 이미 평문이었던 소스는 dst 를 쓰지 않고 끝난다. 그런 항목을
                # 기록하면 valid() 를 영영 통과 못 하는 유령 항목만 남는다.
                if dst.exists():
                    cache.record(p, [dst])
                r["decrypted"] += 1
            except Exception as e:
                print(f"\n  [FAIL] {p.name}: {e}")
                r["failed"] += 1
        if not files:
            # 소스가 하나도 없으면 게임 경로가 틀렸을 가능이 높다. 여기서 prune
            # 하면 정상적인 산출물을 전부 지우므로 아무것도 하지 않는다.
            return r
        stale = cache.prune(files) if skip_existing else []
        if stale:
            print(f"  [CACHE] 소스가 사라진 산출물 {len(stale)}개 정리")
        cache.save()
        return r

    def extract_all_decrypted(
        self,
        skip_existing: bool = True,
        progress_cb=None,
        workers: int = 0,
    ) -> dict:
        total_files = self.iter_decrypted_files()
        # skip_existing=True 는 '캐시로 스킵'. False(--force) 는 전부 재처리.
        # tool_paths 에 asset_extractor 도 넣는다 — 실제 추출 로직이 거기 있으므로
        # 그 코드를 고치면 캐시가 무효화돼야 옛 산출물이 남지 않는다.
        cache = ExtractCache(
            self.output_dir / ".extract_cache.json",
            tool_paths=[
                Path(__file__).resolve(),
                Path(asset_extractor.__file__),
            ],
        )

        # 작업 목록: (재처리 대상, 존재하는 옛 산출물을 지워야 하는지)
        jobs = []
        r = {
            "extracted": 0,
            "skipped": 0,
            "failed": 0,
            "total": len(total_files),
            "assets": {
                "Texture2D": 0,
                "Sprite": 0,
                "TextAsset": 0,
                "AudioClip": 0,
                "other": 0,
            },
        }
        for p in total_files:
            out_dirs = _extract_out_dirs(self.output_dir, p.stem)
            if skip_existing and cache.valid(p, out_dirs):
                r["skipped"] += 1
                continue
            # 소스가 바뀐 번들은 옛 산출물(이름이 사라진 PNG 등)이 남지 않게 지운다.
            wipe = any(d.exists() for d in out_dirs)
            jobs.append((p, wipe))

        if not total_files:
            # decrypted 디렉토리가 비었다 — 경로가 틀렸을 가능이 높다. prune 하면
            # 정상적인 산출물을 전부 지우므로 아무것도 하지 않는다.
            return r

        total = len(jobs)
        if jobs:
            workers = workers or int(os.environ.get("EXTRACT_WORKERS", "0")) or min(
                8, (os.cpu_count() or 4)
            )
            workers = max(1, min(workers, total))
        done_count = [0]

        def tick(name, status, counts, msg):
            done_count[0] += 1
            if status == "failed":
                print(f"\n  [FAIL] {name}: {msg}")
                r["failed"] += 1
            elif status == "extracted":
                r["extracted"] += 1
                for t, c in counts.items():
                    r["assets"][t] = r["assets"].get(t, 0) + c
            if progress_cb:
                progress_cb(done_count[0] - 1, total, name)

        # jobs 가 비어도(전부 캐시 히트) 아래 prune 은 돌려야 한다 — 소스가 사라진
        # 항목 정리는 캐시 히트와 무관하다.
        if not jobs:
            pass
        elif workers > 1:
            # 프로세스 풀. Worker 안에서 AssetExtractor 를 새로 만드므로 상태 공유 없음.
            args_iter = (
                (src, self.normalized_dir, self.output_dir, wipe) for src, wipe in jobs
            )
            with ProcessPoolExecutor(max_workers=workers) as pool:
                for src, (name, status, counts, msg) in zip(
                    (s for s, _ in jobs), pool.map(_extract_bundle_worker, args_iter, chunksize=4)
                ):
                    if status != "failed":
                        cache.record(src, _extract_out_dirs(self.output_dir, src.stem))
                    tick(name, status, counts, msg)
        else:
            for src, wipe in jobs:
                name, status, counts, msg = _extract_bundle_worker(
                    (src, self.normalized_dir, self.output_dir, wipe)
                )
                if status != "failed":
                    cache.record(src, _extract_out_dirs(self.output_dir, src.stem))
                tick(name, status, counts, msg)

        stale = cache.prune(total_files) if skip_existing else []
        if stale:
            print(f"  [CACHE] 소스가 사라진 산출물 {len(stale)}개 정리")
        cache.save()
        return r
