#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

# WSL 감지 및 가상환경(venv) 준비
if grep -qi microsoft /proc/version 2>/dev/null || [ -n "${WSL_DISTRO_NAME:-}" ]; then
  echo "[INFO] WSL 환경이 감지되었습니다."
fi

# 1. venv 가상환경 생성 (없는 경우)
if [ ! -d "venv" ]; then
  echo "[INFO] venv 가상환경을 생성합니다..."
  python3 -m venv venv
fi

# 2. 가상환경 활성화
pip install Pillow

pip install -r requirements.txt

# Check game/catalog status
python main.py status

# Decrypt all bundles (1,899 files from Data/eb/)
python main.py decrypt

# Decrypt + extract assets in one pass
python main.py decrypt-extract

# Decrypt templets (game data tables) from decrypted bundles
python decrypt_templets_v2.py

# Search catalog for keys
python main.py catalog --search "icon"