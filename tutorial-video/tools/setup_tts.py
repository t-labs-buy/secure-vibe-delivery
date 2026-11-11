"""One-time setup of the local, open-source narration voice (Kokoro-82M, Apache 2.0)
and the speech-to-text used by check.py (Whisper). Works on macOS, Linux and Windows.

    python3 setup_tts.py         # creates ~/.cache/demo-video-tts (about 1.5 GB with models)

Safe to re-run. Needs uv (https://docs.astral.sh/uv/); uv fetches a Python 3.12 for the
environment if there is none, because Kokoro does not support newer Pythons yet.
Whisper is mlx-whisper on Apple Silicon and faster-whisper (CPU) elsewhere.
"""
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

ENV = Path(os.environ.get("KOKORO_ENV", Path.home() / ".cache" / "demo-video-tts"))
PY = ENV / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
SPACY_MODEL = ("en_core_web_sm @ https://github.com/explosion/spacy-models/releases/download/"
               "en_core_web_sm-3.8.0/en_core_web_sm-3.8.0-py3-none-any.whl")
WARM = """
import warnings; warnings.filterwarnings("ignore")
from kokoro import KPipeline
KPipeline(lang_code="a", repo_id="hexgrad/Kokoro-82M")
print("Kokoro ready")
"""


def main():
    if not shutil.which("uv"):
        sys.exit("Need uv: " + ('powershell -c "irm https://astral.sh/uv/install.ps1 | iex"' if os.name == "nt"
                                else "curl -LsSf https://astral.sh/uv/install.sh | sh") + "  (or: pip install uv)")
    if not shutil.which("ffmpeg"):
        print("warning: ffmpeg not found — install it (brew install ffmpeg, apt install ffmpeg, "
              "winget install Gyan.FFmpeg); voice.py and build.py need it")
    if not PY.exists():
        subprocess.run(["uv", "venv", str(ENV), "--python", "3.12", "-q"], check=True)
    apple = sys.platform == "darwin" and platform.machine() == "arm64"
    # faster-whisper 1.2 passes an argument that PyAV 16+ removed, so hold PyAV back.
    pkgs = ["kokoro>=0.9", "soundfile", SPACY_MODEL, *(["mlx-whisper"] if apple else ["faster-whisper", "av<16"])]
    subprocess.run(["uv", "pip", "install", "-q", "--python", str(PY), *pkgs], check=True)
    # Warm the model downloads so the first real run is quick.
    subprocess.run([str(PY), "-c", WARM], check=True)
    print(f"TTS environment: {PY}")


if __name__ == "__main__":
    main()
