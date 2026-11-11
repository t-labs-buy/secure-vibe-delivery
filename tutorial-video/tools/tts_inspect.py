"""Inspection helpers that run in the TTS environment (used by check.py).

    echo '{"transcribe": ["a.wav", ...]}'          | python tts_inspect.py   → {"a.wav": "text", ...}
    echo '{"phonemes": ["SAP", "L2C"], "lang": "a"}' | python tts_inspect.py → {"SAP": "sˈæp", ...}
"""
import json
import sys
import warnings

warnings.filterwarnings("ignore")


def transcribe(files, prompt):
    """Whisper small: mlx-whisper on Apple Silicon, faster-whisper (CPU) everywhere else."""
    try:
        import mlx_whisper
    except ImportError:
        from faster_whisper import WhisperModel
        model = WhisperModel("small", device="cpu", compute_type="int8")
        return {f: "".join(seg.text for seg in model.transcribe(f, language="en", initial_prompt=prompt)[0]).strip()
                for f in files}
    return {f: mlx_whisper.transcribe(f, path_or_hf_repo="mlx-community/whisper-small-mlx",
                                      language="en", initial_prompt=prompt)["text"].strip()
            for f in files}


def main():
    job = json.load(sys.stdin)
    out = {}
    if job.get("transcribe"):
        out.update(transcribe(job["transcribe"], job.get("prompt")))
    if job.get("phonemes"):
        from misaki import en
        g = en.G2P(trf=False, british=job.get("lang") == "b", fallback=None)
        for w in job["phonemes"]:
            out[w] = g(w)[0]
    json.dump(out, sys.stdout)


if __name__ == "__main__":
    main()
