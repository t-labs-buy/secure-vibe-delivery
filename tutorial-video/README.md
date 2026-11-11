# Demo video

<!-- One paragraph: what the video shows, for whom, what stays live in the meeting. -->

| File | What it is |
|---|---|
| `demo-video.mp4` | The narrated, captioned video (gitignored; rebuild with the commands below). |
| `script.md` | Timed narration, one section per scene. Generated; edit `scenes.json` instead. |
| `scenes.json` | The story: scenes, captions, voice-over, cue phrases, cards, pronunciation, masks. |
| `scenes.py` | One function per app scene: what happens on screen at each cue. |
| `captures/` | Full-resolution stills of key moments, for slides. |
| `tools/` | The demo-video engine (from the `demo-video` skill; refresh with its `init.py`). |

## Regenerating

```bash
python3 tools/setup_tts.py       # once per machine: local Kokoro voice + Whisper
python3 tools/voice.py           # narration + cue times (cached)
python3 tools/record.py          # screen recordings timed to the narration; or name scenes
python3 tools/build.py           # MP4 + script.md
python3 tools/check.py           # transcript diff, late cues, contact sheets, leaks
```

- **Caption or card change:** run `build.py` only.
- **Voice-over, cues or voice change:** re-record the affected scenes, then build.

## The voice

Kokoro-82M (open source, Apache 2.0) runs locally; nothing is sent to a service.

- **Other voices:** `VOICE=bf_emma` / `am_michael` / `bm_george`.
- **Pace:** `VOICE_SPEED=0.95`.
- **macOS voice:** `TTS=say VOICE=Daniel`.
- **Silent cut:** `VOICE=`.

After changing any of these, re-record, then build.

## Things to know

- **Source:** the ArchFlow demo, `docs/architecture/demo/index.html`, opened as a local file. No sign-in, no app, nothing written; nothing needed masking.
- **Script:** narration is word for word from `docs/secure-vibe-delivery-demo-video-script.md`.
- **Illustrative figures:** the numbers in the demo's speech bubbles (82% coverage, p95 410 ms, health score 61, run_id 7f3a) are examples, not a real run. The voice-over says "In this example".
- **How scenes keep state:** each scene runs in a fresh browser, so `open_demo(pg, done)` clicks the timeline scrubber to jump to the step where the previous scene ended, then scenes advance with **Step** on their cues. Speed is set to 2.0× so each step finishes before the next cue.
- **Layout for recording:** `scenes.py` lifts the demo's 1500 px width cap with injected CSS. Don't use CSS `zoom` instead: the drawn cursor then lands in the wrong place.
- **Playwright:** run the tools with `uv run --no-project --with playwright==1.61.0 python tools/<tool>.py`; 1.61.0 matches the Chromium build already cached on this machine.
- **Pronunciation:** Snyk, Semgrep, pytest and github have phonetic rules in `scenes.json`; Kokoro drops them otherwise. Whisper's "sneak", "svd" and "tlabs by github" in `check.py` are correct readings.
- **Pause:** the 2-second silence at about 2:16 is deliberate (before "Now the gate decides").
