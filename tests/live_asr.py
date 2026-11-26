"""Run inside the CPU worker image with the prepared model volume, see docs/TRANSCRIPTION.md."""
import shutil
import sqlite3
import subprocess
import tempfile
import time
from pathlib import Path

from app import asr_store, worker


def main():
    fixture = Path(__file__).parent / "fixtures/speech-ru.ogg"
    model_dir = Path("/models")
    worker.prepare_models(model_dir, print)
    engine = worker.load_engine(model_dir)
    with tempfile.TemporaryDirectory() as tmp, sqlite3.connect(":memory:") as db:
        data = Path(tmp)
        media = data / "media"
        media.mkdir()
        asr_store.init_db(db)
        shutil.copyfile(fixture, media / "audio")
        # Repeating speech across 45 s exercises both the block boundary and the final tail.
        subprocess.run(["ffmpeg", "-nostdin", "-v", "error", "-f", "lavfi", "-i",
                        "color=s=64x64:r=1", "-stream_loop", "7", "-i", str(fixture),
                        "-map", "0:v", "-map", "1:a", "-shortest", "-c:v", "mpeg4",
                        "-c:a", "aac", "-f", "mp4", str(media / "video")], check=True)
        (media / "invalid").write_bytes(b"invalid synthetic media")
        subprocess.run(["ffmpeg", "-nostdin", "-v", "error", "-f", "lavfi", "-i",
                        "anullsrc=r=16000:cl=mono", "-t", "1", "-f", "wav", str(media / "silence")],
                       check=True)
        for job_id in ("audio", "video", "invalid", "silence"):
            with db:
                db.execute("INSERT INTO transcripts(id,owner,filename) VALUES (?,1,?)", (job_id, job_id))
            started = time.monotonic()
            assert worker.work(db, data, engine)
            state, result, seconds, error = db.execute(
                "SELECT status,body,seconds,error FROM transcripts WHERE id=?", (job_id,)).fetchone()
            print(f"{job_id} status={state} audio_s={seconds} wall_s={time.monotonic()-started:.2f}", flush=True)
            if job_id in ("audio", "video"):
                assert state == "done", error
                assert "день" in result.lower() and "текст" in result.lower(), result
                if job_id == "video":
                    assert result.lower().count("день") >= 7, result
            else:
                assert state == "failed" and error


if __name__ == "__main__":
    main()
