"""Run inside the CPU worker image with the prepared model volume, see docs/TRANSCRIPTION.md."""
import re
import shutil
import sqlite3
import subprocess
import tempfile
import time
from pathlib import Path

from app import asr_store, folder_watch, worker


def seconds(clock):
    hours, minutes, rest = clock.split(":")
    return 3600 * int(hours) + 60 * int(minutes) + float(rest)


def check_folder_timestamps(engine, fixture):
    with tempfile.TemporaryDirectory() as tmp:
        data = Path(tmp)
        root = data / "watch"
        source = root / "Записи"
        source.mkdir(parents=True)
        recording = source / "Встреча.flac"
        subprocess.run(["ffmpeg", "-nostdin", "-v", "error", "-i", str(fixture), "-filter_complex",
                        "[0:a]asplit=2[a][b];[a]adelay=3000:all=1[early];[b]adelay=47500:all=1[late];"
                        "[early][late]amix=inputs=2:duration=longest:normalize=0[out]",
                        "-map", "[out]", str(recording)], check=True)
        db = folder_watch.connect(data / "queue.db")
        asr_store.init_db(db)
        with db:
            db.execute("INSERT INTO watch_resources(name,kind) VALUES ('Папка','local')")
            db.execute("""INSERT INTO watch_rules(name,input_resource,input_folder,delete_source)
                          VALUES ('Тест',1,'Записи',1)""")
        for moment in (100, 115):
            folder_watch.scan_once(db, "", root, now=moment)
        while folder_watch.work(db, data, engine, "", root, now=116):
            pass
        row = db.execute("SELECT state,error FROM watch_files").fetchone()
        assert row["state"] == "done", tuple(row)
        path = source / folder_watch.DEFAULT_FOLDER / "Встреча.txt"
        assert not recording.exists()
        result = path.read_text(encoding="utf-8")
        spans = re.findall(r"^\[([\d:.]+) – ([\d:.]+)\] (.+)$", result, re.M)
        assert len(spans) >= 2 and result.lower().count("день") == 2, result
        times = [(seconds(start), seconds(end)) for start, end, _ in spans]
        assert all(a < b and (i == 0 or a >= times[i - 1][1]) for i, (a, b) in enumerate(times)), times
        assert 2.5 <= times[0][0] <= 4, times
        assert any(47 <= start <= 48.5 for start, _ in times), times
        assert 52 < times[-1][1] < 56, times
        path.unlink()
        folder_watch.scan_once(db, "", root, now=131)
        assert folder_watch.work(db, data, None, "", root, now=131)
        assert path.read_text() == result
        print(result, end="")
        print("Confirmed timed TXT restoration after source removal.")
        db.close()



def main():
    fixture = Path(__file__).parent / "fixtures/speech-ru.ogg"
    model_dir = Path("/models")
    worker.prepare_models(model_dir, print)
    engine = worker.load_engine(model_dir)
    check_folder_timestamps(engine, fixture)
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
