"""Local GigaAM v3 E2E RNNT inference for the IS Manager recording queue."""
import fcntl
import hashlib
import json
import logging
import math
import os
import select
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from contextlib import closing
from pathlib import Path

from .asr_store import claim, init_db, source_path

MODEL = "v3_e2e_rnnt"
MODEL_URL = "https://cdn.chatwm.opensmodel.sberdevices.ru/GigaAM/"
MODEL_FILES = {
    MODEL + ".ckpt": "f60c62fe45902d967000770a12f260de7c5ac4d4b8e5e852f1df8c548e3958b5",
    MODEL + "_tokenizer.model": "828c12c991019eef952a960661f25a92d6ad279591e2ea466b4aeddf1d20a18a",
}
RATE = 16000
MAX_SECONDS = 6 * 3600
FORMATS = ("wav,mp3,flac,ogg,matroska,webm,mov,mp4,m4a,3gp,3g2,mj2,avi,asf,"
           "aac,ac3,eac3,amr,aiff,mpeg,mpegts,flv,caf,ape,w64,au")
LOG = logging.getLogger("asr")


class RecordingError(ValueError):
    """A diagnostic safe to show to the owner of the recording."""


def status(data_dir, label, ready=False):
    path = data_dir / "asr-status.tmp"
    path.write_text(json.dumps({"time": time.time(), "ready": ready, "label": label}))
    path.replace(data_dir / "asr-status.json")


def _verified(path, expected):
    if not path.is_file():
        return False
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest() == expected


def prepare_models(directory, notify):
    directory.mkdir(parents=True, exist_ok=True)
    for name, expected in MODEL_FILES.items():
        dest = directory / name
        if _verified(dest, expected):
            continue
        # Parallel installs can share one model volume. Keep interrupted downloads for resumption.
        with (directory / ".download.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            if _verified(dest, expected):
                continue
            part = dest.with_suffix(dest.suffix + ".part")
            offset = part.stat().st_size if part.is_file() else 0
            request = urllib.request.Request(MODEL_URL + name)
            if offset:
                request.add_header("Range", f"bytes={offset}-")
            notify("Загружается GigaAM v3 E2E RNNT")
            try:
                response = urllib.request.urlopen(request, timeout=45)
            except urllib.error.HTTPError as exc:
                if exc.code != 416 or not offset:
                    raise
                # A previous download may have completed just before the worker stopped.
                response = None
            if response is not None:
                append = offset and getattr(response, "status", None) == 206
                with response, part.open("ab" if append else "wb") as out:
                    last_update = time.monotonic()
                    while chunk := response.read(1024 * 1024):
                        out.write(chunk)
                        if time.monotonic() - last_update >= 10:
                            notify(f"Загружается GigaAM · {out.tell() // 1048576} МиБ")
                            last_update = time.monotonic()
            if not _verified(part, expected):
                part.unlink(missing_ok=True)
                raise ValueError("Контрольная сумма весов или токенизатора GigaAM не совпадает")
            part.replace(dest)


def load_engine(directory):
    import gigaam
    import torch
    from silero_vad import load_silero_vad
    from .telemetry import asr_threads, cgroup_directory

    device = os.getenv("ASR_DEVICE", "cpu")
    if device not in {"cpu", "cuda"} or (device == "cuda" and not torch.cuda.is_available()):
        raise RuntimeError("Проверьте ASR_DEVICE и доступность ускорителя")
    torch.set_num_threads(asr_threads(cgroup_directory()))
    # NNPACK requires larger batches; probing it on every convolution floods logs on some CPUs.
    torch.backends.nnpack.set_flags(False)
    vad = load_silero_vad(onnx=True)
    model = gigaam.load_model(MODEL, device=device, use_flash=False, fp16_encoder=device == "cuda",
                              download_root=str(directory))
    recognize(model, torch.zeros(RATE))
    return vad, model


def recognize(model, speech):
    import torch

    with torch.inference_mode():
        p = next(model.parameters())
        audio = speech.to(device=p.device, dtype=p.dtype).unsqueeze(0)
        lengths = torch.tensor([audio.shape[-1]], device=p.device)
        encoded, length = model.forward(audio, lengths)
        return str(model.decoding.decode(model.head, encoded, length)[0][0]).strip()


def probe(path):
    command = ["ffprobe", "-v", "error", "-protocol_whitelist", "file", "-format_whitelist", FORMATS,
               "-select_streams", "a:0", "-show_entries", "stream=index:format=duration",
               "-of", "json", str(path)]
    try:
        result = subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30)
        info = json.loads(result.stdout)
    except (subprocess.SubprocessError, ValueError) as exc:
        raise RecordingError("Не удалось открыть запись. Проверьте, воспроизводится ли она у вас. Сохраните копию в MP3 или WAV и выберите её для распознавания.") from exc
    if not info.get("streams"):
        raise RecordingError("В файле нет звуковой дорожки. Выберите видео со звуком или отдельную аудиозапись.")
    try:
        duration = float(info.get("format", {}).get("duration", ""))
    except ValueError:
        duration = 0
    if duration > MAX_SECONDS:
        raise RecordingError("Запись длиннее шести часов. Разделите её на части.")
    return duration if math.isfinite(duration) and duration > 0 else 0


def decode(path):
    command = ["ffmpeg", "-nostdin", "-v", "error", "-xerror", "-protocol_whitelist", "file",
               "-format_whitelist", FORMATS, "-threads", "2", "-i", str(path), "-map", "0:a:0",
               "-t", str(MAX_SECONDS + 1), "-ac", "1", "-ar", str(RATE), "-f", "s16le", "pipe:1"]
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as proc:
        try:
            while True:
                if not select.select([proc.stdout], [], [], 60)[0]:
                    raise RecordingError("Извлечение звука остановилось. Проверьте исходный файл.")
                chunk = os.read(proc.stdout.fileno(), 131072)
                if not chunk:
                    break
                yield chunk
            if proc.wait(timeout=30):
                raise RecordingError("Не удалось прочитать звуковую дорожку. Сохраните её в MP3 или WAV и загрузите полученный файл.")
        finally:
            if proc.poll() is None:
                proc.kill()


def timestamp(samples):
    seconds, millis = divmod(samples * 1000 // RATE, 1000)
    minutes, seconds = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    return f"{hours:02}:{minutes:02}:{seconds:02}.{millis:03}"


def transcribe(path, engine, progress, *, timed=False):
    import numpy as np
    import torch
    from silero_vad import get_speech_timestamps

    duration = probe(path)
    progress(0, 0)
    vad, model = engine
    lines = []
    pending = bytearray()
    consumed = 0
    previous_end = None
    block_bytes = RATE * 2 * 45
    last_report = time.monotonic()

    def report(samples):
        seconds = int(samples / RATE)
        progress(seconds, min(99, int(seconds / duration * 100)) if duration else 0)

    def process(final):
        nonlocal consumed, previous_end, last_report
        pcm = np.frombuffer(pending, dtype="<i2").astype(np.float32) / 32768
        audio = torch.from_numpy(pcm)
        spans = get_speech_timestamps(audio, vad, sampling_rate=RATE, min_speech_duration_ms=250,
                                      min_silence_duration_ms=700, speech_pad_ms=200,
                                      max_speech_duration_s=12)
        # Keep the final utterance and a short lead-in if the decoder has more data.
        cut = len(audio) if final else len(audio) - RATE
        for span in spans:
            start, end = span["start"], span["end"]
            if not final and end > cut:
                cut = min(cut, start)
                break
            result = recognize(model, audio[start:end])
            if time.monotonic() - last_report >= 2:
                report(consumed + end)
                last_report = time.monotonic()
            if result:
                gap = (consumed + start - previous_end) / RATE if previous_end is not None else 0
                separator = "\n\n" if gap >= 2 else " "
                if timed:
                    lines.append(f"[{timestamp(consumed + start)} – {timestamp(consumed + end)}] {result}\n")
                else:
                    lines.append((separator if lines else "") + result)
                previous_end = consumed + end
        consumed += cut
        del pending[:cut * 2]
        report(consumed)

    with closing(decode(path)) as audio_stream:
        for chunk in audio_stream:
            pending.extend(chunk)
            if consumed + len(pending) // 2 > RATE * MAX_SECONDS:
                raise RecordingError("Запись длиннее шести часов. Разделите её на части.")
            if len(pending) >= block_bytes:
                process(False)
        if pending:
            process(True)
    if not lines:
        raise RecordingError("Речь не обнаружена. Проверьте громкость и выбранную аудиодорожку.")
    return "".join(lines)


def recover(db):
    with db:
        db.execute("""
            UPDATE transcripts SET status=CASE WHEN recoveries=0 THEN 'queued' ELSE 'failed' END,
                progress=0,seconds=0,recoveries=recoveries+1,
                finished_at=CASE WHEN recoveries>0 THEN unixepoch() END,
                started_at=CASE WHEN recoveries>0 THEN started_at END,
                recognizing_at=CASE WHEN recoveries>0 THEN recognizing_at END,
                error=CASE WHEN recoveries=0 THEN '' ELSE 'Обработка дважды прервалась. Нажмите «Повторить обработку». Если ошибка повторится, сообщите администратору время сбоя.' END
            WHERE status='running'
        """)


def work(db, data_dir, engine):
    with db:
        item = claim(db)
    if item is None:
        return False
    job_id = item[0]

    def progress(seconds, percent):
        with db:
            db.execute("UPDATE transcripts SET seconds=?,progress=?,recognizing_at=coalesce(recognizing_at,unixepoch()) WHERE id=?",
                       (seconds, percent, job_id))
        status(data_dir, "GigaAM обрабатывает запись", True)

    try:
        text = transcribe(source_path(data_dir, job_id), engine, progress)
    except sqlite3.OperationalError:
        raise
    except Exception as exc:
        LOG.error("Recording %s failed (%s)", job_id, type(exc).__name__)
        error = str(exc) if isinstance(exc, RecordingError) else "Сбой распознавания. Нажмите «Повторить обработку». Если ошибка повторится, сообщите администратору время сбоя."
        with db:
            db.execute("UPDATE transcripts SET status='failed',finished_at=unixepoch(),error=? WHERE id=?", (error, job_id))
    else:
        with db:
            db.execute("UPDATE transcripts SET status='done',finished_at=unixepoch(),progress=100,original=?,body=? WHERE id=?",
                       (text, text, job_id))
    return True


def main():
    from . import folder_watch, telemetry

    data = Path(os.getenv("DATA_DIR", "/data"))
    if sys.argv[1:] == ["health"]:
        try:
            state = json.loads((data / "asr-status.json").read_text())
            return 0 if state["ready"] and time.time() - state["time"] < 180 else 1
        except (OSError, ValueError, KeyError):
            return 1
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    data.mkdir(parents=True, exist_ok=True)
    with (data / "asr-worker.lock").open("a") as lock:
        # Only the holder may reclaim interrupted work after a container restart.
        fcntl.flock(lock, fcntl.LOCK_EX)
        threading.Thread(target=telemetry.publish_worker, args=(data,), daemon=True, name="asr-resources").start()
        database = os.getenv("DATABASE") or data / "ismanager.sqlite3"
        db = folder_watch.connect(database)
        init_db(db)
        recover(db)
        folder_watch.recover(db, data)
        secret = os.getenv("SECRET_KEY", "")
        interval = max(1, int(os.getenv("WATCH_POLL_SECONDS", folder_watch.INTERVAL)))
        threading.Thread(target=folder_watch.scan_loop, args=(database, secret, interval),
                         daemon=True, name="watch-scan").start()
        directory = Path(os.getenv("MODEL_DIR", "/models"))
        while True:
            try:
                status(data, "Подготовка GigaAM v3 E2E RNNT")
                prepare_models(directory, lambda label: status(data, label))
                engine = load_engine(directory)
                break
            except Exception as exc:
                LOG.error("Model preparation failed: %s: %s", type(exc).__name__, exc)
                status(data, "Ошибка подготовки GigaAM. Подробности в журнале worker, повтор через минуту.")
                time.sleep(60)
        LOG.info("GigaAM v3 E2E RNNT ready (%s)", os.getenv("ASR_DEVICE", "cpu"))
        last_idle = 0
        resume_after_lock = False
        while True:
            if time.monotonic() - last_idle > 15:
                status(data, "GigaAM v3 E2E RNNT готова к работе", True)
                last_idle = time.monotonic()
            try:
                if resume_after_lock:
                    with db:
                        db.execute("UPDATE transcripts SET status='queued',started_at=NULL,recognizing_at=NULL WHERE status='running'")
                    folder_watch.recover(db, data)
                    resume_after_lock = False
                uploaded = work(db, data, engine)
                watched = folder_watch.work(db, data, engine, secret)
            except sqlite3.OperationalError as exc:
                error_code = getattr(exc, "sqlite_errorcode", 0) & 255
                if error_code not in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}:
                    raise
                db.rollback()
                resume_after_lock = True
                LOG.warning("Queue database busy. Retrying.")
                time.sleep(2)
                continue
            if not uploaded and not watched:
                time.sleep(1)


if __name__ == "__main__":
    sys.exit(main())
