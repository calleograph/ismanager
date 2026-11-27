"""Directory resources for watched recordings. No host mounts are required for SMB."""
from contextlib import contextmanager
import ctypes
from dataclasses import dataclass
import errno
import fcntl
import hashlib
import ipaddress
import os
from pathlib import Path
import re
import secrets
import signal
import stat as mode

MAX_AUDIO = 512 * 1024 * 1024
MAX_TXT = 8_000_000
MEDIA_EXTENSIONS = frozenset(
    ".aac .ac3 .aif .aiff .alac .amr .ape .avi .caf .dv .flac .flv .m2ts .m4a .m4b .m4v .mka .mkv "
    ".mov .mp2 .mp3 .mp4 .mpeg .mpg .mts .oga .ogg .ogv .opus .ts .vob .wav .webm .wma .wmv .3gp .3g2".split()
)
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


class SourceRetainedError(PermissionError):
    """The transcript is durable but the original cannot safely be removed."""


class SourceChangedError(OSError):
    """The recording is no longer the version selected by the watcher."""


@dataclass(frozen=True)
class Snapshot:
    name: str
    size: int
    mtime_ns: int
    file_id: str


def _component(name):
    if (not isinstance(name, str) or not name or len(name.encode("utf-8")) > 255
            or name.endswith((".", " ")) or re.search(r'[<>:"/\\|?*\x00-\x1f\x7f]', name)
            or re.fullmatch(r"(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?", name, re.I)):
        raise ValueError("Недопустимое имя файла или каталога.")
    return name


def relative_folder(value):
    if not isinstance(value, str) or len(value) > 2048:
        raise ValueError("Недопустимый путь к каталогу.")
    if not value:
        return ""
    path = value.replace("\\", "/")
    if path.startswith("/"):
        raise ValueError("Требуется путь от корня ресурса.")
    return "/".join(_component(part) for part in path.rstrip("/").split("/"))


def validate_resource(resource, watch_root=None):
    data = dict(resource)
    kind = data.get("kind")
    path = data.get("path") or ""
    cfg = dict(kind=kind, path=path, server="", share="", domain="", username="", password="", port=445)
    if kind == "local":
        root = Path(watch_root or os.getenv("WATCH_ROOT", "/watch"))
        if not root.is_absolute():
            raise ValueError("WATCH_ROOT должен быть абсолютным путём.")
        if Path(path).is_absolute():
            try:
                local = Path(path).relative_to(root)
            except ValueError:
                raise ValueError("Каталог должен находиться внутри WATCH_ROOT.") from None
            path = "" if local == Path(".") else local.as_posix()
        cfg["path"] = relative_folder(path)
    elif kind == "smb":
        host = str(data.get("server") or "").strip()
        try:
            host = str(ipaddress.ip_address(host))
            if "%" in host:
                raise ValueError
        except ValueError:
            if len(host) > 253 or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*", host):
                raise ValueError("Укажите DNS-имя или IP-адрес SMB-сервера.") from None
        try:
            port = int(data.get("port") or 445)
        except (TypeError, ValueError):
            raise ValueError("Некорректный порт SMB.") from None
        user = data.get("username") or ""
        domain = data.get("domain") or ""
        if not 1 <= port <= 65535 or not user or len(user) > 256 or len(domain) > 255 or re.search(r"[\x00-\x1f\x7f]", user + domain):
            raise ValueError("Проверьте порт и учётную запись SMB.")
        cfg.update(server=host.lower(), port=port, share=_component(data.get("share")),
                   path=relative_folder(path), username=user, domain=domain, password=data.get("password") or "")
    else:
        raise ValueError("Неизвестный вид ресурса.")
    return cfg


def _snapshot(name, st):
    if not mode.S_ISREG(st.st_mode) or getattr(st, "st_file_attributes", 0) & 0x400:
        raise ValueError("Ожидался обычный файл.")
    change = getattr(st, "st_chgtime_ns", st.st_ctime_ns)
    return Snapshot(name, st.st_size, st.st_mtime_ns, f"{st.st_dev}:{st.st_ino}:{change}")


def _hash_stream(stream, limit, dest=None, overflow=ValueError):
    digest = hashlib.sha256()
    total = 0
    while chunk := stream.read(1024 * 1024):
        total += len(chunk)
        if total > limit:
            raise overflow("Размер файла превысил ожидаемый.")
        digest.update(chunk)
        if dest is not None:
            dest.write(chunk)
    return digest.hexdigest(), total


def _read_lease(stream, required):
    # Linux sends the configured signal when a new writer needs to break the
    # lease. SIGURG is ignored by default and does not terminate the worker.
    try:
        fd = stream.fileno()
        fcntl.fcntl(fd, fcntl.F_SETSIG, signal.SIGURG)
        fcntl.fcntl(fd, fcntl.F_SETLEASE, fcntl.F_RDLCK)
        return True
    except OSError as error:
        if error.errno in (errno.EAGAIN, errno.EBUSY):
            raise SourceChangedError("Файл ещё открыт для записи. Исходник сохранён.") from None
        if required:
            raise SourceRetainedError("TXT готов. Исходник сохранён: права или файловая система не позволяют исключить запись.") from None
        # Copying from a read-only or foreign-owned share can use snapshot checks.
        return False


def _check_lease(stream):
    if fcntl.fcntl(stream.fileno(), fcntl.F_GETLEASE) != fcntl.F_RDLCK:
        raise SourceChangedError("Запрошено изменение файла. Исходник сохранён.")


def _same_after_move(a, b):
    # Renaming a file updates inode change time, but preserves identity and last write time.
    return (a.size, a.mtime_ns, a.file_id.rsplit(":", 1)[0]) == (b.size, b.mtime_ns, b.file_id.rsplit(":", 1)[0])


def _backup_name(name, suffix):
    stem = Path(name).stem.encode("utf-8")[:160].decode("utf-8", "ignore")
    return f"{stem}.{suffix}"


def _move(src_fd, src, dst_fd, dst):
    # Linux renameat2 provides an atomic rename without replacing a concurrent arrival.
    fn = ctypes.CDLL(None, use_errno=True).renameat2
    if fn(src_fd, os.fsencode(src), dst_fd, os.fsencode(dst), 1):
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code), dst)
    os.fsync(dst_fd)
    if src_fd != dst_fd:
        os.fsync(src_fd)


class _Local:
    def __init__(self, fd):
        self.fd = fd

    def scan(self):
        return os.scandir(self.fd)

    def stat(self, name):
        return os.stat(name, dir_fd=self.fd, follow_symlinks=False)

    def open(self, name, write=False, allow_rename=False):
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY if write else os.O_RDONLY | os.O_NONBLOCK
        fd = os.open(name, flags | os.O_NOFOLLOW, 0o600, dir_fd=self.fd)
        if not mode.S_ISREG(os.fstat(fd).st_mode):
            os.close(fd)
            raise ValueError("Ожидался обычный файл.")
        return os.fdopen(fd, "wb" if write else "rb")

    def move(self, old, new):
        _move(self.fd, old, self.fd, new)

    def unlink(self, name):
        os.unlink(name, dir_fd=self.fd)

    def delete_source(self, snap, sha):
        # An fd pins this private directory even if the producer replaces an entry
        # in its spool. A crash leaves a recoverable, visible original on disk.
        recovery = "IS Manager - recovery"
        try:
            os.mkdir(recovery, 0o700, dir_fd=self.fd)
            os.fsync(self.fd)
        except FileExistsError:
            pass
        recovery_fd = os.open(recovery, DIR_FLAGS, dir_fd=self.fd)
        name_tag = hashlib.sha256((snap.name + "\0" + snap.file_id + sha).encode()).hexdigest()[:24]
        saved = _backup_name(snap.name, name_tag + Path(snap.name).suffix)
        claimed = _Local(recovery_fd)
        try:
            info = os.fstat(recovery_fd)
            if info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise SourceRetainedError("TXT готов. Исходник сохранён: каталог восстановления не является закрытым.")
            try:
                claimed.stat(saved)
            except FileNotFoundError:
                try:
                    current = _snapshot(snap.name, self.stat(snap.name))
                except FileNotFoundError:
                    return False
                if current != snap:
                    raise SourceChangedError("Исходная запись изменилась.")
                # Check producers before touching their pathname. Recheck the
                # claimed inode because a directory entry can still be renamed.
                with self.open(snap.name) as source:
                    if _snapshot(snap.name, os.fstat(source.fileno())) != snap:
                        raise SourceChangedError("Исходная запись была заменена.")
                    _read_lease(source, required=True)
                    _move(self.fd, snap.name, recovery_fd, saved)
            try:
                with claimed.open(saved) as stream:
                    before = _snapshot(snap.name, os.fstat(stream.fileno()))
                    if not _same_after_move(snap, before):
                        raise SourceChangedError("Исходная запись была заменена.")
                    _read_lease(stream, required=True)
                    actual, _ = _hash_stream(stream, snap.size, overflow=SourceChangedError)
                    if actual != sha or before != _snapshot(snap.name, os.fstat(stream.fileno())):
                        raise SourceChangedError("Содержимое исходной записи изменилось.")
                    _check_lease(stream)
                    claimed.unlink(saved)
                    os.fsync(recovery_fd)
                return True
            except BaseException:
                try:
                    _move(recovery_fd, saved, self.fd, snap.name)
                except FileExistsError:
                    pass  # The new arrival and the quarantined file are both retained.
                raise
        finally:
            os.close(recovery_fd)


@contextmanager
def _smb_errors():
    from smbprotocol.exceptions import NtStatus, SMBException
    from spnego.exceptions import SpnegoError

    try:
        yield
    except (SMBException, SpnegoError) as error:
        status = getattr(error, "ntstatus", None) or getattr(error, "status", None)
        number = {
            NtStatus.STATUS_ACCESS_DENIED: errno.EACCES, NtStatus.STATUS_OBJECT_NAME_COLLISION: errno.EEXIST,
            NtStatus.STATUS_SHARING_VIOLATION: errno.EBUSY, NtStatus.STATUS_CANNOT_DELETE: errno.EPERM,
            NtStatus.STATUS_PRIVILEGE_NOT_HELD: errno.EACCES,
            NtStatus.STATUS_OBJECT_NAME_NOT_FOUND: errno.ENOENT, NtStatus.STATUS_OBJECT_PATH_NOT_FOUND: errno.ENOENT,
        }.get(status, getattr(error, "errno", None) or errno.EIO)
        raise OSError(number, "SMB: операция с каталогом не выполнена.") from None


class _ServerConnections(dict):
    """A DFS referral may reuse credentials only on the configured SMB endpoint."""
    def __init__(self, host, port):
        super().__init__()
        self.endpoint = f"{host.lower()}:{port}"

    def get(self, key, default=None):
        # smbprotocol consults the per-session cache before creating a TCP connection.
        if key != self.endpoint:
            raise PermissionError("Переадресация учётных данных на другой сервер SMB запрещена.")
        return super().get(key, default)


class _SMB:
    def __init__(self, path, options):
        self.path = path
        self.options = options

    def unc(self, name):
        return self.path + "\\" + name

    def scan(self):
        import smbclient
        return smbclient.scandir(self.path, **self.options)

    def stat(self, name):
        import smbclient
        with _smb_errors():
            return smbclient.stat(self.unc(name), follow_symlinks=False, **self.options)

    def open(self, name, write=False, allow_rename=False):
        import smbclient
        from smbprotocol.open import CreateOptions
        with _smb_errors():
            return smbclient.open_file(self.unc(name), mode="xb" if write else "rb", share_access="rd" if allow_rename else "r",
                                       create_options=CreateOptions.FILE_OPEN_REPARSE_POINT, **self.options)

    def move(self, old, new):
        import smbclient
        try:
            with _smb_errors():
                smbclient.rename(self.unc(old), self.unc(new), **self.options)
        except PermissionError as error:
            # Samba can report ACCESS_DENIED for an occupied destination in a no-replace rename.
            try:
                self.stat(new)
            except FileNotFoundError:
                raise error
            raise FileExistsError("Место назначения уже занято.") from None

    def unlink(self, name):
        import smbclient
        with _smb_errors():
            smbclient.remove(self.unc(name), **self.options)

    def delete_source(self, snap, sha):
        import smbclient
        from smbclient._io import SMBFileTransaction, set_info
        from smbprotocol.file_info import FileDispositionInformation
        from smbprotocol.open import CreateOptions, FilePipePrinterAccessMask as Access

        # The server denies writes and renames while this handle is held. Set
        # disposition on this verified handle, not on a second pathname lookup.
        try:
            with _smb_errors():
                stream = smbclient.open_file(self.unc(snap.name), "rb", buffering=0, share_access="r",
                                             desired_access=Access.FILE_READ_DATA | Access.FILE_READ_ATTRIBUTES | Access.DELETE,
                                             create_options=CreateOptions.FILE_OPEN_REPARSE_POINT, **self.options)
        except FileNotFoundError:
            return False
        with stream:
            if _snapshot(snap.name, self.stat(snap.name)) != snap:
                raise SourceChangedError("Исходная запись изменилась.")
            if _hash_stream(stream, snap.size, overflow=SourceChangedError)[0] != sha:
                raise SourceChangedError("Содержимое исходной записи изменилось.")
            info = FileDispositionInformation()
            info["delete_pending"] = True
            with SMBFileTransaction(stream) as transaction:
                set_info(transaction, info)
            return True


class Directory:
    def __init__(self, backend):
        self._io = backend

    def probe(self):
        with self._io.scan() as listing:
            next(iter(listing), None)

    def stat(self, name):
        return _snapshot(name, self._io.stat(_component(name)))

    def list_media(self):
        with self._io.scan() as listing:
            for entry in listing:
                if entry.name.startswith(".") or Path(entry.name).suffix.lower() not in MEDIA_EXTENSIONS:
                    continue
                try:
                    yield self.stat(entry.name)
                except (FileNotFoundError, ValueError):
                    continue

    def copy_source(self, snap, destination, max_bytes=MAX_AUDIO):
        if snap.size > max_bytes:
            raise ValueError("Запись превышает допустимый размер.")
        if self.stat(snap.name) != snap:
            raise SourceChangedError("Исходная запись изменилась.")
        dest = Path(destination)
        with self._io.open(snap.name) as src, os.fdopen(
            os.open(dest, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600), "wb"
        ) as out:
            try:
                leased = False
                if isinstance(self._io, _Local):
                    if _snapshot(snap.name, os.fstat(src.fileno())) != snap:
                        raise SourceChangedError("Исходная запись была заменена.")
                    leased = _read_lease(src, required=False)
                sha, total = _hash_stream(src, min(snap.size, max_bytes), out, SourceChangedError)
                if total != snap.size or self.stat(snap.name) != snap:
                    raise SourceChangedError("Исходная запись изменилась во время чтения.")
                if leased:
                    _check_lease(src)
                out.flush()
                os.fsync(out.fileno())
            except BaseException:
                dest.unlink(missing_ok=True)
                raise
        return sha

    def read_text(self, name):
        snap = self.stat(name)
        if Path(name).suffix.lower() != ".txt" or snap.size > MAX_TXT:
            raise ValueError("Ожидался текстовый файл допустимого размера.")
        with self._io.open(name) as stream:
            data = stream.read(MAX_TXT + 1)
        if len(data) > MAX_TXT:
            raise ValueError("Текстовый файл слишком большой.")
        return data.decode("utf-8")

    def _output_hash(self, name):
        try:
            snap = self.stat(name)
        except ValueError:
            raise FileExistsError("На месте результата уже есть другой объект.") from None
        if snap.size > MAX_TXT:
            raise FileExistsError("На месте результата уже есть другой файл.")
        with self._io.open(name) as stream:
            return _hash_stream(stream, MAX_TXT)[0]

    @contextmanager
    def _guard_previous_text(self, name):
        # Hold the previous result read-only (allow our own rename). Another
        # writer or an unverifiable filesystem leaves the canonical name untouched.
        try:
            stream = self._io.open(name, allow_rename=True)
        except OSError as error:
            if error.errno in (errno.EACCES, errno.EBUSY, errno.EPERM):
                raise FileExistsError("Имеющийся TXT занят.") from None
            raise
        with stream:
            if isinstance(self._io, _Local):
                try:
                    _read_lease(stream, required=True)
                except (SourceChangedError, SourceRetainedError):
                    raise FileExistsError("Имеющийся TXT занят или не допускает безопасную замену.") from None
            yield stream

    def publish_text(self, name, text, *, previous_sha256=None):
        _component(name)
        data = text.encode("utf-8")
        if Path(name).suffix.lower() != ".txt" or len(data) > MAX_TXT:
            raise ValueError("Ожидался текстовый результат допустимого размера.")
        if previous_sha256 is not None and not re.fullmatch(r"[0-9a-f]{64}", previous_sha256):
            raise ValueError("Некорректная контрольная сумма.")
        current_sha = hashlib.sha256(data).hexdigest()
        tmp = ".ismanager-" + secrets.token_hex(16) + ".part"
        with self._io.open(tmp, write=True) as out:
            try:
                out.write(data)
                out.flush()
                if isinstance(self._io, _Local):
                    os.fsync(out.fileno())
                else:
                    # Flush the remote handle as well as Python's write buffer.
                    out.raw.flush()
            except BaseException:
                # On SMB the writing handle must close before removing a partial.
                out.close()
                self._io.unlink(tmp)
                raise
        try:
            try:
                self._io.move(tmp, name)
                return
            except FileExistsError:
                old = self._output_hash(name)
            if old == current_sha:
                if isinstance(self._io, _Local):
                    os.fsync(self._io.fd)
                return
            if old != previous_sha256:
                raise FileExistsError("На месте результата уже есть другой файл.")
            backup = _backup_name(name, f"previous-{old[:12]}-{secrets.token_hex(5)}.txt")
            with self._guard_previous_text(name) as guarded:
                self._io.move(name, backup)
                try:
                    if self._output_hash(backup) != old:
                        raise FileExistsError("Текст был изменён другим пользователем.")
                    if isinstance(self._io, _Local):
                        try:
                            _check_lease(guarded)
                        except SourceChangedError:
                            raise FileExistsError("Текст открыт другим пользователем.") from None
                    self._io.move(tmp, name)
                except BaseException:
                    try:
                        self._io.move(backup, name)
                    except FileExistsError:
                        pass  # Another writer owns the name. The previous version remains visible.
                    raise
        finally:
            try:
                self._io.unlink(tmp)
            except FileNotFoundError:
                pass

    def delete_source(self, snap, sha256):
        _component(snap.name)
        if Path(snap.name).suffix.lower() not in MEDIA_EXTENSIONS or not re.fullmatch(r"[0-9a-f]{64}", sha256):
            raise ValueError("Проверьте снимок записи и контрольную сумму.")
        try:
            return self._io.delete_source(snap, sha256)
        except OSError as error:
            if error.errno in (errno.EACCES, errno.EPERM, errno.EROFS, errno.ENOTDIR, errno.ELOOP):
                raise SourceRetainedError("TXT готов. Исходник сохранён: недостаточно прав для безопасного удаления.") from None
            if error.errno == errno.EBUSY:
                raise SourceChangedError("Запись ещё используется. Исходник сохранён.") from None
            raise


@contextmanager
def open_storage(resource, secret_key, watch_root=None, *, folder="", create=False):
    cfg = validate_resource(resource, watch_root)
    parts = [part for path in (cfg["path"], relative_folder(folder)) for part in path.split("/") if part]
    if cfg["kind"] == "local":
        fd = os.open(watch_root or os.getenv("WATCH_ROOT", "/watch"), DIR_FLAGS)
        try:
            for part in parts:
                if create:
                    try:
                        os.mkdir(part, 0o750, dir_fd=fd)
                        os.fsync(fd)
                    except FileExistsError:
                        pass
                child = os.open(part, DIR_FLAGS, dir_fd=fd)
                os.close(fd)
                fd = child
            yield Directory(_Local(fd))
        finally:
            os.close(fd)
        return

    import smbclient
    from cryptography.fernet import InvalidToken
    from .credentials import credential_cipher
    from smbclient._pool import ClientConfig

    if not secret_key:
        raise ValueError("Ключ для SMB не настроен.")
    try:
        password = credential_cipher(secret_key).decrypt(cfg["password"].encode()).decode()
    except (ValueError, InvalidToken):
        raise ValueError("Не удалось открыть учётные данные SMB.") from None
    user = cfg["domain"] + "\\" + cfg["username"] if cfg["domain"] else cfg["username"]
    cache = _ServerConnections(cfg["server"], cfg["port"])
    ClientConfig(skip_dfs=True)
    options = dict(port=cfg["port"], connection_cache=cache, username=user, password=password,
                   auth_protocol="ntlm", connection_timeout=10)
    try:
        with _smb_errors():
            smbclient.register_session(cfg["server"], **options)
            unc = "\\\\" + cfg["server"] + "\\" + cfg["share"]
            for part in parts:
                unc += "\\" + part
                if create:
                    try:
                        smbclient.mkdir(unc, **options)
                    except OSError as error:
                        if error.errno != errno.EEXIST:
                            raise
                st = smbclient.stat(unc, follow_symlinks=False, **options)
                if not mode.S_ISDIR(st.st_mode) or st.st_file_attributes & 0x400:
                    raise ValueError("Ожидался каталог SMB без точки повторной обработки.")
            directory = Directory(_SMB(unc, options))
        with _smb_errors():
            yield directory
    finally:
        smbclient.reset_connection_cache(fail_on_error=False, connection_cache=cache)
