"""Artifact store: ids are uuid4 hex, files <id>.png / <id>.cover.png.

Only validated ids ever reach the filesystem layer; paths are built from
the fixed directory + id + fixed suffix, so traversal is impossible.
"""

import errno
import os
import re
import threading
import uuid

from .config import MAX_ARTIFACT_FILE_BYTES
from .errors import StegoError

_ID_RE = re.compile(r"[0-9a-f]{32}")
_FILE_RE = re.compile(r"([0-9a-f]{32})(\.cover)?\.png")
_SUFFIX = {"stego": ".png", "cover": ".cover.png"}
_lock = threading.Lock()


def new_id():
    return uuid.uuid4().hex


def validate_id(value, field="artifact_id"):
    if not isinstance(value, str) or _ID_RE.fullmatch(value) is None:
        raise StegoError("INVALID_REQUEST", f"{field} must be 32 lowercase hex characters")
    return value


class ArtifactStore:
    def __init__(self, directory, retention_max=0):
        self.directory = os.path.abspath(directory)
        self.retention_max = max(0, int(retention_max))

    def _path(self, artifact_id, kind):
        validate_id(artifact_id)
        if kind not in _SUFFIX:
            raise StegoError("INTERNAL_ERROR", "bad artifact kind")
        return os.path.join(self.directory, artifact_id + _SUFFIX[kind])

    def writable(self):
        d = self.directory
        while d and not os.path.exists(d):
            parent = os.path.dirname(d)
            if parent == d:
                break
            d = parent
        return os.path.isdir(d) and os.access(d, os.W_OK)

    def write(self, artifact_id, kind, data):
        final = self._path(artifact_id, kind)
        tmp = os.path.join(self.directory, f".{artifact_id}.{uuid.uuid4().hex}.tmp")
        try:
            os.makedirs(self.directory, exist_ok=True)
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
            try:
                with os.fdopen(fd, "wb") as fh:
                    fh.write(data)
                    fh.flush()
                    os.fsync(fh.fileno())
                try:
                    os.link(tmp, final)  # atomic publish; fails if final exists (never overwrite)
                except FileExistsError:
                    raise StegoError("IMAGE_WRITE_FAILED", "artifact already exists")
                except OSError as exc:
                    if exc.errno not in (errno.EPERM, errno.ENOTSUP, errno.EOPNOTSUPP, errno.EXDEV):
                        raise
                    # filesystem without hard links: reserve name exclusively, then atomic replace
                    try:
                        os.close(os.open(final, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644))
                    except FileExistsError:
                        raise StegoError("IMAGE_WRITE_FAILED", "artifact already exists")
                    os.replace(tmp, final)
            finally:
                try:
                    os.unlink(tmp)
                except FileNotFoundError:
                    pass
        except StegoError:
            raise
        except OSError as exc:
            raise StegoError("IMAGE_WRITE_FAILED", "could not write artifact", {"errno": exc.errno}) from exc

    def read(self, artifact_id, kind):
        path = self._path(artifact_id, kind)
        try:
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except FileNotFoundError:
            raise StegoError("ARTIFACT_NOT_FOUND", "artifact not found")
        except OSError as exc:
            raise StegoError("ARTIFACT_NOT_FOUND", "artifact not readable", {"errno": exc.errno}) from exc
        with os.fdopen(fd, "rb") as fh:
            size = os.fstat(fh.fileno()).st_size
            if size > MAX_ARTIFACT_FILE_BYTES:
                raise StegoError("IMAGE_TOO_LARGE", "artifact file too large")
            return fh.read(size)

    def exists(self, artifact_id, kind):
        return os.path.isfile(self._path(artifact_id, kind))

    def delete(self, artifact_id, kinds=("stego", "cover")):
        for k in kinds:
            try:
                os.unlink(self._path(artifact_id, k))
            except FileNotFoundError:
                pass
            except OSError:
                pass

    def list_ids(self):
        """Artifact ids oldest-first by (mtime_ns, id)."""
        try:
            names = os.listdir(self.directory)
        except FileNotFoundError:
            return []
        newest = {}
        for n in names:
            m = _FILE_RE.fullmatch(n)
            if not m:
                continue
            try:
                t = os.stat(os.path.join(self.directory, n)).st_mtime_ns
            except OSError:
                continue
            newest[m.group(1)] = max(newest.get(m.group(1), 0), t)
        return [i for _, i in sorted((t, i) for i, t in newest.items())]

    def enforce_retention(self, keep_id=None):
        """Delete oldest artifacts beyond retention_max (0 = keep all). Returns deleted ids."""
        if self.retention_max <= 0:
            return []
        with _lock:
            ids = self.list_ids()
            excess = len(ids) - self.retention_max
            deleted = []
            for i in ids:
                if excess <= 0:
                    break
                if i == keep_id:
                    continue
                self.delete(i)
                deleted.append(i)
                excess -= 1
            return deleted


def default_store():
    from . import config
    return ArtifactStore(config.artifact_dir(), config.retention_max())
