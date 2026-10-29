import os
import threading

import pytest

from stego import artifacts
from stego.artifacts import ArtifactStore, new_id, validate_id
from stego.errors import StegoError


@pytest.fixture
def store(tmp_path):
    return ArtifactStore(tmp_path / "a" / "b")  # directory created lazily


def code(fn, *a):
    with pytest.raises(StegoError) as ei:
        fn(*a)
    return ei.value.code


def test_new_id_format():
    ids = {new_id() for _ in range(50)}
    assert len(ids) == 50 and all(len(i) == 32 and validate_id(i) == i for i in ids)


@pytest.mark.parametrize("bad", ["", "abc", "A" * 32, "g" * 32, "0" * 31, "0" * 33, "0" * 32 + "\n", " " + "0" * 32,
                                 "../" + "0" * 29, "0" * 28 + "/../", "0" * 32 + ".png", None, 5, b"0" * 32, ["0" * 32],
                                 "0" * 16 + "/" + "0" * 15, "0" * 16 + "\\" + "0" * 15, "%2e%2e" + "0" * 26, "0" * 31 + "\x00"])
def test_invalid_ids_rejected(store, bad):
    assert code(validate_id, bad) == "INVALID_REQUEST"
    assert code(store.read, bad, "stego") == "INVALID_REQUEST"
    assert code(store.write, bad, "stego", b"x") == "INVALID_REQUEST"
    assert code(store.exists, bad, "cover") == "INVALID_REQUEST"


def test_traversal_never_reads_outside(tmp_path):
    (tmp_path / "secret.png").write_bytes(b"secret")
    store = ArtifactStore(tmp_path / "art")
    store.write("a" * 32, "stego", b"ok")
    for attempt in ("../secret", "../secret.png", "..", "/etc/passwd", "a" * 32 + "/../../secret"):
        assert code(store.read, attempt, "stego") == "INVALID_REQUEST"
    assert store.read("a" * 32, "stego") == b"ok"


def test_file_names_and_roundtrip(store):
    aid = new_id()
    store.write(aid, "stego", b"S")
    store.write(aid, "cover", b"C")
    assert sorted(os.listdir(store.directory)) == sorted([f"{aid}.png", f"{aid}.cover.png"])
    assert store.read(aid, "stego") == b"S" and store.read(aid, "cover") == b"C"
    assert store.exists(aid, "stego")


def test_not_found(store):
    assert code(store.read, new_id(), "stego") == "ARTIFACT_NOT_FOUND"
    store.write(new_id(), "stego", b"x")
    assert code(store.read, new_id(), "cover") == "ARTIFACT_NOT_FOUND"


def test_no_overwrite(store):
    aid = new_id()
    store.write(aid, "stego", b"first")
    assert code(store.write, aid, "stego", b"second") == "IMAGE_WRITE_FAILED"
    assert store.read(aid, "stego") == b"first"
    assert not [n for n in os.listdir(store.directory) if n.endswith(".tmp")]


def test_atomic_write_leaves_no_partial_file(store, monkeypatch):
    aid = new_id()

    def boom(fd):
        raise OSError(5, "disk error")

    monkeypatch.setattr(artifacts.os, "fsync", boom)
    assert code(store.write, aid, "stego", b"data") == "IMAGE_WRITE_FAILED"
    assert os.listdir(store.directory) == []  # neither final nor tmp remain


def test_readers_never_see_partial_content(store):
    aid = new_id()
    blob = b"x" * 2_000_000
    seen = []
    stop = threading.Event()

    def reader():
        while not stop.is_set():
            try:
                seen.append(len(store.read(aid, "stego")))
            except StegoError:
                seen.append(None)

    t = threading.Thread(target=reader)
    t.start()
    store.write(aid, "stego", blob)
    stop.set()
    t.join()
    assert set(seen) <= {None, len(blob)}


def test_symlink_not_followed(store, tmp_path):
    os.makedirs(store.directory, exist_ok=True)
    (tmp_path / "target").write_bytes(b"x")
    aid = new_id()
    os.symlink(tmp_path / "target", os.path.join(store.directory, aid + ".png"))
    assert code(store.read, aid, "stego") == "ARTIFACT_NOT_FOUND"


def test_retention_default_keeps_all(tmp_path):
    store = ArtifactStore(tmp_path)
    ids = [new_id() for _ in range(8)]
    for i in ids:
        store.write(i, "stego", b"x")
        assert store.enforce_retention(keep_id=i) == []
    assert len(store.list_ids()) == 8


def test_retention_n_removes_oldest_both_files(tmp_path):
    store = ArtifactStore(tmp_path, retention_max=3)
    ids = []
    for k in range(6):
        i = new_id()
        ids.append(i)
        store.write(i, "cover", b"c")
        store.write(i, "stego", b"s")
        os.utime(os.path.join(store.directory, i + ".png"), ns=(k * 10**9, k * 10**9))
        os.utime(os.path.join(store.directory, i + ".cover.png"), ns=(k * 10**9, k * 10**9))
        store.enforce_retention(keep_id=i)
    assert store.list_ids() == ids[-3:]
    assert sorted(os.listdir(tmp_path)) == sorted([f"{i}{s}" for i in ids[-3:] for s in (".png", ".cover.png")])


def test_retention_never_deletes_keep_id_and_ignores_foreign_files(tmp_path):
    (tmp_path / "notes.txt").write_text("keep")
    store = ArtifactStore(tmp_path, retention_max=1)
    a, b = new_id(), new_id()
    store.write(a, "stego", b"1")
    os.utime(os.path.join(tmp_path, a + ".png"), ns=(5 * 10**9,) * 2)
    store.write(b, "stego", b"2")
    os.utime(os.path.join(tmp_path, b + ".png"), ns=(1 * 10**9,) * 2)  # b looks oldest
    assert store.enforce_retention(keep_id=b) == [a]
    assert store.list_ids() == [b] and (tmp_path / "notes.txt").exists()


def test_config_env(monkeypatch):
    from stego import config
    monkeypatch.delenv("IOD_STEGO_ARTIFACT_DIR", raising=False)
    monkeypatch.delenv("IOD_STEGO_RETENTION_MAX_ARTIFACTS", raising=False)
    assert config.artifact_dir().endswith(os.path.join("data", "stego-artifacts")) and config.retention_max() == 0
    monkeypatch.setenv("IOD_STEGO_RETENTION_MAX_ARTIFACTS", "7")
    assert config.retention_max() == 7
    for bad in ("x", "-4", ""):
        monkeypatch.setenv("IOD_STEGO_RETENTION_MAX_ARTIFACTS", bad)
        assert config.retention_max() == 0


def test_writable_probe(tmp_path):
    assert ArtifactStore(tmp_path / "does" / "not" / "exist").writable()
