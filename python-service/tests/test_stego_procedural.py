import numpy as np
import pytest
from PIL import Image

from stego import procedural as p


def test_generator_deterministic_and_bw():
    a = np.array(p.decode_latent(p.encode_text("seed"), 64))
    assert np.array_equal(a, np.array(p.decode_latent(p.encode_text("seed"), 64)))
    assert p.decode_latent(p.encode_text("seed"), 64).mode == "1"
    assert p.encode_text("x").shape == (256,)


@pytest.mark.parametrize("data", [b"", b"\xff\xfe\x00binary", "नमस्ते".encode()])
@pytest.mark.parametrize("mode", ["1", "RGB"])
def test_bytes_roundtrip(tmp_path, data, mode):
    base = p.decode_latent(p.encode_text("t"), 64) if mode == "1" else Image.new("RGB", (64, 64), "gray")
    path = tmp_path / "i.png"
    p.embed_bytes(base, data).save(path)
    assert p.extract_bytes(path) == data


def test_text_wrappers(tmp_path):
    path = tmp_path / "i.png"
    p.embed(p.decode_latent(p.encode_text("t"), 64), "héllo").save(path)
    assert p.extract(path) == "héllo"
    p.embed_bytes(p.decode_latent(p.encode_text("t"), 64), b"\xff\xfe").save(path)
    with pytest.raises(ValueError):
        p.extract(path)  # non-UTF-8 -> ValueError (UnicodeDecodeError), as before
    with pytest.raises(ValueError, match="Input too large"):
        p.embed_bytes(Image.new("RGB", (32, 32)), b"x" * 5000)
