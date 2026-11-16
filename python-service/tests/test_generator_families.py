"""Procedural cover families: validity, determinism, freshness, diversity, no payload input."""
import inspect
import os

import numpy as np
import pytest

from stego.errors import StegoError
from stego.generator import GENERATOR_VERSION, families as F, select as S

SEED = bytes(range(16))


@pytest.mark.parametrize("family", F.FAMILIES)
@pytest.mark.parametrize("mode,size", [("RGB", (320, 240)), ("L", (320, 240)), ("RGB", (96, 96)), ("RGB", (200, 136))])
def test_every_family_returns_a_valid_image(family, mode, size):
    w, h = size
    arr, info = F.generate(SEED, w, h, mode, family)
    assert arr.dtype == np.uint8 and arr.flags["C_CONTIGUOUS"]
    assert arr.shape == ((h, w, 3) if mode == "RGB" else (h, w))
    assert 0 <= int(arr.min()) and int(arr.max()) <= 255
    # the tone mapping leaves head-room: no clipping at either end
    assert int(arr.min()) >= 3 and int(arr.max()) <= 252
    assert info["family"] == family and info["generator_version"] == GENERATOR_VERSION == "procgen-1"
    assert (info["width"], info["height"], info["mode"], info["channels"]) == (w, h, mode, 3 if mode == "RGB" else 1)
    assert len(info["seed_fingerprint"]) == 16 and info["generate_ms"] > 0
    assert "seed" not in info and SEED.hex() not in str(info)


@pytest.mark.parametrize("family", F.FAMILIES)
def test_same_seed_and_config_is_byte_identical_and_seed_changes_everything(family):
    a, ia = F.generate(SEED, 160, 120, "RGB", family)
    b, ib = F.generate(bytes(SEED), 160, 120, "RGB", family)
    assert a.tobytes() == b.tobytes()
    ia.pop("generate_ms"), ib.pop("generate_ms")
    assert ia == ib
    c, ic = F.generate(SEED[::-1], 160, 120, "RGB", family)
    assert not np.array_equal(a, c) and ic["seed_fingerprint"] != ia["seed_fingerprint"]
    # size, mode and detail bias are part of the function
    assert F.generate(SEED, 168, 120, "RGB", family)[0].shape != a.shape
    assert not np.array_equal(F.generate(SEED, 160, 120, "RGB", family, detail_bias=0.9)[0], a)


def test_family_choice_is_part_of_the_seed_and_respects_enabled_families():
    fams = {F.generate(bytes([i]) * 16, 96, 96)[1]["family"] for i in range(40)}
    assert fams == set(F.FAMILIES), "all families are reachable from random seeds"
    for i in range(10):
        assert F.generate(bytes([i]) * 16, 96, 96, enabled=("strata", "cells"))[1]["family"] in ("strata", "cells")
    with pytest.raises(StegoError) as e:
        F.generate(SEED, 96, 96, family="terrain", enabled=("cells",))
    assert e.value.code == "GENERATOR_CONFIG_INVALID"
    for bad in (dict(mode="CMYK"), dict(enabled=("fractal",)), dict(enabled=())):
        with pytest.raises(StegoError):
            F.generate(SEED, 96, 96, **bad)
    with pytest.raises(StegoError) as e:
        F.generate(b"abc", 96, 96)
    assert e.value.code == "COVER_GENERATION_FAILED"


def test_images_are_not_binary_flat_noise_or_all_alike():
    stats = []
    for i, fam in enumerate(F.FAMILIES * 3):
        arr, _ = F.generate(bytes([i + 1]) * 16, 240, 176, "RGB", fam)
        y = arr.astype(np.float64) @ [0.299, 0.587, 0.114]
        assert len(np.unique(arr)) > 100, "not binary / posterised"
        assert y.std() > 12, "not flat"
        c = np.corrcoef(y[:, :-1].ravel(), y[:, 1:].ravel())[0, 1]
        assert c > 0.9, "spatially correlated, i.e. not white noise"
        stats.append((round(y.mean()), round(y.std()), tuple(np.round(arr.reshape(-1, 3).mean(0)).astype(int))))
    assert len(set(stats)) == len(stats), "texture statistics differ between covers"
    hues = {int(np.argmax(s[2])) for s in stats}
    assert len(hues) >= 2, "palettes are not one fixed template"


def test_no_tiling_inside_one_image():
    arr, _ = F.generate(SEED, 320, 240, "RGB", "terrain")
    q = arr[:120, :160].astype(int)
    for other in (arr[120:, :160], arr[:120, 160:], arr[120:, 160:]):
        assert np.abs(q - other.astype(int)).mean() > 4


def test_production_seeds_are_fresh_os_random(monkeypatch):
    monkeypatch.delenv("IOD_STEGO_GENERATOR_TEST_SEED", raising=False)
    calls = []
    real = os.urandom
    monkeypatch.setattr(os, "urandom", lambda n: (calls.append(n), real(n))[1])
    seeds = [S.fresh_seed() for _ in range(50)]
    assert calls == [F.SEED_BYTES] * 50 and len(set(seeds)) == 50 and S.seeding_mode() == "os-random"


def test_test_seed_hook_is_process_level_and_deterministic(monkeypatch):
    monkeypatch.setenv("IOD_STEGO_GENERATOR_TEST_SEED", "fixture-A")
    monkeypatch.setattr(S, "_test_counter", [0])
    a = [S.fresh_seed() for _ in range(3)]
    monkeypatch.setattr(S, "_test_counter", [0])
    assert [S.fresh_seed() for _ in range(3)] == a and len(set(a)) == 3
    assert S.seeding_mode() == "test-fixed"


def test_the_generator_has_no_payload_parameter():
    """Payload-aware selection passes a LENGTH to the selector; the image function never sees payload data."""
    params = set(inspect.signature(F.generate).parameters)
    assert params == {"seed", "width", "height", "mode", "family", "enabled", "detail_bias"}
    assert "payload" not in "".join(inspect.signature(S.select_cover).parameters).replace("payload_bytes", "")
    src = inspect.getsource(F)
    for word in ("payload", "plaintext", "ciphertext", "frame_b64"):
        assert word not in src.replace("payload size", "")


def test_seed_fingerprint_is_one_way_label():
    fp = F.seed_fingerprint(SEED)
    assert fp == F.seed_fingerprint(SEED) and fp != F.seed_fingerprint(SEED[::-1]) and SEED.hex()[:8] not in fp


def test_lattice_safety_bound(monkeypatch):
    monkeypatch.setattr(F, "MAX_LATTICE_CELLS", 10)
    with pytest.raises(StegoError) as e:
        F.generate(SEED, 96, 96, family="terrain")
    assert e.value.code == "COVER_GENERATION_FAILED"
