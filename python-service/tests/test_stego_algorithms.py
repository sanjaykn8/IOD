"""Round-trip, boundary, and corruption tests for all 5 steganography
algorithms. Run against REAL generated test images (no mocking of the
image/crypto layer) -- see `fixtures.py` for how the images are built.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import numpy as np
import pytest

from stego.registry import ALGORITHMS, all_algorithm_ids
from stego.base import StegoCapacityError, StegoExtractError


def make_test_image(h=96, w=96, seed=0, kind="natural"):
    rng = np.random.default_rng(seed)
    if kind == "natural":
        # Smooth gradient plus moderate noise plus a moderately dark and
        # moderately bright patch -- realistic photographic dynamic
        # range, exercising both the smooth and high-detail branches of
        # adaptive_lsb, without the fully-saturated 0/255 extremes that
        # are a documented, separately-tested boundary case (see
        # `test_saturated_regions_fail_closed_not_corrupt` below).
        yy, xx = np.meshgrid(np.linspace(0, 255, h), np.linspace(0, 255, w), indexing="ij")
        base = (0.5 * yy + 0.5 * xx)
        noise = rng.normal(0, 8, size=(h, w))
        img = np.clip(base + noise, 0, 255)
        img[: h // 4, : w // 4] = 20  # a dark-but-not-saturated block
        img[h // 2 :, w // 2 :] = 235  # a bright-but-not-saturated block
        rgb = np.stack([img, np.roll(img, 5, axis=0), np.roll(img, 5, axis=1)], axis=2)
        return np.clip(rgb, 0, 255).astype(np.uint8)
    elif kind == "flat":
        return np.full((h, w, 3), 128, dtype=np.uint8)
    elif kind == "saturated":
        # Deliberately adversarial: large fully-saturated 0 and 255
        # blocks, which leave QIM-style transform embedders (DCT/DWT/SVD)
        # no headroom to perturb a coefficient without clipping. Used
        # only by the dedicated boundary test -- every algorithm must
        # either round-trip correctly here or fail closed
        # (`StegoCapacityError`), never silently corrupt.
        img = np.zeros((h, w), dtype=np.float64)
        img[: h // 2, :] = 0
        img[h // 2 :, :] = 255
        rgb = np.stack([img, img, img], axis=2)
        return rgb.astype(np.uint8)
    elif kind == "random":
        return rng.integers(0, 256, size=(h, w, 3), dtype=np.uint8)
    raise ValueError(kind)


ALL_IDS = all_algorithm_ids()


@pytest.mark.parametrize("algo_id", ALL_IDS)
def test_round_trip_small_payload(algo_id):
    algo = ALGORITHMS[algo_id]
    img = make_test_image(kind="natural")
    payload = b"IOD-R1-ENROLL-TEST-PAYLOAD-0123456789"
    cap = algo.capacity_bytes(img)
    assert cap >= len(payload), f"{algo_id}: unexpectedly low capacity {cap} on 64x64 test image"
    result = algo.embed(img, payload)
    recovered = algo.extract(result.stego_pixels, len(payload), result.algorithm_params)
    assert recovered == payload, f"{algo_id}: round trip corrupted payload"


@pytest.mark.parametrize("algo_id", ALL_IDS)
def test_round_trip_empty_payload(algo_id):
    algo = ALGORITHMS[algo_id]
    img = make_test_image(kind="natural")
    result = algo.embed(img, b"")
    recovered = algo.extract(result.stego_pixels, 0, result.algorithm_params)
    assert recovered == b""


@pytest.mark.parametrize("algo_id", ALL_IDS)
def test_round_trip_random_image(algo_id):
    algo = ALGORITHMS[algo_id]
    img = make_test_image(kind="random", seed=42)
    payload = bytes(range(64)) * 2
    cap = algo.capacity_bytes(img)
    if len(payload) > cap:
        payload = payload[:cap]
    if len(payload) == 0:
        pytest.skip(f"{algo_id}: zero capacity on this random image size")
    result = algo.embed(img, payload)
    recovered = algo.extract(result.stego_pixels, len(payload), result.algorithm_params)
    assert recovered == payload


@pytest.mark.parametrize("algo_id", ALL_IDS)
def test_capacity_exceeded_raises(algo_id):
    algo = ALGORITHMS[algo_id]
    img = make_test_image(h=16, w=16, kind="flat")
    cap = algo.capacity_bytes(img)
    too_big = bytes(cap + 1024)
    with pytest.raises(StegoCapacityError):
        algo.embed(img, too_big)


@pytest.mark.parametrize("algo_id", ALL_IDS)
def test_corrupted_stego_image_detected_or_wrong_output(algo_id):
    """A corrupted/undersized stego image must not silently succeed with
    wrong-length output: either it raises, or the recovered bytes differ
    from the original payload (never a silent false-positive match)."""
    algo = ALGORITHMS[algo_id]
    img = make_test_image(kind="natural")
    payload = b"some registration payload bytes 1234"
    result = algo.embed(img, payload)
    corrupted = result.stego_pixels.copy().astype(np.int32)
    # Random, non-symmetric per-pixel noise. (A clean global inversion
    # like `pixels ^ 0xFF` turns out to be a SYMMETRY of every parity-
    # based scheme here -- e.g. DCT/SVD coefficients negate exactly and
    # PVD pair differences negate exactly, both of which preserve the
    # embedded bit's parity -- so it is not actually destructive and
    # would be the wrong corruption to test with.)
    rng = np.random.default_rng(123)
    noise = rng.integers(-40, 41, size=corrupted.shape)
    corrupted = np.clip(corrupted + noise, 0, 255).astype(np.uint8)
    try:
        recovered = algo.extract(corrupted, len(payload), result.algorithm_params)
        assert recovered != payload
    except StegoExtractError:
        pass  # also an acceptable, honest failure mode


@pytest.mark.parametrize("algo_id", ALL_IDS)
def test_grayscale_like_image_rgb_with_equal_channels(algo_id):
    """RGB image where R==G==B (a grayscale image stored as RGB) --
    exercises channel-independence of the per-channel algorithms."""
    algo = ALGORITHMS[algo_id]
    base = make_test_image(kind="natural")[:, :, 0]
    img = np.stack([base, base, base], axis=2)
    payload = b"gray-equivalent-payload"
    cap = algo.capacity_bytes(img)
    assert cap >= len(payload)
    result = algo.embed(img, payload)
    recovered = algo.extract(result.stego_pixels, len(payload), result.algorithm_params)
    assert recovered == payload


@pytest.mark.parametrize("algo_id", ALL_IDS)
def test_saturated_regions_fail_closed_not_corrupt(algo_id):
    """Adversarial fully-saturated (0/255) image: every algorithm must
    either embed+extract correctly, or raise StegoCapacityError -- a
    silent round-trip mismatch is the one outcome never acceptable."""
    algo = ALGORITHMS[algo_id]
    img = make_test_image(kind="saturated")
    payload = b"saturated-boundary-case-payload"
    cap = algo.capacity_bytes(img)
    if len(payload) > cap:
        pytest.skip(f"{algo_id}: payload exceeds capacity on this adversarial image, not the case under test")
    try:
        result = algo.embed(img, payload)
    except StegoCapacityError:
        return  # honest, documented failure mode -- acceptable
    recovered = algo.extract(result.stego_pixels, len(payload), result.algorithm_params)
    assert recovered == payload, f"{algo_id}: silently corrupted payload on a saturated image instead of failing closed"


@pytest.mark.parametrize("algo_id", ALL_IDS)
def test_deterministic_given_same_inputs(algo_id):
    algo = ALGORITHMS[algo_id]
    img = make_test_image(kind="natural")
    payload = b"determinism-check-payload"
    r1 = algo.embed(img, payload)
    r2 = algo.embed(img, payload)
    assert np.array_equal(r1.stego_pixels, r2.stego_pixels), f"{algo_id}: embed is not deterministic"
