"""Planner (allocation + per-patch selection + refinement) and codec (embed / extract without re-segmentation)."""
import numpy as np
import pytest

from stego import codec, images
from stego.algorithms import BY_ID
from stego.config import Limits
from stego.errors import StegoError
from stego.patch import manifest as M, planner, segment as S
from stego_helpers import bw_cover, mixed_cover, natural_cover, payload

LIM = Limits()
COVERS = {
    "mixed_rgb": lambda: mixed_cover(),
    "mixed_gray": lambda: mixed_cover(160, 200, 1),
    "natural_rgb": lambda: natural_cover(120, 160),
    "natural_gray_odd": lambda: natural_cover(101, 131, channels=1),
    "bw": lambda: bw_cover(128, 128),
}


def frame_for(pl, wire):
    """Structure of Frame v2 with a dummy 32-byte tag (the real tag is computed in Rust; Python never checks it)."""
    assert pl.parsed.payload_len == len(wire) + 32
    return M.frame_header(len(pl.manifest), len(wire)) + pl.manifest + wire + bytes(range(32))


@pytest.mark.parametrize("name", list(COVERS))
@pytest.mark.parametrize("wire_len", [33, 150, 420])
def test_plan_embed_png_extract_exact(name, wire_len):
    cov = COVERS[name]()
    pl = planner.plan(cov, wire_len + 32)
    wire = payload(wire_len, seed=wire_len)
    frame = frame_for(pl, wire)
    stego, man, per = codec.embed_frame(cov, frame, LIM)
    back, _ = images.decode_png(images.encode_png(stego), LIM)
    got, man2, pre, ext = codec.extract_frame(back, LIM)
    assert got == frame and pre.frame_len == len(frame) and pre.manifest_len == len(pl.manifest)
    assert man2.patches == man.patches and np.array_equal(man2.cell_labels, pl.seg.cell_labels)
    assert [e["patch_id"] for e in ext] == [p["patch_id"] for p in per if p["used"]]
    # the cover itself is unchanged and the stego differs
    assert not np.array_equal(stego, cov)


def test_chunks_are_sequential_contiguous_and_cover_the_payload_once():
    cov = mixed_cover()
    pl = planner.plan(cov, 600)
    used = [(i, e) for i, e in enumerate(pl.parsed.patches) if e.alg_id]
    assert len(used) >= 2
    off = 0
    for _, e in used:                      # ascending patch id
        assert e.offset == off and e.length >= 1
        off += e.length
    assert off == 600 == pl.parsed.payload_len
    d = pl.diagnostics
    assert d["used_patches"] == len(used) and sum(d["algorithms_used"].values()) == len(used)
    for p in d["patches"]:
        if p["used"]:
            e = pl.parsed.patches[p["patch_id"]]
            assert (p["payload_offset"], p["payload_length"], p["alg_id"], p["param"]) == (e.offset, e.length, e.alg_id, e.param)
            assert p["measured_capacity_bytes"] >= p["payload_length"] and p["dry_run"]["ok"]
            r = p["retrieval"]
            assert r["selected"] == p["selected"] == BY_ID[e.alg_id].name and r["ranking"][0] == p["selected"]
            assert p["variant"] == BY_ID[e.alg_id].variant
        else:
            assert p["selected"] is None and p["payload_length"] == 0
        assert p["features"]["pixels"] > 0 and "bbox" in p["features"]


def test_plan_is_deterministic_and_has_no_priority_input():
    cov = mixed_cover()
    a, b = planner.plan(cov, 300), planner.plan(cov.copy(), 300)
    assert a.manifest == b.manifest
    import inspect
    assert "priority" not in inspect.signature(planner.plan).parameters
    assert "priority" not in str(a.diagnostics).lower()


def test_mixed_cover_uses_more_than_one_algorithm():
    pl = planner.plan(mixed_cover(256, 320), 900)
    assert len(pl.diagnostics["algorithms_used"]) >= 2, pl.diagnostics["algorithms_used"]


def test_bootstrap_rows_are_reserved_from_every_patch():
    cov = mixed_cover()
    pl = planner.plan(cov, 500)
    wire = payload(468)
    frame = frame_for(pl, wire)
    stego, man, _ = codec.embed_frame(cov, frame, LIM)
    rr = man.reserved_rows
    assert rr >= 1 and rr == M.reserved_rows_for(len(pl.manifest), cov.shape[1], 3)
    d = stego.astype(int) - cov.astype(int)
    assert np.abs(d[:rr]).max() <= 1                      # only carrier LSBs in the reserved rows
    carrier = M.carrier_bits(len(pl.manifest))
    assert not np.any(d.reshape(-1)[carrier:rr * cov.shape[1] * 3])   # unused tail of the reserved rows is untouched
    eff = M.effective_masks(man)
    assert np.all(eff[:rr] == 255)
    for f in pl.diagnostics["patches"]:
        assert f["features"]["usable_pixels"] <= f["features"]["pixels"]


def test_capacity_shortfall_triggers_bounded_refinement_then_rejection():
    cov = natural_cover(64, 64, channels=1)
    with pytest.raises(StegoError) as e:
        planner.plan(cov, 60000)
    assert e.value.code == "PATCH_CAPACITY_INSUFFICIENT"
    att = e.value.details["attempts"]
    cfg = S.SegConfig()
    assert [a["level"] for a in att] == list(range(cfg.max_refine_levels + 1))
    assert all(a["outcome"] != "OK" for a in att)
    # min_level beyond the limit is refused
    with pytest.raises(StegoError):
        planner.plan(cov, 100, cfg, cfg.max_refine_levels + 1)


def test_refinement_can_rescue_a_plan_and_records_the_attempts(monkeypatch):
    cov = mixed_cover()
    real = planner._allocate
    calls = {"n": 0}

    def flaky(feats, caps, total, target):
        calls["n"] += 1
        if calls["n"] == 1:
            return None, []
        return real(feats, caps, total, target)
    monkeypatch.setattr(planner, "_allocate", flaky)
    pl = planner.plan(cov, 200)
    d = pl.diagnostics
    assert d["refinement_level"] == 1 and [a["outcome"] for a in d["attempts"]] == ["CAPACITY_INSUFFICIENT", "OK"]
    assert d["attempts"][1]["regions"] <= d["attempts"][0]["regions"]


def test_no_silent_fallback_when_the_selected_algorithm_fails(monkeypatch):
    """If the KB's choice fails its dry run, the plan is refined/rejected; it never swaps in another algorithm."""
    cov = natural_cover(96, 128, channels=1)
    from stego.algorithms import BY_NAME
    first = planner.plan(cov, 120)
    names = set(first.diagnostics["algorithms_used"])

    def broken(self, ctx, region, out, payload_, param=0):
        raise StegoError("ENCODE_VERIFY_FAILED", "forced failure")
    for n in names:
        monkeypatch.setattr(type(BY_NAME[n]), "embed", broken)
    try:
        pl = planner.plan(cov, 120)
    except StegoError as exc:
        assert exc.code == "NO_ELIGIBLE_ALGORITHM"
        assert all(a["outcome"].startswith("DRY_RUN_FAILED") or a["outcome"] != "OK" for a in exc.details["attempts"])
    else:   # a coarser level legitimately selected different (working) algorithms via the KB
        assert not (set(pl.diagnostics["algorithms_used"]) & names)
        assert pl.diagnostics["refinement_level"] >= 1
        assert pl.diagnostics["attempts"][0]["outcome"].startswith("DRY_RUN_FAILED")


def test_invalid_plan_arguments():
    cov = natural_cover(64, 64)
    for bad in (32, 0, -5, True, "100", 1.5):
        with pytest.raises(StegoError):
            planner.plan(cov, bad)
    for tc in (0, 7, 10 ** 6):
        with pytest.raises(StegoError):
            planner.plan(cov, 100, target_chunk=tc)


# ------------------------------------------------------------------ codec strictness
def _plan_and_frame(cov=None, n=200):
    cov = mixed_cover() if cov is None else cov
    pl = planner.plan(cov, n + 32)
    return cov, pl, frame_for(pl, payload(n))


def test_embed_rejects_a_manifest_for_another_image():
    cov, pl, frame = _plan_and_frame()
    for other in (natural_cover(96, 128), mixed_cover(192, 256, 1)):
        with pytest.raises(StegoError) as e:
            codec.embed_frame(other, frame, LIM)
        assert e.value.code == "MANIFEST_INVALID"


def test_embed_fails_closed_when_a_patch_cannot_carry_its_chunk():
    cov, pl, frame = _plan_and_frame()
    flat = np.full_like(cov, 128)      # same geometry, but e.g. edge/PVD capacities differ; force a mismatch
    m = pl.parsed
    ents = list(m.patches)
    i = next(k for k, e in enumerate(ents) if e.alg_id)
    ents[i] = M.PatchEntry(7, 16, ents[i].offset, ents[i].length)      # dct_svd: 1 bit per block -> far too small
    bad = M.pack(M.Manifest(m.channels, m.width, m.height, m.cell, m.reserved_rows, m.payload_len, tuple(ents), m.cell_labels))
    frame2 = M.frame_header(len(bad), m.payload_len - 32) + bad + frame[16 + len(pl.manifest):]
    with pytest.raises(StegoError) as e:
        codec.embed_frame(cov, frame2, LIM)
    assert e.value.code == "PATCH_EMBED_FAILED" and e.value.details["algorithm"] == "dct_svd"
    del flat


def test_extract_uses_the_manifest_map_not_a_new_segmentation(monkeypatch):
    cov, pl, frame = _plan_and_frame()
    stego, _, _ = codec.embed_frame(cov, frame, LIM)

    def boom(*a, **k):
        raise AssertionError("receiver re-segmented the image")
    monkeypatch.setattr(S, "segment", boom)
    got, _, _, _ = codec.extract_frame(stego, LIM)
    assert got == frame


def test_extract_fails_closed_on_tampered_carrier_or_missing_bootstrap():
    cov, pl, frame = _plan_and_frame()
    stego, man, _ = codec.embed_frame(cov, frame, LIM)
    with pytest.raises(StegoError) as e:
        codec.extract_frame(cov, LIM)                       # plain cover: no bootstrap
    assert e.value.code in ("BOOTSTRAP_MISSING", "BOOTSTRAP_CORRUPT", "UNSUPPORTED_VERSION")
    for bit in (3, 40, 70, 8 * 16 + 5, 8 * 16 + 8 * 30, 8 * (16 + len(pl.manifest)) + 3):
        t = stego.copy()
        t.reshape(-1)[bit] ^= 1
        with pytest.raises(StegoError):
            codec.extract_frame(t, LIM)
    with pytest.raises(StegoError):
        codec.extract_frame(stego[: stego.shape[0] // 2], LIM)   # cropped: manifest dims mismatch


def test_payload_tamper_changes_the_recovered_frame_so_the_mac_will_fail():
    """Python cannot authenticate: a flipped payload sample yields a DIFFERENT frame (Rust then rejects it)."""
    cov, pl, frame = _plan_and_frame()
    stego, man, per = codec.embed_frame(cov, frame, LIM)
    eff = M.effective_masks(man)
    used = [p for p in per if p["used"]]
    hits = 0
    for p in used[:4]:
        ys, xs = np.nonzero(eff == p["patch_id"])
        t = stego.copy()
        t[ys[: ys.size // 2], xs[: ys.size // 2]] ^= 0xFF
        try:
            got = codec.extract_frame(t, LIM)[0]
        except StegoError:
            hits += 1
            continue
        hits += got != frame
    assert hits == len(used[:4])


def test_frame_limits_are_enforced():
    cov, pl, frame = _plan_and_frame()
    small = Limits(max_frame_bytes=len(frame) - 1)
    with pytest.raises(StegoError) as e:
        codec.embed_frame(cov, frame, small)
    assert e.value.code == "FRAME_TOO_LARGE"
    stego, _, _ = codec.embed_frame(cov, frame, LIM)
    with pytest.raises(StegoError) as e:
        codec.extract_frame(stego, small)
    assert e.value.code in ("FRAME_LENGTH_INVALID", "FRAME_TOO_LARGE")
