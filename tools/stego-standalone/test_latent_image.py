import tempfile
import unittest
from pathlib import Path

import numpy as np
from PIL import Image

from latent_image import encode_text, decode_latent, embed, extract, HEADER


class RoundTripTests(unittest.TestCase):
    def test_exact_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "image.png"
            for text in ["", "a3f0" * 16, "Hello\r\nWorld\x00", "नमस्ते 🌍"]:
                with self.subTest(text=text):
                    embed(decode_latent(encode_text(text), 64), text).save(path)
                    self.assertEqual(extract(path), text)
                    with Image.open(path) as saved:
                        self.assertEqual(saved.mode, "1")

    def test_legacy_color_image(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "legacy.png"
            embed(Image.new("RGB", (32, 32), "gray"), "legacy payload").save(path)
            self.assertEqual(extract(path), "legacy payload")

    def test_repeatability_and_input_sensitivity(self):
        first = np.array(decode_latent(encode_text("first"), 32))
        self.assertTrue(np.array_equal(first, np.array(decode_latent(encode_text("first"), 32))))
        self.assertFalse(np.array_equal(first, np.array(decode_latent(encode_text("second"), 32))))

    def test_capacity_and_corruption(self):
        base = decode_latent(encode_text("test"), 32)
        capacity = 32 * 32 // 16 - HEADER.size
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "image.png"
            embed(base, "x" * capacity).save(path)
            self.assertEqual(extract(path), "x" * capacity)
            with self.assertRaises(ValueError):
                embed(base, "x" * (capacity + 1))
            pixels = np.array(embed(base, "test"))
            pairs = np.random.default_rng(2026).permutation(pixels.size // 2) * 2
            pixels.reshape(-1)[pairs[HEADER.size * 8] + 1] ^= True
            Image.fromarray(pixels).save(path)
            with self.assertRaisesRegex(ValueError, "checksum"):
                extract(path)
            Image.new("RGB", (32, 32)).save(path)
            with self.assertRaisesRegex(ValueError, "No supported"):
                extract(path)


if __name__ == "__main__":
    unittest.main()
