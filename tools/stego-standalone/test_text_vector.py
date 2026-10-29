import json
import tempfile
import unittest
from pathlib import Path
import numpy as np
from text_vector import encode_semantic_text, save_vector


class LearnedVectorTests(unittest.TestCase):
    def test_semantics_and_exports(self):
        a = encode_semantic_text("A dog is running in the park.")
        b = encode_semantic_text("A puppy runs outdoors in a park.")
        c = encode_semantic_text("The database server uses SQL transactions.")
        self.assertEqual(a.shape, (384,))
        self.assertEqual(a.dtype, np.float32)
        self.assertAlmostEqual(float(np.linalg.norm(a)), 1, places=5)
        self.assertGreater(float(a @ b), float(a @ c))
        np.testing.assert_allclose(a, encode_semantic_text("A dog is running in the park."), atol=1e-6)
        with tempfile.TemporaryDirectory() as folder:
            for suffix in [".npy", ".txt", ".json"]:
                path = Path(folder) / ("vector" + suffix)
                save_vector(path, "A dog is running in the park.", a)
                if suffix == ".npy":
                    restored = np.load(path, allow_pickle=False)
                elif suffix == ".txt":
                    restored = np.loadtxt(path)
                else:
                    restored = json.loads(path.read_text(encoding="utf-8"))["vector"]
                np.testing.assert_allclose(a, restored, atol=1e-8)

    def test_empty_and_long_input(self):
        with self.assertRaises(ValueError):
            encode_semantic_text("   ")
        with self.assertRaisesRegex(ValueError, "512"):
            encode_semantic_text("word " * 600)


if __name__ == "__main__":
    unittest.main()
