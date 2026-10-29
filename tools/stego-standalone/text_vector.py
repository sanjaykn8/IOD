"""Learned sentence embeddings, separate from the procedural image generator."""
import json
from pathlib import Path
import numpy as np

MODEL_NAME = "BAAI/bge-small-en-v1.5"
CACHE_DIR = Path(__file__).resolve().parent / "models"
MODEL_DIR = CACHE_DIR / "bge-small-en-v1.5"
MODEL_REVISION = "aa8f8b060edb00e03bfdd08813a2949946c8ba55"
_model = None
_length_tokenizer = None


def get_model():
    global _model, _length_tokenizer
    if _model is None:
        from fastembed import TextEmbedding
        options = {"specific_model_path": str(MODEL_DIR)} if (MODEL_DIR / "READY").exists() else {}
        _model = TextEmbedding(model_name=MODEL_NAME, cache_dir=str(CACHE_DIR), threads=4, **options)
        from tokenizers import Tokenizer
        _length_tokenizer = Tokenizer.from_str(_model.model.tokenizer.to_str())
        _length_tokenizer.no_truncation()
        _length_tokenizer.no_padding()
    return _model


def encode_semantic_text(text):
    if not text.strip():
        raise ValueError("Enter some text first.")
    model = get_model()
    count = len(_length_tokenizer.encode(text).ids)
    if count > 512:
        raise ValueError(f"Your text contains {count} tokens. This model supports 512 including special tokens; shorten the text.")
    vector = np.asarray(next(model.embed([text])), dtype=np.float32)
    if vector.shape != (384,) or not np.isfinite(vector).all():
        raise ValueError("The encoder returned an invalid embedding.")
    return vector


def save_vector(path, text, vector):
    path = Path(path)
    if path.suffix.lower() == ".npy":
        np.save(path, vector, allow_pickle=False)
    elif path.suffix.lower() == ".txt":
        np.savetxt(path, vector, fmt="%.9g", header=f"Learned text embedding | {MODEL_NAME} | 384 float32 values")
    elif path.suffix.lower() == ".json":
        path.write_text(json.dumps({
            "representation": "learned_text_embedding",
            "model": MODEL_NAME,
            "runtime": "FastEmbed ONNX (quantized)",
            "model_revision": MODEL_REVISION if (MODEL_DIR / "READY").exists() else "FastEmbed cached version",
            "dimensions": 384,
            "dtype": "float32",
            "text": text,
            "vector": vector.tolist(),
        }, ensure_ascii=False, indent=2), encoding="utf-8")
    else:
        raise ValueError("Choose .json, .npy, or .txt for your vector.")
