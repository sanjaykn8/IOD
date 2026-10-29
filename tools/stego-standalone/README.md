# Local latent image generator

## Desktop application

Double-click **Latent Image.lnk** in this folder or the **Latent Image** desktop shortcut.
Enter your text and click **Create learned text vector** to inspect and save its embedding.
For images, click **Generate procedural image**, then **Save PNG**.
Use **Extract text from image** to recover, copy, or save hidden text.
Text encoding needs a model download on first use, then runs locally with cached weights.
Keep this project folder and its `.venv` folder together.


## Learned text vectors

The text-vector button uses the pretrained `BAAI/bge-small-en-v1.5` encoder
through FastEmbed/ONNX on your CPU. Its output is a normalized 384-dimensional
float32 text embedding. It is a learned representation, not a hash-derived vector.
The model is intended for English text and accepts up to 512 tokens including
special tokens. The application rejects longer input rather than silently omitting it.
Hashes can be encoded as text but have no recoverable underlying meaning.

Save as JSON to include the original text, model name, dimensions, and values;
save as NPY for numerical use or TXT for a readable list of values.
This embedding is not a Stable Diffusion image latent and does not reconstruct
the exact input. The image feature still uses the separate procedural method below.
Model details: https://huggingface.co/BAAI/bge-small-en-v1.5

## Procedural images

Converts a text string or hash into a deterministic 256-dimensional hash-derived vector,
decodes that vector into an abstract black and white image, and embeds the exact original
UTF-8 input in the parity of pairs of black and white pixels, distributed across the image.

This is a procedural image generator, not a trained AI model: text meaning does
not determine depicted objects. Hashes are treated as literal strings, not reversed.
The vector controls the generated patterns and colors. Exact recovery comes from
the separately embedded payload, not from inverting the vector.

## Setup (Windows PowerShell)

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

## Generate and extract

```powershell
.\.venv\Scripts\python.exe latent_image.py generate --text "Hello world" --output output.png --latent-output latent.npy
.\.venv\Scripts\python.exe latent_image.py extract output.png
.\.venv\Scripts\python.exe latent_image.py extract output.png --output recovered.txt
```

For multiline text or characters that are awkward to quote in a shell:

```powershell
.\.venv\Scripts\python.exe latent_image.py generate --input-file input.txt --output output.png
```

Use `--size 1024` for more capacity. The default 512 × 512 image holds up to
16,342 UTF-8 bytes. PNG must be preserved without resizing, cropping, filtering,
or JPEG conversion. Such changes can destroy the payload. Share the original
file rather than a screenshot or a recompressed social-media image.

Hidden data is not encrypted. Anyone with the extraction algorithm can recover
it. SHA-256 detects accidental payload damage; it does not authenticate the sender.
The optional vector file is not needed for extraction. Same input and generation
settings produce the same pixels within the same software environment.

Earlier RGB images remain extractable. New images use only black and white pixels (1-bit PNG). The hidden payload may subtly change the pattern; this is not designed to resist steganalysis.

## Integration status

This folder is the original standalone tool; parts of it are now shared with the
IOD simulator's Python service (`python-service/src/stego/`).

- **Shared:** the procedural generator (`encode_text`, `decode_latent`) and the legacy
  text embed/extract (`embed`, `extract`, `MAGIC`, `BW_MAGIC`, `HEADER`) now live in
  `python-service/src/stego/procedural.py`, with new byte-oriented helpers
  (`embed_bytes`, `extract_bytes`). `latent_image.py` is a thin wrapper that imports them
  (it adds `../../python-service/src` to `sys.path`) and keeps the `generate` / `extract`
  CLI and the legacy file format unchanged. The procedural B/W image is also the
  fallback cover of the service when no webcam is available.
- **Not shared (stays standalone):** `app.py` (Tkinter GUI, unchanged) and
  `text_vector.py` (FastEmbed text embeddings). Neither is a dependency of the service.
- The service's transport (bootstrap + five algorithms) is a different, independent format
  from the legacy `LIMG01`/`LIMG02` payload used here; the two are not interchangeable.
- Tests: `python -m unittest` in this folder (the `test_text_vector` tests need `fastembed`
  and a model download, see `requirements.txt`).
