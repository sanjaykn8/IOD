"""Local desktop interface for latent images."""
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
import queue
import threading
import numpy as np
from PIL import Image, ImageTk
from latent_image import encode_text, decode_latent, embed, extract, HEADER
from text_vector import encode_semantic_text, save_vector, MODEL_NAME


class App:
    def __init__(self, root):
        self.root = root
        self.image = None
        root.title("Latent Image — Black & White")
        root.geometry("1000x800")
        root.minsize(780, 620)
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TButton", padding=9)
        outer = ttk.Frame(root, padding=20)
        outer.pack(fill="both", expand=True)
        ttk.Label(outer, text="Text vectors & black-and-white images", font=("Segoe UI", 19, "bold")).pack(anchor="w")
        ttk.Label(outer, text="Create a learned text embedding, or a procedural image with hidden text.").pack(anchor="w", pady=(6, 16))
        columns = ttk.Frame(outer)
        columns.pack(fill="both", expand=True)
        left = ttk.Frame(columns)
        left.pack(side="left", fill="both", expand=True, padx=(0, 20))
        ttk.Label(left, text="Your text or hash", font=("Segoe UI", 11, "bold")).pack(anchor="w")
        self.input = tk.Text(left, height=10, width=36, wrap="word", font=("Segoe UI", 11), undo=True)
        self.input.pack(fill="both", expand=True, pady=8)
        ttk.Button(left, text="Load text file…", command=self.load_text).pack(anchor="w")
        self.vector_button = ttk.Button(left, text="Create learned text vector", command=self.create_vector)
        self.vector_button.pack(fill="x", pady=(12, 4))
        ttk.Label(left, text="English text · 384 values · pretrained BGE encoder", wraplength=380).pack(anchor="w")
        row = ttk.Frame(left)
        row.pack(fill="x", pady=12)
        ttk.Label(row, text="Image size").pack(side="left")
        self.size = tk.StringVar(value="512")
        ttk.Combobox(row, textvariable=self.size, values=["256", "512", "1024"], width=8, state="readonly").pack(side="left", padx=10)
        ttk.Button(left, text="Generate procedural image", command=self.generate).pack(fill="x", pady=4)
        self.save_button = ttk.Button(left, text="Save PNG…", command=self.save, state="disabled")
        self.save_button.pack(fill="x", pady=4)
        ttk.Separator(left).pack(fill="x", pady=12)
        ttk.Button(left, text="Extract text from image…", command=self.recover).pack(fill="x")
        self.preview = ttk.Label(columns, text="Your image preview appears here", anchor="center", width=52)
        self.preview.pack(side="right", fill="both", expand=True)
        self.status = tk.StringVar(value="Ready. Text vectors use a local model; image patterns use the original hash method.")
        ttk.Label(outer, textvariable=self.status, wraplength=850).pack(anchor="w", pady=(16, 8))
        ttk.Label(outer, text="Keep the original PNG. Editing or resizing can destroy hidden data. Hidden text is not encrypted.", wraplength=850).pack(anchor="w")

    def create_vector(self):
        text = self.input.get("1.0", "end-1c")
        if not text.strip():
            messagebox.showinfo("Enter text", "Enter the text you want to encode first.")
            return
        self.vector_button.configure(state="disabled")
        self.status.set("Creating learned text embedding… The first run may download the model.")
        results = queue.Queue()
        def work():
            try:
                results.put((encode_semantic_text(text), None))
            except Exception as error:
                results.put((None, str(error)))
        def poll():
            try:
                vector, error = results.get_nowait()
            except queue.Empty:
                self.root.after(100, poll)
                return
            self.vector_button.configure(state="normal")
            if error:
                self.status.set("Could not create the text vector.")
                messagebox.showerror("Text encoder", error)
            else:
                self.show_vector(text, vector)
                self.status.set("Learned text embedding created: 384 values. View or save it in the vector window.")
        threading.Thread(target=work, daemon=True).start()
        self.root.after(100, poll)

    def show_vector(self, text, vector):
        window = tk.Toplevel(self.root)
        window.title("Learned text vector")
        window.geometry("720x560")
        ttk.Label(window, text=f"{MODEL_NAME}\n384 dimensions · float32 · norm {np.linalg.norm(vector):.6f}", padding=12).pack(anchor="w")
        ttk.Label(window, text="A learned text embedding, not an image latent. It cannot reconstruct your exact text.", wraplength=680, padding=12).pack(anchor="w")
        box = tk.Text(window, wrap="word", font=("Consolas", 10))
        box.pack(fill="both", expand=True, padx=12)
        value = np.array2string(vector, precision=8, threshold=1000, separator=", ")
        box.insert("1.0", value)
        box.configure(state="disabled")
        def save():
            path = filedialog.asksaveasfilename(parent=window, defaultextension=".json", initialfile="text-vector.json", filetypes=[("JSON with text and model", "*.json"), ("NumPy vector", "*.npy"), ("Readable values", "*.txt")])
            if path:
                try:
                    save_vector(path, text, vector)
                except (OSError, ValueError) as error:
                    messagebox.showerror("Could not save vector", str(error), parent=window)
        def copy():
            window.clipboard_clear()
            window.clipboard_append(value)
        row = ttk.Frame(window, padding=12)
        row.pack(fill="x")
        ttk.Button(row, text="Save vector…", command=save).pack(side="left")
        ttk.Button(row, text="Copy values", command=copy).pack(side="left", padx=10)

    def show_image(self, image):
        preview = image.copy().convert("RGB")
        preview.thumbnail((420, 440), Image.Resampling.NEAREST)
        self.photo = ImageTk.PhotoImage(preview)
        self.preview.configure(image=self.photo, text="")

    def load_text(self):
        path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if path:
            try:
                text = Path(path).read_bytes().decode("utf-8")
                self.input.delete("1.0", "end")
                self.input.insert("1.0", text)
            except (OSError, ValueError) as error:
                messagebox.showerror("Could not load text", str(error))

    def generate(self):
        try:
            text = self.input.get("1.0", "end-1c")
            size = int(self.size.get())
            capacity = size * size // 16 - HEADER.size
            if len(text.encode("utf-8")) > capacity:
                raise ValueError(f"This size holds {capacity:,} UTF-8 bytes. Choose a larger size or shorten your text.")
            image = embed(decode_latent(encode_text(text), size), text)
            self.image = image
            self.generated_text = text
            self.show_image(image)
            self.save_button.configure(state="normal")
            self.status.set(f"Generated {size} × {size} image. Save PNG to keep this image and its hidden text.")
        except (ValueError, OSError) as error:
            messagebox.showerror("Could not generate image", str(error))

    def save(self):
        if self.image is None:
            return
        path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG image", "*.png")], initialfile="latent-image.png")
        if path:
            try:
                if Path(path).suffix.lower() != ".png":
                    raise ValueError("Please save with a .png extension.")
                self.image.save(path, format="PNG")
                if extract(path) != self.generated_text:
                    raise ValueError("The saved image failed verification.")
                self.status.set(f"Saved and verified: {path}")
            except (OSError, ValueError) as error:
                messagebox.showerror("Could not save image", str(error))

    def recover(self):
        path = filedialog.askopenfilename(filetypes=[("PNG images", "*.png")])
        if not path:
            return
        try:
            text = extract(path)
        except (OSError, ValueError) as error:
            messagebox.showerror("Could not extract text", str(error))
            return
        window = tk.Toplevel(self.root)
        window.title("Recovered text")
        window.geometry("560x380")
        box = tk.Text(window, wrap="word", font=("Segoe UI", 11))
        box.pack(fill="both", expand=True, padx=15, pady=15)
        box.insert("1.0", text)
        box.configure(state="disabled")
        def copy():
            window.clipboard_clear()
            window.clipboard_append(text)
        def save_text():
            target = filedialog.asksaveasfilename(parent=window, defaultextension=".txt", filetypes=[("Text files", "*.txt")])
            if target:
                try:
                    Path(target).write_bytes(text.encode("utf-8"))
                except OSError as error:
                    messagebox.showerror("Could not save text", str(error), parent=window)
        actions = ttk.Frame(window, padding=10)
        actions.pack(fill="x")
        ttk.Button(actions, text="Copy text", command=copy).pack(side="left", padx=5)
        ttk.Button(actions, text="Save text…", command=save_text).pack(side="left")
        self.status.set("Hidden text recovered and checksum verified.")


if __name__ == "__main__":
    root = tk.Tk()
    App(root)
    root.mainloop()
