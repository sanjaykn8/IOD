// Browser webcam capture: getUserMedia -> canvas -> lossless PNG -> POST /api/stego/cover/upload.
// The frame never leaves the machine except to the local gateway; the service re-validates and re-encodes it.
import { useCallback, useEffect, useRef, useState } from "react";
import { Camera, CameraOff, Upload } from "lucide-react";
import { Button } from "@/components/ui/button";
import { stegoApi } from "@/lib/stego-api";
import type { StegoUploadedCover } from "@/types/api";

const MAX_W = 1280, MAX_H = 960; // downscale in the browser only above this (recorded in the UI, never silently in the service)

export function cameraErrorText(e: unknown): string {
  const name = e instanceof DOMException ? e.name : "";
  if (!window.isSecureContext) return "The browser only allows camera access on https:// or localhost. Open the UI at http://127.0.0.1:5173 or http://localhost:5173.";
  if (!navigator.mediaDevices?.getUserMedia) return "This browser does not expose a camera API.";
  switch (name) {
    case "NotAllowedError": case "SecurityError": return "Camera permission was denied. Allow camera access for this site in the browser, then try again.";
    case "NotFoundError": case "OverconstrainedError": return "No camera was found on this computer.";
    case "NotReadableError": case "AbortError": return "The camera is busy or unavailable (another application may be using it).";
    default: return "The camera could not be started.";
  }
}

function toBase64(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
}

export async function blobToCoverB64(blob: Blob): Promise<string> {
  return toBase64(await blob.arrayBuffer());
}

export function BrowserWebcam({ disabled, onCover }: { disabled?: boolean; onCover: (c: StegoUploadedCover, previewUrl: string) => void }) {
  const videoRef = useRef<HTMLVideoElement>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const [on, setOn] = useState(false);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ tone: "info" | "danger"; text: string } | null>(null);

  const stop = useCallback(() => {
    streamRef.current?.getTracks().forEach((t) => t.stop());
    streamRef.current = null;
    if (videoRef.current) videoRef.current.srcObject = null;
    setOn(false);
  }, []);
  useEffect(() => stop, [stop]);

  async function start() {
    setMsg(null);
    try {
      if (!navigator.mediaDevices?.getUserMedia) throw new Error("unsupported");
      const stream = await navigator.mediaDevices.getUserMedia({ video: { width: { ideal: 640 }, height: { ideal: 480 } }, audio: false });
      streamRef.current = stream;
      const v = videoRef.current;
      if (v) { v.srcObject = stream; await v.play().catch(() => undefined); }
      setOn(true);
    } catch (e) {
      stop();
      setMsg({ tone: "danger", text: cameraErrorText(e) });
    }
  }

  async function capture() {
    const v = videoRef.current;
    if (!v || !v.videoWidth || !v.videoHeight) { setMsg({ tone: "danger", text: "The camera has not produced a frame yet. Wait a moment and try again." }); return; }
    setBusy(true); setMsg(null);
    try {
      const scale = Math.min(1, MAX_W / v.videoWidth, MAX_H / v.videoHeight);
      const w = Math.max(1, Math.round(v.videoWidth * scale)), h = Math.max(1, Math.round(v.videoHeight * scale));
      const canvas = document.createElement("canvas");
      canvas.width = w; canvas.height = h;
      const ctx = canvas.getContext("2d");
      if (!ctx) throw new Error("no 2d context");
      ctx.drawImage(v, 0, 0, w, h);
      const blob: Blob | null = await new Promise((res) => canvas.toBlob(res, "image/png"));
      if (!blob) throw new Error("png encode failed");
      const r = await stegoApi.uploadCover(await blobToCoverB64(blob), "browser_webcam");
      if (!r.ok) { setMsg({ tone: "danger", text: `${r.error.code}: ${r.error.message}` }); return; }
      onCover(r.data.cover, canvas.toDataURL("image/png"));
      setMsg({ tone: "info", text: `Frame captured (${r.data.cover.width}×${r.data.cover.height}${scale < 1 ? `, downscaled in the browser from ${v.videoWidth}×${v.videoHeight}` : ""}) and stored as the cover.` });
    } catch {
      setMsg({ tone: "danger", text: "Capturing the frame failed." });
    } finally { setBusy(false); }
  }

  return (
    <div className="stego-webcam" aria-label="Browser webcam capture">
      <video ref={videoRef} muted playsInline className="stego-webcam-video" style={{ display: on ? "block" : "none", maxWidth: 320, borderRadius: 6 }} aria-label="Live camera preview" />
      <div className="button-row">
        {!on
          ? <Button variant="outline" disabled={disabled} onClick={() => void start()}><Camera /> Start browser webcam</Button>
          : <>
              <Button disabled={disabled || busy} onClick={() => void capture()}><Camera /> {busy ? "Capturing" : "Capture frame as cover"}</Button>
              <Button variant="outline" onClick={stop}><CameraOff /> Stop camera</Button>
            </>}
      </div>
      {msg ? <p className="stego-muted" role={msg.tone === "danger" ? "alert" : "status"}>{msg.text}</p> : null}
    </div>
  );
}

export function CoverFileUpload({ disabled, onCover }: { disabled?: boolean; onCover: (c: StegoUploadedCover, previewUrl: string) => void }) {
  const [msg, setMsg] = useState<string | null>(null);
  async function pick(file: File | undefined) {
    if (!file) return;
    setMsg(null);
    if (file.type !== "image/png") { setMsg("Only PNG files are accepted (lossless). JPEG covers are refused."); return; }
    if (file.size > 8 * 1024 * 1024) { setMsg("The file is larger than 8 MiB."); return; }
    const r = await stegoApi.uploadCover(await blobToCoverB64(file), "uploaded");
    if (!r.ok) { setMsg(`${r.error.code}: ${r.error.message}`); return; }
    onCover(r.data.cover, URL.createObjectURL(file));
    setMsg(`Cover stored (${r.data.cover.width}×${r.data.cover.height}).`);
  }
  return (
    <label className="stego-upload">
      <span><Upload className="stego-inline-icon" aria-hidden="true" /> Upload PNG cover</span>
      <input type="file" accept="image/png" disabled={disabled} onChange={(ev) => void pick(ev.target.files?.[0])} aria-label="Upload PNG cover" />
      {msg ? <small className="stego-muted" role="status">{msg}</small> : null}
    </label>
  );
}
