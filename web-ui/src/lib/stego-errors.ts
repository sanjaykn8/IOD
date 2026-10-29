// Stable error codes (docs/stego-implementation-note.md 4.1/4.2) -> human text.
export type StegoErrorTone = "danger" | "warning" | "info";
export interface StegoErrorView { title: string; text: string; tone: StegoErrorTone }

const TABLE: Record<string, StegoErrorView> = {
  NO_AUTH_SESSION: { title: "No authenticated session", text: "Run mutual authentication (M1-M8) for this drone pair first. Image transport only carries application messages after authentication.", tone: "warning" },
  NO_GROUP_KEY: { title: "Group key not established", text: "Establish the group key (K1-K3) on the Secure Communication page before sending image messages.", tone: "warning" },
  STEGO_BACKEND_UNAVAILABLE: { title: "Steganography backend unavailable", text: "The Python image service is not reachable from the core. The system fails closed: nothing was sent and no plaintext fallback was used.", tone: "danger" },
  GATEWAY_UNREACHABLE: { title: "Gateway unreachable", text: "The browser could not reach the Node gateway. Check that the gateway and core are running.", tone: "danger" },
  FRAME_TOO_LARGE: { title: "Message too large for the cover image", text: "The sealed frame does not fit the image capacity limit. Shorten the message or use a larger cover.", tone: "warning" },
  IMAGE_TOO_LARGE: { title: "Image too large", text: "The cover or stego image exceeds the configured size limit.", tone: "warning" },
  IMAGE_TOO_SMALL: { title: "Image too small", text: "The cover image is too small to embed the transport bootstrap and frame.", tone: "warning" },
  NO_ELIGIBLE_ALGORITHM: { title: "No eligible algorithm", text: "Every algorithm was excluded (capacity or quality limits). See the candidate table for each exclusion reason.", tone: "warning" },
  ALGORITHM_NOT_ELIGIBLE: { title: "Chosen algorithm is not eligible", text: "The manually forced algorithm failed a safety check (capacity or distortion limit). Manual override does not bypass safety limits; pick another algorithm or use automatic selection.", tone: "warning" },
  IMAGE_DECODE_ERROR: { title: "Corrupt or unreadable image", text: "The stego image could not be decoded. It may be damaged or not a valid PNG.", tone: "danger" },
  BOOTSTRAP_MISSING: { title: "No embedded header found", text: "The image carries no valid bootstrap header (corrupt image, or an image that never held a message).", tone: "danger" },
  BOOTSTRAP_CORRUPT: { title: "Embedded header is corrupt", text: "The bootstrap header failed its integrity check; the image was probably modified or damaged.", tone: "danger" },
  UNSUPPORTED_VERSION: { title: "Unsupported transport version", text: "The image was produced by a different transport format version than this build understands.", tone: "danger" },
  FRAME_AUTH_FAILED: { title: "Frame authentication failed", text: "The frame MAC did not verify: the data was tampered with, or it was built for another channel, session or direction. The message was rejected.", tone: "danger" },
  REPLAY: { title: "Replay rejected", text: "This frame carries a sequence number that was already accepted. Replays are dropped.", tone: "danger" },
  AEAD_FAILED: { title: "Decryption failed", text: "The AEAD tag did not verify, so the message was not decrypted.", tone: "danger" },
  AEAD_AUTH_FAILED: { title: "Decryption failed", text: "The AEAD tag did not verify, so the message was not decrypted.", tone: "danger" },
  AEAD_OPEN_FAILED: { title: "Decryption failed", text: "The AEAD tag did not verify, so the message was not decrypted.", tone: "danger" },
  EXTRACT_FAILED: { title: "Extraction failed", text: "The embedded frame could not be extracted from the image.", tone: "danger" },
  EMBED_VERIFY_FAILED: { title: "Embedding self-check failed", text: "The freshly embedded image did not decode back to the same frame, so it was not used.", tone: "danger" },
  ENCODE_VERIFY_FAILED: { title: "Encoding self-check failed", text: "The trial or final encode did not verify.", tone: "danger" },
  IMAGE_WRITE_FAILED: { title: "Could not save the image", text: "The stego image could not be written to the artifact directory.", tone: "danger" },
  ARTIFACT_NOT_FOUND: { title: "Image artifact not found", text: "The saved image file is missing (retention or storage problem).", tone: "danger" },
  INVALID_REQUEST: { title: "Invalid request", text: "The core rejected the request fields.", tone: "danger" },
};

export function describeStegoError(code: string | undefined, message?: string): StegoErrorView {
  const c = code || "UNKNOWN";
  if (TABLE[c]) return TABLE[c];
  if (c.startsWith("CAMERA_")) {
    return { title: "Webcam not used", text: "The webcam could not provide a frame, so a procedural cover image was used instead. This is a fallback, not a failure.", tone: "info" };
  }
  if (c.startsWith("BOOTSTRAP_")) return { title: "Embedded header problem", text: "The embedded bootstrap header is invalid.", tone: "danger" };
  if (c.startsWith("AEAD")) return { title: "Decryption failed", text: "The AEAD check did not pass; the message was not decrypted.", tone: "danger" };
  return { title: "Operation failed", text: message || "The core reported an error.", tone: "danger" };
}

export const CAMERA_REASONS: Record<string, string> = {
  CAMERA_ABSENT: "no camera device found",
  CAMERA_PERMISSION_DENIED: "camera permission denied",
  CAMERA_TIMEOUT: "camera timed out",
  CAMERA_BACKEND_UNAVAILABLE: "camera backend (OpenCV) not available",
  CAMERA_CAPTURE_FAILED: "camera capture failed",
  CAMERA_DISABLED: "camera disabled by configuration",
};
