// Stable error codes (docs/api.md) -> human text.
export type StegoErrorTone = "danger" | "warning" | "info";
export interface StegoErrorView {
  title: string;
  text: string;
  tone: StegoErrorTone;
}

const TABLE: Record<string, StegoErrorView> = {
  NO_AUTH_SESSION: {
    title: "No authenticated session",
    text: "Run mutual authentication (M1-M8) for this drone pair first. Image transport only carries application messages after authentication.",
    tone: "warning",
  },
  NO_GROUP_KEY: {
    title: "Group key not established",
    text: "Establish the group key (K1-K3) on the Secure Communication page before sending image messages.",
    tone: "warning",
  },
  STEGO_BACKEND_UNAVAILABLE: {
    title: "Steganography backend unavailable",
    text: "The Python image service is not reachable from the core. The system fails closed: nothing was sent and no plaintext fallback was used.",
    tone: "danger",
  },
  GATEWAY_UNREACHABLE: {
    title: "Gateway unreachable",
    text: "The browser could not reach the Node gateway. Check that the gateway and core are running.",
    tone: "danger",
  },
  FRAME_TOO_LARGE: {
    title: "Message too large",
    text: "The sealed frame exceeds the configured frame size limit. Shorten the message.",
    tone: "warning",
  },
  COVER_GENERATION_FAILED: {
    title: "Cover generation failed",
    text: "The local cover generator could not produce a cover. Nothing was sent, and no other cover source is substituted.",
    tone: "danger",
  },
  COVER_QUALITY_REJECTED: {
    title: "No generated cover passed the quality checks",
    text: "Every candidate cover failed a coherence gate or scored below the quality floor (see the candidate table for the reasons). Nothing was sent; a low-quality cover is never used as a fallback. Try again or allow more candidates within the profile.",
    tone: "warning",
  },
  GENERATION_BUDGET_EXCEEDED: {
    title: "Cover generation budget exceeded",
    text: "The processing budget of the resource profile ran out before a suitable cover could be generated and planned. Nothing was sent. Use a smaller cover, fewer candidates, or a larger budget within the profile ceiling.",
    tone: "warning",
  },
  GENERATOR_CONFIG_INVALID: {
    title: "Cover generation settings rejected",
    text: "The settings are outside what the active resource profile allows. A request can only tighten the profile, and it cannot choose a seed, a file, a camera, a stored cover or an algorithm.",
    tone: "warning",
  },
  GENERATOR_MEMORY_LIMIT: {
    title: "Cover generation would exceed the memory limit",
    text: "The pre-flight memory estimate for this size and candidate count is above the profile's working-memory limit. Nothing was generated.",
    tone: "warning",
  },
  IMAGE_TOO_LARGE: {
    title: "Image too large",
    text: "The cover or stego image exceeds the configured size limit.",
    tone: "warning",
  },
  IMAGE_TOO_SMALL: {
    title: "Image too small",
    text: "The cover image is too small to embed the transport bootstrap and frame.",
    tone: "warning",
  },
  NO_ELIGIBLE_ALGORITHM: {
    title: "No eligible algorithm for a patch",
    text: "For at least one patch every knowledge-base entry was excluded by the structured filters (geometry, capacity, hard-avoid rules), also after the bounded coarser re-segmentation. Nothing was sent; there is no fallback algorithm.",
    tone: "warning",
  },
  PATCH_CAPACITY_INSUFFICIENT: {
    title: "Cover cannot carry this message patch-wise",
    text: "No generated cover within the allowed size can carry the sealed frame patch-wise: either the message is above the embedding-rate limit for that size, or the measured patch capacity was too small at every segmentation level. Shorten the message, raise the cover size within the profile, or allow payload-driven resize. Nothing was sent.",
    tone: "warning",
  },
  PATCH_EMBED_FAILED: {
    title: "A patch could not carry its chunk",
    text: "A patch failed to embed or re-extract its chunk with the selected algorithm, also after the bounded re-planning. No other algorithm is substituted; the message was not sent.",
    tone: "danger",
  },
  PATCH_UNSUPPORTED: {
    title: "Patch geometry not supported",
    text: "The algorithm cannot work on this patch mask (for example no complete block inside it).",
    tone: "warning",
  },
  SEGMENTATION_FAILED: {
    title: "Segmentation failed",
    text: "The cover could not be segmented within the configured limits (refinement level exhausted or invalid settings).",
    tone: "danger",
  },
  MANIFEST_INVALID: {
    title: "Patch manifest rejected",
    text: "The patch manifest failed strict validation (bounds, versions, patch map, offsets or lengths). The image is not processed further.",
    tone: "danger",
  },
  MANIFEST_TOO_LARGE: {
    title: "Patch manifest too large",
    text: "The declared manifest size exceeds the allowed maximum.",
    tone: "danger",
  },
  UNKNOWN_ALGORITHM: {
    title: "Unknown algorithm id",
    text: "The manifest names an algorithm id outside the whitelist of ten.",
    tone: "danger",
  },
  FRAME_MALFORMED: {
    title: "Malformed frame",
    text: "The reconstructed frame does not have the Frame v2 structure (images produced by the older single-algorithm format are not accepted).",
    tone: "danger",
  },
  FRAME_VERSION_UNSUPPORTED: {
    title: "Unsupported frame version",
    text: "The frame was produced by a different transport version.",
    tone: "danger",
  },
  FRAME_LENGTH_INVALID: {
    title: "Invalid frame length",
    text: "The length declared in the image bootstrap is inconsistent with the manifest or the limits.",
    tone: "danger",
  },
  FRAME_LENGTH_MISMATCH: {
    title: "Frame length mismatch",
    text: "The bootstrap length differs from the reconstructed frame.",
    tone: "danger",
  },
  KB_INVALID: {
    title: "Knowledge base invalid",
    text: "The static algorithm knowledge base failed validation at start-up; the image service refuses to plan.",
    tone: "danger",
  },
  BACKEND_MALFORMED_RESPONSE: {
    title: "Image service returned an inconsistent response",
    text: "The core rejected a response of the image service (it is not trusted).",
    tone: "danger",
  },
  ARTIFACT_HASH_MISMATCH: {
    title: "Saved image changed",
    text: "The saved image bytes differ from what the image service reported.",
    tone: "danger",
  },
  IMAGE_DECODE_ERROR: {
    title: "Corrupt or unreadable image",
    text: "The stego image could not be decoded. It may be damaged or not a valid PNG.",
    tone: "danger",
  },
  BOOTSTRAP_MISSING: {
    title: "No embedded header found",
    text: "The image carries no valid bootstrap header (corrupt image, or an image that never held a message).",
    tone: "danger",
  },
  BOOTSTRAP_CORRUPT: {
    title: "Embedded header is corrupt",
    text: "The bootstrap header failed its integrity check; the image was probably modified or damaged.",
    tone: "danger",
  },
  UNSUPPORTED_VERSION: {
    title: "Unsupported transport version",
    text: "The image was produced by a different transport format version than this build understands.",
    tone: "danger",
  },
  FRAME_AUTH_FAILED: {
    title: "Frame authentication failed",
    text: "The frame MAC (computed in the core over the patch manifest and the payload) did not verify: the manifest, the patch data or the payload was modified, or the image belongs to another channel, session or direction. The message was rejected.",
    tone: "danger",
  },
  REPLAY: {
    title: "Replay rejected",
    text: "This frame carries a sequence number that was already accepted. Replays are dropped.",
    tone: "danger",
  },
  AEAD_FAILED: {
    title: "Decryption failed",
    text: "The AEAD tag did not verify, so the message was not decrypted.",
    tone: "danger",
  },
  AEAD_AUTH_FAILED: {
    title: "Decryption failed",
    text: "The AEAD tag did not verify, so the message was not decrypted.",
    tone: "danger",
  },
  AEAD_OPEN_FAILED: {
    title: "Decryption failed",
    text: "The AEAD tag did not verify, so the message was not decrypted.",
    tone: "danger",
  },
  EXTRACT_FAILED: {
    title: "Extraction failed",
    text: "The embedded frame could not be extracted from the image.",
    tone: "danger",
  },
  EMBED_VERIFY_FAILED: {
    title: "Embedding self-check failed",
    text: "The freshly embedded image did not decode back to the same frame, so it was not used.",
    tone: "danger",
  },
  ENCODE_VERIFY_FAILED: {
    title: "Encoding self-check failed",
    text: "The trial or final encode did not verify.",
    tone: "danger",
  },
  IMAGE_WRITE_FAILED: {
    title: "Could not save the image",
    text: "The stego image could not be written to the artifact directory.",
    tone: "danger",
  },
  ARTIFACT_NOT_FOUND: {
    title: "Image artifact not found",
    text: "The saved image file is missing (retention or storage problem).",
    tone: "danger",
  },
  INVALID_REQUEST: {
    title: "Invalid request",
    text: "The core rejected the request fields.",
    tone: "danger",
  },
};

export function describeStegoError(code: string | undefined, message?: string): StegoErrorView {
  const c = code || "UNKNOWN";
  if (TABLE[c]) return TABLE[c];
  if (c.startsWith("BOOTSTRAP_"))
    return {
      title: "Embedded header problem",
      text: "The embedded bootstrap header is invalid.",
      tone: "danger",
    };
  if (c.startsWith("AEAD"))
    return {
      title: "Decryption failed",
      text: "The AEAD check did not pass; the message was not decrypted.",
      tone: "danger",
    };
  return {
    title: "Operation failed",
    text: message || "The core reported an error.",
    tone: "danger",
  };
}
