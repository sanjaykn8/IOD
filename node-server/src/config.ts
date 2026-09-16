// Central configuration, all overridable via environment variables so
// the same build works unchanged across the Windows/Linux launch
// scripts (see /scripts).
export const config = {
  port: parseInt(process.env.IOD_NODE_PORT || "4000", 10),
  rustBaseUrl: process.env.IOD_RUST_BASE_URL || "http://127.0.0.1:8787",
  pythonBaseUrl: process.env.IOD_PYTHON_BASE_URL || "http://127.0.0.1:5001",
  eventPollIntervalMs: parseInt(process.env.IOD_EVENT_POLL_MS || "500", 10),
};
