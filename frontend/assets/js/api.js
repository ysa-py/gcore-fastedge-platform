// Thin API client. Same-origin only; session lives in an HttpOnly cookie.
// Every mutating request carries X-Requested-With (CSRF defense-in-depth;
// the server enforces both this header and same-origin requests).

const XRW = "fastedge-admin";

export class ApiError extends Error {
  constructor(status, code, message, details, requestId) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details || [];
    this.requestId = requestId;
  }
}

async function request(method, path, body) {
  const opts = {
    method,
    credentials: "same-origin",
    headers: { "X-Requested-With": XRW },
  };
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  let resp;
  try {
    resp = await fetch(path, opts);
  } catch {
    throw new ApiError(0, "NETWORK", "Network request failed. Check your connection.");
  }
  let data = null;
  const text = await resp.text();
  if (text) {
    try { data = JSON.parse(text); } catch { /* non-JSON body */ }
  }
  if (!resp.ok) {
    const err = (data && data.error) || {};
    throw new ApiError(resp.status, err.code || "UNKNOWN", err.message || resp.statusText, err.details, data && data.request_id);
  }
  return data;
}

export const api = {
  get: (p) => request("GET", p),
  post: (p, b) => request("POST", p, b === undefined ? {} : b),
  put: (p, b) => request("PUT", p, b),
  patch: (p, b) => request("PATCH", p, b),
  del: (p) => request("DELETE", p),
};
