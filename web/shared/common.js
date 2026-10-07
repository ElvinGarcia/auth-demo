// Small fetch wrapper used by every level.
export async function api(path, body) {
  const options =
    body === undefined
      ? {}
      : {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        };
  const res = await fetch(path, options);
  let data = null;
  try {
    data = await res.json();
  } catch {
    // empty or non-JSON body
  }
  return { ok: res.ok, status: res.status, data };
}

// FastAPI returns `detail` as a string for our errors and a list for validation errors.
export function errorText(result) {
  const detail = result.data && result.data.detail;
  if (Array.isArray(detail)) return detail.map((d) => d.msg).join("; ");
  return detail || `Request failed (${result.status})`;
}
