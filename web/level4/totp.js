// Browser-side TOTP (RFC 6238) and a small "authenticator app" widget.
// This is what a phone app does: it holds the secret and computes codes from the clock.
// Uses the Web Crypto API, which needs https or localhost.

const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32Decode(text) {
  const clean = text.replace(/[\s=-]/g, "").toUpperCase();
  let bits = 0, value = 0;
  const out = [];
  for (const ch of clean) {
    const idx = B32.indexOf(ch);
    if (idx === -1) throw new Error("Not a valid base32 secret");
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 0xff); bits -= 8; }
  }
  return new Uint8Array(out);
}

export function secondsLeft(nowMs = Date.now(), step = 30) {
  return step - (Math.floor(nowMs / 1000) % step);
}

export async function totp(secret, nowMs = Date.now(), step = 30, digits = 6) {
  const key = await crypto.subtle.importKey(
    "raw", base32Decode(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const counter = Math.floor(nowMs / 1000 / step);
  const msg = new DataView(new ArrayBuffer(8));
  msg.setUint32(0, Math.floor(counter / 2 ** 32));
  msg.setUint32(4, counter >>> 0);
  const mac = new DataView(await crypto.subtle.sign("HMAC", key, msg.buffer));
  const offset = mac.getUint8(mac.byteLength - 1) & 0x0f;
  const bin = mac.getUint32(offset) & 0x7fffffff;
  return String(bin % 10 ** digits).padStart(digits, "0");
}

// Builds the widget with DOM calls only (secrets are data, never HTML).
export function mountAuthenticator(container, { secret = "", label = "Secret key" } = {}) {
  const wrap = document.createElement("div");
  const lab = document.createElement("label");
  lab.textContent = label;
  const input = document.createElement("input");
  input.className = "mono";
  input.autocomplete = "off";
  input.spellcheck = false;
  input.value = secret;
  lab.htmlFor = input.id = "auth-secret-" + Math.random().toString(36).slice(2);
  const code = document.createElement("div");
  code.className = "authcode";
  code.setAttribute("aria-live", "off");
  const timer = document.createElement("div");
  timer.className = "muted";
  timer.style.fontSize = "0.85rem";
  wrap.append(lab, input, code, timer);
  container.replaceChildren(wrap);

  async function tick() {
    if (!input.value.trim()) { code.textContent = "------"; timer.textContent = "Paste a secret key above."; return; }
    try {
      code.textContent = await totp(input.value);
      timer.textContent = `New code in ${secondsLeft()}s`;
    } catch (err) {
      code.textContent = "------";
      timer.textContent = err.message;
    }
  }
  tick();
  setInterval(tick, 500);
  return {
    setSecret(s) { input.value = s; tick(); },
    getSecret() { return input.value.trim(); },
    currentCode() { return totp(input.value.trim()); },
  };
}
