// Thin wrapper around navigator.credentials. The server sends and expects base64url
// strings; the browser API wants ArrayBuffers. Nothing here is secret: the private key
// never leaves the authenticator.

export const supported = !!(window.PublicKeyCredential && navigator.credentials);

export function b64uToBuf(text) {
  const b64 = text.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(text.length / 4) * 4, "=");
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)).buffer;
}

export function bufToB64u(buffer) {
  let bin = "";
  for (const byte of new Uint8Array(buffer)) bin += String.fromCharCode(byte);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const descriptors = (list) => (list || []).map((c) => ({ ...c, id: b64uToBuf(c.id) }));

export async function createCredential(options) {
  const cred = await navigator.credentials.create({
    publicKey: {
      ...options,
      challenge: b64uToBuf(options.challenge),
      user: { ...options.user, id: b64uToBuf(options.user.id) },
      excludeCredentials: descriptors(options.excludeCredentials),
    },
  });
  return {
    id: cred.id,
    rawId: bufToB64u(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: bufToB64u(cred.response.clientDataJSON),
      attestationObject: bufToB64u(cred.response.attestationObject),
      transports: cred.response.getTransports ? cred.response.getTransports() : [],
    },
    clientExtensionResults: cred.getClientExtensionResults(),
  };
}

export async function getAssertion(options) {
  const cred = await navigator.credentials.get({
    publicKey: {
      ...options,
      challenge: b64uToBuf(options.challenge),
      allowCredentials: descriptors(options.allowCredentials),
    },
  });
  const response = {
    clientDataJSON: bufToB64u(cred.response.clientDataJSON),
    authenticatorData: bufToB64u(cred.response.authenticatorData),
    signature: bufToB64u(cred.response.signature),
  };
  if (cred.response.userHandle) response.userHandle = bufToB64u(cred.response.userHandle);
  return {
    id: cred.id,
    rawId: bufToB64u(cred.rawId),
    type: cred.type,
    response,
    clientExtensionResults: cred.getClientExtensionResults(),
  };
}

// Friendly text for the errors people actually hit.
export function explain(err) {
  switch (err && err.name) {
    case "NotAllowedError": return "Cancelled or timed out. Try again and approve the prompt.";
    case "InvalidStateError": return "This security key is already registered.";
    case "SecurityError": return "The browser refused: this page's address is not valid for the site name the server uses. Open it as http://localhost:8000 .";
    case "NotSupportedError": return "This browser or device does not support the requested security key type.";
    default: return (err && err.message) || "Something went wrong.";
  }
}
