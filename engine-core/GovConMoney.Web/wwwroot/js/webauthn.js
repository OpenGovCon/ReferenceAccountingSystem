function b64urlToBytes(value) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const pad = base64.length % 4;
  const padded = pad ? base64 + "=".repeat(4 - pad) : base64;
  const str = atob(padded);
  const bytes = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i += 1) {
    bytes[i] = str.charCodeAt(i);
  }
  return bytes;
}

function bytesToB64url(bytes) {
  let str = "";
  const arr = bytes instanceof ArrayBuffer ? new Uint8Array(bytes) : bytes;
  for (const b of arr) {
    str += String.fromCharCode(b);
  }
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function mapRegisterOptions(options) {
  const mapped = { ...options };
  mapped.challenge = b64urlToBytes(options.challenge);
  mapped.user = { ...options.user, id: b64urlToBytes(options.user.id) };
  mapped.excludeCredentials = (options.excludeCredentials || []).map((x) => ({ ...x, id: b64urlToBytes(x.id) }));
  return mapped;
}

function mapAssertionOptions(options) {
  const mapped = { ...options };
  mapped.challenge = b64urlToBytes(options.challenge);
  mapped.allowCredentials = (options.allowCredentials || []).map((x) => ({ ...x, id: b64urlToBytes(x.id) }));
  return mapped;
}

function serializeAttestation(credential) {
  const response = credential.response;
  return {
    id: credential.id,
    rawId: bytesToB64url(credential.rawId),
    type: credential.type,
    response: {
      attestationObject: bytesToB64url(response.attestationObject),
      clientDataJson: bytesToB64url(response.clientDataJSON),
      transports: typeof response.getTransports === "function" ? response.getTransports() : []
    },
    clientExtensionResults: credential.getClientExtensionResults()
  };
}

function serializeAssertion(credential) {
  const response = credential.response;
  return {
    id: credential.id,
    rawId: bytesToB64url(credential.rawId),
    type: credential.type,
    response: {
      authenticatorData: bytesToB64url(response.authenticatorData),
      clientDataJson: bytesToB64url(response.clientDataJSON),
      signature: bytesToB64url(response.signature),
      userHandle: response.userHandle ? bytesToB64url(response.userHandle) : null
    },
    clientExtensionResults: credential.getClientExtensionResults()
  };
}

window.govConPasskeys = {
  register: async function () {
    const beginRes = await fetch("/api/passkeys/register/options", {
      method: "POST",
      credentials: "include",
      headers: { "Accept": "application/json" }
    });
    if (!beginRes.ok) {
      throw new Error("Unable to start passkey registration");
    }

    const beginData = await beginRes.json();
    const credential = await navigator.credentials.create({ publicKey: mapRegisterOptions(beginData.options) });
    if (!credential) {
      throw new Error("Passkey creation was cancelled");
    }

    const finishRes = await fetch("/api/passkeys/register/complete", {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json", "Accept": "application/json" },
      body: JSON.stringify({
        flowId: beginData.flowId,
        attestation: serializeAttestation(credential)
      })
    });

    if (!finishRes.ok) {
      const text = await finishRes.text();
      throw new Error(text || "Unable to complete passkey registration");
    }
  },

  login: async function (username) {
    const optionsRes = await fetch("/api/passkeys/login/options", {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json", "Accept": "application/json" },
      body: JSON.stringify({ username })
    });
    if (!optionsRes.ok) {
      throw new Error("Unable to start passkey login");
    }

    const beginData = await optionsRes.json();
    const assertion = await navigator.credentials.get({ publicKey: mapAssertionOptions(beginData.options) });
    if (!assertion) {
      throw new Error("Passkey assertion was cancelled");
    }

    const finishRes = await fetch("/api/passkeys/login/complete", {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json", "Accept": "application/json" },
      body: JSON.stringify({
        flowId: beginData.flowId,
        assertion: serializeAssertion(assertion)
      })
    });

    if (!finishRes.ok) {
      const text = await finishRes.text();
      throw new Error(text || "Unable to complete passkey login");
    }

    window.location.assign("/home");
  }
};
