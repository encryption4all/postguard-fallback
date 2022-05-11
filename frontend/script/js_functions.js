const PKG_URL = "https://stable.irmaseal-pkg.ihub.ru.nl";

export function irma_get_usk(keyrequest, timestamp) {
  return window
    .startIrma({
      url: PKG_URL,
      start: {
        url: (o) => `${o.url}/v2/request/start`,
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(keyrequest),
      },
      mapping: {
        sessionPtr: (r) => {
          const ptr = r.sessionPtr;
          ptr.u = `https://ihub.ru.nl/irma/1/${ptr.u}`;
          return ptr;
        },
      },
      result: {
        url: (o, { sessionToken }) => `${o.url}/v2/request/jwt/${sessionToken}`,
        parseResponse: (r) => {
          return r
            .text()
            .then((encoded) => {
              return fetch(
                `${PKG_URL}/v2/request/key/${timestamp.toString()}`,
                {
                  headers: {
                    Authorization: `Bearer ${encoded}`,
                  },
                }
              );
            })
            .then((r) => r.json())
            .then((json) => {
              if (json.status !== "DONE" || json.proofStatus !== "VALID")
                throw new Error("not done and valid");
              return json.key;
            });
        },
      },
    })
    .catch((e) => console.error(e));
}

export async function irma_sign(hash) {
  try {
    const signature = await window.startIrma({
      maxAge: 300,
      start: {
        url: (o) => `${o.url}/api/sign`,
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          hash,
          attributes: ["pbdf.sidn-pbdf.email.email"],
        }),
      },
      state: { serverSentEvents: false },
      mapping: {
        sessionPtr: (r) => r.sessionPtr,
      },
      result: {
        url: (o, { sessionToken }) =>
          `${o.url}/api/sign_result?session=${sessionToken}`,
        parseResponse: (r) => r.text(),
      },
    });

    return signature;
  } catch (e) {
    console.error(e);
    return null;
  }
}

export async function encrypt(message, key, iv) {
  try {
    const keyHash = await crypto.subtle.digest("SHA-256", key);
    const aesKey = await window.crypto.subtle.importKey(
      "raw",
      keyHash,
      "AES-GCM",
      true,
      ["encrypt"]
    );
    const ct = await window.crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv,
      },
      aesKey,
      new TextEncoder().encode(message)
    );

    return new Uint8Array(ct);
  } catch (e) {
    console.error(e);
    return null;
  }
}

export async function decrypt(ciphertext, key, iv) {
  try {
    const keyHash = await crypto.subtle.digest("SHA-256", key);
    const aesKey = await window.crypto.subtle.importKey(
      "raw",
      keyHash,
      "AES-GCM",
      true,
      ["decrypt"]
    );
    const encoded = await window.crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv,
      },
      aesKey,
      ciphertext
    );

    return new TextDecoder().decode(encoded).toString();
  } catch (e) {
    console.error(e);
    return null;
  }
}

export async function decrypt_cfb_hmac(ciphertext, key, iv) {
  try {
    const aesKey = await window.crypto.subtle.importKey(
      "raw",
      key,
      { name: "AES-CTR", length: 32 * 8 },
      true,
      ["decrypt"]
    );
    const encoded = await window.crypto.subtle.decrypt(
      {
        name: "AES-CTR",
        counter: iv,
        length: 64,
      },
      aesKey,
      ciphertext
    );

    return encoded;
  } catch (e) {
    console.error(e);
    return null;
  }
}
