// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// MSRC's side: open a bundle, choose what to withhold, and sign what is left.
// Withholding drops the disclosure from the exported bundle; the black bars
// are a preview of what a later reader will not be able to open.
//
// The release key lives in this tab, like the researcher's signing key: the
// server only ever sees its public half and the bytes to be signed.

"use strict";

const ALGORITHM = { name: "ECDSA", namedCurve: "P-256" };

const state = {
  key: null,
  publicKeyPem: null,
  bundleB64: null,
  chunks: [],
  fields: [],
  redacted: new Set(),
};

const $ = (id) => document.getElementById(id);

function b64encode(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function b64decode(text) {
  const binary = atob(text);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

async function post(url, payload) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  });
  const document_ = await response.json();
  if (!response.ok) throw new Error(document_.detail ?? response.statusText);
  return document_;
}

function key(kind, name) {
  return `${kind}:${name}`;
}

function toPem(spki) {
  const body = b64encode(spki)
    .replace(/(.{64})/g, "$1\n")
    .trimEnd();
  return `-----BEGIN PUBLIC KEY-----\n${body}\n-----END PUBLIC KEY-----\n`;
}

function pemToDer(pem) {
  const match = pem.match(/-----BEGIN ([A-Z0-9 ]+)-----([\s\S]+?)-----END \1-----/);
  if (!match) throw new Error("that file is not a PEM document");
  if (match[1] !== "PRIVATE KEY") {
    throw new Error(`expected a PKCS#8 "PRIVATE KEY" block, found "${match[1]}"`);
  }
  return b64decode(match[2].replace(/\s+/g, ""));
}

// Imported extractable only long enough to take the public half; the handle
// that signs cannot be exported.
async function importKeyPair(pem) {
  let jwk;
  try {
    const imported = await crypto.subtle.importKey(
      "pkcs8",
      pemToDer(pem),
      ALGORITHM,
      true,
      ["sign"],
    );
    jwk = await crypto.subtle.exportKey("jwk", imported);
  } catch (error) {
    throw new Error(
      `that key could not be read as a PKCS#8 P-256 private key: ${error.message}`,
    );
  }
  const [privateKey, publicKey] = await Promise.all([
    crypto.subtle.importKey(
      "jwk",
      { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y, d: jwk.d },
      ALGORITHM,
      false,
      ["sign"],
    ),
    crypto.subtle.importKey(
      "jwk",
      { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y },
      ALGORITHM,
      true,
      ["verify"],
    ),
  ]);
  return { privateKey, publicKey };
}

function render() {
  const fields = $("fields");
  fields.replaceChildren();
  for (const field of state.fields) {
    const row = document.createElement("label");
    row.className = "field";

    const box = document.createElement("input");
    box.type = "checkbox";
    box.checked = state.redacted.has(key("field", field.name));
    box.addEventListener("change", () => {
      const id = key("field", field.name);
      if (box.checked) state.redacted.add(id);
      else state.redacted.delete(id);
      render();
    });

    const label = document.createElement("span");
    label.textContent = `${field.label}: `;

    const value = document.createElement("span");
    if (state.redacted.has(key("field", field.name))) {
      value.className = "bar";
      value.textContent = "\u00a0".repeat(Math.max(field.value.length, 3));
    } else {
      value.textContent = field.value;
    }

    row.append(box, label, value);
    fields.append(row);
  }

  const body = $("body-text");
  body.replaceChildren();
  for (const chunk of state.chunks) {
    const span = document.createElement("span");
    const id = key("chunk", chunk.index);
    if (state.redacted.has(id)) {
      span.className = "bar";
      span.textContent = "\u00a0".repeat(Math.max(chunk.text.length, 1));
    } else {
      span.className = "chunk";
      span.textContent = chunk.text;
    }
    span.title = `chunk ${chunk.index}`;
    span.addEventListener("click", () => {
      if (state.redacted.has(id)) state.redacted.delete(id);
      else state.redacted.add(id);
      render();
    });
    body.append(span);
  }
}

$("load-key").addEventListener("click", async () => {
  const file = $("key-file").files[0];
  $("key-state").textContent = file ? "Importing..." : "Generating...";
  try {
    state.key = file
      ? await importKeyPair(await file.text())
      : await crypto.subtle.generateKey(ALGORITHM, false, ["sign"]);
    const spki = await crypto.subtle.exportKey("spki", state.key.publicKey);
    state.publicKeyPem = toPem(spki);
    // Registered so that statements issued from now on name this key in cnf.
    await post("/api/msrc/key", { public_key_pem: state.publicKeyPem });
    $("key-state").textContent = file
      ? "Loaded your release key and registered its public half."
      : "Generated a release key and registered its public half.";
  } catch (error) {
    state.key = null;
    $("key-state").textContent = `Could not load that key: ${error.message}`;
  }
});

$("load").addEventListener("click", async () => {
  const file = $("bundle-file").files[0];
  if (!file) {
    $("load-state").textContent = "Choose a bundle file first.";
    return;
  }
  $("load-state").textContent = "Reading...";
  try {
    state.bundleB64 = b64encode(await file.arrayBuffer());
    const { inspection } = await post("/api/msrc/inspect", {
      bundle_b64: state.bundleB64,
    });
    state.fields = inspection.fields.filter((field) => field.disclosed);
    state.chunks = (inspection.body.chunks ?? []).filter((chunk) => chunk.disclosed);
    state.redacted = new Set();
    $("load-state").textContent =
      `Loaded ${file.name}: ${state.fields.length} fields, ${state.chunks.length} body chunks.`;
    $("editor").hidden = false;
    $("export-section").hidden = false;
    $("export-state").textContent = "";
    render();
  } catch (error) {
    // A signed release wraps the bundle, so it will not parse as one. Every
    // redaction starts from the original bundle rather than from a release.
    const hint = /top level item must be a map/.test(error.message)
      ? " If that is a signed release, redact the original bundle instead."
      : "";
    $("load-state").textContent = `Could not load that bundle: ${error.message}${hint}`;
    $("editor").hidden = true;
    $("export-section").hidden = true;
  }
});

$("export").addEventListener("click", async () => {
  if (!state.key) {
    $("export-state").textContent = "Load a release key first.";
    return;
  }
  $("export-state").textContent = "Signing...";
  try {
    const prepared = await post("/api/msrc/release", {
      bundle_b64: state.bundleB64,
      public_key_pem: state.publicKeyPem,
      redact_fields: state.fields
        .map((field) => field.name)
        .filter((name) => state.redacted.has(key("field", name))),
      redact_body_chunks: state.chunks
        .map((chunk) => chunk.index)
        .filter((index) => state.redacted.has(key("chunk", index))),
    });

    // The only thing this key ever signs.
    const signature = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      state.key.privateKey,
      b64decode(prepared.to_be_signed_b64),
    );

    const result = await post("/api/msrc/sign", {
      release_id: prepared.release_id,
      signature_b64: b64encode(signature),
    });

    const blob = new Blob([b64decode(result.release_b64)], {
      type: "application/cose",
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "release.cose";
    link.click();
    URL.revokeObjectURL(url);

    $("export-state").textContent =
      `Signed ${prepared.presented_bytes} bytes of bundle into a ${result.release_bytes}-byte release.`;
  } catch (error) {
    $("export-state").textContent = `Export failed: ${error.message}`;
  }
});
