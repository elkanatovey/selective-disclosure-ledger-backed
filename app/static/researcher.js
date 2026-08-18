// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// The researcher's key lives here and nowhere else. Generated or imported, the
// signing handle is non-extractable, so this script cannot read it out either:
// it can only ask WebCrypto to sign the bytes the server prepared.

"use strict";

const ALGORITHM = { name: "ECDSA", namedCurve: "P-256" };

const state = { key: null, enrollmentId: null };

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

// The imported key is extractable only long enough to take its public half,
// which is all enrollment needs. The signing handle returned below is not.
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

function setStages(stages) {
  const list = $("stages");
  list.replaceChildren();
  for (const stage of stages) {
    const item = document.createElement("li");
    item.textContent = `${stage.name}: ${stage.detail}`;
    list.append(item);
  }
}

$("enroll").addEventListener("click", async () => {
  const file = $("key-file").files[0];
  $("key-state").textContent = file ? "Importing..." : "Generating...";
  try {
    state.key = file
      ? await importKeyPair(await file.text())
      : await crypto.subtle.generateKey(ALGORITHM, false, ["sign"]);
    const spki = await crypto.subtle.exportKey("spki", state.key.publicKey);
    const enrolled = await post("/api/enroll", {
      public_key_pem: toPem(spki),
      subject: "Demo researcher",
    });
    state.enrollmentId = enrolled.enrollment_id;
    $("key-state").textContent =
      `Enrolled ${enrolled.enrollment_id} (${file ? "your key" : "ephemeral key"}) as ${enrolled.issuer_did}`;
    $("submit").disabled = false;
  } catch (error) {
    $("key-state").textContent = `Enrollment failed: ${error.message}`;
  }
});

$("report").addEventListener("submit", async (event) => {
  event.preventDefault();
  $("outcome").textContent = "";
  $("bundle-link").hidden = true;
  setStages([]);

  try {
    const prepared = await post("/api/prepare", {
      enrollment_id: state.enrollmentId,
      title: $("title").value,
      body: $("body").value,
      component: $("component").value,
      severity: $("severity").value,
      fingerprint: $("fingerprint").value,
      references: $("references")
        .value.split("\n")
        .map((line) => line.trim())
        .filter(Boolean),
    });

    // The only thing this key ever signs.
    const signature = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      state.key.privateKey,
      b64decode(prepared.to_be_signed_b64),
    );

    const result = await post("/api/submit", {
      prepare_id: prepared.prepare_id,
      signature_b64: b64encode(signature),
    });

    setStages([
      {
        name: "prepare",
        detail: `${prepared.disclosure_count} disclosures held back.`,
      },
      ...result.stages,
    ]);
    $("outcome").textContent =
      `Submitted ${result.submission_id} at transaction ${result.txid}.`;

    const link = $("bundle-link");
    link.href = `/api/submissions/${result.submission_id}/bundle`;
    link.textContent = `Download the proof bundle (${result.bundle_bytes} bytes)`;
    link.hidden = false;
  } catch (error) {
    $("outcome").textContent = `Failed: ${error.message}`;
  }
});
