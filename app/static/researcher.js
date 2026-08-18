// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// The researcher's key lives here and nowhere else. It is generated
// non-extractable, so this script cannot read it out either: it can only ask
// WebCrypto to sign the bytes the server prepared.

"use strict";

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
  $("key-state").textContent = "Generating...";
  try {
    // Non-extractable: the private half cannot be exported, by anyone.
    state.key = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign"],
    );
    const spki = await crypto.subtle.exportKey("spki", state.key.publicKey);
    const enrolled = await post("/api/enroll", {
      public_key_pem: toPem(spki),
      subject: "Demo researcher",
    });
    state.enrollmentId = enrolled.enrollment_id;
    $("key-state").textContent =
      `Enrolled ${enrolled.enrollment_id} as ${enrolled.issuer_did}`;
    $("submit").disabled = false;
  } catch (error) {
    $("key-state").textContent = `Enrollment failed: ${error.message}`;
  }
});

$("report").addEventListener("submit", async (event) => {
  event.preventDefault();
  $("outcome").textContent = "";
  $("inspection").textContent = "";
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

    const inspected = await fetch(`/api/submissions/${result.submission_id}`);
    if (inspected.ok) {
      const document_ = await inspected.json();
      $("inspection").textContent = JSON.stringify(document_.inspection, null, 2);
    }
  } catch (error) {
    $("outcome").textContent = `Failed: ${error.message}`;
  }
});
