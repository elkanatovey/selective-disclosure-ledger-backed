// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// MSRC's side: open a bundle, choose what to withhold, and sign what is left.
// Withholding drops the disclosure from the exported bundle; the black bars
// are a preview of what a later reader will not be able to open.

"use strict";

const state = { bundleB64: null, chunks: [], fields: [], redacted: new Set() };

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
    $("load-state").textContent = `Could not load that bundle: ${error.message}`;
    $("editor").hidden = true;
    $("export-section").hidden = true;
  }
});

$("export").addEventListener("click", async () => {
  $("export-state").textContent = "Signing...";
  try {
    const result = await post("/api/msrc/release", {
      bundle_b64: state.bundleB64,
      redact_fields: state.fields
        .map((field) => field.name)
        .filter((name) => state.redacted.has(key("field", name))),
      redact_body_chunks: state.chunks
        .map((chunk) => chunk.index)
        .filter((index) => state.redacted.has(key("chunk", index))),
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
      `Signed ${result.presented_bytes} bytes of bundle into a ${result.release_bytes}-byte release.`;
  } catch (error) {
    $("export-state").textContent = `Export failed: ${error.message}`;
  }
});
