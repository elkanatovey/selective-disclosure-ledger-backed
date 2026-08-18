// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// The reader's side: check a signed release, then show what it opens and what
// it holds back. The trust anchor is supplied by the reader, never by the file.

"use strict";

const $ = (id) => document.getElementById(id);

function b64encode(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
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

function renderChecks(report) {
  const list = $("checks");
  list.replaceChildren();
  for (const check of report.checks) {
    const item = document.createElement("li");
    item.className = `check ${check.status}`;

    const label = document.createElement("strong");
    label.textContent = `${check.label}: ${check.status}`;

    const detail = document.createElement("div");
    detail.className = "hint";
    detail.textContent = check.detail ?? "";

    item.append(label, detail);
    list.append(item);
  }
}

function renderContents(contents) {
  const fields = $("fields");
  fields.replaceChildren();
  for (const field of contents.fields) {
    const row = document.createElement("p");
    row.className = "field";

    const label = document.createElement("span");
    label.textContent = `${field.label}: `;

    const value = document.createElement("span");
    if (field.disclosed) {
      value.textContent = field.value;
    } else {
      value.className = "bar";
      value.textContent = "\u00a0".repeat(8);
      value.title = "committed to, not opened by this release";
    }

    row.append(label, value);
    fields.append(row);
  }

  const body = $("body-text");
  body.replaceChildren();
  const chunkSize = contents.chunk_size ?? 6;
  for (const chunk of contents.body.chunks ?? []) {
    const span = document.createElement("span");
    if (chunk.disclosed) {
      span.textContent = chunk.text;
    } else {
      span.className = "bar";
      // The length is unknown once withheld: at most one chunk of text.
      span.textContent = "\u00a0".repeat(chunkSize);
      span.title = `chunk ${chunk.index}: committed to, not opened`;
    }
    body.append(span);
  }
}

$("verify").addEventListener("click", async () => {
  const release = $("release-file").files[0];
  const root = $("root-file").files[0];
  if (!release || !root) {
    $("verify-state").textContent =
      "Choose both a release and the MSRC root certificate.";
    return;
  }
  $("verify-state").textContent = "Checking...";
  try {
    const scitt = $("scitt-file").files[0];
    const result = await post("/api/verify", {
      release_b64: b64encode(await release.arrayBuffer()),
      msrc_root_pem: await root.text(),
      scitt_key_pem: scitt ? await scitt.text() : "",
    });

    renderChecks(result.report);
    $("checks-section").hidden = false;

    if (result.contents) {
      renderContents(result.contents);
      $("contents-section").hidden = false;
    } else {
      $("contents-section").hidden = true;
    }

    const attribution = result.attributable
      ? ""
      : " Nobody is named as the discloser, so this release is unattributable.";
    $("verify-state").textContent = result.passed
      ? `Every check this tool owns passed.${attribution}`
      : `Failed: ${result.report.detail ?? "a check did not pass"}.${attribution}`;
  } catch (error) {
    $("verify-state").textContent = `Could not check that: ${error.message}`;
    $("checks-section").hidden = true;
    $("contents-section").hidden = true;
  }
});
