// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// MSRC page. Field and chunk rendering comes from the server side inspection
// report; this script only tracks which stable indices to drop.

(function () {
  "use strict";

  var api = window.demo;
  var currentBundleId = null;
  var chunkButtons = [];

  var importForm = api.byId("import-form");
  var bundleInput = api.byId("bundle-file");
  var refreshStored = api.byId("refresh-stored");
  var storedBody = document.querySelector("#stored-table tbody");
  var loadStatus = api.byId("load-status");
  var panel = api.byId("disclosure-panel");
  var fieldList = api.byId("field-list");
  var bodyChunks = api.byId("body-chunks");
  var redactSelection = api.byId("redact-selection");
  var restoreSelection = api.byId("restore-selection");
  var clearSelection = api.byId("clear-selection");
  var presentButton = api.byId("present-button");
  var presentationLink = api.byId("presentation-link");
  var presentStatus = api.byId("present-status");

  function renderFields(fields) {
    api.clear(fieldList);
    fields.forEach(function (field) {
      var item = document.createElement("li");
      var input = document.createElement("input");
      input.type = "checkbox";
      input.id = "redact-field-" + field.name;
      input.value = field.name;
      input.className = "field-toggle";
      input.disabled = !field.disclosed;
      var label = document.createElement("label");
      label.setAttribute("for", input.id);
      label.textContent = field.disclosed
        ? "Drop " + field.label
        : field.label + " (already dropped)";
      var value = document.createElement("span");
      value.className = "value";
      value.textContent = field.disclosed ? field.value || "" : "redacted";
      item.appendChild(input);
      item.appendChild(label);
      item.appendChild(value);
      fieldList.appendChild(item);
    });
  }

  function renderChunks(chunks) {
    api.clear(bodyChunks);
    chunkButtons = [];
    chunks.forEach(function (chunk) {
      var button = document.createElement("button");
      button.type = "button";
      button.className = "chunk";
      button.textContent = chunk.text;
      button.setAttribute("data-index", String(chunk.index));
      button.setAttribute("data-disclosed", chunk.disclosed ? "true" : "false");
      button.setAttribute("aria-pressed", chunk.disclosed ? "false" : "true");
      button.setAttribute("aria-label", "Chunk " + chunk.index + ": " + chunk.text);
      button.disabled = !chunk.disclosed;
      button.addEventListener("click", function () {
        var pressed = button.getAttribute("aria-pressed") === "true";
        button.setAttribute("aria-pressed", pressed ? "false" : "true");
      });
      chunkButtons.push(button);
      bodyChunks.appendChild(button);
    });
  }

  function renderInspection(payload) {
    currentBundleId = payload.bundle_id;
    renderFields(payload.inspection.fields || []);
    renderChunks(payload.inspection.body_chunks || []);
    panel.hidden = false;
    presentationLink.hidden = true;
    api.setStatus(presentStatus, "", null);
    api.setStatus(
      loadStatus,
      "Loaded " +
        payload.bundle_bytes +
        " bytes from " +
        payload.source +
        ". Chunk size is " +
        payload.inspection.chunk_size +
        " characters.",
      "pass",
    );
  }

  async function inspectUpload(event) {
    event.preventDefault();
    var file = api.requireFile(bundleInput, "bundle file", loadStatus);
    if (!file) {
      return;
    }
    var data = new FormData();
    data.append("bundle", file);
    api.setStatus(loadStatus, "Inspecting bundle...", null);
    var result = await api.postForm("/api/msrc/inspect", data);
    if (!result.ok || !result.payload) {
      api.setStatus(loadStatus, api.describeError(result.payload, result), "fail");
      return;
    }
    renderInspection(result.payload);
  }

  async function inspectStored(submissionId) {
    api.setStatus(loadStatus, "Fetching stored submission...", null);
    var result = await api.postForm(
      "/api/msrc/submissions/" + submissionId + "/inspect",
      new FormData(),
    );
    if (!result.ok || !result.payload) {
      api.setStatus(loadStatus, api.describeError(result.payload, result), "fail");
      return;
    }
    renderInspection(result.payload);
  }

  async function refreshStoredList() {
    var result = await api.getJson("/api/msrc/submissions");
    api.clear(storedBody);
    if (!result.ok || !result.payload) {
      api.setStatus(loadStatus, api.describeError(result.payload, result), "fail");
      return;
    }
    result.payload.submissions.forEach(function (submission) {
      var row = document.createElement("tr");
      api.cell(row, submission.created_at);
      api.cell(row, submission.title);
      api.cell(row, submission.scitt_txid || "");
      api.cell(row, submission.bundle_bytes);
      var actionCell = document.createElement("td");
      var button = document.createElement("button");
      button.type = "button";
      button.textContent = "Inspect";
      button.addEventListener("click", function () {
        inspectStored(submission.submission_id);
      });
      actionCell.appendChild(button);
      row.appendChild(actionCell);
      storedBody.appendChild(row);
    });
  }

  function applyToSelection(pressed) {
    var selection = window.getSelection();
    if (!selection || selection.rangeCount === 0 || selection.isCollapsed) {
      api.setStatus(
        presentStatus,
        "Select a passage in the body first, or activate individual chunks.",
        "fail",
      );
      return;
    }
    var range = selection.getRangeAt(0);
    var changed = 0;
    chunkButtons.forEach(function (button) {
      if (button.disabled) {
        return;
      }
      if (range.intersectsNode(button)) {
        button.setAttribute("aria-pressed", pressed ? "true" : "false");
        changed += 1;
      }
    });
    selection.removeAllRanges();
    api.setStatus(
      presentStatus,
      changed + (pressed ? " chunks marked for removal." : " chunks restored."),
      null,
    );
  }

  function clearAll() {
    chunkButtons.forEach(function (button) {
      if (!button.disabled) {
        button.setAttribute("aria-pressed", "false");
      }
    });
    document.querySelectorAll(".field-toggle").forEach(function (input) {
      input.checked = false;
    });
    api.setStatus(presentStatus, "All redactions cleared.", null);
  }

  function selection() {
    var fields = [];
    document.querySelectorAll(".field-toggle").forEach(function (input) {
      if (input.checked && !input.disabled) {
        fields.push(input.value);
      }
    });
    var chunks = [];
    chunkButtons.forEach(function (button) {
      if (!button.disabled && button.getAttribute("aria-pressed") === "true") {
        chunks.push(Number(button.getAttribute("data-index")));
      }
    });
    return { redact_fields: fields, redact_body_chunks: chunks };
  }

  async function present() {
    if (!currentBundleId) {
      api.setStatus(presentStatus, "Load a bundle first.", "fail");
      return;
    }
    presentButton.disabled = true;
    var result = await api.postJson(
      "/api/msrc/imports/" + currentBundleId + "/present",
      selection(),
    );
    presentButton.disabled = false;
    if (!result.ok || !result.payload) {
      api.setStatus(presentStatus, api.describeError(result.payload, result), "fail");
      return;
    }
    presentationLink.href = result.payload.download_url;
    presentationLink.hidden = false;
    api.setStatus(
      presentStatus,
      "Presented bundle is " +
        result.payload.bundle_bytes +
        " bytes. Dropped " +
        result.payload.redacted_fields.length +
        " fields and " +
        result.payload.redacted_body_chunks.length +
        " body chunks.",
      "pass",
    );
  }

  importForm.addEventListener("submit", inspectUpload);
  refreshStored.addEventListener("click", refreshStoredList);
  redactSelection.addEventListener("click", function () {
    applyToSelection(true);
  });
  restoreSelection.addEventListener("click", function () {
    applyToSelection(false);
  });
  clearSelection.addEventListener("click", clearAll);
  presentButton.addEventListener("click", present);
  refreshStoredList();
})();
