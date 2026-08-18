// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Researcher page. One button performs the whole submission: sign, register
// with SCITT, then deliver the bundle to the mock MSRC service.

(function () {
  "use strict";

  var api = window.demo;
  var enrollmentId = null;
  var lastSubmission = null;

  var form = api.byId("researcher-form");
  var privateKeyInput = api.byId("private-key");
  var subjectInput = api.byId("subject");
  var enrollButton = api.byId("enroll-button");
  var enrollmentStatus = api.byId("enrollment-status");
  var submitButton = api.byId("submit-button");
  var submitStatus = api.byId("submit-status");
  var stageList = api.byId("stage-list");
  var recovery = api.byId("recovery");
  var recoveryMessage = api.byId("recovery-message");
  var bundleLink = api.byId("bundle-link");
  var statementLink = api.byId("statement-link");
  var transparentLink = api.byId("transparent-link");
  var retryButton = api.byId("retry-button");
  var refreshButton = api.byId("refresh-submissions");
  var submissionsBody = document.querySelector("#submissions-table tbody");

  function toneForStatus(status) {
    if (status === "complete") {
      return "pass";
    }
    if (status === "partial") {
      return "partial";
    }
    return "fail";
  }

  function renderStages(stages) {
    api.clear(stageList);
    (stages || []).forEach(function (stage) {
      var item = document.createElement("li");
      item.appendChild(api.badge(stage.status));
      var label = document.createElement("span");
      label.textContent = " " + stage.label;
      item.appendChild(label);
      if (stage.detail) {
        var detail = document.createElement("p");
        detail.className = "hint";
        detail.textContent = stage.detail;
        item.appendChild(detail);
      }
      stageList.appendChild(item);
    });
  }

  function renderResult(result) {
    if (!result) {
      return;
    }
    lastSubmission = result;
    renderStages(result.stages);
    api.setStatus(submitStatus, result.message, toneForStatus(result.status));

    recovery.hidden = false;
    if (result.status === "complete") {
      recoveryMessage.textContent =
        "Everything completed. Keep the registered statement and the " +
        "transparency token: a verifier needs both exact byte sequences.";
    } else if (result.scitt && result.scitt.registered) {
      recoveryMessage.textContent =
        "SCITT registration succeeded (transaction " +
        result.scitt.txid +
        "). The remaining steps did not complete, so this submission is not " +
        "finished. Download the bundle or retry delivery.";
    } else {
      recoveryMessage.textContent =
        "SCITT did not register this statement, so nothing was sent to MSRC.";
    }

    if (result.bundle_url) {
      bundleLink.href = result.bundle_url;
      bundleLink.hidden = false;
    } else {
      bundleLink.hidden = true;
    }
    if (result.statement_url) {
      statementLink.href = result.statement_url;
      statementLink.hidden = false;
    } else {
      statementLink.hidden = true;
    }
    if (result.transparent_url) {
      transparentLink.href = result.transparent_url;
      transparentLink.hidden = false;
    } else {
      transparentLink.hidden = true;
    }
    retryButton.hidden = !result.retry_url;
  }

  async function enroll() {
    var file = api.requireFile(privateKeyInput, "private key file", enrollmentStatus);
    if (!file) {
      return;
    }
    enrollButton.disabled = true;
    api.setStatus(enrollmentStatus, "Deriving the public key locally...", null);
    var data = new FormData();
    data.append("private_key", file);
    data.append("subject", subjectInput.value);
    var result = await api.postForm("/api/researcher/enroll", data);
    enrollButton.disabled = false;
    if (!result.ok || !result.payload) {
      api.setStatus(
        enrollmentStatus,
        api.describeError(result.payload, result),
        "fail",
      );
      return;
    }
    enrollmentId = result.payload.enrollment_id;
    submitButton.disabled = false;
    api.setStatus(
      enrollmentStatus,
      "Enrolled. The mock MSRC issued a leaf certificate of " +
        result.payload.leaf_certificate_bytes +
        " bytes from the derived public key. The private key was not sent.",
      "pass",
    );
  }

  async function submit(event) {
    event.preventDefault();
    if (!enrollmentId) {
      api.setStatus(submitStatus, "Enroll before submitting.", "fail");
      return;
    }
    var file = api.requireFile(privateKeyInput, "private key file", submitStatus);
    if (!file) {
      return;
    }
    submitButton.disabled = true;
    api.setStatus(submitStatus, "Signing, registering and delivering...", null);
    var data = new FormData();
    data.append("enrollment_id", enrollmentId);
    data.append("private_key", file);
    ["title", "body", "component", "severity", "fingerprint", "references"].forEach(
      function (name) {
        data.append(name, api.byId(name).value);
      },
    );
    var result = await api.postForm("/api/researcher/submit", data);
    submitButton.disabled = false;
    if (result.payload && result.payload.stages) {
      renderResult(result.payload);
    } else {
      api.setStatus(submitStatus, api.describeError(result.payload, result), "fail");
    }
    await refresh();
  }

  async function retry() {
    if (!lastSubmission || !lastSubmission.retry_url) {
      return;
    }
    retryButton.disabled = true;
    api.setStatus(submitStatus, "Retrying delivery to MSRC...", null);
    var result = await api.postForm(lastSubmission.retry_url, new FormData());
    retryButton.disabled = false;
    if (result.payload && result.payload.stages) {
      renderResult(result.payload);
    } else {
      api.setStatus(submitStatus, api.describeError(result.payload, result), "fail");
    }
    await refresh();
  }

  function downloadCell(row, submission) {
    var td = document.createElement("td");
    var statement = document.createElement("a");
    statement.href =
      "/api/researcher/submissions/" + submission.submission_id + "/statement";
    statement.textContent = "statement";
    statement.setAttribute("download", "");
    td.appendChild(statement);
    if (submission.scitt_txid) {
      td.appendChild(document.createTextNode(" "));
      var token = document.createElement("a");
      token.href =
        "/api/researcher/submissions/" + submission.submission_id + "/transparent";
      token.textContent = "token";
      token.setAttribute("download", "");
      td.appendChild(token);
    }
    if (submission.bundle_bytes) {
      td.appendChild(document.createTextNode(" "));
      var bundle = document.createElement("a");
      bundle.href =
        "/api/researcher/submissions/" + submission.submission_id + "/bundle";
      bundle.textContent = "bundle";
      bundle.setAttribute("download", "");
      td.appendChild(bundle);
    }
    row.appendChild(td);
  }

  async function refresh() {
    var result = await api.getJson("/api/researcher/submissions");
    if (!result.ok || !result.payload) {
      return;
    }
    api.clear(submissionsBody);
    result.payload.submissions.forEach(function (submission) {
      var row = document.createElement("tr");
      api.cell(row, submission.created_at);
      api.cell(row, submission.title);
      var statusCell = document.createElement("td");
      statusCell.appendChild(api.badge(submission.status));
      row.appendChild(statusCell);
      api.cell(row, submission.scitt_txid || "not registered");
      downloadCell(row, submission);
      submissionsBody.appendChild(row);
    });
  }

  enrollButton.addEventListener("click", enroll);
  form.addEventListener("submit", submit);
  retryButton.addEventListener("click", retry);
  refreshButton.addEventListener("click", refresh);
  refresh();
})();
