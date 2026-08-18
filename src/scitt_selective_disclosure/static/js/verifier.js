// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Verifier page. Two independent engines report: the C++ selective-disclosure
// tool and the official upstream SCITT verifier. Their verdicts are rendered
// separately so a partial failure is never presented as an overall success.
// This file performs no cryptographic work of any kind.

(function () {
  "use strict";

  var api = window.demo;

  var verifyForm = api.byId("verify-form");
  var bundleInput = api.byId("verify-bundle");
  var msrcRootInput = api.byId("verify-msrc-root");
  var scittTrustInput = api.byId("verify-scitt-trust");
  var verifyStatus = api.byId("verify-status");
  var checkBody = document.querySelector("#check-table tbody");
  var sourceBody = document.querySelector("#source-table tbody");
  var reportLink = api.byId("report-link");
  var reportForm = api.byId("report-form");
  var reportInput = api.byId("report-file");

  function renderRows(body, entries) {
    api.clear(body);
    entries.forEach(function (entry) {
      var row = document.createElement("tr");
      api.cell(row, entry.label);
      var statusCell = document.createElement("td");
      statusCell.appendChild(api.badge(entry.status));
      row.appendChild(statusCell);
      api.cell(row, entry.detail || "");
      body.appendChild(row);
    });
  }

  function summarise(report) {
    var checks = report.checks || [];
    var passed = checks.filter(function (check) {
      return check.status === "pass";
    }).length;
    return passed + " of " + checks.length + " checks passed";
  }

  function renderReport(report, origin) {
    renderRows(sourceBody, report.sources || []);
    renderRows(checkBody, report.checks || []);
    var overall = report.overall || "unknown";
    api.setStatus(
      verifyStatus,
      origin + ": overall result is " + overall + " (" + summarise(report) + ").",
      overall === "pass" ? "pass" : "fail",
    );
  }

  async function verify(event) {
    event.preventDefault();
    var bundle = api.requireFile(bundleInput, "bundle file", verifyStatus);
    var msrcRoot = api.requireFile(msrcRootInput, "MSRC root file", verifyStatus);
    var scittTrust = api.requireFile(scittTrustInput, "SCITT trust file", verifyStatus);
    if (!bundle || !msrcRoot || !scittTrust) {
      return;
    }
    var data = new FormData();
    data.append("bundle", bundle);
    data.append("msrc_root", msrcRoot);
    data.append("scitt_trust", scittTrust);
    api.setStatus(verifyStatus, "Verifying...", null);
    reportLink.hidden = true;
    var result = await api.postForm("/api/verifier/verify", data);
    if (!result.ok || !result.payload) {
      api.setStatus(verifyStatus, api.describeError(result.payload, result), "fail");
      return;
    }
    renderReport(result.payload.report, "Verification");
    reportLink.href = result.payload.report_url + "/download";
    reportLink.hidden = false;
  }

  async function importReport(event) {
    event.preventDefault();
    var file = api.requireFile(reportInput, "report file", verifyStatus);
    if (!file) {
      return;
    }
    var data = new FormData();
    data.append("report", file);
    var result = await api.postForm("/api/verifier/reports/import", data);
    if (!result.ok || !result.payload) {
      api.setStatus(verifyStatus, api.describeError(result.payload, result), "fail");
      return;
    }
    reportLink.hidden = true;
    renderReport(result.payload, "Imported report");
  }

  verifyForm.addEventListener("submit", verify);
  reportForm.addEventListener("submit", importReport);
})();
