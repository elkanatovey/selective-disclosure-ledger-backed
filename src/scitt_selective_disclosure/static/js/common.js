// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Shared helpers. This file performs no cryptographic work: every security
// artifact is handled server side by the C++ selective-disclosure tool.

(function (global) {
  "use strict";

  function byId(id) {
    return document.getElementById(id);
  }

  function clear(node) {
    while (node.firstChild) {
      node.removeChild(node.firstChild);
    }
  }

  function setStatus(node, message, tone) {
    if (!node) {
      return;
    }
    node.textContent = message;
    if (tone) {
      node.setAttribute("data-tone", tone);
    } else {
      node.removeAttribute("data-tone");
    }
  }

  function badge(status) {
    var span = document.createElement("span");
    span.className = "badge";
    span.setAttribute("data-status", status || "unknown");
    span.textContent = status || "unknown";
    return span;
  }

  function cell(row, value) {
    var td = document.createElement("td");
    td.textContent = value === null || value === undefined ? "" : String(value);
    row.appendChild(td);
    return td;
  }

  function describeError(payload, response) {
    if (payload && typeof payload === "object") {
      var message = payload.message || payload.error;
      if (message) {
        return payload.detail ? message + " " + payload.detail : message;
      }
    }
    return "Request failed with status " + response.status + ".";
  }

  async function request(url, options) {
    var response = await fetch(url, options);
    var payload = null;
    var contentType = response.headers.get("content-type") || "";
    if (contentType.indexOf("application/json") !== -1) {
      try {
        payload = await response.json();
      } catch (error) {
        payload = null;
      }
    }
    return { ok: response.ok, status: response.status, payload: payload };
  }

  async function getJson(url) {
    return request(url, { method: "GET", headers: { accept: "application/json" } });
  }

  async function postForm(url, formData) {
    return request(url, { method: "POST", body: formData });
  }

  async function postJson(url, body) {
    return request(url, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify(body),
    });
  }

  function requireFile(input, label, statusNode) {
    if (!input || !input.files || input.files.length !== 1) {
      setStatus(statusNode, "Choose a " + label + " first.", "fail");
      return null;
    }
    return input.files[0];
  }

  global.demo = {
    byId: byId,
    clear: clear,
    setStatus: setStatus,
    badge: badge,
    cell: cell,
    describeError: describeError,
    getJson: getJson,
    postForm: postForm,
    postJson: postJson,
    requireFile: requireFile,
  };
})(window);
