const state = {
  currentPath: "",
  selectedPath: "",
  selectedIsDir: true,
  entries: [],
};

const rootDirLabel = document.getElementById("rootDirLabel");
const breadcrumbs = document.getElementById("breadcrumbs");
const fileList = document.getElementById("fileList");
const selectedTarget = document.getElementById("selectedTarget");
const modeSelect = document.getElementById("modeSelect");
const runButton = document.getElementById("runButton");
const statusLine = document.getElementById("statusLine");
const filePreview = document.getElementById("filePreview");
const summaryGrid = document.getElementById("summaryGrid");
const findingList = document.getElementById("findingList");
const findingsCount = document.getElementById("findingsCount");
const rawJson = document.getElementById("rawJson");
const warningBox = document.getElementById("warningBox");
const artifactBox = document.getElementById("artifactBox");
const selectCurrentDirBtn = document.getElementById("selectCurrentDirBtn");
const cancelButton = document.getElementById("cancelButton");
const runButtonLabel = runButton.textContent;
const cancelButtonLabel = cancelButton.textContent;

let runStartedAt = null;
let runTimerId = null;
let cancelRequested = false;

function escapeHtml(value) {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function setStatus(text) {
  statusLine.textContent = text;
}

function formatElapsed(ms) {
  const totalSeconds = Math.max(0, Math.floor(ms / 1000));
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  if (!minutes) {
    return `${seconds}s`;
  }
  return `${minutes}m ${seconds}s`;
}

function startRunTimer(mode, targetPath) {
  stopRunTimer();
  runStartedAt = Date.now();
  cancelRequested = false;
  runButton.textContent = "Running...";
  cancelButton.textContent = cancelButtonLabel;
  cancelButton.disabled = false;
  const targetLabel = targetPath || ".";
  const updateStatus = () => {
    const elapsed = formatElapsed(Date.now() - runStartedAt);
    setStatus(`Running ${mode} analysis on ${targetLabel} · ${elapsed} elapsed`);
  };
  updateStatus();
  runTimerId = window.setInterval(updateStatus, 1000);
}

function stopRunTimer(finalMessage = null) {
  if (runTimerId != null) {
    window.clearInterval(runTimerId);
    runTimerId = null;
  }
  runStartedAt = null;
  cancelRequested = false;
  runButton.textContent = runButtonLabel;
  cancelButton.textContent = cancelButtonLabel;
  cancelButton.disabled = true;
  if (finalMessage) {
    setStatus(finalMessage);
  }
}

async function cancelAnalysis() {
  if (runStartedAt == null || cancelRequested) {
    return;
  }

  cancelRequested = true;
  cancelButton.disabled = true;
  cancelButton.textContent = "Cancelling...";

  try {
    const response = await fetch("/api/analyze/cancel", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
    });
    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.error || "Failed to cancel analysis");
    }
    setStatus(payload.message || "Cancellation requested.");
  } catch (error) {
    cancelRequested = false;
    cancelButton.disabled = false;
    cancelButton.textContent = cancelButtonLabel;
    setStatus(`Cancellation failed: ${error.message}`);
  }
}

function toClassToken(value, fallback = "unknown") {
  const normalized = String(value || fallback)
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return normalized || fallback;
}

function formatSeverityTitle(severity) {
  if (!severity || severity === "unknown") {
    return "Unspecified";
  }
  return severity
    .split("-")
    .map((segment) => segment.charAt(0).toUpperCase() + segment.slice(1))
    .join(" ");
}

function setSelectedTarget(path, isDir) {
  state.selectedPath = path;
  state.selectedIsDir = isDir;
  const label = path || ".";
  selectedTarget.value = isDir ? `${label} (directory)` : label;
  renderEntries();
  if (!isDir && path) {
    loadPreview(path);
  } else {
    filePreview.textContent = "Directory selected. Run analysis on the folder or pick a Solidity file to preview it.";
  }
}

function renderBreadcrumbs() {
  const segments = state.currentPath ? state.currentPath.split("/") : [];
  const crumbs = [{ label: ".", path: "" }];
  let cursor = "";
  for (const segment of segments) {
    cursor = cursor ? `${cursor}/${segment}` : segment;
    crumbs.push({ label: segment, path: cursor });
  }

  breadcrumbs.innerHTML = crumbs
    .map(
      ({ label, path }) =>
        `<button class="crumb" data-path="${escapeHtml(path)}">${escapeHtml(label)}</button>`
    )
    .join("");

  breadcrumbs.querySelectorAll(".crumb").forEach((button) => {
    button.addEventListener("click", () => {
      loadFiles(button.dataset.path || "");
    });
  });
}

function renderEntries() {
  if (!state.entries.length) {
    fileList.innerHTML = `<p class="empty-state">No Solidity files or subdirectories were found here.</p>`;
    return;
  }

  fileList.innerHTML = state.entries
    .map((entry) => {
      const active = entry.relative_path === state.selectedPath ? "active" : "";
      const meta = entry.is_dir ? "Directory" : "Solidity file";
      return `
        <button class="file-item ${active}" data-path="${escapeHtml(entry.relative_path)}" data-dir="${entry.is_dir}">
          <div class="file-name">${escapeHtml(entry.name)}</div>
          <div class="file-meta">${meta}</div>
        </button>
      `;
    })
    .join("");

  fileList.querySelectorAll(".file-item").forEach((button) => {
    button.addEventListener("click", () => {
      const path = button.dataset.path || "";
      const isDir = button.dataset.dir === "true";
      if (isDir) {
        loadFiles(path);
      } else {
        setSelectedTarget(path, false);
      }
    });
  });
}

async function loadFiles(path = "") {
  setStatus("Loading workspace entries...");
  const response = await fetch(`/api/files?path=${encodeURIComponent(path)}`);
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.error || "Failed to load workspace entries");
  }

  rootDirLabel.textContent = payload.root_dir;
  state.currentPath = payload.current_path || "";
  state.entries = payload.entries || [];

  renderBreadcrumbs();
  renderEntries();
  setSelectedTarget(state.currentPath, true);
  setStatus("Current folder selected. Pick a Solidity file to analyze just one contract.");
}

async function loadPreview(path) {
  try {
    const response = await fetch(`/api/file?path=${encodeURIComponent(path)}`);
    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.error || "Failed to load file preview");
    }
    filePreview.textContent = payload.content;
  } catch (error) {
    filePreview.textContent = `Preview unavailable: ${error.message}`;
  }
}

function renderSummary(cards) {
  if (!cards.length) {
    summaryGrid.innerHTML = `<p class="empty-state">Run an analysis to populate summary cards.</p>`;
    return;
  }
  summaryGrid.innerHTML = cards
    .map(
      (card) => `
        <article class="summary-card">
          <p class="summary-label">${escapeHtml(card.label)}</p>
          <p class="summary-value">${escapeHtml(card.value)}</p>
        </article>
      `
    )
    .join("");
}

function renderWarnings(warnings) {
  if (!warnings.length) {
    warningBox.classList.add("hidden");
    warningBox.innerHTML = "";
    return;
  }
  warningBox.classList.remove("hidden");
  warningBox.innerHTML = `
    <strong>Analyzer warnings</strong>
    <ul class="artifact-list">
      ${warnings.map((warning) => `<li>${escapeHtml(warning)}</li>`).join("")}
    </ul>
  `;
}

function renderArtifacts(runDir, artifacts) {
  if (!artifacts.length) {
    artifactBox.classList.add("hidden");
    artifactBox.innerHTML = "";
    return;
  }
  artifactBox.classList.remove("hidden");
  artifactBox.innerHTML = `
    <strong>Run artifacts${runDir ? ` · ${escapeHtml(runDir)}` : ""}</strong>
    <ul class="artifact-list">
      ${artifacts
        .map((artifact) => `<li>${escapeHtml(artifact.name)} <span class="file-meta">${escapeHtml(artifact.relative_path)}</span></li>`)
        .join("")}
    </ul>
  `;
}

function renderFindings(findings) {
  findingsCount.textContent = String(findings.length);
  if (!findings.length) {
    findingList.innerHTML = `<p class="empty-state">No findings were returned for this run.</p>`;
    return;
  }

  const severityOrder = ["high", "medium", "low", "unknown"];
  const grouped = new Map();

  for (const finding of findings) {
    const severity = toClassToken(finding.severity || "unknown");
    if (!grouped.has(severity)) {
      grouped.set(severity, []);
    }
    grouped.get(severity).push(finding);
  }

  const orderedSeverities = [
    ...severityOrder.filter((severity) => grouped.has(severity)),
    ...Array.from(grouped.keys())
      .filter((severity) => !severityOrder.includes(severity))
      .sort(),
  ];

  const sections = [];
  for (const severity of orderedSeverities) {
    const items = grouped.get(severity) || [];
    if (!items.length) {
      continue;
    }

    const title = `${formatSeverityTitle(severity)} Severity`;
    const cards = items
      .map((finding) => {
        const severityLabel = finding.severity || "unknown";
        const severityClass = toClassToken(severityLabel);
        const labels = [
          `<span class="badge kind">${escapeHtml(finding.kind)}</span>`,
          `<span class="badge layer">${escapeHtml(finding.layer)}</span>`,
          `<span class="badge severity ${escapeHtml(severityClass)}">${escapeHtml(severityLabel)}</span>`,
        ];
        if (finding.confidence) {
          const confidenceClass = toClassToken(finding.confidence);
          labels.push(
            `<span class="badge confidence ${escapeHtml(confidenceClass)}">confidence: ${escapeHtml(finding.confidence)}</span>`
          );
        }
        if (finding.category) {
          labels.push(`<span class="badge category">${escapeHtml(finding.category)}</span>`);
        }

        const meta = [
          finding.function ? `function: ${finding.function}` : null,
          finding.file ? `file: ${finding.file}` : null,
          finding.start != null ? `start: ${finding.start}` : null,
          finding.end != null ? `end: ${finding.end}` : null,
          finding.evidence ? `evidence: ${finding.evidence}` : null,
        ]
          .filter(Boolean)
          .map((value) => escapeHtml(String(value)))
          .join(" · ");

        const confidenceRow = finding.confidence
          ? `<div class="finding-confidence-row">Confidence <strong>${escapeHtml(finding.confidence)}</strong></div>`
          : "";

        return `
          <article class="finding-card ${escapeHtml(severityClass)}">
            <div class="finding-head">${labels.join("")}</div>
            ${confidenceRow}
            <p class="finding-message">${escapeHtml(finding.message)}</p>
            <div class="finding-meta">${meta || "No location metadata"}</div>
          </article>
        `;
      })
      .join("");

    sections.push(`
      <section class="severity-group ${escapeHtml(severity)}">
        <header class="severity-header">
          <div>
            <p class="severity-kicker">Severity Group</p>
            <h3>${escapeHtml(title)}</h3>
          </div>
          <span class="severity-count">${items.length}</span>
        </header>
        <div class="severity-group-list">
          ${cards}
        </div>
      </section>
    `);
  }

  findingList.innerHTML = sections.join("");
}

async function runAnalysis() {
  const targetPath = state.selectedPath || state.currentPath;
  if (!targetPath && targetPath !== "") {
    setStatus("Choose a target before running the analyzer.");
    return;
  }

  runButton.disabled = true;
  startRunTimer(modeSelect.value, targetPath || ".");

  try {
    const response = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        path: targetPath,
        mode: modeSelect.value,
      }),
    });
    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.error || "Analysis failed");
    }

    renderSummary(payload.summary_cards || []);
    renderFindings(payload.findings || []);
    renderWarnings(payload.warnings || []);
    renderArtifacts(payload.run_dir, payload.artifacts || []);
    rawJson.textContent = payload.raw_json || "";
    const elapsed = formatElapsed(Date.now() - runStartedAt);
    stopRunTimer(`Completed ${payload.mode} analysis for ${payload.target_path || "."} in ${elapsed}.`);
  } catch (error) {
    const cancelled = error.message.toLowerCase().includes("cancelled");
    if (cancelled) {
      renderWarnings([error.message]);
    } else {
      renderSummary([]);
      renderFindings([]);
      renderWarnings([error.message]);
      renderArtifacts(null, []);
      rawJson.textContent = "";
    }
    const elapsed = runStartedAt == null ? "0s" : formatElapsed(Date.now() - runStartedAt);
    stopRunTimer(
      cancelled
        ? `Analysis cancelled after ${elapsed}.`
        : `Analysis failed after ${elapsed}.`
    );
  } finally {
    runButton.disabled = false;
    if (runStartedAt != null) {
      stopRunTimer();
    }
  }
}

runButton.addEventListener("click", runAnalysis);
cancelButton.addEventListener("click", cancelAnalysis);
selectCurrentDirBtn.addEventListener("click", () => {
  setSelectedTarget(state.currentPath, true);
});

loadFiles().catch((error) => {
  setStatus(error.message);
  fileList.innerHTML = `<p class="empty-state">${escapeHtml(error.message)}</p>`;
});
