const state = {
  currentPath: "",
  selectedPath: "",
  selectedIsDir: true,
  selectedFinding: null,
  selectedFindingId: null,
  entries: [],
  directSubdirectories: 0,
  directSolidityFiles: 0,
  recursiveSolidityFiles: 0,
  showSuppressedWarnings: false,
  reportMarkdown: "",
  reportMarkdownFilename: "chainvet-report.md",
  reportPdfBase64: "",
  reportPdfError: "",
  reportFilename: "chainvet-report.pdf",
};

const rootDirHeader = document.getElementById("rootDirHeader");
const explorerStats = document.getElementById("explorerStats");
const breadcrumbs = document.getElementById("breadcrumbs");
const fileList = document.getElementById("fileList");
const selectedTargetHero = document.getElementById("selectedTargetHero");
const selectedTargetPath = document.getElementById("selectedTargetPath");
const selectedTargetKind = document.getElementById("selectedTargetKind");
const modeSelect = document.getElementById("modeSelect");
const activeModeLabel = document.getElementById("activeModeLabel");
const runButton = document.getElementById("runButton");
const cancelButton = document.getElementById("cancelButton");
const markdownReportButton = document.getElementById("markdownReportButton");
const pdfReportButton = document.getElementById("pdfReportButton");
const statusLine = document.getElementById("statusLine");
const progressPhase = document.getElementById("progressPhase");
const progressElapsed = document.getElementById("progressElapsed");
const progressMetaNote = document.getElementById("progressMetaNote");
const progressStateLabel = document.getElementById("runStateLabel");
const progressStateDot = document.getElementById("progressStateDot");
const progressFill = document.getElementById("progressFill");
const summaryGrid = document.getElementById("summaryGrid");
const findingList = document.getElementById("findingList");
const findingsCount = document.getElementById("findingsCount");
const findingsFilterState = document.getElementById("findingsFilterState");
const warningBox = document.getElementById("warningBox");
const findingSearch = document.getElementById("findingSearch");
const detailsPane = document.getElementById("detailsPane");
const detailsTitle = document.getElementById("detailsTitle");
const detailsSubtitle = document.getElementById("detailsSubtitle");

const runButtonLabelEl = runButton.querySelector(".lc-rb-run-label") || runButton;
const cancelButtonLabelEl = cancelButton.querySelector(".lc-rb-cancel-label") || cancelButton;
const runButtonLabel = runButtonLabelEl.textContent;
const cancelButtonLabel = cancelButtonLabelEl.textContent;

let runStartedAt = null;
let runTimerId = null;
let statusPollId = null;
let cancelRequested = false;
let latestStatusSnapshot = null;
let allFindings = [];
let latestWarnings = [];

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function basename(path) {
  if (!path) {
    return ".";
  }
  const parts = String(path).split("/").filter(Boolean);
  return parts.at(-1) || ".";
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

function formatClockElapsed(ms) {
  const totalSeconds = Math.max(0, Math.floor(ms / 1000));
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;
  return [hours, minutes, seconds].map((value) => String(value).padStart(2, "0")).join(":");
}

function clearReportDownload() {
  state.reportMarkdown = "";
  state.reportMarkdownFilename = "chainvet-report.md";
  state.reportPdfBase64 = "";
  state.reportPdfError = "";
  state.reportFilename = "chainvet-report.pdf";
  if (markdownReportButton) {
    markdownReportButton.disabled = true;
  }
  if (pdfReportButton) {
    pdfReportButton.disabled = true;
    pdfReportButton.title = "";
  }
}

function setReportDownload(markdown, markdownFilename, pdfBase64, pdfFilename, pdfError) {
  state.reportMarkdown = String(markdown || "");
  state.reportMarkdownFilename = String(markdownFilename || "chainvet-report.md");
  state.reportPdfBase64 = String(pdfBase64 || "");
  state.reportPdfError = String(pdfError || "");
  state.reportFilename = String(pdfFilename || "chainvet-report.pdf");
  if (markdownReportButton) {
    markdownReportButton.disabled = !state.reportMarkdown;
  }
  if (pdfReportButton) {
    pdfReportButton.disabled = !state.reportPdfBase64;
    pdfReportButton.title = state.reportPdfError;
  }
}

function downloadMarkdownReport() {
  if (!state.reportMarkdown) {
    setStatus("Run an analysis before exporting a Markdown report.");
    return;
  }
  const blob = new Blob([state.reportMarkdown], { type: "text/markdown;charset=utf-8" });
  downloadBlob(blob, state.reportMarkdownFilename);
  setStatus(`Downloaded ${state.reportMarkdownFilename}.`);
}

function downloadPdfReport() {
  if (!state.reportPdfBase64) {
    setStatus(state.reportPdfError || "Run an analysis before exporting a PDF report.");
    return;
  }
  const binary = atob(state.reportPdfBase64);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  const blob = new Blob([bytes], { type: "application/pdf" });
  downloadBlob(blob, state.reportFilename);
  setStatus(`Downloaded ${state.reportFilename}.`);
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function humanizeMode(mode) {
  const value = String(mode || "").trim().toLowerCase();
  if (!value) {
    return "Static";
  }
  return value.charAt(0).toUpperCase() + value.slice(1);
}

function modeLabel(mode) {
  const value = String(mode || "").trim().toLowerCase();
  switch (value) {
    case "symbolic":
      return "Symbolic Execution";
    case "fuzzing":
      return "Fuzzing Analysis";
    case "hybrid":
      return "Hybrid Analysis";
    case "static":
    default:
      return "Static Analysis";
  }
}

function padCount(value) {
  return String(Number(value || 0)).padStart(2, "0");
}

function titleCaseToken(value) {
  return String(value || "unknown")
    .split("-")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function confidenceLabel(value) {
  if (!value) {
    return null;
  }
  return `${String(value).toUpperCase()} CONF.`;
}

function setStatus(text) {
  statusLine.textContent = text;
}

function setProgressVisual(stateName, label, phaseText, elapsedMs, progressPercent = null, metaNote = null) {
  progressStateLabel.textContent = label;
  progressStateLabel.className = `lc-rb-status-name state-${stateName}`;
  progressStateDot.className = `lc-rb-dot dot-${stateName}`;
  progressPhase.textContent = phaseText;
  progressPhase.title = phaseText;
  progressElapsed.textContent = formatClockElapsed(elapsedMs || 0);
  if (stateName === "running" && progressPercent != null) {
    progressFill.className = "progress-fill progress-running-known";
    progressFill.style.width = `${Math.max(8, Math.min(100, progressPercent))}%`;
  } else {
    progressFill.className = `progress-fill progress-${stateName}`;
    progressFill.style.width = "";
  }
  progressMetaNote.textContent =
    metaNote ??
    (stateName === "running"
      ? "live analysis"
      : stateName === "complete"
        ? "results ready"
        : stateName === "cancelled"
          ? "run cancelled"
          : stateName === "failed"
            ? "run failed"
            : "standby");
}

function buildProgressMetrics(status = {}) {
  const totalTargets = Number(status.total_targets || 0);
  const completedTargets = Number(status.completed_targets || 0);
  const remainingTargets = Number(
    status.remaining_targets != null
      ? status.remaining_targets
      : Math.max(totalTargets - completedTargets, 0)
  );

  return {
    totalTargets,
    completedTargets,
    remainingTargets,
  };
}

function summarizeProgressScope(mode, targetPath, status = {}, cancelling = false) {
  const { totalTargets, completedTargets, remainingTargets } = buildProgressMetrics(status);
  const scopeLabel = basename(status.target_path || targetPath || ".");
  const currentLabel = basename(status.current_target || "");

  if (totalTargets > 1) {
    const action = cancelling ? "Cancelling" : "Running";
    const phaseText = `${action} ${humanizeMode(mode)} analysis for ${scopeLabel} · ${completedTargets}/${totalTargets} complete · ${remainingTargets} remaining`;
      const metaNote =
      currentLabel && !cancelling
        ? `Current target: ${currentLabel}`
        : `${totalTargets} target${totalTargets === 1 ? "" : "s"} queued`;
    return {
      phaseText,
      metaNote,
      progressPercent: ((completedTargets + (cancelling ? 0 : 0.35)) / totalTargets) * 100,
    };
  }

  const targetLabel = currentLabel || basename(status.target_path || targetPath || ".");
  return {
    phaseText: cancelling
      ? `Cancelling ${humanizeMode(mode)} analysis on ${targetLabel}...`
      : `Running ${humanizeMode(mode)} analysis on ${targetLabel}...`,
    metaNote: cancelling ? "Stop requested" : "Live analysis",
    progressPercent: totalTargets > 0 ? ((completedTargets + (cancelling ? 0 : 0.35)) / totalTargets) * 100 : null,
  };
}

function syncModePresentation() {
  activeModeLabel.textContent = modeLabel(modeSelect.value);
}

function syncTargetPresentation() {
  const path = state.selectedPath || state.currentPath || ".";
  selectedTargetHero.textContent = basename(path);
  selectedTargetPath.textContent = path;
  selectedTargetKind.textContent = state.selectedIsDir ? "Folder Target" : "File Target";
}

function setSelectedTarget(path, isDir) {
  state.selectedPath = path;
  state.selectedIsDir = isDir;
  state.selectedFinding = null;
  state.selectedFindingId = null;
  syncTargetPresentation();
  renderEntries();
  setStatus(
    isDir
      ? `Directory target selected: ${path || "."}`
      : `Single Solidity file selected: ${path}`
  );
  renderDetailsPane();
}

function findingId(finding, fallbackIndex = 0) {
  if (!finding) return "";
  return [
    finding.kind || "",
    finding.layer || "",
    finding.file || "",
    finding.function || "",
    finding.start ?? "",
    finding.end ?? "",
    String(finding.message || "").slice(0, 32),
    fallbackIndex,
  ].join("|");
}

function setSelectedFinding(finding, id) {
  state.selectedFinding = finding;
  state.selectedFindingId = id;
  renderDetailsPane();
  if (findingList) {
    findingList.querySelectorAll(".lc-finding").forEach((node) => {
      node.dataset.selected = node.dataset.findingId === id ? "true" : "false";
    });
  }
}

function clearSelectedFinding() {
  if (!state.selectedFinding) return;
  state.selectedFinding = null;
  state.selectedFindingId = null;
  if (findingList) {
    findingList.querySelectorAll('.lc-finding[data-selected="true"]').forEach((node) => {
      node.dataset.selected = "false";
    });
  }
  renderDetailsPane();
}

function renderDetailsPane() {
  if (!detailsPane) return;
  if (state.selectedFinding) {
    renderDetailsFinding(state.selectedFinding);
    return;
  }
  if (state.selectedPath && !state.selectedIsDir) {
    renderDetailsFile(state.selectedPath);
    return;
  }
  if (state.selectedPath || state.selectedIsDir) {
    renderDetailsDirectory(state.selectedPath || "");
    return;
  }
  renderDetailsEmpty();
}

function renderDetailsEmpty() {
  detailsPane.dataset.mode = "empty";
  if (detailsTitle) detailsTitle.textContent = "Details";
  if (detailsSubtitle) detailsSubtitle.textContent = "selected finding or file preview";
  detailsPane.innerHTML = `
    <div class="lc-details-empty">
      <p class="lc-empty-title">Nothing selected.</p>
      <p class="lc-empty-sub">Click a finding to see its details, or pick a Solidity file in the workspace to preview the source.</p>
    </div>
  `;
}

function renderDetailsDirectory(path) {
  detailsPane.dataset.mode = "directory";
  const displayPath = path || ".";
  if (detailsTitle) detailsTitle.textContent = "Directory";
  if (detailsSubtitle) detailsSubtitle.textContent = displayPath;
  detailsPane.innerHTML = `
    <div class="lc-detail-dir">
      <div class="lc-detail-filepreview-head">
        <span class="material-symbols-outlined">folder</span>
        <span>${escapeHtml(displayPath)}</span>
      </div>
      <div class="lc-detail-dir-grid">
        <div class="lc-detail-dir-cell">
          <span class="lc-detail-dir-cell-label">subdirs</span>
          <span class="lc-detail-dir-cell-value">${state.directSubdirectories}</span>
        </div>
        <div class="lc-detail-dir-cell">
          <span class="lc-detail-dir-cell-label">.sol here</span>
          <span class="lc-detail-dir-cell-value">${state.directSolidityFiles}</span>
        </div>
        <div class="lc-detail-dir-cell" style="grid-column: span 2;">
          <span class="lc-detail-dir-cell-label">.sol reachable</span>
          <span class="lc-detail-dir-cell-value">${state.recursiveSolidityFiles}</span>
        </div>
      </div>
      <p class="lc-empty-sub" style="text-align:left; margin-top: 0.5rem;">
        The selected analyzer will run against every Solidity file reachable from this folder.
      </p>
    </div>
  `;
}

async function renderDetailsFile(path) {
  detailsPane.dataset.mode = "file";
  if (detailsTitle) detailsTitle.textContent = "File preview";
  if (detailsSubtitle) detailsSubtitle.textContent = path;
  detailsPane.innerHTML = `
    <div class="lc-detail-filepreview">
      <div class="lc-detail-filepreview-head">
        <span class="material-symbols-outlined">description</span>
        <span>${escapeHtml(path)}</span>
      </div>
      <pre class="lc-detail-code">Loading…</pre>
    </div>
  `;
  const codeEl = detailsPane.querySelector(".lc-detail-code");
  try {
    const response = await fetch(`/api/file?path=${encodeURIComponent(path)}`);
    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.error || "Failed to load file preview");
    }
    if (state.selectedFinding || state.selectedPath !== path) return;
    if (codeEl) codeEl.textContent = payload.content;
  } catch (error) {
    if (codeEl) codeEl.textContent = `Preview unavailable: ${error.message}`;
  }
}

function renderDetailsFinding(finding) {
  detailsPane.dataset.mode = "finding";
  const heading = finding.kind ? titleCaseToken(finding.kind) : "Finding";
  if (detailsTitle) detailsTitle.textContent = heading;
  const loc = [
    finding.file ? basename(finding.file) : null,
    finding.function ? `${finding.function}()` : null,
  ].filter(Boolean).join(" :: ");
  if (detailsSubtitle) detailsSubtitle.textContent = loc || "selected finding";

  const tone = severityTone(finding.severity);
  const tags = [
    `<span class="lc-tag lc-tag-sev-${tone.tag}">${escapeHtml(String(finding.severity || "unspecified").toLowerCase())}</span>`,
  ];
  if (finding.confidence) {
    tags.push(`<span class="lc-tag lc-tag-neutral">conf · ${escapeHtml(String(finding.confidence).toLowerCase())}</span>`);
  }

  const rows = [];
  if (finding.file) {
    rows.push(`<div class="lc-detail-row"><span class="lc-detail-row-label">file</span><span class="lc-detail-row-value">${escapeHtml(finding.file)}</span></div>`);
  }
  if (finding.function) {
    rows.push(`<div class="lc-detail-row"><span class="lc-detail-row-label">function</span><span class="lc-detail-row-value lc-detail-row-value-accent">${escapeHtml(finding.function)}()</span></div>`);
  }
  if (finding.start != null) {
    const span = finding.end != null && finding.end !== finding.start
      ? `${finding.start} – ${finding.end}`
      : `${finding.start}`;
    rows.push(`<div class="lc-detail-row"><span class="lc-detail-row-label">span</span><span class="lc-detail-row-value">${escapeHtml(span)}</span></div>`);
  }
  if (finding.layer) {
    rows.push(`<div class="lc-detail-row"><span class="lc-detail-row-label">layer</span><span class="lc-detail-row-value">${escapeHtml(finding.layer)}</span></div>`);
  }
  if (finding.category) {
    rows.push(`<div class="lc-detail-row"><span class="lc-detail-row-label">category</span><span class="lc-detail-row-value">${escapeHtml(finding.category)}</span></div>`);
  }
  if (finding.evidence) {
    rows.push(`<div class="lc-detail-row"><span class="lc-detail-row-label">evidence</span><span class="lc-detail-row-value">${escapeHtml(finding.evidence)}</span></div>`);
  }

  detailsPane.innerHTML = `
    <div class="lc-detail-finding">
      <header class="lc-detail-head">
        <h3 class="lc-detail-kind">${escapeHtml(heading)}</h3>
        <div class="lc-detail-tags">${tags.join("")}</div>
      </header>

      ${rows.length ? `
        <section class="lc-detail-section">
          <span class="lc-detail-section-label">Location &amp; metadata</span>
          ${rows.join("")}
        </section>
      ` : ""}

      ${finding.message ? `
        <section class="lc-detail-section">
          <span class="lc-detail-section-label">Message</span>
          <p class="lc-detail-message">${escapeHtml(finding.message)}</p>
        </section>
      ` : ""}
    </div>
  `;
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
    .map(({ label, path }, index) => {
      const separator =
        index === 0 ? "" : `<span class="lc-crumb-separator" aria-hidden="true">/</span>`;
      return `${separator}<button class="lc-crumb" data-path="${escapeHtml(path)}" type="button">${escapeHtml(label)}</button>`;
    })
    .join("");

  breadcrumbs.querySelectorAll(".lc-crumb").forEach((button) => {
    button.addEventListener("click", () => {
      loadFiles(button.dataset.path || "");
    });
  });
}

function renderEntries() {
  if (!state.entries.length) {
    fileList.innerHTML = `<div class="lc-empty-block"><p class="lc-empty-title">Empty directory.</p><p class="lc-empty-sub">No Solidity files or subdirectories were found here.</p></div>`;
    return;
  }

  const directories = state.entries.filter((entry) => entry.is_dir);
  const files = state.entries.filter((entry) => !entry.is_dir);
  const renderSection = (title, items, iconName, extraClass) => {
    if (!items.length) {
      return "";
    }
    return `
      <section class="lc-filelist-section">
        <div class="lc-filelist-header">
          <span class="lc-filelist-eyebrow">${escapeHtml(title)}</span>
          <span class="lc-filelist-count">${items.length}</span>
        </div>
        ${items
          .map((entry) => {
            const active = entry.relative_path === state.selectedPath;
            return `
              <button class="lc-fileitem ${extraClass}" data-active="${active}" data-path="${escapeHtml(entry.relative_path)}" data-dir="${entry.is_dir}" type="button">
                <span class="material-symbols-outlined lc-fileitem-icon">${iconName}</span>
                <span class="lc-fileitem-name">${escapeHtml(entry.name)}</span>
                <span class="lc-fileitem-meta">${entry.is_dir ? "›" : ".sol"}</span>
              </button>
            `;
          })
          .join("")}
      </section>
    `;
  };

  fileList.innerHTML = [
    renderSection("Folders", directories, "folder", "lc-fileitem-dir"),
    renderSection("Solidity files", files, "description", "lc-fileitem-file"),
  ]
    .filter(Boolean)
    .join("");

  fileList.querySelectorAll(".lc-fileitem").forEach((button) => {
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

  if (rootDirHeader) {
    rootDirHeader.querySelector("span:last-child").textContent = payload.root_dir;
  }
  state.currentPath = payload.current_path || "";
  state.entries = payload.entries || [];
  state.directSubdirectories = Number(payload.direct_subdirectories || 0);
  state.directSolidityFiles = Number(payload.direct_solidity_files || 0);
  state.recursiveSolidityFiles = Number(payload.recursive_solidity_files || 0);
  if (explorerStats) {
    explorerStats.textContent =
      `${state.directSubdirectories} folders · ${state.directSolidityFiles} .sol here · ${state.recursiveSolidityFiles} reachable`;
  }

  renderBreadcrumbs();
  renderEntries();
  setSelectedTarget(state.currentPath, true);
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

function summaryChipTone(label) {
  switch (label) {
    case "Mode":              return "lc-chip lc-chip-accent";
    case "Displayed Findings":return "lc-chip";
    case "Unique Kinds":      return "lc-chip lc-chip-info";
    case "High Severity":     return "lc-chip lc-chip-error";
    case "High Confidence":   return "lc-chip lc-chip-good";
    case "Warnings":          return "lc-chip lc-chip-warn";
    default:                  return "lc-chip";
  }
}

function summaryChipShortLabel(label) {
  switch (label) {
    case "Displayed Findings":return "findings";
    case "Unique Kinds":      return "kinds";
    case "High Severity":     return "high";
    case "High Confidence":   return "conf high";
    case "Warnings":          return "warnings";
    case "Mode":              return "mode";
    default: return String(label || "").toLowerCase();
  }
}

function renderSummary(cards) {
  const order = [
    "Mode",
    "Displayed Findings",
    "Unique Kinds",
    "High Severity",
    "High Confidence",
    "Warnings",
  ];
  const orderedCards = [...cards].sort((left, right) => {
    const leftIndex = order.indexOf(left.label);
    const rightIndex = order.indexOf(right.label);
    return (leftIndex === -1 ? order.length : leftIndex) - (rightIndex === -1 ? order.length : rightIndex);
  });

  if (!cards.length) {
    summaryGrid.innerHTML = `<span class="lc-chip lc-chip-muted">awaiting run</span>`;
    return;
  }

  summaryGrid.innerHTML = orderedCards
    .map((card) => `
      <span class="${summaryChipTone(card.label)}">
        ${escapeHtml(summaryChipShortLabel(card.label))}
        <span class="lc-chip-value">${escapeHtml(card.value)}</span>
      </span>
    `)
    .join("");
}

function renderWarnings(warnings) {
  latestWarnings = (warnings || []).map((warning) => {
    if (typeof warning === "string") {
      return {
        title: "Analyzer Warning",
        message: warning,
        category: "general",
        suppressed_by_default: false,
      };
    }
    return {
      title: warning.title || "Analyzer Warning",
      message: warning.message || "",
      category: warning.category || "general",
      suppressed_by_default: Boolean(warning.suppressed_by_default),
    };
  });

  if (!latestWarnings.length) {
    warningBox.innerHTML = `<p class="lc-empty-text">Analyzer warnings will appear here when available.</p>`;
    return;
  }

  const suppressedWarnings = latestWarnings.filter((warning) => warning.suppressed_by_default);
  const visibleWarnings = latestWarnings.filter(
    (warning) => !warning.suppressed_by_default || state.showSuppressedWarnings
  );

  const hiddenSummary =
    suppressedWarnings.length > 0
      ? `
        <div class="lc-warning-summary">
          <div class="lc-warning-summary-copy">
            <span class="lc-warning-summary-title">Expected benchmark compatibility warnings are hidden.</span>
            <span class="lc-warning-summary-meta">${suppressedWarnings.length} suppressed</span>
          </div>
          <button id="warningToggle" class="lc-warning-toggle" type="button">
            ${state.showSuppressedWarnings ? "Hide" : "Show"}
          </button>
        </div>
      `
      : "";

  const visibleMarkup = visibleWarnings.length
    ? visibleWarnings
        .map((warning) => {
          const quietClass =
            warning.category === "compatibility" ? "lc-warning lc-warning-quiet" : "lc-warning";
          return `
            <div class="${quietClass}">
              <div class="lc-warning-title">${escapeHtml(warning.title)}</div>
              <pre class="lc-warning-message">${escapeHtml(warning.message)}</pre>
            </div>
          `;
        })
        .join("")
    : `<p class="lc-empty-text">No actionable warnings.</p>`;

  warningBox.innerHTML = `${hiddenSummary}${visibleMarkup}`;
  warningBox.querySelector("#warningToggle")?.addEventListener("click", () => {
    state.showSuppressedWarnings = !state.showSuppressedWarnings;
    renderWarnings(latestWarnings);
  });
}

function renderArtifacts(runDir, artifacts) {
  void runDir;
  void artifacts;
}

function groupedSeverityOrder(groups) {
  const preferred = ["high", "medium", "low", "info", "unknown"];
  return [
    ...preferred.filter((value) => groups.has(value)),
    ...Array.from(groups.keys()).filter((value) => !preferred.includes(value)).sort(),
  ];
}

function severityTone(severity) {
  const normalized = String(severity || "unknown").toLowerCase();
  if (normalized.includes("high") || normalized.includes("critical")) {
    return { key: "high", label: "High severity", tag: "high" };
  }
  if (normalized.includes("medium") || normalized.includes("moderate")) {
    return { key: "medium", label: "Medium severity", tag: "medium" };
  }
  if (normalized.includes("low")) {
    return { key: "low", label: "Low severity", tag: "low" };
  }
  if (normalized.includes("info")) {
    return { key: "info", label: "Informational", tag: "info" };
  }
  return { key: "unknown", label: "Unspecified", tag: "unknown" };
}

function renderFindings(findings) {
  const query = String(findingSearch?.value || "").trim();
  const totalCount = allFindings.length;
  findingsCount.textContent = query
    ? `surfaced · ${padCount(findings.length)} / ${padCount(totalCount)}`
    : `surfaced · ${padCount(findings.length)}`;
  findingsFilterState.textContent = query
    ? `filter: ${query}`
    : totalCount
      ? `${totalCount} total`
      : "";

  if (!findings.length) {
    findingList.innerHTML = `
      <div class="lc-empty-block">
        <p class="lc-empty-title">${escapeHtml(query ? "No findings matched the current filter." : "No findings surfaced.")}</p>
        <p class="lc-empty-sub">${escapeHtml(query ? "Try a broader search or clear the filter." : "Try a different analyzer or target, or open the raw output for suppressed and auxiliary details.")}</p>
      </div>
    `;
    return;
  }

  const grouped = new Map();
  for (const finding of findings) {
    const tone = severityTone(finding.severity);
    if (!grouped.has(tone.key)) {
      grouped.set(tone.key, { tone, items: [] });
    }
    grouped.get(tone.key).items.push(finding);
  }

  const findingIndexByNode = new Map();
  let globalIndex = 0;

  const sections = groupedSeverityOrder(grouped).map((severityKey) => {
    const { tone, items } = grouped.get(severityKey);
    const cards = items
      .map((finding, index) => {
        const fid = findingId(finding, globalIndex++);
        findingIndexByNode.set(fid, finding);

        const heading = finding.kind ? titleCaseToken(finding.kind) : "Finding";
        const functionName = finding.function ? finding.function : null;
        const fileName = finding.file ? basename(finding.file) : null;
        const confidence = finding.confidence
          ? `<span class="lc-tag lc-tag-neutral">conf · ${escapeHtml(String(finding.confidence).toLowerCase())}</span>`
          : "";
        const sevTag = `<span class="lc-tag lc-tag-sev-${tone.tag}">${escapeHtml(String(finding.severity || "unspecified").toLowerCase())}</span>`;

        const locParts = [];
        if (fileName) {
          locParts.push(`<span>${escapeHtml(fileName)}</span>`);
        }
        if (functionName) {
          if (locParts.length) {
            locParts.push(`<span class="lc-finding-loc-sep">::</span>`);
          }
          locParts.push(`<span class="lc-finding-loc-func">${escapeHtml(functionName)}()</span>`);
        }
        const locationLine = locParts.length
          ? `<div class="lc-finding-loc"><span class="material-symbols-outlined" style="font-size:13px;color:var(--text-3);">code</span>${locParts.join("")}</div>`
          : "";

        const isSelected = fid === state.selectedFindingId;

        return `
          <button class="lc-finding" type="button" data-finding-id="${escapeHtml(fid)}" data-selected="${isSelected ? "true" : "false"}">
            <div class="lc-finding-bar lc-finding-bar-${tone.tag}"></div>
            <div class="lc-finding-body">
              <div class="lc-finding-head">
                <h4 class="lc-finding-kind">${escapeHtml(heading)}</h4>
                <div class="lc-finding-tags">${sevTag}${confidence}</div>
              </div>
              ${locationLine}
              <p class="lc-finding-message">${escapeHtml(finding.message || `Finding ${index + 1} in this severity group.`)}</p>
            </div>
          </button>
        `;
      })
      .join("");

    return `
      <div class="lc-finding-group">
        <header class="lc-finding-group-header">
          <span class="lc-sev-dot lc-sev-dot-${tone.tag}"></span>
          <span class="lc-finding-group-name">${escapeHtml(tone.label)}</span>
          <span class="lc-finding-group-count">${padCount(items.length)}</span>
        </header>
        <div class="lc-finding-stack" style="display:flex; flex-direction:column; gap:0.55rem;">
          ${cards}
        </div>
      </div>
    `;
  });

  findingList.innerHTML = sections.join("");

  findingList.querySelectorAll(".lc-finding").forEach((button) => {
    button.addEventListener("click", () => {
      const fid = button.dataset.findingId || "";
      const finding = findingIndexByNode.get(fid);
      if (!finding) return;
      if (state.selectedFindingId === fid) {
        clearSelectedFinding();
      } else {
        setSelectedFinding(finding, fid);
      }
    });
  });
}

function applyFindingFilter() {
  const query = String(findingSearch?.value || "").trim().toLowerCase();
  if (!query) {
    renderFindings(allFindings);
    return;
  }

  const filtered = allFindings.filter((finding) =>
    [
      finding.kind,
      finding.layer,
      finding.category,
      finding.confidence,
      finding.message,
      finding.function,
      finding.file,
      finding.evidence,
    ]
      .filter(Boolean)
      .some((value) => String(value).toLowerCase().includes(query))
  );
  renderFindings(filtered);
}

async function fetchAnalysisStatus() {
  const response = await fetch("/api/analyze/status");
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.error || "Failed to load analysis status");
  }
  return payload;
}

function updateRunningStatus(mode, targetPath, elapsedMs, cancelling, status = {}) {
  const { phaseText, metaNote, progressPercent } = summarizeProgressScope(
    mode,
    targetPath,
    status,
    cancelling
  );
  setProgressVisual(
    "running",
    cancelling ? "Cancelling" : "Analysis Running",
    phaseText,
    elapsedMs,
    progressPercent,
    metaNote
  );
}

function updatePhaseStatus(mode, targetPath, elapsedMs, phase, status = {}) {
  const { totalTargets, completedTargets, remainingTargets } = buildProgressMetrics(status);
  const progressPercent = totalTargets > 0 ? (completedTargets / totalTargets) * 100 : 8;
  const targetLabel = basename(status.target_path || targetPath || ".");
  const currentLabel = basename(status.current_target || "");
  const countSummary =
    totalTargets > 1
      ? `${completedTargets}/${totalTargets} complete · ${remainingTargets} remaining`
      : null;

  if (phase === "preparing" || phase === "starting") {
    setProgressVisual(
      "running",
      "Preparing Analysis",
      totalTargets > 1
        ? `Preparing ${humanizeMode(mode)} analysis for ${targetLabel} · ${countSummary}`
        : `Preparing ${humanizeMode(mode)} analysis for ${targetLabel}...`,
      elapsedMs,
      progressPercent,
      currentLabel ? `Current target: ${currentLabel}` : totalTargets > 0 ? `${totalTargets} target${totalTargets === 1 ? "" : "s"} queued` : "Preparing targets"
    );
    return;
  }

  if (phase === "finalizing") {
    setProgressVisual(
      "running",
      "Finalizing Results",
      totalTargets > 1
        ? `Finalizing ${humanizeMode(mode)} analysis for ${targetLabel} · ${countSummary}`
        : `Finalizing ${humanizeMode(mode)} analysis results...`,
      elapsedMs,
      totalTargets > 0 ? ((completedTargets + 0.9) / totalTargets) * 100 : 92,
      currentLabel ? `Current target: ${currentLabel}` : "Finalizing results"
    );
  }
}

function startStatusPolling() {
  stopStatusPolling();
  syncAnalysisStatus();
  statusPollId = window.setInterval(syncAnalysisStatus, 1500);
}

function stopStatusPolling() {
  if (statusPollId != null) {
    window.clearInterval(statusPollId);
    statusPollId = null;
  }
}

async function syncAnalysisStatus() {
  try {
    const payload = await fetchAnalysisStatus();
    if (!payload.running) {
      return;
    }

    latestStatusSnapshot = payload;

    if (runStartedAt == null && payload.elapsed_ms != null) {
      runStartedAt = Date.now() - payload.elapsed_ms;
      runButton.disabled = true;
      runButtonLabelEl.textContent = "Running...";
      cancelButton.disabled = Boolean(payload.cancel_requested);
      cancelButtonLabelEl.textContent = payload.cancel_requested ? "Cancelling..." : cancelButtonLabel;
    }

    if (payload.phase === "preparing" || payload.phase === "starting" || payload.phase === "finalizing") {
      updatePhaseStatus(payload.mode, payload.target_path, payload.elapsed_ms || 0, payload.phase, payload);
    } else {
      updateRunningStatus(
        payload.mode,
        payload.target_path,
        payload.elapsed_ms || 0,
        Boolean(payload.cancel_requested),
        payload
      );
    }
  } catch (error) {
    if (runStartedAt != null) {
      setStatus(`Status sync failed: ${error.message}`);
    }
  }
}

function startRunTimer(mode, targetPath) {
  stopRunTimer();
  runStartedAt = Date.now();
  cancelRequested = false;
  latestStatusSnapshot = {
    mode,
    target_path: targetPath,
    cancel_requested: false,
    phase: "preparing",
    total_targets: 0,
    completed_targets: 0,
    remaining_targets: 0,
    current_target: "",
  };
  runButton.disabled = true;
  cancelButton.disabled = false;
  runButtonLabelEl.textContent = "Running...";
  cancelButtonLabelEl.textContent = cancelButtonLabel;
  updatePhaseStatus(mode, targetPath, 0, "preparing", latestStatusSnapshot);

  runTimerId = window.setInterval(() => {
    const elapsedMs = Date.now() - runStartedAt;
    const snapshot = latestStatusSnapshot;
    if (!snapshot) {
      updatePhaseStatus(mode, targetPath, elapsedMs, "preparing", {
        target_path: targetPath,
        total_targets: 0,
        completed_targets: 0,
        remaining_targets: 0,
      });
      return;
    }

    if (snapshot.phase === "preparing" || snapshot.phase === "starting" || snapshot.phase === "finalizing") {
      updatePhaseStatus(snapshot.mode || mode, snapshot.target_path || targetPath, elapsedMs, snapshot.phase, snapshot);
      return;
    }

    updateRunningStatus(
      snapshot.mode || mode,
      snapshot.target_path || targetPath,
      elapsedMs,
      Boolean(snapshot.cancel_requested || cancelRequested),
      snapshot
    );
  }, 1000);

  startStatusPolling();
}

function stopRunTimer() {
  if (runTimerId != null) {
    window.clearInterval(runTimerId);
    runTimerId = null;
  }
  stopStatusPolling();
  runStartedAt = null;
  cancelRequested = false;
  latestStatusSnapshot = null;
  runButtonLabelEl.textContent = runButtonLabel;
  runButton.disabled = false;
  cancelButtonLabelEl.textContent = cancelButtonLabel;
  cancelButton.disabled = true;
}

async function cancelAnalysis() {
  if (runStartedAt == null || cancelRequested) {
    return;
  }

  cancelRequested = true;
  cancelButton.disabled = true;
  cancelButtonLabelEl.textContent = "Cancelling...";
  const cancellationSnapshot = latestStatusSnapshot
    ? { ...latestStatusSnapshot, cancel_requested: true }
    : {
        target_path: state.selectedPath || state.currentPath,
        total_targets: 0,
        completed_targets: 0,
        remaining_targets: 0,
        current_target: state.selectedPath || state.currentPath,
      };
  latestStatusSnapshot = cancellationSnapshot;
  updateRunningStatus(
    modeSelect.value,
    state.selectedPath || state.currentPath,
    Date.now() - runStartedAt,
    true,
    cancellationSnapshot
  );

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
    cancelButtonLabelEl.textContent = cancelButtonLabel;
    setStatus(`Cancellation failed: ${error.message}`);
  }
}

async function runAnalysis() {
  const targetPath = state.selectedPath || state.currentPath;
  if (targetPath == null) {
    setStatus("Choose a target before running the analyzer.");
    return;
  }

  clearReportDownload();
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
    allFindings = payload.findings || [];
    state.selectedFinding = null;
    state.selectedFindingId = null;
    renderFindings(allFindings);
    applyFindingFilter();
    renderWarnings(payload.warnings || []);
    renderArtifacts(payload.run_dir, payload.artifacts || []);
    renderDetailsPane();
    setReportDownload(
      payload.report_markdown,
      payload.report_markdown_filename,
      payload.report_pdf_base64,
      payload.report_filename,
      payload.report_pdf_error
    );

    const elapsedMs = Date.now() - runStartedAt;
    const processedTargets = Number(payload.raw_report?.target_count || 1);
    setProgressVisual(
      "complete",
      "Analysis Completed",
      `Completed ${humanizeMode(payload.mode)} analysis for ${basename(payload.target_path || ".")}`,
      elapsedMs,
      100,
      `${processedTargets} TARGET${processedTargets === 1 ? "" : "S"} PROCESSED`
    );
    setStatus(`Completed ${payload.mode} analysis for ${payload.target_path || "."} in ${formatElapsed(elapsedMs)}.`);
  } catch (error) {
    const elapsedMs = runStartedAt == null ? 0 : Date.now() - runStartedAt;
    const cancelled = String(error.message).toLowerCase().includes("cancelled");

    if (cancelled) {
      renderWarnings([error.message]);
      setProgressVisual(
        "cancelled",
        "Analysis Cancelled",
        "The active run was cancelled before completion.",
        elapsedMs,
        100
      );
      setStatus(`Analysis cancelled after ${formatElapsed(elapsedMs)}.`);
    } else {
      renderSummary([]);
      allFindings = [];
      state.selectedFinding = null;
      state.selectedFindingId = null;
      renderFindings([]);
      renderWarnings([error.message]);
      renderArtifacts(null, []);
      renderDetailsPane();
      clearReportDownload();
      setProgressVisual(
        "failed",
        "Analysis Failed",
        "The analyzer did not complete successfully.",
        elapsedMs,
        100
      );
      setStatus(`Analysis failed after ${formatElapsed(elapsedMs)}.`);
    }
  } finally {
    stopRunTimer();
  }
}

runButton.addEventListener("click", runAnalysis);
cancelButton.addEventListener("click", cancelAnalysis);
markdownReportButton?.addEventListener("click", downloadMarkdownReport);
pdfReportButton?.addEventListener("click", downloadPdfReport);
modeSelect.addEventListener("change", syncModePresentation);
findingSearch?.addEventListener("input", applyFindingFilter);

syncModePresentation();
setProgressVisual("idle", "Idle", "Ready to analyze the selected target.", 0);
renderDetailsPane();

syncAnalysisStatus();
loadFiles().catch((error) => {
  setStatus(error.message);
  fileList.innerHTML = `<div class="lc-empty-block"><p class="lc-empty-title">Workspace unavailable.</p><p class="lc-empty-sub">${escapeHtml(error.message)}</p></div>`;
});
