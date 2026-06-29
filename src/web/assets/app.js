const state = {
  currentPath: "",
  selectedPath: "",
  selectedIsDir: true,
  entries: [],
  directSubdirectories: 0,
  directSolidityFiles: 0,
  recursiveSolidityFiles: 0,
  rawExpanded: false,
  showSuppressedWarnings: false,
};

const rootDirHeader = document.getElementById("rootDirHeader");
const explorerStats = document.getElementById("explorerStats");
const breadcrumbs = document.getElementById("breadcrumbs");
const fileList = document.getElementById("fileList");
const filePreview = document.getElementById("filePreview");
const selectedTargetHero = document.getElementById("selectedTargetHero");
const selectedTargetPath = document.getElementById("selectedTargetPath");
const selectedTargetKind = document.getElementById("selectedTargetKind");
const modeSelect = document.getElementById("modeSelect");
const activeModeLabel = document.getElementById("activeModeLabel");
const runButton = document.getElementById("runButton");
const cancelButton = document.getElementById("cancelButton");
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
const rawJson = document.getElementById("rawJson");
const rawOutputToggle = document.getElementById("rawOutputToggle");
const rawOutputPanel = document.getElementById("rawOutputPanel");
const rawOutputMeta = document.getElementById("rawOutputMeta");
const rawOutputChevron = document.getElementById("rawOutputChevron");
const findingSearch = document.getElementById("findingSearch");

const runButtonLabel = runButton.textContent;
const cancelButtonLabel = cancelButton.textContent;

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

function formatBytes(length) {
  const size = Number(length || 0);
  if (size < 1024) {
    return `${size} B`;
  }
  if (size < 1024 * 1024) {
    return `${(size / 1024).toFixed(1)} KB`;
  }
  return `${(size / (1024 * 1024)).toFixed(1)} MB`;
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
    case "fuzzing":
      return "Fuzzing Analysis";
    case "hybrid":
      return "Hybrid Analysis";
    case "symbolic":
      return "Symbolic Analysis";
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
  progressStateLabel.className = `text-sm font-medium state-${stateName}`;
  progressStateDot.className = `w-2 h-2 rounded-full dot-${stateName}`;
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
      ? "Live analysis"
      : stateName === "complete"
        ? "Results ready"
        : stateName === "cancelled"
          ? "Run cancelled"
          : stateName === "failed"
            ? "Run failed"
            : "Ready");
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

function updateRawOutputMeta(raw) {
  rawOutputMeta.textContent = `analyzer_output.json (${formatBytes(raw.length)})`;
}

function toggleRawOutput(force = null) {
  state.rawExpanded = force == null ? !state.rawExpanded : Boolean(force);
  rawOutputPanel.classList.toggle("hidden", !state.rawExpanded);
  rawOutputChevron.textContent = state.rawExpanded ? "keyboard_arrow_down" : "keyboard_arrow_up";
}

function setSelectedTarget(path, isDir) {
  state.selectedPath = path;
  state.selectedIsDir = isDir;
  syncTargetPresentation();
  renderEntries();
  setStatus(
    isDir
      ? `Directory target selected: ${path || "."}`
      : `Single Solidity file selected: ${path}`
  );
  if (!isDir && path) {
    loadPreview(path);
  } else {
    renderDirectoryPreview(path);
  }
}

function renderDirectoryPreview(path) {
  const displayPath = path || ".";
  filePreview.innerHTML = `
    <div class="preview-directory space-y-2">
      <p><strong>Directory target:</strong> ${escapeHtml(displayPath)}</p>
      <p><strong>Subdirectories (direct):</strong> ${state.directSubdirectories}</p>
      <p><strong>Solidity files here:</strong> ${state.directSolidityFiles}</p>
      <p><strong>Solidity files reachable:</strong> ${state.recursiveSolidityFiles}</p>
      <p><strong>Run behavior:</strong> the selected mode will analyze every Solidity file reachable from this folder target.</p>
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
        index === 0 ? "" : `<span class="browser-crumb-separator" aria-hidden="true">/</span>`;
      return `${separator}<button class="browser-crumb" data-path="${escapeHtml(path)}" type="button">${escapeHtml(label)}</button>`;
    })
    .join("");

  breadcrumbs.querySelectorAll(".browser-crumb").forEach((button) => {
    button.addEventListener("click", () => {
      loadFiles(button.dataset.path || "");
    });
  });
}

function renderEntries() {
  if (!state.entries.length) {
    fileList.innerHTML = `<div class="results-empty">No Solidity files or subdirectories were found here.</div>`;
    return;
  }

  const directories = state.entries.filter((entry) => entry.is_dir);
  const files = state.entries.filter((entry) => !entry.is_dir);
  const renderSection = (title, items, kindLabel, iconName, extraClass) => {
    if (!items.length) {
      return "";
    }
    return `
      <section class="browser-section">
        <div class="browser-section-header">
          <span class="browser-section-title">${escapeHtml(title)}</span>
          <span class="browser-section-count">${items.length}</span>
        </div>
        ${items
          .map((entry) => {
            const active = entry.relative_path === state.selectedPath;
            const meta = entry.is_dir ? "Open folder" : "Analyze this file";
            return `
              <button class="browser-entry ${extraClass}" data-active="${active}" data-path="${escapeHtml(entry.relative_path)}" data-dir="${entry.is_dir}" type="button">
                <div class="browser-entry-row">
                  <span class="material-symbols-outlined browser-entry-icon">${iconName}</span>
                  <div class="min-w-0 flex-1">
                    <div class="browser-entry-title">
                      <div class="browser-entry-name truncate">${escapeHtml(entry.name)}</div>
                      <span class="browser-entry-badge">${escapeHtml(kindLabel)}</span>
                    </div>
                    <div class="browser-entry-meta">${escapeHtml(meta)}</div>
                  </div>
                </div>
              </button>
            `;
          })
          .join("")}
      </section>
    `;
  };

  fileList.innerHTML = [
    renderSection("Folders", directories, "dir", "folder", "browser-entry-dir"),
    renderSection("Solidity Files", files, "sol", "description", "browser-entry-file"),
  ]
    .filter(Boolean)
    .join("");

  fileList.querySelectorAll(".browser-entry").forEach((button) => {
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

function summaryAccent(label, index) {
  void index;
  const toneByLabel = {
    Mode: "summary-card summary-card-info",
    "Displayed Findings": "summary-card summary-card-good",
    "Unique Kinds": "summary-card summary-card-info",
    "High Severity": "summary-card summary-card-error",
    "High Confidence": "summary-card summary-card-good",
    "Selected Targets": "summary-card summary-card-info",
    "SE Findings": "summary-card summary-card-good",
    "Injected Seeds": "summary-card summary-card-good",
    Warnings: "summary-card summary-card-warn",
  };
  return toneByLabel[label] || "summary-card";
}

function renderSummary(cards) {
  const order = [
    "Mode",
    "Displayed Findings",
    "Unique Kinds",
    "High Severity",
    "High Confidence",
    "Selected Targets",
    "SE Findings",
    "Injected Seeds",
    "Warnings",
  ];
  const orderedCards = [...cards].sort((left, right) => {
    const leftIndex = order.indexOf(left.label);
    const rightIndex = order.indexOf(right.label);
    return (leftIndex === -1 ? order.length : leftIndex) - (rightIndex === -1 ? order.length : rightIndex);
  });

  if (!cards.length) {
    summaryGrid.innerHTML = `
      <div class="summary-card summary-card-muted">
        <span class="text-[10px] uppercase font-bold text-on-surface-variant tracking-tighter">No Summary Yet</span>
      </div>
    `;
    return;
  }

  summaryGrid.innerHTML = orderedCards
    .map(
      (card, index) => `
        <div class="${summaryAccent(card.label, index)}">
          <span class="text-[10px] uppercase font-bold text-on-surface-variant tracking-tighter">${escapeHtml(card.label)}</span>
          <span class="mt-2 text-xl font-headline font-bold">${escapeHtml(card.value)}</span>
        </div>
      `
    )
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
    warningBox.innerHTML = `<p class="empty-box">Analyzer warnings will appear here when available.</p>`;
    return;
  }

  const suppressedWarnings = latestWarnings.filter((warning) => warning.suppressed_by_default);
  const visibleWarnings = latestWarnings.filter(
    (warning) => !warning.suppressed_by_default || state.showSuppressedWarnings
  );

  const hiddenSummary =
    suppressedWarnings.length > 0
      ? `
        <div class="warning-summary-box">
          <div class="warning-summary-copy">
            <span class="warning-summary-title">Expected benchmark compatibility warnings are hidden by default.</span>
            <span class="warning-summary-meta">${suppressedWarnings.length} hidden</span>
          </div>
          <button id="warningToggle" class="warning-toggle" type="button">
            ${state.showSuppressedWarnings ? "Hide" : "Show"}
          </button>
        </div>
      `
      : "";

  const visibleMarkup = visibleWarnings.length
    ? visibleWarnings
        .map((warning) => {
          const quietClass =
            warning.category === "compatibility" ? "warning-box warning-box-quiet" : "warning-box";
          return `
            <div class="${quietClass}">
              <div class="warning-box-title">${escapeHtml(warning.title)}</div>
              <pre class="warning-box-message">${escapeHtml(warning.message)}</pre>
            </div>
          `;
        })
        .join("")
    : `<p class="empty-box">No actionable warnings are currently visible.</p>`;

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
  const preferred = ["high", "medium", "low", "unknown"];
  return [
    ...preferred.filter((value) => groups.has(value)),
    ...Array.from(groups.keys()).filter((value) => !preferred.includes(value)).sort(),
  ];
}

function severityTone(severity) {
  const normalized = String(severity || "unknown").toLowerCase();
  if (normalized.includes("high") || normalized.includes("critical")) {
    return {
      key: "high",
      chip: "bg-error/10 text-error",
      card:
        "bg-surface-container p-5 rounded-2xl border-l-4 border-error hover:scale-[1.02] transition-transform duration-200",
      countChip: "bg-error/10 text-error",
      label: "High Severity Findings",
      badgePrefix: "CRITICAL_THREATS",
    };
  }
  if (normalized.includes("medium")) {
    return {
      key: "medium",
      chip: "bg-orange-400/10 text-orange-400",
      card:
        "bg-surface-container-low p-5 rounded-xl border border-outline-variant/10 hover:bg-surface-container transition-colors",
      countChip: "bg-orange-400/10 text-orange-400",
      label: "Medium Severity Findings",
      badgePrefix: "MODERATE_RISKS",
    };
  }
  if (normalized.includes("low")) {
    return {
      key: "low",
      chip: "bg-secondary/10 text-secondary",
      card:
        "bg-surface-container-low p-5 rounded-xl border border-outline-variant/10 hover:bg-surface-container transition-colors",
      countChip: "bg-secondary/10 text-secondary",
      label: "Low Severity Findings",
      badgePrefix: "LOW_RISKS",
    };
  }
  return {
    key: "unknown",
    chip: "bg-surface-container-highest text-on-surface-variant",
    card:
      "bg-surface-container-low p-5 rounded-xl border border-outline-variant/10 hover:bg-surface-container transition-colors",
    countChip: "bg-surface-container-highest text-on-surface-variant",
    label: "Unspecified Findings",
    badgePrefix: "UNCATEGORIZED",
  };
}

function renderFindings(findings) {
  const query = String(findingSearch?.value || "").trim();
  const totalCount = allFindings.length;
  findingsCount.textContent = query
    ? `SURFACED: ${padCount(findings.length)} / ${padCount(totalCount)}`
    : `SURFACED: ${padCount(findings.length)}`;
  findingsFilterState.textContent = query
    ? `filter: ${query}`
    : totalCount
      ? "all surfaced findings"
      : "";

  if (!findings.length) {
    findingList.innerHTML = `
      <div class="results-empty">
        <p class="text-sm font-medium text-on-surface">${
          query ? "No findings matched the current filter." : "No surfaced findings were returned for this run."
        }</p>
        <p class="text-xs text-on-surface-variant mt-2">${
          query
            ? "Try a broader search term or clear the findings filter."
            : "Try another mode, a narrower target, or inspect the raw output for suppressed and auxiliary details."
        }</p>
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

  const sections = groupedSeverityOrder(grouped).map((severityKey) => {
    const { tone, items } = grouped.get(severityKey);
    const cards = items
      .map((finding, index) => {
        const confidence = confidenceLabel(finding.confidence);
        const heading = finding.kind ? titleCaseToken(finding.kind) : "Finding";
        const locationText = finding.function || basename(finding.file) || "No location metadata";
        const layerText = [
          finding.layer ? `${finding.layer}` : null,
          finding.category ? `${finding.category}` : null,
          finding.evidence ? `${finding.evidence}` : null,
        ].filter(Boolean).join(" · ");
        const spanText = [
          finding.file ? basename(finding.file) : null,
          finding.start != null ? `start ${finding.start}` : null,
          finding.end != null ? `end ${finding.end}` : null,
        ].filter(Boolean).join(" · ");

        return `
          <div class="${tone.card}">
            <div class="flex justify-between items-start mb-4 gap-3">
              <span class="px-2 py-1 ${tone.chip} rounded text-[10px] font-bold uppercase">${escapeHtml(titleCaseToken(finding.kind))}</span>
              ${
                confidence
                  ? `
                    <div class="flex items-center gap-1 bg-tertiary/10 text-tertiary px-2 py-1 rounded text-[10px]">
                      <span class="material-symbols-outlined text-[10px]" style="font-variation-settings: 'FILL' 1;">analytics</span>
                      ${escapeHtml(confidence)}
                    </div>
                  `
                  : ""
              }
            </div>
            <h4 class="font-bold text-on-surface mb-2">${escapeHtml(heading)}</h4>
            <div class="text-xs text-on-surface-variant space-y-3">
              <div class="finding-card-detail font-mono">
                <span class="material-symbols-outlined text-xs">function</span>
                ${escapeHtml(locationText)}
              </div>
              ${layerText ? `
                <div class="finding-card-detail">
                  <span class="material-symbols-outlined text-xs">layers</span>
                  ${escapeHtml(layerText)}
                </div>
              ` : ""}
              ${spanText ? `
                <div class="finding-card-detail font-mono">
                  <span class="material-symbols-outlined text-xs">pin_drop</span>
                  ${escapeHtml(spanText)}
                </div>
              ` : ""}
              <p class="text-[11px] leading-relaxed opacity-80">${escapeHtml(finding.message || `Finding ${index + 1} in this severity group.`)}</p>
            </div>
          </div>
        `;
      })
      .join("");

    return `
      <div>
        <div class="flex items-center gap-4 mb-6">
          <h3 class="font-headline text-lg font-bold">${escapeHtml(tone.label)}</h3>
          <span class="${tone.countChip} px-2 py-0.5 rounded text-xs font-bold font-mono">${escapeHtml(`${tone.badgePrefix}: ${String(items.length).padStart(2, "0")}`)}</span>
        </div>
        <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          ${cards}
        </div>
      </div>
    `;
  });

  findingList.innerHTML = sections.join("");
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
      runButton.textContent = "Running...";
      cancelButton.disabled = Boolean(payload.cancel_requested);
      cancelButton.textContent = payload.cancel_requested ? "Cancelling..." : cancelButtonLabel;
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
  runButton.textContent = "Running...";
  cancelButton.textContent = cancelButtonLabel;
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
  runButton.textContent = runButtonLabel;
  runButton.disabled = false;
  cancelButton.textContent = cancelButtonLabel;
  cancelButton.disabled = true;
}

async function cancelAnalysis() {
  if (runStartedAt == null || cancelRequested) {
    return;
  }

  cancelRequested = true;
  cancelButton.disabled = true;
  cancelButton.textContent = "Cancelling...";
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
    cancelButton.textContent = cancelButtonLabel;
    setStatus(`Cancellation failed: ${error.message}`);
  }
}

async function runAnalysis() {
  const targetPath = state.selectedPath || state.currentPath;
  if (targetPath == null) {
    setStatus("Choose a target before running the analyzer.");
    return;
  }

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
    renderFindings(allFindings);
    applyFindingFilter();
    renderWarnings(payload.warnings || []);
    renderArtifacts(payload.run_dir, payload.artifacts || []);
    rawJson.textContent = payload.raw_json || "";
    updateRawOutputMeta(payload.raw_json || "");

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
      renderFindings([]);
      renderWarnings([error.message]);
      renderArtifacts(null, []);
      rawJson.textContent = "";
      updateRawOutputMeta("");
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
modeSelect.addEventListener("change", syncModePresentation);
rawOutputToggle.addEventListener("click", () => toggleRawOutput());
findingSearch?.addEventListener("input", applyFindingFilter);

syncModePresentation();
toggleRawOutput(false);
setProgressVisual("idle", "Idle", "Ready to analyze the selected target.", 0);

syncAnalysisStatus();
loadFiles().catch((error) => {
  setStatus(error.message);
  fileList.innerHTML = `<div class="results-empty">${escapeHtml(error.message)}</div>`;
});
