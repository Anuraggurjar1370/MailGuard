/**
 * MailGuard Frontend Application Logic - Phase 2.
 * Manages tab switching, animated gauge, Chart.js Tactic Radar,
 * gamified training simulator, batch scanning, attachment risk checker,
 * active learning feedback, and report printing.
 */

document.addEventListener("DOMContentLoaded", () => {
  // Navigation Tabs
  const navTabs = {
    scan: document.getElementById("nav-scan-tab"),
    sim: document.getElementById("nav-sim-tab"),
    batch: document.getElementById("nav-batch-tab"),
    attach: document.getElementById("nav-attach-tab"),
    eml: document.getElementById("nav-eml-tab"),
    url: document.getElementById("nav-url-tab"),
    models: document.getElementById("nav-models-tab"),
  };

  const views = {
    scan: document.getElementById("view-scanner"),
    sim: document.getElementById("view-sim"),
    batch: document.getElementById("view-batch"),
    attach: document.getElementById("view-attach"),
    eml: document.getElementById("view-eml"),
    url: document.getElementById("view-url"),
    models: document.getElementById("view-models"),
  };

  let radarChartInstance = null;
  let currentScanData = null;

  // Simulator State
  let simCurrentScenario = null;
  let simScore = 0;
  let simStreak = 0;

  function switchTab(activeKey) {
    Object.keys(navTabs).forEach((key) => {
      if (key === activeKey) {
        navTabs[key].classList.add("active");
        views[key].classList.remove("hidden");
      } else {
        navTabs[key].classList.remove("active");
        views[key].classList.add("hidden");
      }
    });

    if (activeKey === "models") {
      loadModelBenchmarks();
    } else if (activeKey === "sim" && !simCurrentScenario) {
      loadNextSimulatorScenario();
    }
  }

  Object.keys(navTabs).forEach((k) => {
    if (navTabs[k]) {
      navTabs[k].addEventListener("click", () => switchTab(k));
    }
  });

  // Toast notification helper
  function showToast(message, type = "success") {
    const toast = document.getElementById("toast-banner");
    toast.textContent = message;
    toast.className = `fixed top-20 right-6 z-50 transform transition-all duration-300 p-4 rounded-xl shadow-2xl border text-xs font-semibold flex items-center space-x-2 ${
      type === "success"
        ? "bg-emerald-950/90 border-emerald-500/50 text-emerald-300"
        : "bg-rose-950/90 border-rose-500/50 text-rose-300"
    }`;
    toast.style.opacity = "1";
    toast.style.transform = "translateY(0)";

    setTimeout(() => {
      toast.style.opacity = "0";
      toast.style.transform = "translateY(-20px)";
    }, 3500);
  }

  // Presets
  const SAMPLE_PHISHING = {
    subject: "CRITICAL: Your PayPal Account Has Been Suspended [Action Required]",
    sender: "security-alert@paypa1-support-verify.com",
    body: `Dear Valued Customer,

We detected unauthorized login attempts to your PayPal account from an unrecognized IP address (185.220.101.5). To protect your financial assets, your account access has been restricted immediately.

You must verify your identity within 24 hours or your balance will be permanently locked.

Click here immediately to restore access:
http://paypal-verification-center.info/login/restore.php?token=92847291

Failure to confirm your credentials will result in legal escalation and account forfeiture.

Security Team,
PayPal Holdings Inc.`
  };

  const SAMPLE_LEGITIMATE = {
    subject: "Sprint Retrospective & Demo - Friday 3 PM",
    sender: "sarah.jenkins@acme-corp.com",
    body: `Hi team,

A quick reminder that our bi-weekly Sprint 42 retrospective and demo will take place this Friday at 3:00 PM in Conference Room B and over Google Meet.

Please update your Jira tickets and add any discussion points or action items to the shared Notion retrospective board beforehand:
https://acme-corp.atlassian.net/jira/software/projects/MG/boards/12

Looking forward to seeing the new latency improvements!

Best regards,
Sarah Jenkins
Engineering Lead | Acme Corporation`
  };

  document.getElementById("btn-sample-phish").addEventListener("click", () => {
    switchTab("scan");
    document.getElementById("scan-subject").value = SAMPLE_PHISHING.subject;
    document.getElementById("scan-sender").value = SAMPLE_PHISHING.sender;
    document.getElementById("scan-body").value = SAMPLE_PHISHING.body;
    runScan();
  });

  document.getElementById("btn-sample-legit").addEventListener("click", () => {
    switchTab("scan");
    document.getElementById("scan-subject").value = SAMPLE_LEGITIMATE.subject;
    document.getElementById("scan-sender").value = SAMPLE_LEGITIMATE.sender;
    document.getElementById("scan-body").value = SAMPLE_LEGITIMATE.body;
    runScan();
  });

  document.getElementById("btn-clear-input").addEventListener("click", () => {
    document.getElementById("scan-subject").value = "";
    document.getElementById("scan-sender").value = "";
    document.getElementById("scan-body").value = "";
    document.getElementById("results-card").classList.add("hidden");
    document.getElementById("empty-state").classList.remove("hidden");
  });

  // Animated Gauge
  function updateGauge(score) {
    const circle = document.getElementById("gauge-circle");
    const scoreLabel = document.getElementById("gauge-score");
    const circumference = 339.29;
    const offset = circumference - (score / 100) * circumference;

    circle.style.strokeDashoffset = offset;
    scoreLabel.textContent = score;

    if (score >= 70) {
      circle.style.stroke = "#f43f5e";
    } else if (score >= 40) {
      circle.style.stroke = "#f59e0b";
    } else {
      circle.style.stroke = "#10b981";
    }
  }

  // Tactic Radar Chart (Chart.js)
  function renderTacticRadar(tacticsData) {
    const canvas = document.getElementById("tactic-radar-canvas");
    if (!canvas) return;

    const scores = (tacticsData && tacticsData.scores) ? tacticsData.scores : {
      urgency: 0, fear: 0, authority: 0, reward: 0, credentials: 0
    };

    const labels = ["Urgency", "Fear/Threat", "Authority", "Reward Bait", "Credentials"];
    const values = [
      scores.urgency || 0,
      scores.fear || 0,
      scores.authority || 0,
      scores.reward || 0,
      scores.credentials || 0
    ];

    if (radarChartInstance) {
      radarChartInstance.destroy();
    }

    radarChartInstance = new Chart(canvas, {
      type: "radar",
      data: {
        labels: labels,
        datasets: [{
          label: "Tactic Pressure",
          data: values,
          backgroundColor: "rgba(14, 165, 233, 0.25)",
          borderColor: "#38bdf8",
          pointBackgroundColor: "#0284c7",
          pointBorderColor: "#fff",
          borderWidth: 2,
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          r: {
            angleLines: { color: "rgba(51, 65, 85, 0.6)" },
            grid: { color: "rgba(51, 65, 85, 0.6)" },
            pointLabels: {
              color: "#94a3b8",
              font: { size: 9, family: "'Plus Jakarta Sans', sans-serif", weight: "600" }
            },
            ticks: { display: false, max: 100, min: 0 }
          }
        },
        plugins: {
          legend: { display: false }
        }
      }
    });
  }

  // Run Text Scan
  async function runScan() {
    const subject = document.getElementById("scan-subject").value.trim();
    const sender = document.getElementById("scan-sender").value.trim();
    const body = document.getElementById("scan-body").value.trim();

    if (!body && !subject) {
      alert("Please provide email text or subject to analyze.");
      return;
    }

    const scanBtn = document.getElementById("btn-run-scan");
    scanBtn.disabled = true;
    scanBtn.innerHTML = `Analyzing Email Layers...`;

    try {
      const response = await fetch("/api/v1/predict", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text: body, subject: subject, sender: sender }),
      });

      if (!response.ok) throw new Error(response.statusText);
      const data = await response.json();
      currentScanData = data;
      displayScanResults(data);
    } catch (err) {
      alert("Analysis error: " + err.message);
    } finally {
      scanBtn.disabled = false;
      scanBtn.innerHTML = `<span>Run Multi-Layer Inspection</span>`;
    }
  }

  document.getElementById("btn-run-scan").addEventListener("click", runScan);

  // Display Scan Results
  function displayScanResults(data) {
    document.getElementById("empty-state").classList.add("hidden");
    const resultsCard = document.getElementById("results-card");
    resultsCard.classList.remove("hidden");

    updateGauge(data.risk_score);

    // Verdict Badge
    const badge = document.getElementById("verdict-badge");
    badge.className = "px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider";
    if (data.verdict === "Dangerous") {
      badge.classList.add("badge-dangerous");
    } else if (data.verdict === "Suspicious") {
      badge.classList.add("badge-suspicious");
    } else {
      badge.classList.add("badge-safe");
    }
    badge.textContent = data.verdict;

    document.getElementById("verdict-title").textContent = `${data.verdict} Email`;
    document.getElementById("verdict-desc").textContent = data.verdict_description;
    document.getElementById("scan-latency").textContent = `${data.latency_ms}ms`;
    document.getElementById("classifier-name").textContent = data.model_name;

    // Brand Impersonation Banner
    const brandBanner = document.getElementById("brand-warning-banner");
    const brandText = document.getElementById("brand-warning-text");
    if (data.brand_impersonation && data.brand_impersonation.is_impersonation_detected) {
      brandBanner.classList.remove("hidden");
      brandText.textContent = data.brand_impersonation.warning;
    } else {
      brandBanner.classList.add("hidden");
    }

    // Key Reasons
    const reasonsContainer = document.getElementById("key-reasons-list");
    reasonsContainer.innerHTML = "";
    data.key_reasons.forEach((reason) => {
      const item = document.createElement("div");
      item.className = "flex items-start space-x-2 text-xs text-slate-300 p-2 rounded-lg bg-slate-900/60 border border-slate-800/80";
      item.innerHTML = `<span class="text-cyan-400 font-bold">&#8226;</span><span>${escapeHtml(reason)}</span>`;
      reasonsContainer.appendChild(item);
    });

    // Render Radar Chart
    renderTacticRadar(data.tactics);

    // XAI Highlighted Text
    document.getElementById("highlighted-text-container").innerHTML = data.highlighted_html || "(No text content)";

    // URL Findings Section
    const urlList = document.getElementById("url-findings-list");
    urlList.innerHTML = "";
    if (data.urls_detected && data.urls_detected.length > 0) {
      data.urls_detected.forEach((u) => {
        const item = document.createElement("div");
        item.className = "p-2.5 rounded-lg bg-slate-900 border border-slate-800 text-xs flex items-center justify-between";
        item.innerHTML = `
          <span class="font-mono text-cyan-300 font-semibold truncate max-w-sm">${escapeHtml(u.defanged_url)}</span>
          <span class="px-2 py-0.5 rounded text-[10px] font-bold ${u.verdict === 'Dangerous' ? 'text-rose-400 bg-rose-950/40' : 'text-emerald-400 bg-emerald-950/40'}">${u.verdict} (${u.url_risk_score}/100)</span>
        `;
        urlList.appendChild(item);
      });
    } else {
      urlList.innerHTML = "<p class='text-xs text-slate-500 italic'>No external links detected.</p>";
    }
  }

  // Active Learning Feedback handlers
  document.getElementById("btn-feedback-accurate").addEventListener("click", async () => {
    if (!currentScanData) return;
    await fetch("/api/v1/feedback", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email_snippet: document.getElementById("scan-body").value.slice(0, 150),
        predicted_verdict: currentScanData.verdict,
        user_reported_label: "Accurate"
      })
    });
    showToast("Feedback recorded: Thank you for confirming accuracy!", "success");
  });

  document.getElementById("btn-feedback-false").addEventListener("click", async () => {
    if (!currentScanData) return;
    await fetch("/api/v1/feedback", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email_snippet: document.getElementById("scan-body").value.slice(0, 150),
        predicted_verdict: currentScanData.verdict,
        user_reported_label: "Reported Incorrect",
        comments: "Flagged by user for review"
      })
    });
    showToast("Correction queued: Sample queued for model review.", "error");
  });

  // Print Report
  document.getElementById("btn-print-report").addEventListener("click", () => {
    window.print();
  });

  // Download Single Email PDF Report from Scanner
  const btnDownloadPdfScan = document.getElementById("btn-download-pdf-scan");
  if (btnDownloadPdfScan) {
    btnDownloadPdfScan.addEventListener("click", () => {
      if (!currentScanData) {
        alert("Please run a scan first before downloading the PDF report.");
        return;
      }
      const payload = {
        ...currentScanData,
        subject: document.getElementById("scan-subject").value || "(No Subject)",
        sender: document.getElementById("scan-sender").value || "(Unknown Sender)",
        text: document.getElementById("scan-body").value || ""
      };
      downloadPdfReport(payload, `mailguard_report_${Date.now()}.pdf`);
    });
  }

  async function downloadPdfReport(reportData, filename = "mailguard_report.pdf") {
    try {
      showToast("Generating official forensic PDF report...", "success");
      const resp = await fetch("/api/v1/report/pdf", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(reportData)
      });
      if (!resp.ok) throw new Error("Server returned " + resp.statusText);
      const blob = await resp.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
      showToast("PDF report downloaded successfully!", "success");
    } catch (err) {
      alert("Failed to download PDF report: " + err.message);
    }
  }

  async function downloadBatchPdfReport(batchData, filename = "mailguard_batch_dossier.pdf") {
    try {
      showToast("Compiling multi-page dataset PDF dossier...", "success");
      const resp = await fetch("/api/v1/report/batch-pdf", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(batchData)
      });
      if (!resp.ok) throw new Error("Server returned " + resp.statusText);
      const blob = await resp.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
      showToast("Batch PDF dossier downloaded!", "success");
    } catch (err) {
      alert("Failed to download batch dossier: " + err.message);
    }
  }

  // Adversarial Robustness Test
  document.getElementById("btn-test-adversarial").addEventListener("click", async () => {
    const body = document.getElementById("scan-body").value.trim();
    const subject = document.getElementById("scan-subject").value.trim();
    if (!body && !subject) {
      alert("Please enter email text to test adversarial evasion.");
      return;
    }

    const advBox = document.getElementById("adversarial-test-box");
    advBox.classList.remove("hidden");
    document.getElementById("adv-summary-text").textContent = "Synthesizing Cyrillic homoglyphs, zero-width characters, and leetspeak mutations...";

    try {
      const resp = await fetch("/api/v1/analyze/adversarial", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text: body, subject: subject })
      });
      const data = await resp.json();

      document.getElementById("adv-robust-badge").textContent = `Robustness: ${data.robustness_score}% (${data.status})`;
      document.getElementById("adv-summary-text").textContent = data.summary;
      document.getElementById("adv-perturbed-text").textContent = data.perturbed_preview;
      showToast(`Adversarial Test Complete: ${data.robustness_score}% Robustness`, "success");
    } catch (e) {
      document.getElementById("adv-summary-text").textContent = "Adversarial test error: " + e.message;
    }
  });

  // -------------------------------------------------------------
  // SIMULATOR QUIZ LOGIC
  // -------------------------------------------------------------
  async function loadNextSimulatorScenario() {
    const feedbackBox = document.getElementById("sim-feedback-box");
    const btnGroup = document.getElementById("sim-btn-group");
    feedbackBox.classList.add("hidden");
    btnGroup.classList.remove("hidden");

    try {
      const resp = await fetch("/api/v1/simulator/next");
      const scenario = await resp.json();
      simCurrentScenario = scenario;

      document.getElementById("sim-diff-badge").textContent = `Difficulty: ${scenario.difficulty}`;
      document.getElementById("sim-subject").textContent = scenario.subject;
      document.getElementById("sim-sender").textContent = scenario.sender;
      document.getElementById("sim-body").textContent = scenario.body;
    } catch (e) {
      console.error(e);
    }
  }

  async function handleSimulatorGuess(userGuessIsPhish) {
    if (!simCurrentScenario) return;

    try {
      const resp = await fetch("/api/v1/simulator/answer", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          scenario_id: simCurrentScenario.id,
          user_guess_is_phish: userGuessIsPhish
        })
      });
      const data = await resp.json();

      if (data.is_correct) {
        simScore += data.points_earned;
        simStreak += 1;
        showToast("Correct! +100 Points", "success");
      } else {
        simStreak = 0;
        showToast("Incorrect! Review the security indicators below.", "error");
      }

      // Update Ranks
      let rank = "Novice Guard";
      if (simScore >= 500) rank = "Champion Defender 🏆";
      else if (simScore >= 300) rank = "Security Sentinel 🛡️";
      else if (simScore >= 100) rank = "Cyber Analyst 🔍";

      document.getElementById("sim-score").textContent = simScore;
      document.getElementById("sim-streak").textContent = `🔥 ${simStreak}`;
      document.getElementById("sim-level").textContent = rank;

      // Show Feedback Box
      document.getElementById("sim-btn-group").classList.add("hidden");
      const fbBox = document.getElementById("sim-feedback-box");
      fbBox.classList.remove("hidden");

      const title = document.getElementById("sim-result-title");
      if (data.is_correct) {
        fbBox.className = "p-5 rounded-xl border border-emerald-500/40 bg-emerald-950/30 space-y-3";
        title.className = "text-base font-bold text-emerald-400";
        title.textContent = `🎯 Excellent Job! This email is indeed ${data.ground_truth}.`;
      } else {
        fbBox.className = "p-5 rounded-xl border border-rose-500/40 bg-rose-950/30 space-y-3";
        title.className = "text-base font-bold text-rose-400";
        title.textContent = `⚠️ Careful! This email is actually ${data.ground_truth}.`;
      }

      document.getElementById("sim-explanation").textContent = data.explanation;
      const indList = document.getElementById("sim-indicators-list");
      indList.innerHTML = "";
      data.indicators.forEach((ind) => {
        const li = document.createElement("li");
        li.textContent = ind;
        indList.appendChild(li);
      });
    } catch (e) {
      alert("Error submitting answer: " + e.message);
    }
  }

  document.getElementById("btn-guess-phish").addEventListener("click", () => handleSimulatorGuess(true));
  document.getElementById("btn-guess-legit").addEventListener("click", () => handleSimulatorGuess(false));
  document.getElementById("btn-next-scenario").addEventListener("click", loadNextSimulatorScenario);

  // -------------------------------------------------------------
  // DATASET ATTACHMENT & BATCH CLASSIFIER LOGIC
  // -------------------------------------------------------------
  const SAMPLE_BENCHMARK_BATCH = [
    {
      subject: "CRITICAL: Your PayPal Account Has Been Suspended",
      sender: "security-alert@paypa1-support-verify.com",
      text: "Dear customer, unauthorized activity was detected on your PayPal balance. Your account is restricted. Verify your credentials immediately at http://paypal-verification-center.info/restore.php to avoid account closure."
    },
    {
      subject: "Sprint Retrospective and Planning Demo - Friday",
      sender: "sarah.jenkins@acme-corp.com",
      text: "Hi team, a quick reminder that our Sprint 42 retrospective and demo will take place this Friday at 3:00 PM in Conference Room B. Please update Jira tickets."
    },
    {
      subject: "URGENT: Outstanding Invoice INV-8491 Overdue Payment Required",
      sender: "billing@supplier-paym3nt-portal.com",
      text: "Dear Accounts Payable, our payment bank details have changed. Please wire $34,500 immediately to the updated account on http://185.220.101.5/invoice.pdf to prevent legal escalation."
    },
    {
      subject: "Your Amazon.com order #112-9481948 has shipped",
      sender: "ship-confirm@amazon.com",
      text: "Hello Alex, your package with Amazon Logistics tracking #9284719 has shipped and is scheduled to arrive tomorrow by 8 PM."
    },
    {
      subject: "Microsoft 365: Your password expires in 2 hours",
      sender: "admin@m1crosoft-security-verify.net",
      text: "Your Office 365 enterprise password will expire today. Keep current password by logging in here: http://login-microsoftonline.account-update.xyz/auth"
    },
    {
      subject: "Quarterly Financial Review Notes",
      sender: "finance@acme-corp.com",
      text: "Attached is the presentation deck for Q3 earnings review. Revenue exceeded projections by 12%. Let us know if you have questions."
    },
    {
      subject: "Netflix: Update payment method - membership suspended",
      sender: "support@netf1ix-billing-update.com",
      text: "We could not process your latest subscription payment. Your membership is suspended. Update your card at http://netflix-member-renew.biz/update now."
    },
    {
      subject: "Lunch orders for tomorrow's team gathering",
      sender: "social-comm@company.org",
      text: "Hey everyone! Please fill out the lunch preference sheet by 5 PM today so we can order catering for tomorrow's town hall."
    },
    {
      subject: "DHL Express: Shipment awaiting customs duty fee ($2.95)",
      sender: "tracking@dhl-delivery-clearance.org",
      text: "Your incoming parcel is held at the sorting depot. A mandatory clearance fee of $2.95 is required. Pay now at http://dhl-express-redelivery-portal.com."
    },
    {
      subject: "GitHub: Security advisory for your repository",
      sender: "notifications@github.com",
      text: "We identified a low-severity dependency vulnerability in package-lock.json. Dependabot has opened a pull request with recommended bump."
    },
    {
      subject: "CEO Urgent Request: Are you available right now?",
      sender: "ceo.personal.mail@gmail.com",
      text: "I am in an executive board meeting and cannot take calls. I need you to purchase five $100 Apple gift cards for a partner gift. Send the claim codes directly to this email."
    },
    {
      subject: "Meeting Notes: Architecture Review and DB Scaling",
      sender: "tech-lead@acme-corp.com",
      text: "Thanks for attending today's architecture sync. We agreed on read-replicas for PostgreSQL and adding Redis caching for batch queries."
    }
  ];

  let currentBatchData = null;
  let currentDatasetFile = null;
  let currentActiveFilter = "all";
  let activeModalRecord = null;

  // Drag and drop / file input elements
  const datasetDropzone = document.getElementById("dataset-dropzone");
  const batchFileInput = document.getElementById("batch-file-input");
  const datasetFileBar = document.getElementById("dataset-file-bar");
  const datasetFileName = document.getElementById("dataset-file-name");
  const datasetFileSize = document.getElementById("dataset-file-size");
  const datasetRowPreview = document.getElementById("dataset-row-preview");
  const btnRunBatchDataset = document.getElementById("btn-run-batch-dataset");

  if (datasetDropzone && batchFileInput) {
    datasetDropzone.addEventListener("click", () => batchFileInput.click());
    datasetDropzone.addEventListener("dragover", (e) => {
      e.preventDefault();
      datasetDropzone.classList.add("border-cyan-500", "bg-cyan-950/20");
    });
    datasetDropzone.addEventListener("dragleave", () => {
      datasetDropzone.classList.remove("border-cyan-500", "bg-cyan-950/20");
    });
    datasetDropzone.addEventListener("drop", (e) => {
      e.preventDefault();
      datasetDropzone.classList.remove("border-cyan-500", "bg-cyan-950/20");
      if (e.dataTransfer.files.length > 0) {
        handleDatasetFileSelected(e.dataTransfer.files[0]);
      }
    });
    batchFileInput.addEventListener("change", (e) => {
      if (e.target.files.length > 0) {
        handleDatasetFileSelected(e.target.files[0]);
      }
    });
  }

  function handleDatasetFileSelected(file) {
    currentDatasetFile = file;
    datasetFileBar.classList.remove("hidden");
    datasetFileName.textContent = file.name;
    const sizeKb = (file.size / 1024).toFixed(1);
    datasetFileSize.textContent = `${sizeKb} KB`;
    datasetRowPreview.textContent = `Attached & Ready to Classify`;
    showToast(`Dataset file attached: ${file.name}`, "success");
  }

  if (btnRunBatchDataset) {
    btnRunBatchDataset.addEventListener("click", async () => {
      if (!currentDatasetFile) {
        alert("Please select or drop an email dataset file first.");
        return;
      }
      await uploadAndClassifyDataset(currentDatasetFile);
    });
  }

  document.getElementById("btn-load-sample-batch").addEventListener("click", () => {
    executeBatchJson(SAMPLE_BENCHMARK_BATCH);
  });

  async function uploadAndClassifyDataset(file) {
    const tbody = document.getElementById("batch-tbody");
    tbody.innerHTML = `<tr><td colspan="7" class="p-8 text-center text-cyan-400 font-medium">Parsing and classifying dataset through multi-layer detection pipeline...</td></tr>`;

    btnRunBatchDataset.disabled = true;
    btnRunBatchDataset.innerHTML = `Analyzing Dataset...`;

    const formData = new FormData();
    formData.append("file", file);

    try {
      const resp = await fetch("/api/v1/predict/dataset", {
        method: "POST",
        body: formData
      });
      if (!resp.ok) {
        let errDetail = `Server error (${resp.status}): ${resp.statusText}`;
        try {
          const err = await resp.json();
          if (err && err.detail) {
            errDetail = typeof err.detail === "string" ? err.detail : JSON.stringify(err.detail);
          }
        } catch (_) {
          try {
            const rawText = await resp.text();
            if (rawText) errDetail = rawText.slice(0, 200);
          } catch (__) {}
        }
        throw new Error(errDetail);
      }
      const data = await resp.json();
      currentBatchData = data;
      renderBatchResults(data);
      if (data.dataset_total_rows && data.dataset_total_rows > data.total_scanned) {
        datasetRowPreview.textContent = `Analyzed ${data.total_scanned} of ${data.dataset_total_rows} emails in ${file.name}`;
      }
      showToast(`Classified ${data.total_scanned} emails from dataset!`, "success");
    } catch (e) {
      tbody.innerHTML = `<tr><td colspan="7" class="p-8 text-center text-rose-400 font-semibold">Dataset scan error: ${escapeHtml(e.message)}</td></tr>`;
      alert("Error analyzing dataset: " + e.message);
    } finally {
      btnRunBatchDataset.disabled = false;
      btnRunBatchDataset.innerHTML = `<span>Flag & Classify Dataset</span>`;
    }
  }

  async function executeBatchJson(emails) {
    const tbody = document.getElementById("batch-tbody");
    tbody.innerHTML = `<tr><td colspan="7" class="p-8 text-center text-cyan-400 font-medium">Processing ${emails.length} benchmark emails through multi-layer pipeline...</td></tr>`;

    try {
      const resp = await fetch("/api/v1/predict/batch", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ emails: emails })
      });
      if (!resp.ok) throw new Error(resp.statusText);
      const data = await resp.json();
      currentBatchData = data;
      renderBatchResults(data);
      showToast(`Classified ${data.total_scanned} benchmark emails!`, "success");
    } catch (e) {
      tbody.innerHTML = `<tr><td colspan="7" class="p-8 text-center text-rose-400 font-semibold">Batch scan error: ${e.message}</td></tr>`;
    }
  }

  function renderBatchResults(data) {
    document.getElementById("batch-stats-bar").classList.remove("hidden");
    document.getElementById("batch-controls-bar").classList.remove("hidden");

    const total = data.total_scanned || 0;
    const flagged = (data.dangerous_count || 0) + (data.suspicious_count || 0);
    const legit = data.safe_count || 0;
    const rate = total > 0 ? ((flagged / total) * 100).toFixed(1) : 0;

    let avgRisk = 0;
    if (data.results && data.results.length > 0) {
      const sumRisk = data.results.reduce((acc, r) => acc + (r.risk_score || 0), 0);
      avgRisk = Math.round(sumRisk / data.results.length);
    }

    document.getElementById("batch-total").textContent = total;
    document.getElementById("batch-flagged-phish").textContent = flagged;
    document.getElementById("batch-verified-legit").textContent = legit;
    document.getElementById("batch-phish-rate").textContent = `${rate}%`;
    document.getElementById("batch-avg-risk").textContent = `${avgRisk}/100`;

    document.getElementById("count-all").textContent = total;
    document.getElementById("count-phish").textContent = flagged;
    document.getElementById("count-legit").textContent = legit;

    populateFilteredTable();
  }

  function populateFilteredTable() {
    if (!currentBatchData || !currentBatchData.results) return;

    const tbody = document.getElementById("batch-tbody");
    const searchTerm = (document.getElementById("batch-search-input").value || "").toLowerCase().trim();

    let filtered = currentBatchData.results.filter((r) => {
      const isPhish = r.verdict === "Dangerous" || r.verdict === "Suspicious";
      if (currentActiveFilter === "phish" && !isPhish) return false;
      if (currentActiveFilter === "legit" && isPhish) return false;

      if (searchTerm) {
        const textToSearch = `${r.subject} ${r.sender} ${r.primary_tactic || ''}`.toLowerCase();
        if (!textToSearch.includes(searchTerm)) return false;
      }
      return true;
    });

    tbody.innerHTML = "";

    if (filtered.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" class="p-6 text-center text-slate-500">No emails matched current filter/search.</td></tr>`;
      return;
    }

    filtered.forEach((r, idx) => {
      const tr = document.createElement("tr");
      tr.className = "hover:bg-slate-900/60 transition";

      const isPhish = r.verdict === "Dangerous" || r.verdict === "Suspicious";
      const flagBadge = isPhish
        ? `<span class="px-2.5 py-1 rounded text-[10px] font-bold bg-rose-500/20 text-rose-300 border border-rose-500/30">🚩 FLAGGED PHISH (${r.verdict})</span>`
        : `<span class="px-2.5 py-1 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">✅ VERIFIED LEGIT</span>`;

      const riskColor = r.risk_score >= 70 ? 'text-rose-400' : r.risk_score >= 40 ? 'text-amber-400' : 'text-emerald-400';

      tr.innerHTML = `
        <td class="p-3 text-slate-500 font-mono">${r.index || (idx + 1)}</td>
        <td class="p-3 font-semibold text-white max-w-xs truncate" title="${escapeHtml(r.subject)}">${escapeHtml(r.subject)}</td>
        <td class="p-3 text-slate-400 max-w-xs truncate" title="${escapeHtml(r.sender)}">${escapeHtml(r.sender)}</td>
        <td class="p-3">${flagBadge}</td>
        <td class="p-3 text-center font-mono font-bold ${riskColor}">${r.risk_score}/100</td>
        <td class="p-3 text-cyan-300">${escapeHtml(r.primary_tactic || 'None')}</td>
        <td class="p-3 text-right">
          <div class="flex items-center justify-end space-x-1.5">
            <button class="btn-view-report px-2.5 py-1 rounded-lg text-[11px] font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition" data-idx="${r.index || (idx + 1)}">
              📄 View Report
            </button>
            <button class="btn-download-row-pdf px-2.5 py-1 rounded-lg text-[11px] font-bold bg-cyan-950/70 hover:bg-cyan-900 text-cyan-300 border border-cyan-700/50 transition flex items-center space-x-1" data-idx="${r.index || (idx + 1)}">
              <svg class="w-3 h-3 text-cyan-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>
              <span>PDF</span>
            </button>
          </div>
        </td>
      `;
      tbody.appendChild(tr);
    });

    // Attach row button listeners
    tbody.querySelectorAll(".btn-view-report").forEach((btn) => {
      btn.addEventListener("click", () => {
        const itemIdx = parseInt(btn.getAttribute("data-idx"));
        const item = currentBatchData.results.find((x) => (x.index || 0) === itemIdx) || currentBatchData.results[itemIdx - 1];
        if (item) openEmailReportModal(item);
      });
    });

    tbody.querySelectorAll(".btn-download-row-pdf").forEach((btn) => {
      btn.addEventListener("click", () => {
        const itemIdx = parseInt(btn.getAttribute("data-idx"));
        const item = currentBatchData.results.find((x) => (x.index || 0) === itemIdx) || currentBatchData.results[itemIdx - 1];
        if (item) {
          const safeSubject = (item.subject || "email").replace(/[^a-zA-Z0-9_-]/g, "_").slice(0, 30);
          downloadPdfReport(item, `mailguard_report_${itemIdx}_${safeSubject}.pdf`);
        }
      });
    });
  }

  // Filter Buttons
  document.getElementById("batch-filter-all").addEventListener("click", () => {
    currentActiveFilter = "all";
    updateFilterStyles("batch-filter-all");
    populateFilteredTable();
  });
  document.getElementById("batch-filter-phish").addEventListener("click", () => {
    currentActiveFilter = "phish";
    updateFilterStyles("batch-filter-phish");
    populateFilteredTable();
  });
  document.getElementById("batch-filter-legit").addEventListener("click", () => {
    currentActiveFilter = "legit";
    updateFilterStyles("batch-filter-legit");
    populateFilteredTable();
  });

  function updateFilterStyles(activeId) {
    ["batch-filter-all", "batch-filter-phish", "batch-filter-legit"].forEach((id) => {
      const el = document.getElementById(id);
      if (id === activeId) {
        el.className = "px-3 py-1.5 rounded-lg font-semibold bg-slate-800 text-white transition";
      } else {
        el.className = "px-3 py-1.5 rounded-lg font-semibold text-slate-400 hover:bg-slate-800 transition";
      }
    });
  }

  // Live Search
  document.getElementById("batch-search-input").addEventListener("input", () => {
    populateFilteredTable();
  });

  // Download Complete Batch PDF Dossier
  document.getElementById("btn-download-batch-pdf").addEventListener("click", () => {
    if (!currentBatchData) {
      alert("No batch data available to download.");
      return;
    }
    downloadBatchPdfReport(currentBatchData, `mailguard_batch_dossier_${Date.now()}.pdf`);
  });

  // Export Results as CSV
  document.getElementById("btn-export-batch-csv").addEventListener("click", () => {
    if (!currentBatchData || !currentBatchData.results) {
      alert("No results to export.");
      return;
    }
    const headers = ["Index", "Subject", "Sender", "Verdict", "Flag Status", "Risk Score", "Phishing Probability", "Primary Tactic", "Latency MS"];
    const rows = currentBatchData.results.map((r, i) => [
      r.index || (i + 1),
      `"${(r.subject || '').replace(/"/g, '""')}"`,
      `"${(r.sender || '').replace(/"/g, '""')}"`,
      r.verdict,
      r.flag_status,
      r.risk_score,
      r.phishing_probability,
      `"${(r.primary_tactic || 'None').replace(/"/g, '""')}"`,
      r.latency_ms
    ]);

    const csvContent = "data:text/csv;charset=utf-8," + [headers.join(","), ...rows.map(e => e.join(","))].join("\n");
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `mailguard_dataset_classified_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    link.remove();
    showToast("CSV dataset exported successfully!", "success");
  });

  // -------------------------------------------------------------
  // DETAILED EMAIL FORENSIC REPORT MODAL LOGIC
  // -------------------------------------------------------------
  const modal = document.getElementById("modal-email-report");
  const btnCloseModal = document.getElementById("btn-close-modal");
  const btnCloseModalBottom = document.getElementById("btn-close-modal-bottom");
  const btnDownloadModalPdf = document.getElementById("btn-download-modal-pdf");

  function openEmailReportModal(record) {
    activeModalRecord = record;
    document.getElementById("modal-report-title").textContent = `Forensic Audit Report - Email #${record.index || 1}`;

    const isPhish = record.verdict === "Dangerous" || record.verdict === "Suspicious";
    const banner = document.getElementById("modal-verdict-banner");
    const flagBadge = document.getElementById("modal-flag-badge");
    const verdictBadge = document.getElementById("modal-verdict-badge");
    const riskScore = document.getElementById("modal-risk-score");

    if (record.verdict === "Dangerous") {
      banner.className = "p-4 rounded-xl border border-rose-500/50 bg-rose-950/30 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3";
      flagBadge.className = "px-2.5 py-1 rounded-full text-xs font-bold uppercase tracking-wider bg-rose-500/30 text-rose-300 border border-rose-500/40";
      flagBadge.textContent = "🚩 FLAGGED AS PHISHING";
      verdictBadge.className = "px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-rose-950 text-rose-400";
      verdictBadge.textContent = "Dangerous";
      riskScore.className = "text-3xl font-black text-rose-400";
    } else if (record.verdict === "Suspicious") {
      banner.className = "p-4 rounded-xl border border-amber-500/50 bg-amber-950/30 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3";
      flagBadge.className = "px-2.5 py-1 rounded-full text-xs font-bold uppercase tracking-wider bg-amber-500/30 text-amber-300 border border-amber-500/40";
      flagBadge.textContent = "🚩 FLAGGED AS SUSPICIOUS";
      verdictBadge.className = "px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-amber-950 text-amber-400";
      verdictBadge.textContent = "Suspicious";
      riskScore.className = "text-3xl font-black text-amber-400";
    } else {
      banner.className = "p-4 rounded-xl border border-emerald-500/50 bg-emerald-950/30 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3";
      flagBadge.className = "px-2.5 py-1 rounded-full text-xs font-bold uppercase tracking-wider bg-emerald-500/30 text-emerald-300 border border-emerald-500/40";
      flagBadge.textContent = "✅ VERIFIED AS LEGITIMATE";
      verdictBadge.className = "px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-emerald-950 text-emerald-400";
      verdictBadge.textContent = "Safe";
      riskScore.className = "text-3xl font-black text-emerald-400";
    }

    riskScore.textContent = `${record.risk_score || 0}/100`;
    document.getElementById("modal-verdict-desc").textContent = record.verdict_description || (isPhish ? "High threat indicators present." : "Standard benign email patterns.");

    document.getElementById("modal-subject").textContent = record.subject || "(No Subject)";
    document.getElementById("modal-sender").textContent = record.sender || "(Unknown Sender)";
    document.getElementById("modal-probability").textContent = `${((record.phishing_probability || 0) * 100).toFixed(1)}%`;
    document.getElementById("modal-model-name").textContent = record.model_name || "Soft-Voting Ensemble";

    // Brand Alert
    const brandBox = document.getElementById("modal-brand-box");
    const brandText = document.getElementById("modal-brand-text");
    if (record.brand_impersonation && record.brand_impersonation.is_impersonation_detected) {
      brandBox.classList.remove("hidden");
      brandText.textContent = record.brand_impersonation.warning;
    } else {
      brandBox.classList.add("hidden");
    }

    // Reasons List
    const reasonsList = document.getElementById("modal-reasons-list");
    reasonsList.innerHTML = "";
    const reasons = record.key_reasons || ["No critical threats detected."];
    reasons.forEach((r) => {
      const item = document.createElement("div");
      item.className = "flex items-start space-x-2 text-xs text-slate-300 p-2 rounded-lg bg-slate-950 border border-slate-800/80";
      item.innerHTML = `<span class="text-cyan-400 font-bold">&#8226;</span><span>${escapeHtml(r)}</span>`;
      reasonsList.appendChild(item);
    });

    // Tactics Grid
    const tacticsGrid = document.getElementById("modal-tactics-grid");
    tacticsGrid.innerHTML = "";
    const tScores = (record.tactics && record.tactics.scores) ? record.tactics.scores : { urgency: 0, fear: 0, authority: 0, reward: 0, credentials: 0 };
    const tKeys = [
      { key: "urgency", label: "Urgency" },
      { key: "fear", label: "Fear" },
      { key: "authority", label: "Authority" },
      { key: "reward", label: "Reward" },
      { key: "credentials", label: "Credentials" }
    ];
    tKeys.forEach((tk) => {
      const val = tScores[tk.key] || 0;
      const tile = document.createElement("div");
      tile.className = "p-2 rounded-lg bg-slate-950 border border-slate-800";
      tile.innerHTML = `
        <span class="text-[9px] uppercase text-slate-400 block">${tk.label}</span>
        <span class="font-bold text-xs ${val >= 50 ? 'text-rose-400' : 'text-slate-300'}">${val}</span>
      `;
      tacticsGrid.appendChild(tile);
    });

    // URLs List
    const urlsList = document.getElementById("modal-urls-list");
    urlsList.innerHTML = "";
    if (record.urls_detected && record.urls_detected.length > 0) {
      record.urls_detected.forEach((u) => {
        const item = document.createElement("div");
        item.className = "p-2 rounded-lg bg-slate-950 border border-slate-800 text-xs flex items-center justify-between";
        item.innerHTML = `
          <span class="font-mono text-cyan-300 font-semibold truncate max-w-md">${escapeHtml(u.defanged_url)}</span>
          <span class="px-2 py-0.5 rounded text-[10px] font-bold ${u.verdict === 'Dangerous' ? 'text-rose-400 bg-rose-950/40' : 'text-emerald-400 bg-emerald-950/40'}">${u.verdict} (${u.url_risk_score}/100)</span>
        `;
        urlsList.appendChild(item);
      });
    } else {
      urlsList.innerHTML = "<p class='text-xs text-slate-500 italic'>No external links detected.</p>";
    }

    // Body excerpt
    document.getElementById("modal-body-excerpt").textContent = record.text || "(No email body text)";

    modal.classList.remove("hidden");
  }

  function closeModal() {
    modal.classList.add("hidden");
    activeModalRecord = null;
  }

  if (btnCloseModal) btnCloseModal.addEventListener("click", closeModal);
  if (btnCloseModalBottom) btnCloseModalBottom.addEventListener("click", closeModal);
  modal.addEventListener("click", (e) => {
    if (e.target === modal) closeModal();
  });

  if (btnDownloadModalPdf) {
    btnDownloadModalPdf.addEventListener("click", () => {
      if (!activeModalRecord) return;
      const safeSubject = (activeModalRecord.subject || "email").replace(/[^a-zA-Z0-9_-]/g, "_").slice(0, 30);
      downloadPdfReport(activeModalRecord, `mailguard_report_${activeModalRecord.index || 1}_${safeSubject}.pdf`);
    });
  }

  // -------------------------------------------------------------
  // ATTACHMENT CHECKER LOGIC
  // -------------------------------------------------------------
  document.getElementById("btn-check-attach").addEventListener("click", async () => {
    const filename = document.getElementById("attach-filename-input").value.trim();
    if (!filename) {
      alert("Please provide a filename to inspect.");
      return;
    }

    const resultBox = document.getElementById("attach-result-box");
    resultBox.classList.remove("hidden");
    resultBox.innerHTML = "<p class='text-xs text-slate-400'>Inspecting file extension and calculating security posture...</p>";

    const formData = new FormData();
    formData.append("filename", filename);

    try {
      const resp = await fetch("/api/v1/analyze/attachment", {
        method: "POST",
        body: formData
      });
      const data = await resp.json();

      let flagsList = "";
      data.threat_flags.forEach(f => {
        flagsList += `<li class="text-rose-400 font-medium">${escapeHtml(f)}</li>`;
      });

      resultBox.innerHTML = `
        <div class="p-6 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
          <div class="flex items-center justify-between pb-3 border-b border-slate-800">
            <div>
              <span class="text-xs text-slate-400 block">Inspected Filename</span>
              <span class="font-mono text-base font-bold text-white">${escapeHtml(data.filename)}</span>
            </div>
            <div class="text-right">
              <span class="px-3 py-1 rounded-full text-xs font-bold uppercase ${data.verdict === 'Dangerous' ? 'badge-dangerous' : data.verdict === 'Suspicious' ? 'badge-suspicious' : 'badge-safe'}">${data.verdict} (Risk: ${data.risk_score})</span>
            </div>
          </div>
          <div class="text-xs space-y-2">
            <p class="text-slate-300"><strong class="text-white">Detected Extension:</strong> <span class="font-mono text-cyan-300">${escapeHtml(data.extension || 'None')}</span></p>
            <p class="text-slate-300"><strong class="text-white">Deceptive Double Extension:</strong> <span class="${data.is_double_extension ? 'text-rose-400 font-bold' : 'text-emerald-400'}">${data.is_double_extension ? 'YES (Masquerading payload)' : 'No'}</span></p>
            <p class="text-slate-300"><strong class="text-white">Executable Script Flag:</strong> <span class="${data.is_executable ? 'text-rose-400 font-bold' : 'text-emerald-400'}">${data.is_executable ? 'YES (High Risk)' : 'No'}</span></p>
            <div class="pt-2">
              <span class="text-[10px] font-bold uppercase tracking-wider text-slate-400 block mb-1">Threat Flags:</span>
              <ul class="list-disc list-inside space-y-1">
                ${flagsList || "<li class='text-emerald-400'>Clean extension. No malicious flags.</li>"}
              </ul>
            </div>
          </div>
        </div>
      `;
    } catch (e) {
      resultBox.innerHTML = `<p class="text-xs text-rose-400">Error: ${e.message}</p>`;
    }
  });

  // -------------------------------------------------------------
  // EML & URL LOGIC
  // -------------------------------------------------------------
  const dropzone = document.getElementById("eml-dropzone");
  const fileInput = document.getElementById("eml-file-input");

  if (dropzone && fileInput) {
    dropzone.addEventListener("click", () => fileInput.click());
    dropzone.addEventListener("dragover", (e) => { e.preventDefault(); dropzone.classList.add("border-cyan-500"); });
    dropzone.addEventListener("dragleave", () => dropzone.classList.remove("border-cyan-500"));
    dropzone.addEventListener("drop", (e) => {
      e.preventDefault();
      dropzone.classList.remove("border-cyan-500");
      if (e.dataTransfer.files.length > 0) handleEmlFile(e.dataTransfer.files[0]);
    });
    fileInput.addEventListener("change", (e) => {
      if (e.target.files.length > 0) handleEmlFile(e.target.files[0]);
    });
  }

  async function handleEmlFile(file) {
    const emlResults = document.getElementById("eml-results");
    emlResults.classList.remove("hidden");
    emlResults.innerHTML = "<p class='text-sm text-cyan-400'>Parsing RFC 822 MIME headers and evaluating email body...</p>";

    const formData = new FormData();
    formData.append("file", file);

    try {
      const resp = await fetch("/api/v1/analyze/eml", { method: "POST", body: formData });
      if (!resp.ok) throw new Error(resp.statusText);
      const data = await resp.json();

      emlResults.innerHTML = `
        <div class="p-6 rounded-xl bg-slate-900 border border-slate-800 space-y-6">
          <div class="flex items-center justify-between pb-4 border-b border-slate-800">
            <div>
              <span class="text-xs font-mono text-cyan-400">Header Inspection Result</span>
              <h3 class="text-xl font-bold text-white">${escapeHtml(data.subject || '(No Subject)')}</h3>
              <p class="text-xs text-slate-400 mt-1">From: ${escapeHtml(data.from_header)}</p>
            </div>
            <div class="text-right">
              <span class="px-3 py-1 rounded-full text-xs font-bold uppercase ${data.verdict === 'Dangerous' ? 'badge-dangerous' : data.verdict === 'Suspicious' ? 'badge-suspicious' : 'badge-safe'}">${data.verdict} (${data.risk_score}/100)</span>
            </div>
          </div>
          <div class="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-mono">
            <div class="p-3 rounded-lg bg-slate-950 border border-slate-800">
              <span class="text-slate-400 block text-[10px] uppercase">SPF Status</span>
              <span class="font-bold ${data.auth_status.spf === 'pass' ? 'text-emerald-400' : 'text-rose-400'}">${data.auth_status.spf.toUpperCase()}</span>
            </div>
            <div class="p-3 rounded-lg bg-slate-950 border border-slate-800">
              <span class="text-slate-400 block text-[10px] uppercase">DKIM Signature</span>
              <span class="font-bold ${data.auth_status.dkim === 'pass' ? 'text-emerald-400' : 'text-rose-400'}">${data.auth_status.dkim.toUpperCase()}</span>
            </div>
            <div class="p-3 rounded-lg bg-slate-950 border border-slate-800">
              <span class="text-slate-400 block text-[10px] uppercase">DMARC Policy</span>
              <span class="font-bold ${data.auth_status.dmarc === 'pass' ? 'text-emerald-400' : 'text-rose-400'}">${data.auth_status.dmarc.toUpperCase()}</span>
            </div>
          </div>
          <div class="space-y-2">
            <span class="text-xs font-bold text-slate-300 uppercase tracking-wider block">Header Anomalies & Findings</span>
            <ul class="text-xs text-rose-400 list-disc list-inside space-y-1">
              ${data.header_anomalies.map(a => `<li>${escapeHtml(a)}</li>`).join('') || "<li class='text-emerald-400'>All RFC headers aligned. No anomalies.</li>"}
            </ul>
          </div>
        </div>
      `;
    } catch (e) {
      emlResults.innerHTML = `<p class="text-xs text-rose-400">Error parsing .EML: ${e.message}</p>`;
    }
  }

  // URL Analyzer
  document.getElementById("btn-analyze-url").addEventListener("click", async () => {
    const urlInput = document.getElementById("url-input").value.trim();
    if (!urlInput) {
      alert("Please enter a URL to inspect.");
      return;
    }

    const container = document.getElementById("url-standalone-result");
    container.classList.remove("hidden");
    container.innerHTML = "<p class='text-xs text-slate-400'>Inspecting URL statically...</p>";

    try {
      const resp = await fetch("/api/v1/analyze/url", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: urlInput }),
      });
      const data = await resp.json();

      let flagsHtml = "";
      data.threat_flags.forEach((f) => {
        flagsHtml += `<li class="text-rose-400 font-medium">${escapeHtml(f)}</li>`;
      });

      container.innerHTML = `
        <div class="p-6 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
          <div class="flex items-center justify-between">
            <div>
              <span class="text-xs text-slate-400 block">Defanged Target</span>
              <span class="font-mono text-base font-bold text-cyan-400">${escapeHtml(data.defanged_url)}</span>
            </div>
            <div class="text-right">
              <span class="text-xs text-slate-400 block">Threat Score</span>
              <span class="text-2xl font-black ${data.url_risk_score >= 60 ? 'text-rose-400' : data.url_risk_score >= 30 ? 'text-amber-400' : 'text-emerald-400'}">${data.url_risk_score}/100 (${data.verdict})</span>
            </div>
          </div>
          <div class="space-y-2 border-t border-slate-800 pt-3 text-xs">
            <span class="font-bold text-slate-300 uppercase tracking-wider block">Security Findings</span>
            <ul class="list-disc list-inside space-y-1">
              ${flagsHtml || "<li class='text-emerald-400'>No static malicious heuristics triggered.</li>"}
            </ul>
          </div>
        </div>
      `;
    } catch (e) {
      container.innerHTML = `<p class="text-xs text-rose-400">Failed to analyze: ${e.message}</p>`;
    }
  });

  // Benchmarks Table Loader
  async function loadModelBenchmarks() {
    const tbody = document.getElementById("benchmark-tbody");
    try {
      const resp = await fetch("/api/v1/models/metrics");
      const data = await resp.json();

      tbody.innerHTML = "";
      if (data.benchmark_table && data.benchmark_table.length > 0) {
        data.benchmark_table.forEach((row) => {
          const tr = document.createElement("tr");
          tr.className = "hover:bg-slate-900/60 transition";
          tr.innerHTML = `
            <td class="p-3.5 font-bold text-white">${escapeHtml(row["Model"])}</td>
            <td class="p-3.5 text-slate-300">${escapeHtml(row["Accuracy"])}</td>
            <td class="p-3.5 font-bold text-cyan-400">${escapeHtml(row["Recall (Phish)"])}</td>
            <td class="p-3.5 text-slate-300">${escapeHtml(row["Precision"])}</td>
            <td class="p-3.5 text-slate-300">${escapeHtml(row["F1-Score"])}</td>
            <td class="p-3.5 text-slate-300">${escapeHtml(row["ROC-AUC"])}</td>
            <td class="p-3.5 text-emerald-400">${escapeHtml(row["Latency (ms)"])}</td>
            <td class="p-3.5 text-slate-400">${escapeHtml(row["Size (KB)"])}</td>
          `;
          tbody.appendChild(tr);
        });
      }

      // Also load Concept Drift metrics
      try {
        const driftResp = await fetch("/api/v1/monitoring/drift");
        const driftData = await driftResp.json();
        const badge = document.getElementById("drift-status-badge");
        badge.textContent = driftData.drift_status;
        badge.className = `px-2.5 py-0.5 rounded text-[10px] font-bold uppercase ${driftData.alert_triggered ? 'bg-rose-500/20 text-rose-300' : 'bg-emerald-500/20 text-emerald-300'}`;
        document.getElementById("drift-inferences").textContent = driftData.total_inferences_recorded;
        document.getElementById("drift-phish-ratio").textContent = `${(driftData.phishing_ratio * 100).toFixed(1)}%`;
        document.getElementById("drift-legit-ratio").textContent = `${(driftData.legitimate_ratio * 100).toFixed(1)}%`;
        document.getElementById("drift-confidence").textContent = `${(driftData.mean_confidence * 100).toFixed(1)}%`;
        document.getElementById("drift-rec-text").textContent = driftData.recommendation;
      } catch (err) {
        console.error(err);
      }
    } catch (e) {
      tbody.innerHTML = `<tr><td colspan="8" class="p-6 text-center text-rose-400">Failed to load metrics: ${e.message}</td></tr>`;
    }
  }

  function escapeHtml(str) {
    if (!str) return "";
    return str
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }
});
