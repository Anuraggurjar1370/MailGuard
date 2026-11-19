document.addEventListener("DOMContentLoaded", () => {
  const scanBtn = document.getElementById("btn-scan");
  const textInput = document.getElementById("email-text");
  const resultBox = document.getElementById("result-box");
  const badge = document.getElementById("res-badge");
  const score = document.getElementById("res-score");
  const desc = document.getElementById("res-desc");
  const reasons = document.getElementById("res-reasons");

  scanBtn.addEventListener("click", async () => {
    const text = textInput.value.trim();
    if (!text) return;

    scanBtn.disabled = true;
    scanBtn.textContent = "Scanning...";

    try {
      const resp = await fetch("http://127.0.0.1:8000/api/v1/predict", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text: text })
      });

      if (!resp.ok) throw new Error("API Offline or unreachable");
      const data = await resp.json();

      resultBox.style.display = "block";
      badge.textContent = data.verdict;
      badge.className = "verdict-badge " + (data.verdict === "Dangerous" ? "danger" : data.verdict === "Suspicious" ? "suspicious" : "safe");
      score.textContent = `${data.risk_score}/100`;
      desc.textContent = data.verdict_description;

      reasons.innerHTML = "";
      if (data.key_reasons) {
        data.key_reasons.slice(0, 3).forEach(r => {
          const div = document.createElement("div");
          div.textContent = "• " + r;
          reasons.appendChild(div);
        });
      }
    } catch (e) {
      alert("Error: " + e.message + ". Make sure MailGuard API server is running on http://127.0.0.1:8000");
    } finally {
      scanBtn.disabled = false;
      scanBtn.textContent = "Scan for Phishing";
    }
  });
});
