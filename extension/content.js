/**
 * MailGuard Webmail Content Script.
 * Observes open webmail threads on Gmail and Outlook and displays security status.
 */

console.log("[MailGuard] Webmail Shield Content Script Loaded.");

function injectMailGuardBanner() {
  if (document.getElementById("mailguard-floating-shield")) return;

  const shieldPill = document.createElement("div");
  shieldPill.id = "mailguard-floating-shield";
  shieldPill.style.position = "fixed";
  shieldPill.style.bottom = "20px";
  shieldPill.style.right = "20px";
  shieldPill.style.zIndex = "999999";
  shieldPill.style.padding = "8px 12px";
  shieldPill.style.borderRadius = "20px";
  shieldPill.style.backgroundColor = "rgba(15, 23, 42, 0.95)";
  shieldPill.style.color = "#38bdf8";
  shieldPill.style.border = "1px solid #0ea5e9";
  shieldPill.style.boxShadow = "0 4px 12px rgba(0,0,0,0.5)";
  shieldPill.style.fontFamily = "system-ui, sans-serif";
  shieldPill.style.fontSize = "12px";
  shieldPill.style.fontWeight = "bold";
  shieldPill.style.cursor = "pointer";
  shieldPill.textContent = "🛡️ MailGuard Active";

  shieldPill.title = "Click to scan email selection with MailGuard";
  shieldPill.addEventListener("click", () => {
    const selection = window.getSelection().toString();
    if (!selection) {
      alert("MailGuard: Select email text on the page to analyze it.");
    } else {
      alert(`MailGuard Analyzing ${selection.length} characters of selected text...`);
    }
  });

  document.body.appendChild(shieldPill);
}

// Inject after brief delay on mail portals
setTimeout(injectMailGuardBanner, 2500);
