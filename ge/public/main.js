// MediaHub GE - Frontend Logic
document.addEventListener("DOMContentLoaded", () => {
  const statusDot = document.getElementById("status-dot");
  const statusText = document.getElementById("status-text");

  const nameInput = document.getElementById("name-input");
  const greetBtn = document.getElementById("greet-btn");
  const greetResult = document.getElementById("greet-result");

  const sysinfoBtn = document.getElementById("sysinfo-btn");
  const pingBtn = document.getElementById("ping-btn");

  const valOs = document.getElementById("val-os");
  const valArch = document.getElementById("val-arch");
  const valGo = document.getElementById("val-go");
  const valEngine = document.getElementById("val-engine");
  const valPing = document.getElementById("val-ping");

  // Check if running inside Wails
  function isWailsAvailable() {
    return !!(window.go && window.go.main && window.go.main.App);
  }

  function updateConnectionStatus() {
    if (isWailsAvailable()) {
      statusDot.className = "status-dot online";
      statusText.textContent = "Go 백엔드 연결됨";
      return true;
    } else {
      statusDot.className = "status-dot";
      statusText.textContent = "미리보기 모드 (Wails 외부)";
      return false;
    }
  }

  // Initial check with brief retry in case Wails runtime is injected asynchronously
  let checkAttempts = 0;
  const checkTimer = setInterval(() => {
    checkAttempts++;
    if (updateConnectionStatus() || checkAttempts > 10) {
      clearInterval(checkTimer);
    }
  }, 200);

  // Greet handler
  greetBtn.addEventListener("click", async () => {
    const name = nameInput.value.trim() || "User";
    greetResult.innerHTML = '<span class="placeholder">요청 처리 중...</span>';

    try {
      if (isWailsAvailable()) {
        const response = await window.go.main.App.Greet(name);
        greetResult.innerHTML = `<span class="success-text">📥 ${escapeHtml(response)}</span>`;
      } else {
        // Fallback for standalone browser testing
        greetResult.innerHTML = `<span class="success-text">📥 [모의 응답] Hello ${escapeHtml(name)}! MediaHub GE (더미 모드)가 정상 동작 중입니다.</span>`;
      }
    } catch (err) {
      greetResult.innerHTML = `<span style="color: var(--error);">오류: ${escapeHtml(String(err))}</span>`;
    }
  });

  // Enter key triggers greet
  nameInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      greetBtn.click();
    }
  });

  // System info handler
  sysinfoBtn.addEventListener("click", async () => {
    try {
      if (isWailsAvailable()) {
        const info = await window.go.main.App.GetSystemInfo();
        valOs.textContent = info.os || "windows";
        valArch.textContent = info.arch || "amd64";
        valGo.textContent = info.goVersion || "go1.26";
        valEngine.textContent = info.engine || "Wails v2";
      } else {
        // Fallback for standalone browser preview
        valOs.textContent = navigator.platform || "Browser";
        valArch.textContent = "x64 (Browser Preview)";
        valGo.textContent = "Go (Wails 실행 대기)";
        valEngine.textContent = "Wails v2 (Dummy)";
      }
    } catch (err) {
      console.error("시스템 정보 조회 실패:", err);
    }
  });

  // Ping handler
  pingBtn.addEventListener("click", async () => {
    valPing.textContent = "핑 전송 중...";
    try {
      if (isWailsAvailable()) {
        const result = await window.go.main.App.Ping();
        valPing.textContent = result;
      } else {
        const now = new Date().toTimeString().split(" ")[0];
        valPing.textContent = `pong (${now}) [Preview]`;
      }
    } catch (err) {
      valPing.textContent = "오류 발생";
      console.error(err);
    }
  });

  function escapeHtml(str) {
    return str
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }
});

