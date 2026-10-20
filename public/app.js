import {
  OAUTH_PROFILES,
  getOAuthProfile,
  microsoftTokenEndpoint,
} from "/profiles.js";

const $ = (id) => document.getElementById(id);
const form = $("token-form");
const fields = $("request-fields");
const helpDialog = $("help-dialog");
let result = null;
let accessVisible = false;
let jsonVisible = false;
let expiryTimer;
let toastTimer;
let activeController;
let requestSequence = 0;

function icon(name) {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
  use.setAttribute("href", `#i-${name}`);
  svg.append(use);
  return svg;
}

function toast(message, isError = false) {
  clearTimeout(toastTimer);
  $("toast-message").textContent = message;
  $("toast").classList.toggle("error", isError);
  $("toast").hidden = false;
  toastTimer = setTimeout(() => {
    $("toast").hidden = true;
  }, 4000);
}

function setStatus(label, state = "") {
  $("result-status").textContent = label;
  $("result-status").className = `result-status ${state}`.trim();
}

function updateAuth() {
  const method = $("auth-method").value;
  const needsSecret = method !== "none";
  const needsClientId = needsSecret || Boolean(getOAuthProfile($("profile").value));
  $("client-secret-field").hidden = !needsSecret;
  $("client-secret").required = needsSecret;
  $("client-secret").disabled = !needsSecret;
  $("client-id").required = needsClientId;
  $("client-id-required").hidden = !needsClientId;
  $("client-id-optional").hidden = needsClientId;
  $("auth-hint").textContent = {
    none: "Dành cho public client hoặc dịch vụ không yêu cầu secret.",
    body: "Gửi client_id và client_secret trong form body.",
    basic: "Gửi thông tin client qua header Authorization: Basic.",
  }[method];
  if (!needsSecret) {
    $("client-secret").value = "";
    setRevealed($("client-secret"), false);
  }
}

function updateMicrosoftEndpoint() {
  if ($("profile").value === "microsoft") {
    $("endpoint").value = microsoftTokenEndpoint($("microsoft-tenant").value.trim());
  }
}

function updateProfile({ preserveToken = false } = {}) {
  const profile = $("profile").value;
  const preset = getOAuthProfile(profile);
  $("endpoint").readOnly = Boolean(preset);
  $("client-id").readOnly = Boolean(preset?.clientId);
  $("client-id").value = preset?.clientId || "";
  $("client-secret").value = "";
  setRevealed($("client-secret"), false);
  if (!preserveToken) $("refresh-token").value = "";
  setRevealed($("refresh-token"), false);
  for (const option of $("auth-method").options) {
    option.disabled = Boolean(preset && !preset.authMethods.includes(option.value));
    option.hidden = option.disabled;
  }
  $("auth-method").disabled = preset?.authMethods.length === 1;
  $("auth-method").value = preset?.authMethod || "none";
  if (preset) $("endpoint").value = preset.endpoint;
  $("microsoft-tenant-field").hidden = profile !== "microsoft";
  $("microsoft-tenant").disabled = profile !== "microsoft";
  $("microsoft-tenant").required = profile === "microsoft";
  $("microsoft-tenant").value = "common";
  $("scope").value = "";
  $("extra-params").replaceChildren();
  $("add-param").disabled = false;
  $("profile-hint").textContent = preset?.hint ||
    "Nhập endpoint và Client ID của ứng dụng đã cấp refresh token.";
  $("profile-docs").hidden = !preset;
  if (preset) {
    $("profile-docs").href = preset.docsUrl;
  } else {
    $("profile-docs").removeAttribute("href");
  }
  updateAuth();
  $("request-error").hidden = true;
  $("error-suggestions").replaceChildren();
  $("error-suggestions").hidden = true;
  $("fix-codex").hidden = true;
  clearResult();
}

function setRevealed(input, revealed) {
  input.type = revealed ? "text" : "password";
  const button = document.querySelector(`[data-reveal="${input.id}"]`);
  button.setAttribute("aria-pressed", String(revealed));
  const label =
    input.id === "client-secret" ? "Client Secret" : "refresh token";
  button.setAttribute("aria-label", `${revealed ? "Ẩn" : "Hiện"} ${label}`);
  button.replaceChildren(icon(revealed ? "eye-off" : "eye"));
}

function setBusy(busy) {
  fields.disabled = busy;
  $("submit-button").disabled = busy;
  $("submit-label").textContent = busy ? "Đang lấy token…" : "Lấy access token";
  form.setAttribute("aria-busy", String(busy));
  if (busy) {
    const spinner = document.createElement("span");
    spinner.className = "spinner";
    spinner.setAttribute("aria-hidden", "true");
    $("submit-icon").replaceChildren(spinner);
  } else {
    $("submit-icon").replaceChildren(icon("flow"));
  }
  $("loading-result").hidden = !busy;
}

function activateTab(name, focus = false) {
  for (const tabName of ["token", "json"]) {
    const selected = name === tabName;
    const tab = $(`tab-${tabName}`);
    tab.setAttribute("aria-selected", String(selected));
    tab.tabIndex = selected ? 0 : -1;
    tab.classList.toggle("active", selected);
    $(`view-${tabName}`).hidden = !selected;
  }
  if (focus) $(`tab-${name}`).focus();
}

function clearResult() {
  clearInterval(expiryTimer);
  result = null;
  accessVisible = false;
  jsonVisible = false;
  $("access-token-value").textContent = "••••••••••••••••••••••••••••••••";
  $("access-token-value").classList.add("masked");
  $("access-token-value").setAttribute("aria-label", "Access token đang ẩn");
  $("toggle-access").setAttribute("aria-pressed", "false");
  $("toggle-access").setAttribute("aria-label", "Hiện access token");
  $("toggle-access").replaceChildren(icon("eye"));
  $("toggle-json").setAttribute("aria-pressed", "false");
  $("toggle-json").textContent = "Hiện token";
  $("json-output").textContent = "";
  $("granted-scope").textContent = "";
  $("token-result").hidden = true;
  $("empty-result").hidden = false;
  $("scope-result").hidden = true;
  $("rotated-section").hidden = true;
  $("expiry-section").hidden = true;
  $("response-time").textContent = "";
  setStatus("Đang chờ");
  activateTab("token");
}

function showError(error) {
  $("error-title").textContent = error.message || "Không thể lấy access token.";
  $("error-detail").textContent = error.detail || "";
  $("error-code").textContent = [
    error.code,
    error.upstreamStatus ? `HTTP ${error.upstreamStatus}` : "",
  ]
    .filter(Boolean)
    .join(" · ");
  const suggestions = [];
  if (error.code === "invalid_client") {
    suggestions.push(
      "Client ID phải trùng với ứng dụng đã cấp refresh token; không dùng ID tài khoản, workspace hoặc UUID tự tạo.",
    );
    suggestions.push(
      $("profile").value === "codex"
        ? "Nếu token thuộc một client Codex tùy biến hoặc ứng dụng khác, chọn Endpoint tùy chỉnh và nhập Client ID gốc."
        : getOAuthProfile($("profile").value)?.hint ||
          "Với token đăng nhập Codex mặc định, chọn dịch vụ Codex. Với dịch vụ khác, kiểm tra Client ID và cách gửi Client Secret.",
    );
  } else if (
    [
      "invalid_grant",
      "invalid_refresh_token",
      "refresh_token_expired",
      "refresh_token_invalidated",
      "refresh_token_reused",
    ].includes(error.code)
  ) {
    suggestions.push(
      "Dùng refresh token mới nhất nếu dịch vụ đã thay token cũ. Tránh đổi token đồng thời ở nhiều app.",
    );
    suggestions.push(
      "Nếu token đã hết hạn hoặc bị thu hồi, đăng nhập lại ứng dụng đã cấp token.",
    );
  }
  $("error-suggestions").replaceChildren(
    ...suggestions.map((message) => {
      const item = document.createElement("li");
      item.textContent = message;
      return item;
    }),
  );
  $("error-suggestions").hidden = suggestions.length === 0;
  let isOpenAi = false;
  try {
    isOpenAi =
      new URL($("endpoint").value).origin === "https://auth.openai.com";
  } catch {
    /* Invalid URLs are handled by validation. */
  }
  $("fix-codex").hidden =
    error.code !== "invalid_client" ||
    !isOpenAi ||
    $("profile").value === "codex";
  $("request-error").hidden = false;
  setStatus("Có lỗi", "failed");
  $("request-error").scrollIntoView({ block: "nearest", behavior: "smooth" });
}

function durationLabel(totalSeconds) {
  if (totalSeconds === 0) return "Đã hết hạn";
  if (totalSeconds >= 86400)
    return `${Math.floor(totalSeconds / 86400)} ngày ${Math.floor((totalSeconds % 86400) / 3600)} giờ`;
  if (totalSeconds >= 3600)
    return `${Math.floor(totalSeconds / 3600)} giờ${totalSeconds % 3600 >= 60 ? ` ${Math.floor((totalSeconds % 3600) / 60)} phút` : ""}`;
  if (totalSeconds >= 60)
    return `${Math.floor(totalSeconds / 60)} phút${totalSeconds % 60 ? ` ${totalSeconds % 60} giây` : ""}`;
  return `${totalSeconds} giây`;
}

function renderJSON() {
  if (!result) return;
  const data = { ...result.token };
  if (!jsonVisible) {
    for (const key of ["access_token", "refresh_token", "id_token"]) {
      if (data[key]) data[key] = "•••••••• [đã ẩn]";
    }
  }
  $("json-output").textContent = JSON.stringify(data, null, 2);
  $("toggle-json").textContent = jsonVisible ? "Ẩn token" : "Hiện token";
  $("toggle-json").setAttribute("aria-pressed", String(jsonVisible));
}

function updateExpiry() {
  if (!result || result.token.expires_in === undefined) return;
  const remaining = Math.max(
    0,
    Math.ceil((result.expiresAt - Date.now()) / 1000),
  );
  const hours = Math.floor(remaining / 3600);
  const minutes = Math.floor((remaining % 3600) / 60);
  const seconds = remaining % 60;
  $("expiry-countdown").textContent = remaining
    ? `${hours ? `${hours}:` : ""}${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`
    : "00:00";
  $("expiry-label").textContent = remaining
    ? "Còn hiệu lực khoảng"
    : "Token đã hết hạn";
  $("expiry-progress").value =
    result.token.expires_in > 0
      ? Math.min(100, (remaining / result.token.expires_in) * 100)
      : 0;
  if (!remaining) {
    setStatus("Đã hết hạn", "expired");
    clearInterval(expiryTimer);
  }
}

function showResult(data) {
  const receivedMs = Date.parse(data.receivedAt);
  result = {
    ...data,
    receivedMs: Number.isFinite(receivedMs) ? receivedMs : Date.now(),
    expiresAt:
      (Number.isFinite(receivedMs) ? receivedMs : Date.now()) +
      (data.token.expires_in ?? 0) * 1000,
  };
  $("empty-result").hidden = true;
  $("token-result").hidden = false;
  $("response-time").textContent = `${data.durationMs} ms`;
  $("token-type").textContent = data.token.token_type;
  $("token-lifetime").textContent =
    data.token.expires_in === undefined
      ? "Không được cung cấp"
      : durationLabel(data.token.expires_in);
  $("scope-result").hidden = !data.token.scope;
  $("granted-scope").textContent = data.token.scope || "";
  $("rotated-section").hidden = !data.token.refresh_token;
  setStatus("Thành công", "success");
  if (data.token.expires_in !== undefined) {
    $("expiry-section").hidden = false;
    const date = new Date(result.expiresAt);
    $("expiry-time").textContent = Number.isNaN(date.getTime())
      ? "Thời hạn theo phản hồi của dịch vụ."
      : `Hết hạn khoảng ${date.toLocaleString("vi-VN", { hour: "2-digit", minute: "2-digit", second: "2-digit", day: "2-digit", month: "2-digit", year: "numeric" })}`;
    updateExpiry();
    if (result.expiresAt > Date.now())
      expiryTimer = setInterval(updateExpiry, 1000);
  }
  renderJSON();
  toast("Đã lấy access token thành công.");
}

async function copyText(text, message) {
  if (!text) return;
  try {
    if (navigator.clipboard?.writeText) {
      try {
        await navigator.clipboard.writeText(text);
        toast(message);
        return;
      } catch {
        /* Try the local selection fallback. */
      }
    }
    const previousFocus = document.activeElement;
    const helper = document.createElement("textarea");
    helper.className = "clipboard-helper";
    helper.value = text;
    helper.setAttribute("aria-label", "Nội dung sao chép");
    document.body.append(helper);
    let copied = false;
    try {
      helper.select();
      copied = document.execCommand("copy");
    } finally {
      helper.remove();
      previousFocus?.focus();
    }
    if (!copied) throw new Error("clipboard_unavailable");
    toast(message);
  } catch {
    toast(
      "Trình duyệt chặn clipboard. Hãy hiện token và sao chép thủ công.",
      true,
    );
  }
}

function addParam() {
  const container = $("extra-params");
  if (container.children.length >= 20) return;
  const row = document.createElement("div");
  row.className = "extra-row";
  const key = document.createElement("input");
  key.type = "text";
  key.placeholder = "Tên, vd: audience";
  key.maxLength = 128;
  key.required = true;
  key.setAttribute("aria-label", "Tên tham số bổ sung");
  key.spellcheck = false;
  const value = document.createElement("input");
  value.type = "text";
  value.placeholder = "Giá trị";
  value.maxLength = 8192;
  value.spellcheck = false;
  value.setAttribute("aria-label", "Giá trị tham số bổ sung");
  const remove = document.createElement("button");
  remove.type = "button";
  remove.className = "icon-button";
  remove.setAttribute("aria-label", "Xóa tham số");
  remove.append(icon("close"));
  remove.addEventListener("click", () => {
    const next =
      row.nextElementSibling?.querySelector("input") ||
      row.previousElementSibling?.querySelector("input");
    row.remove();
    $("add-param").disabled = false;
    (next || $("add-param")).focus();
  });
  row.append(key, value, remove);
  container.append(row);
  $("add-param").disabled = container.children.length >= 20;
  key.focus();
}

function clearSession(notify = true) {
  requestSequence++;
  activeController?.abort();
  activeController = undefined;
  setBusy(false);
  form.reset();
  $("extra-params").replaceChildren();
  $("add-param").disabled = false;
  $("advanced-options").open = false;
  $("request-error").hidden = true;
  $("error-title").textContent = "";
  $("error-detail").textContent = "";
  $("error-code").textContent = "";
  updateProfile();
  setRevealed($("refresh-token"), false);
  if (notify) {
    toast("Đã xóa dữ liệu phiên khỏi app.");
    $("endpoint").focus();
  }
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  if ($("submit-button").disabled) return;
  const payload = {
    profile: $("profile").value,
    tenant: $("profile").value === "microsoft"
      ? $("microsoft-tenant").value.trim()
      : undefined,
    endpoint: $("endpoint").value.trim(),
    refreshToken: $("refresh-token").value.trim(),
    clientId: $("client-id").value.trim(),
    authMethod: $("auth-method").value,
    clientSecret:
      $("auth-method").value === "none" ? "" : $("client-secret").value,
    scope: $("scope").value.trim(),
    extraParams: [...$("extra-params").children].map((row) => {
      const inputs = row.querySelectorAll("input");
      return { key: inputs[0].value.trim(), value: inputs[1].value };
    }),
  };
  const sequence = ++requestSequence;
  const controller = new AbortController();
  activeController = controller;
  let timedOut = false;
  const timeout = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, 26000);
  $("request-error").hidden = true;
  clearResult();
  $("empty-result").hidden = true;
  setBusy(true);
  setStatus("Đang gửi");
  try {
    const response = await fetch("/api/refresh", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-TokenFlow-Request": "1",
      },
      body: JSON.stringify(payload),
      signal: controller.signal,
      cache: "no-store",
    });
    const data = await response.json();
    if (sequence !== requestSequence) return;
    if (!response.ok || data.error) {
      $("empty-result").hidden = false;
      showError(
        data.error || {
          message: "Yêu cầu không thành công.",
          code: `http_${response.status}`,
        },
      );
    } else if (typeof data.token?.access_token === "string") {
      showResult(data);
    } else {
      $("empty-result").hidden = false;
      showError({
        message: "Máy chủ trả về kết quả không hợp lệ.",
        code: "invalid_response",
      });
    }
  } catch (error) {
    if (sequence !== requestSequence) return;
    $("empty-result").hidden = false;
    showError({
      message: timedOut
        ? "Yêu cầu quá thời gian chờ. Hãy thử lại."
        : "Không kết nối được với app. Hãy kiểm tra máy chủ cục bộ đang chạy.",
      code: timedOut ? "request_timeout" : "local_connection_failed",
    });
  } finally {
    clearTimeout(timeout);
    if (sequence === requestSequence) {
      setBusy(false);
      activeController = undefined;
    }
  }
});

$("auth-method").addEventListener("change", updateAuth);
$("profile").addEventListener("change", () => updateProfile());
$("microsoft-tenant").addEventListener("input", updateMicrosoftEndpoint);
$("fix-codex").addEventListener("click", () => {
  $("profile").value = "codex";
  updateProfile({ preserveToken: true });
  toast("Đã điền cấu hình Codex. Bấm Lấy access token để thử lại.");
});
$("add-param").addEventListener("click", addParam);
$("clear-session").addEventListener("click", () => clearSession());
document.querySelectorAll("[data-reveal]").forEach((button) => {
  button.addEventListener("click", () => {
    const input = $(button.dataset.reveal);
    setRevealed(input, input.type === "password");
  });
});
$("toggle-access").addEventListener("click", () => {
  if (!result) return;
  accessVisible = !accessVisible;
  $("access-token-value").textContent = accessVisible
    ? result.token.access_token
    : "••••••••••••••••••••••••••••••••";
  $("access-token-value").classList.toggle("masked", !accessVisible);
  $("access-token-value").setAttribute(
    "aria-label",
    accessVisible ? "Access token" : "Access token đang ẩn",
  );
  $("toggle-access").setAttribute(
    "aria-label",
    `${accessVisible ? "Ẩn" : "Hiện"} access token`,
  );
  $("toggle-access").setAttribute("aria-pressed", String(accessVisible));
  $("toggle-access").replaceChildren(icon(accessVisible ? "eye-off" : "eye"));
});
$("toggle-json").addEventListener("click", () => {
  jsonVisible = !jsonVisible;
  renderJSON();
});
$("copy-token").addEventListener("click", () =>
  copyText(result?.token.access_token, "Đã sao chép access token."),
);
$("copy-json").addEventListener("click", () => {
  if (result)
    copyText(JSON.stringify(result.token, null, 2), "Đã sao chép JSON đầy đủ.");
});
$("copy-refresh").addEventListener("click", () =>
  copyText(result?.token.refresh_token, "Đã sao chép refresh token mới."),
);
$("use-refresh").addEventListener("click", () => {
  if (!result?.token.refresh_token) return;
  $("refresh-token").value = result.token.refresh_token;
  setRevealed($("refresh-token"), false);
  toast("Đã điền refresh token mới cho lần tiếp theo.");
});
for (const name of ["token", "json"]) {
  $(`tab-${name}`).addEventListener("click", () => activateTab(name));
  $(`tab-${name}`).addEventListener("keydown", (event) => {
    if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
    event.preventDefault();
    activateTab(
      event.key === "Home"
        ? "token"
        : event.key === "End"
          ? "json"
          : name === "token"
            ? "json"
            : "token",
      true,
    );
  });
}
document
  .querySelectorAll("[data-open-help]")
  .forEach((button) =>
    button.addEventListener("click", () => helpDialog.showModal()),
  );
$("close-help").addEventListener("click", () => helpDialog.close());
$("got-it").addEventListener("click", () => {
  helpDialog.close();
  $("endpoint").focus();
});
helpDialog.addEventListener("click", (event) => {
  const rect = helpDialog.getBoundingClientRect();
  if (
    event.target === helpDialog &&
    (event.clientX < rect.left ||
      event.clientX > rect.right ||
      event.clientY < rect.top ||
      event.clientY > rect.bottom)
  )
    helpDialog.close();
});
window.addEventListener("pagehide", () => {
  clearSession(false);
  clearTimeout(toastTimer);
  $("toast").hidden = true;
});

for (const [id, preset] of Object.entries(OAUTH_PROFILES)) {
  const option = document.createElement("option");
  option.value = id;
  option.textContent = preset.label;
  $("profile").append(option);
}
updateProfile();
fetch("/api/health", { cache: "no-store" })
  .then((response) => {
    if (!response.ok) throw new Error("offline");
    $("connection-status").classList.add("connected");
    $("connection-label").textContent = "Chạy cục bộ";
  })
  .catch(() => {
    $("connection-status").classList.add("offline");
    $("connection-label").textContent = "Mất kết nối";
  });
