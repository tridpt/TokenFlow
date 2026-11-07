import {
  getOAuthProfile,
  microsoftTokenEndpoint,
} from "../public/profiles.js";

const RESERVED_PARAMETERS = new Set([
  "grant_type",
  "refresh_token",
  "client_id",
  "client_secret",
  "scope",
]);
const MAX_RESPONSE_BYTES = 1024 * 1024;

export class OAuthError extends Error {
  constructor(status, code, message, detail = "", upstreamStatus) {
    super(message);
    this.name = "OAuthError";
    this.status = status;
    this.code = code;
    this.detail = detail;
    this.upstreamStatus = upstreamStatus;
  }
}

function invalid(message) {
  throw new OAuthError(400, "invalid_input", message);
}

function field(value, label, limit, { required = false, trim = true } = {}) {
  if (value === undefined || value === null) value = "";
  if (typeof value !== "string") invalid(`${label} phải là chuỗi văn bản.`);
  const result = trim ? value.trim() : value;
  if (required && !result) invalid(`Vui lòng nhập ${label}.`);
  if (result.length > limit)
    invalid(`${label} vượt quá độ dài cho phép (${limit} ký tự).`);
  return result;
}

export function normalizeRequest(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    invalid("Nội dung yêu cầu phải là một đối tượng JSON.");
  }

  const profile = input.profile ?? "custom";
  const preset = getOAuthProfile(profile);
  if (profile !== "custom" && !preset)
    invalid("Dịch vụ đã chọn không hợp lệ.");
  if (preset) {
    let presetEndpoint = preset.endpoint;
    if (profile === "microsoft") {
      const tenant = field(input.tenant ?? "common", "Tenant Microsoft", 255, {
        required: true,
      });
      if (!/^[a-zA-Z0-9][a-zA-Z0-9.-]*$/.test(tenant))
        invalid("Tenant Microsoft phải là common, consumers, organizations, Tenant ID hoặc tên miền hợp lệ.");
      presetEndpoint = microsoftTokenEndpoint(tenant);
    }
    if (
      input.endpoint !== undefined &&
      input.endpoint !== "" &&
      input.endpoint !== presetEndpoint
    ) {
      invalid(`Endpoint không khớp với ${preset.label}. Chọn Endpoint tùy chỉnh nếu cần URL khác.`);
    }
    if (
      preset.clientId &&
      input.clientId !== undefined &&
      input.clientId !== "" &&
      input.clientId !== preset.clientId
    ) {
      invalid("Cấu hình Codex không khớp. Chọn Endpoint tùy chỉnh nếu cần dùng client riêng.");
    }
    const authMethod = input.authMethod ?? preset.authMethod;
    if (!preset.authMethods.includes(authMethod))
      invalid(`Phương thức xác thực không được hỗ trợ trong cấu hình ${preset.label}.`);
    if (authMethod === "none" && input.clientSecret)
      invalid("Đã chọn không dùng Client Secret. Hãy xóa secret hoặc chọn cách xác thực phù hợp.");
    input = {
      ...input,
      endpoint: presetEndpoint,
      authMethod,
      ...(preset.clientId ? { clientId: preset.clientId } : {}),
    };
  }

  const endpoint = field(input.endpoint, "Token endpoint", 4096, {
    required: true,
  });
  let url;
  try {
    url = new URL(endpoint);
  } catch {
    invalid("Token endpoint phải là URL hợp lệ.");
  }
  const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) {
    invalid(
      "Token endpoint phải dùng HTTPS. HTTP chỉ được phép với localhost.",
    );
  }
  if (/^(169\.254\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(url.hostname)) {
    invalid("Token endpoint không được trỏ tới địa chỉ IP nội bộ hoặc link-local.");
  }
  if (url.username || url.password || url.hash) {
    invalid(
      "Token endpoint không được chứa tài khoản, mật khẩu hoặc phần #fragment.",
    );
  }

  const refreshToken = field(input.refreshToken, "Refresh token", 65536, {
    required: true,
  });
  const clientId = field(input.clientId, "Client ID", 4096, {
    required: Boolean(preset),
  });
  const clientSecret = field(input.clientSecret, "Client Secret", 16384, {
    trim: false,
  });
  const scope = field(input.scope, "Scope", 8192);
  const authMethod = input.authMethod ?? "none";
  if (!["none", "body", "basic"].includes(authMethod))
    invalid("Phương thức xác thực không hợp lệ.");
  if (authMethod !== "none" && (!clientId || !clientSecret)) {
    invalid("Phương thức xác thực đã chọn cần cả Client ID và Client Secret.");
  }

  const extraParams = input.extraParams ?? [];
  if (!Array.isArray(extraParams) || extraParams.length > 20) {
    invalid("Chỉ được thêm tối đa 20 tham số bổ sung.");
  }
  const used = new Set();
  const normalizedExtras = extraParams.map((item) => {
    if (!item || typeof item !== "object" || Array.isArray(item))
      invalid("Tham số bổ sung không hợp lệ.");
    const key = field(item.key, "Tên tham số", 128, { required: true });
    const value = field(item.value, `Giá trị ${key}`, 8192, { trim: false });
    if (!/^[a-zA-Z][a-zA-Z0-9_.:-]*$/.test(key))
      invalid(`Tên tham số "${key}" không hợp lệ.`);
    if (RESERVED_PARAMETERS.has(key.toLowerCase())) {
      invalid(`Hãy nhập ${key} bằng trường riêng của biểu mẫu.`);
    }
    if (used.has(key)) invalid(`Tham số "${key}" bị trùng.`);
    used.add(key);
    return { key, value };
  });

  return {
    profile,
    endpoint: url.href,
    refreshToken,
    clientId,
    clientSecret,
    authMethod,
    scope,
    extraParams: normalizedExtras,
  };
}

function formEncode(value) {
  return new URLSearchParams({ v: value }).toString().slice(2);
}

export function buildTokenRequest(input) {
  const params = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: input.refreshToken,
  });
  const headers = {
    Accept: "application/json",
    "Content-Type": "application/x-www-form-urlencoded",
  };
  if (input.authMethod === "basic") {
    // OAuth 2.0 encodes each credential before building the Basic header (RFC 6749 §2.3.1).
    headers.Authorization = `Basic ${Buffer.from(`${formEncode(input.clientId)}:${formEncode(input.clientSecret)}`).toString("base64")}`;
  } else {
    if (input.clientId) params.set("client_id", input.clientId);
    if (input.authMethod === "body")
      params.set("client_secret", input.clientSecret);
  }
  if (input.scope) params.set("scope", input.scope);
  for (const { key, value } of input.extraParams) params.set(key, value);
  return {
    method: "POST",
    headers,
    body: params.toString(),
    redirect: "manual",
  };
}

function redact(message, input, extraSecrets = []) {
  let result = typeof message === "string" ? message : "";
  const secretValues = [
    input.refreshToken,
    input.clientSecret,
    ...input.extraParams.map(({ value }) => value),
    ...extraSecrets,
  ]
    .filter(Boolean)
    .sort((a, b) => b.length - a.length);
  for (const secret of secretValues) {
    for (const version of new Set([
      secret,
      encodeURIComponent(secret),
      formEncode(secret),
    ])) {
      result = result.split(version).join("[đã ẩn]");
    }
  }
  return result.replace(/[\x00-\x1f\x7f]/g, " ").slice(0, 700);
}

async function readResponse(response) {
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_RESPONSE_BYTES) {
        await reader.cancel();
        throw new OAuthError(
          502,
          "response_too_large",
          "Phản hồi của dịch vụ vượt quá 1 MB.",
        );
      }
      chunks.push(Buffer.from(value));
    }
  } finally {
    reader.releaseLock();
  }
  return Buffer.concat(chunks).toString("utf8");
}

const PROVIDER_ERRORS = {
  invalid_grant: "Refresh token không hợp lệ, đã hết hạn hoặc đã bị thu hồi.",
  invalid_client:
    "Dịch vụ không chấp nhận client. Kiểm tra Client ID của ứng dụng đã cấp token và cách xác thực.",
  unauthorized_client: "Client này không được phép dùng luồng refresh token.",
  invalid_scope: "Scope không hợp lệ hoặc vượt quá quyền đã cấp.",
  invalid_request:
    "Dịch vụ từ chối yêu cầu. Hãy kiểm tra các trường và tham số bổ sung.",
  unsupported_grant_type: "Endpoint này không hỗ trợ grant_type=refresh_token.",
  access_denied: "Dịch vụ từ chối cấp access token.",
};

export async function refreshAccessToken(
  rawInput,
  { fetchImpl = fetch, timeoutMs = 20000 } = {},
) {
  const input = normalizeRequest(rawInput);
  const request = buildTokenRequest(input);
  const startedAt = performance.now();
  let response;
  let responseText;
  try {
    response = await fetchImpl(input.endpoint, {
      ...request,
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (response.status >= 300 && response.status < 400) {
      await response.body?.cancel();
      throw new OAuthError(
        502,
        "redirect_blocked",
        "Endpoint trả về chuyển hướng. Hãy nhập URL token endpoint cuối cùng.",
      );
    }
    responseText = await readResponse(response);
  } catch (error) {
    if (error instanceof OAuthError) throw error;
    if (["TimeoutError", "AbortError"].includes(error.name)) {
      throw new OAuthError(
        504,
        "request_timeout",
        "Dịch vụ phản hồi quá chậm. Hãy thử lại sau.",
      );
    }
    throw new OAuthError(
      502,
      "connection_failed",
      "Không kết nối được tới token endpoint. Hãy kiểm tra URL, mạng và chứng chỉ HTTPS.",
    );
  }

  let data;
  try {
    data = JSON.parse(responseText);
  } catch {
    throw new OAuthError(
      502,
      "invalid_response",
      "Dịch vụ không trả về JSON hợp lệ. Hãy kiểm tra đúng token endpoint.",
      "",
      response.status,
    );
  }
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    throw new OAuthError(
      502,
      "invalid_response",
      "Phản hồi JSON của dịch vụ phải là một đối tượng.",
      "",
      response.status,
    );
  }
  if (!response.ok || data.error) {
    const providerCode =
      typeof data.error === "string" ? data.error : data.error?.code;
    const code =
      typeof providerCode === "string" &&
      /^[a-z][a-z0-9_.-]{0,80}$/i.test(providerCode)
        ? redact(providerCode, input)
        : "oauth_error";
    const description =
      data.error_description ?? data.error?.message ?? data.message;
    const extraSecrets = [
      data.access_token,
      data.refresh_token,
      data.id_token,
    ].filter((value) => typeof value === "string");
    throw new OAuthError(
      response.status === 429 ? 429 : 400,
      code,
      Object.hasOwn(PROVIDER_ERRORS, providerCode)
        ? PROVIDER_ERRORS[providerCode]
        : `Dịch vụ từ chối yêu cầu (HTTP ${response.status}).`,
      redact(description, input, extraSecrets),
      response.status,
    );
  }

  if (
    typeof data.access_token !== "string" ||
    !data.access_token.trim() ||
    data.access_token.length > 131072
  ) {
    throw new OAuthError(
      502,
      "missing_access_token",
      "Phản hồi không có trường access_token hợp lệ.",
      "",
      response.status,
    );
  }
  const token = { access_token: data.access_token, token_type: "Bearer" };
  if (typeof data.token_type === "string" && data.token_type.trim())
    token.token_type = data.token_type.slice(0, 128);
  if (
    typeof data.expires_in === "number" ||
    (typeof data.expires_in === "string" && data.expires_in.trim())
  ) {
    const expiresIn = Number(data.expires_in);
    if (Number.isSafeInteger(expiresIn) && expiresIn >= 0)
      token.expires_in = expiresIn;
  }
  for (const key of ["scope", "refresh_token", "id_token"]) {
    if (typeof data[key] === "string" && data[key]) token[key] = data[key];
  }
  return {
    token,
    receivedAt: new Date().toISOString(),
    durationMs: Math.round(performance.now() - startedAt),
  };
}
