import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import { spawn } from "node:child_process";
import { OAuthError, refreshAccessToken } from "./src/oauth.js";

const PUBLIC_DIR = new URL("./public/", import.meta.url);
const MAX_BODY_BYTES = 256 * 1024;
const STATIC_FILES = new Map([
  ["/", ["index.html", "text/html; charset=utf-8"]],
  ["/index.html", ["index.html", "text/html; charset=utf-8"]],
  ["/styles.css", ["styles.css", "text/css; charset=utf-8"]],
  ["/app.js", ["app.js", "text/javascript; charset=utf-8"]],
  ["/profiles.js", ["profiles.js", "text/javascript; charset=utf-8"]],
  ["/favicon.svg", ["favicon.svg", "image/svg+xml"]],
]);

function securityHeaders(response) {
  response.setHeader("Cache-Control", "no-store");
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("Referrer-Policy", "no-referrer");
  response.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  response.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  response.setHeader(
    "Permissions-Policy",
    "camera=(), microphone=(), geolocation=()",
  );
  response.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  );
}

function json(response, status, data) {
  response.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
  });
  response.end(JSON.stringify(data));
}

async function readJson(request) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size <= MAX_BODY_BYTES) chunks.push(chunk);
  }
  if (size > MAX_BODY_BYTES)
    throw new OAuthError(413, "request_too_large", "Yêu cầu vượt quá 256 KB.");
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new OAuthError(
      400,
      "invalid_json",
      "Nội dung yêu cầu không phải JSON hợp lệ.",
    );
  }
}

export function createApp({ fetchImpl = fetch, timeoutMs = 20000 } = {}) {
  const server = createServer(async (request, response) => {
    securityHeaders(response);
    try {
      const port = server.address()?.port;
      const host = request.headers.host;
      if (![`127.0.0.1:${port}`, `localhost:${port}`].includes(host)) {
        return json(response, 403, {
          error: {
            code: "invalid_host",
            message: "Chỉ chấp nhận kết nối cục bộ.",
          },
        });
      }
      if (request.headers["sec-fetch-site"] === "cross-site") {
        return json(response, 403, {
          error: {
            code: "cross_site_request",
            message: "Không chấp nhận yêu cầu từ website khác.",
          },
        });
      }
      if (
        request.headers.origin &&
        request.headers.origin !== `http://${host}`
      ) {
        return json(response, 403, {
          error: {
            code: "invalid_origin",
            message: "Nguồn yêu cầu không hợp lệ.",
          },
        });
      }
      const pathname = new URL(request.url, `http://${host}`).pathname;
      if (request.method === "GET" && pathname === "/api/health") {
        return json(response, 200, { status: "ok", version: "1.0.0" });
      }
      if (pathname === "/api/refresh") {
        if (request.method !== "POST") {
          response.setHeader("Allow", "POST");
          return json(response, 405, {
            error: {
              code: "method_not_allowed",
              message: "Hãy gửi yêu cầu bằng POST.",
            },
          });
        }
        if (request.headers["x-tokenflow-request"] !== "1") {
          return json(response, 403, {
            error: {
              code: "missing_request_header",
              message: "Thiếu header X-TokenFlow-Request.",
            },
          });
        }
        if (
          request.headers["content-type"]
            ?.split(";")[0]
            .trim()
            .toLowerCase() !== "application/json"
        ) {
          return json(response, 415, {
            error: {
              code: "unsupported_media_type",
              message: "Yêu cầu phải dùng application/json.",
            },
          });
        }
        const input = await readJson(request);
        const result = await refreshAccessToken(input, {
          fetchImpl,
          timeoutMs,
        });
        return json(response, 200, result);
      }
      if (request.method === "GET" && STATIC_FILES.has(pathname)) {
        const [filename, contentType] = STATIC_FILES.get(pathname);
        const contents = await readFile(new URL(filename, PUBLIC_DIR));
        response.writeHead(200, { "Content-Type": contentType });
        return response.end(contents);
      }
      return json(response, 404, {
        error: { code: "not_found", message: "Không tìm thấy tài nguyên." },
      });
    } catch (error) {
      if (response.destroyed || response.writableEnded) return;
      if (error instanceof OAuthError) {
        return json(response, error.status, {
          error: {
            code: error.code,
            message: error.message,
            ...(error.detail ? { detail: error.detail } : {}),
            ...(error.upstreamStatus !== undefined
              ? { upstreamStatus: error.upstreamStatus }
              : {}),
          },
        });
      }
      // Deliberately do not log request bodies, upstream responses, credentials or tokens.
      return json(response, 500, {
        error: {
          code: "internal_error",
          message: "Có lỗi xử lý nội bộ. Hãy thử lại.",
        },
      });
    }
  });
  server.requestTimeout = 30000;
  server.headersTimeout = 15000;
  return server;
}

function openBrowser(url) {
  const command =
    process.platform === "win32"
      ? "rundll32.exe"
      : process.platform === "darwin"
        ? "open"
        : "xdg-open";
  const args =
    process.platform === "win32" ? ["url.dll,FileProtocolHandler", url] : [url];
  const child = spawn(command, args, {
    stdio: "ignore",
    detached: true,
    windowsHide: true,
  });
  child.on("error", () => {});
  child.unref();
}

if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  const port = Number(process.env.PORT ?? 3210);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    console.error("PORT phải là số từ 1 đến 65535.");
    process.exitCode = 1;
  } else {
    const app = createApp();
    app.on("error", (error) => {
      console.error(
        error.code === "EADDRINUSE"
          ? `Cổng ${port} đang được sử dụng. Hãy đặt biến PORT để chọn cổng khác.`
          : "Không thể khởi động máy chủ cục bộ.",
      );
      process.exitCode = 1;
    });
    app.listen(port, "127.0.0.1", () => {
      const url = `http://127.0.0.1:${port}`;
      console.log(`TokenFlow đang chạy tại ${url}\nNhấn Ctrl+C để dừng.`);
      if (process.argv.includes("--open")) openBrowser(url);
    });
  }
}
