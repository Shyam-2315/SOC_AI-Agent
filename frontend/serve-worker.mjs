import { createReadStream } from "node:fs";
import { stat } from "node:fs/promises";
import { createServer } from "node:http";
import { Readable } from "node:stream";
import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";

const rootDir = path.dirname(fileURLToPath(import.meta.url));
const clientDir = path.join(rootDir, "dist", "client");
const workerUrl = pathToFileURL(path.join(rootDir, "dist", "server", "index.js")).href;
const worker = (await import(workerUrl)).default;
const port = Number(process.env.PORT || 8080);
const host = process.env.HOST || "0.0.0.0";

const mimeTypes = new Map([
  [".css", "text/css; charset=utf-8"],
  [".html", "text/html; charset=utf-8"],
  [".ico", "image/x-icon"],
  [".js", "text/javascript; charset=utf-8"],
  [".json", "application/json; charset=utf-8"],
  [".map", "application/json; charset=utf-8"],
  [".png", "image/png"],
  [".svg", "image/svg+xml"],
  [".txt", "text/plain; charset=utf-8"],
  [".webp", "image/webp"],
]);

function headersFromNode(req) {
  const headers = new Headers();
  for (const [key, value] of Object.entries(req.headers)) {
    if (Array.isArray(value)) {
      for (const item of value) headers.append(key, item);
    } else if (value !== undefined) {
      headers.set(key, value);
    }
  }
  return headers;
}

async function tryServeAsset(req, res, pathname) {
  const decoded = decodeURIComponent(pathname);
  if (!decoded.startsWith("/assets/") && decoded !== "/.assetsignore") return false;

  const candidate = path.normalize(path.join(clientDir, decoded));
  if (!candidate.startsWith(clientDir)) return false;

  try {
    const file = await stat(candidate);
    if (!file.isFile()) return false;

    res.writeHead(200, {
      "content-length": file.size,
      "content-type": mimeTypes.get(path.extname(candidate)) || "application/octet-stream",
      "cache-control": "public, max-age=31536000, immutable",
    });
    if (req.method === "HEAD") {
      res.end();
    } else {
      createReadStream(candidate).pipe(res);
    }
    return true;
  } catch {
    return false;
  }
}

async function handleWorkerRequest(req, res) {
  const protocol = req.headers["x-forwarded-proto"] || "http";
  const hostHeader = req.headers.host || `127.0.0.1:${port}`;
  const url = `${protocol}://${hostHeader}${req.url || "/"}`;
  const headers = headersFromNode(req);
  const init = {
    method: req.method,
    headers,
  };

  if (req.method !== "GET" && req.method !== "HEAD") {
    init.body = Readable.toWeb(req);
    init.duplex = "half";
  }

  const response = await worker.fetch(
    new Request(url, init),
    {},
    {
      passThroughOnException() {},
      waitUntil() {},
    },
  );

  res.writeHead(response.status, Object.fromEntries(response.headers.entries()));
  if (response.body && req.method !== "HEAD") {
    Readable.fromWeb(response.body).pipe(res);
  } else {
    res.end();
  }
}

createServer(async (req, res) => {
  try {
    const requestUrl = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);
    if (await tryServeAsset(req, res, requestUrl.pathname)) return;
    await handleWorkerRequest(req, res);
  } catch (error) {
    console.error(error);
    res.writeHead(500, { "content-type": "text/plain; charset=utf-8" });
    res.end("frontend server error");
  }
}).listen(port, host, () => {
  console.log(`Frontend listening on http://${host}:${port}`);
});
