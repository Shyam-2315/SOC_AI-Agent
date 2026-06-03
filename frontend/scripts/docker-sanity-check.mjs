import { readdir, stat } from "node:fs/promises";
import path from "node:path";

const rootDir = process.cwd();
const clientDir = path.join(rootDir, "dist", "client");
const serverDir = path.join(rootDir, "dist", "server");
const serverEntry = process.env.SSR_SERVER_ENTRY || "dist/server/index.js";
const serverEntryPath = path.resolve(rootDir, serverEntry);

async function assertDirectory(label, dir) {
  const info = await stat(dir).catch(() => undefined);
  if (!info?.isDirectory()) {
    throw new Error(`${label} directory is missing: ${path.relative(rootDir, dir)}`);
  }
}

async function assertFile(label, file) {
  const info = await stat(file).catch(() => undefined);
  if (!info?.isFile()) {
    throw new Error(`${label} file is missing: ${path.relative(rootDir, file)}`);
  }
}

async function listFiles(dir) {
  const entries = await readdir(dir, { recursive: true, withFileTypes: true });
  return entries
    .filter((entry) => entry.isFile())
    .map((entry) => path.join(entry.parentPath, entry.name))
    .map((file) => path.relative(dir, file))
    .sort();
}

await assertDirectory("client build", clientDir);
await assertDirectory("server build", serverDir);
await assertFile("SSR server entry", serverEntryPath);

const serverFiles = await listFiles(serverDir);
console.log("Docker frontend SSR entry:", path.relative(rootDir, serverEntryPath));
console.log("Docker frontend dist/server files:");
for (const file of serverFiles) {
  console.log(`- ${file}`);
}
