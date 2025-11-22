import express from "express";
import http from "http";
import WebSocket from "ws";
import pty from "node-pty";
import path from "path";
import fs from "fs";
import cors from "cors";
import { fileURLToPath } from "url";

const app = express();
const server = http.createServer(app);
const PORT = process.env.PORT || 3000;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
// ---- CONFIG ----
const PROJECT_ROOT = path.join(__dirname, "projects", "sample");

// ---- MIDDLEWARE ----
app.use(cors());
app.use(express.json());

// Simple health check
app.get("/health", (req, res) => {
  res.json({ status: "ok", projectRoot: PROJECT_ROOT });
});

/**
 * POST /api/files/save
 * Body: { relativePath: "index.js", content: "..." }
 * Writes to projects/sample/<relativePath>
 */
app.post("/api/files/save", async (req, res) => {
  try {
    const { relativePath, content } = req.body;
    if (!relativePath || typeof content !== "string") {
      return res.status(400).json({ error: "relativePath and content are required" });
    }

    const safePath = path.normalize(relativePath).replace(/^(\.\.(\/|\\|$))+/, "");
    const targetPath = path.join(PROJECT_ROOT, safePath);

    // Ensure directory exists
    await fs.promises.mkdir(path.dirname(targetPath), { recursive: true });
    await fs.promises.writeFile(targetPath, content, "utf8");

    res.json({ ok: true, path: targetPath });
  } catch (err) {
    console.error("Error saving file:", err);
    res.status(500).json({ error: "Failed to save file" });
  }
});

// ---- WEBSOCKET + PTY ----
//
// WS endpoint: ws://<host>/ws/terminal
// When a client connects:
//  - spawn a pty with cwd = PROJECT_ROOT
//  - optional: auto-run "npm install" once (you can cache separately)
//  - user sends keystrokes/commands over ws -> pty.write()
//  - pty output -> ws.send()
//
const wss = new WebSocket.Server({ server, path: "/ws/terminal" });

wss.on("connection", (ws) => {
  console.log("Client connected to terminal");

  const shell = process.platform === "win32" ? "bash.exe" : "bash";
  const shellArgs = [];
  const env = Object.assign({}, process.env);

  const ptyProcess = pty.spawn(shell, shellArgs, {
    name: "xterm-color",
    cols: 80,
    rows: 25,
    cwd: PROJECT_ROOT,
    env
  });

  // OPTION: auto-run project on connect
  // ptyProcess.write("npm install\n");
  // ptyProcess.write("npm start\n");

  ptyProcess.on("data", (data) => {
    try {
      ws.send(data);
    } catch (err) {
      console.error("Error sending WS data:", err);
    }
  });

  ws.on("message", (msg) => {
    // msg can be string or Buffer
    const str = msg.toString();
    ptyProcess.write(str);
  });

  ws.on("close", () => {
    console.log("WS closed, killing pty");
    try {
      ptyProcess.kill();
    } catch (e) {
      console.error("Error killing pty:", e);
    }
  });

  ws.on("error", (err) => {
    console.error("WS error:", err);
  });
});

// ---- START SERVER ----
server.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
  console.log(`Project root: ${PROJECT_ROOT}`);
});
