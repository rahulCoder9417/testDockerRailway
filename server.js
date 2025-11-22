import express from "express";
import http from "http";
import {WebSocketServer} from "ws";
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
app.use(cors(
  {
    origin: [
      "http://localhost:5173",                          // Vite dev
      "https://devsync-runner.onrender.com"        // Your Render domain
    ],
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true
  }
));
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
const wss = new WebSocketServer({ noServer: true });

wss.on("connection", (ws) => {
  console.log("Client connected to terminal");

  const shell = "bash";
  const ptyProcess = pty.spawn(shell, [], {
    name: "xterm-color",
    cols: 80,
    rows: 25,
    cwd: PROJECT_ROOT,
    env: process.env
  });

  ptyProcess.on("data", data => ws.send(data));
  ws.on("message", msg => ptyProcess.write(msg));
  ws.on("close", () => ptyProcess.kill());
});

server.on("upgrade", (req, socket, head) => {
  if (req.url === "/ws/terminal") {
    wss.handleUpgrade(req, socket, head, ws => {
      wss.emit("connection", ws, req);
    });
  } else {
    socket.destroy(); // reject other requests
  }
});

// ---- START SERVER ----
server.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
  console.log(`Project root: ${PROJECT_ROOT}`);
});
