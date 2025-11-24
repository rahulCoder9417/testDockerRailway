import express from "express";
import http from "http";
import { WebSocketServer } from "ws";
import pty from "node-pty";
import path from "path";
import fs from "fs";
import cors from "cors";
import crypto from "crypto";
import { fileURLToPath } from "url";
import { createProxyMiddleware } from "http-proxy-middleware";
import { spawn } from "child_process";
import net from "net";

const app = express();
const server = http.createServer(app);
const PORT = process.env.PORT || 3000;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/**
 * sessions structure:
 * {
 *   [userId]: {
 *     terminals: {
 *       [terminalId]: ptyInstance
 *     },
 *     gui?: {
 *       display: string;      // e.g. ':101'
 *       vncPort: number;      // e.g. 5901
 *       index: number;        // internal index
 *       processes: {
 *         xvfb: ChildProcess;
 *         x11vnc: ChildProcess;
 *         wm?: ChildProcess;
 *       }
 *     }
 *   }
 * }
 */
const sessions = {};

// ---- CONFIG ----
const PROJECT_ROOT = path.join(__dirname, "projects", "sample");

// ---- GUI CONFIG ----
const GUI_BASE_DISPLAY = 100;
const GUI_BASE_VNC_PORT = 5900;
let nextGuiIndex = 1; // increment per GUI session

// ---- TOKEN GENERATION ----
function generatePreviewToken(userId, port) {
  const secret = process.env.PREVIEW_SECRET || "supersecret";
  const data = `${userId}:${port}`;
  return crypto.createHmac("sha256", secret).update(data).digest("hex");
}

function verifyPreviewToken(token, userId, port) {
  const secret = process.env.PREVIEW_SECRET || "supersecret";
  const recalculated = crypto
    .createHmac("sha256", secret)
    .update(`${userId}:${port}`)
    .digest("hex");

  return recalculated === token;
}

// Helper: get or create user session
function getUserSession(userId) {
  if (!sessions[userId]) {
    sessions[userId] = { terminals: {}, gui: null };
  }
  return sessions[userId];
}

/**
 * Start GUI (Xvfb + x11vnc + optional fluxbox) for a user if not already started.
 * Returns the gui session object: { display, vncPort, index, processes }
 */
function ensureGuiSession(userId) {
  const session = getUserSession(userId);

  if (session.gui && session.gui.display && session.gui.vncPort) {
    return session.gui;
  }

  const index = nextGuiIndex++;
  const displayNum = GUI_BASE_DISPLAY + index; // e.g. 101
  const display = `:${displayNum}`; // ':101'
  const vncPort = GUI_BASE_VNC_PORT + index; // 5901, 5902, ...

  // Start Xvfb (virtual display)
  const xvfb = spawn("Xvfb", [display, "-screen", "0", "1920x1080x24"], {
    stdio: "ignore",
    detached: false,
  });

  // Start lightweight window manager (optional but nice)
  const wm = spawn("fluxbox", [], {
    stdio: "ignore",
    detached: false,
    env: {
      ...process.env,
      DISPLAY: display,
    },
  });

  // Start x11vnc to expose the Xvfb display as VNC
  const x11vnc = spawn(
    "x11vnc",
    [
      "-display",
      display,
      "-forever",
      "-nopw",
      "-shared",
      "-rfbport",
      String(vncPort),
    ],
    {
      stdio: "ignore",
      detached: false,
    }
  );

  // Basic error logging
  xvfb.on("error", (err) => console.error("Xvfb error:", err));
  x11vnc.on("error", (err) => console.error("x11vnc error:", err));
  wm.on("error", (err) => console.error("fluxbox error:", err));

  const guiSession = {
    display,
    vncPort,
    index,
    processes: { xvfb, x11vnc, wm },
  };

  session.gui = guiSession;
  console.log(
    `Started GUI session for user=${userId} display=${display} vncPort=${vncPort}`
  );

  return guiSession;
}

/**
 * Optional: stop GUI session for a user (not wired to any route yet)
 */
function stopGuiSession(userId) {
  const session = sessions[userId];
  if (!session || !session.gui) return;

  const { processes } = session.gui;
  for (const key of Object.keys(processes)) {
    try {
      processes[key].kill();
    } catch (e) {
      // ignore
    }
  }
  session.gui = null;
}

// ---- CORS ----
app.use(
  cors({
    origin: ["http://localhost:5173", "https://devsync-runner.onrender.com"],
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true,
  })
);
app.use(express.json());

// ---- HEALTH CHECK ----
app.get("/health", (req, res) => {
  res.json({ status: "ok", projectRoot: PROJECT_ROOT });
});

// ---- SAVE FILE ----
app.post("/api/files/save", async (req, res) => {
  try {
    const { relativePath, content } = req.body;

    if (!relativePath || typeof content !== "string") {
      return res
        .status(400)
        .json({ error: "relativePath and content are required" });
    }

    const safePath = path
      .normalize(relativePath)
      .replace(/^(\.\.(\/|\\|$))+/, "");
    const targetPath = path.join(PROJECT_ROOT, safePath);

    await fs.promises.mkdir(path.dirname(targetPath), { recursive: true });
    await fs.promises.writeFile(targetPath, content, "utf8");

    res.json({ ok: true, path: targetPath });
  } catch (err) {
    console.error("Error saving file:", err);
    res.status(500).json({ error: "Failed to save file" });
  }
});
app.use("/projects", express.static(path.join(__dirname, "projects")));

// ---- SERVE noVNC STATIC FILES ----
// Ubuntu's novnc package puts static files in /usr/share/novnc
app.use("/novnc", express.static("/usr/share/novnc"));

// ---- /gui/:userId → redirects into noVNC with proper WS path ----
app.get("/gui/:userId", (req, res) => {
  const { userId } = req.params;

  // Ensure GUI session is running (starts Xvfb + x11vnc if needed)
  const gui = ensureGuiSession(userId);

  // We will use noVNC's vnc.html, and tell it to connect to /websockify/:userId
  const encodedUser = encodeURIComponent(userId);
  const url = `/novnc/vnc.html?path=websockify/${encodedUser}&autoconnect=true&resize=scale`;

  // Redirect to noVNC client page
  res.redirect(url);
});

// ---- WEBSOCKET + PTY (code runner) ----
const wss = new WebSocketServer({ noServer: true });

// VNC websockify bridge (WS <-> TCP VNC)
const vncWss = new WebSocketServer({ noServer: true });

wss.on("connection", (ws, req) => {
  const userId = req.userId;
  const terminalId = req.terminalId;

  console.log(`WS connected: user=${userId}, terminal=${terminalId}`);

  const session = getUserSession(userId);

  // Build env for PTY; if GUI exists, attach DISPLAY
  let env = { ...process.env };
  if (session.gui && session.gui.display) {
    env.DISPLAY = session.gui.display;
  }

  // Create terminal-specific PTY
  const ptyProcess = pty.spawn("bash", [], {
    name: "xterm-color",
    cols: 80,
    rows: 25,
    cwd: PROJECT_ROOT,
    env,
  });

  // Save PTY instance in session
  session.terminals[terminalId] = ptyProcess;

  // PTY output → WS
  ptyProcess.on("data", (data) => {
    ws.send(data);

    // devserver detection
    const regex = /(localhost|127\.0\.0\.1):(\d{2,5})/g;
    let match;
    console.log(data);
    while ((match = regex.exec(data)) !== null) {
      const port = match[2];
      const token = generatePreviewToken(userId, port);

      ws.send(`PREVIEW:${port}:${token}`);
      console.log(`Dev server port=${port} for user=${userId}`);
    }
  });

  // WS → PTY input
  ws.on("message", (msg) => ptyProcess.write(msg));

  // Cleanup
  ws.on("close", () => {
    try {
      ptyProcess.kill();
    } catch (e) {
      // ignore
    }
    delete session.terminals[terminalId];
    console.log(`Terminal closed: user=${userId}, terminal=${terminalId}`);
  });
});

// VNC websockify bridge: WS <-> TCP (VNC)
vncWss.on("connection", (ws, req) => {
  const url = new URL(req.url, "http://localhost");
  const [, , encodedUserId] = url.pathname.split("/"); // /websockify/:userId
  const userId = decodeURIComponent(encodedUserId || "");

  const session = sessions[userId];
  const gui = session && session.gui;
  if (!gui || !gui.vncPort) {
    console.error("No GUI session or VNC port for user:", userId);
    ws.close();
    return;
  }

  const vncPort = gui.vncPort;

  // Connect to local VNC server (x11vnc)
  const tcpSocket = net.connect(vncPort, "127.0.0.1");

  tcpSocket.on("error", (err) => {
    console.error("VNC TCP error:", err);
    try {
      ws.close();
    } catch {}
  });

  tcpSocket.on("close", () => {
    try {
      ws.close();
    } catch {}
  });

  ws.on("close", () => {
    try {
      tcpSocket.end();
    } catch {}
  });

  // WS → TCP
  ws.on("message", (msg) => {
    if (Buffer.isBuffer(msg)) {
      tcpSocket.write(msg);
    } else if (typeof msg === "string") {
      tcpSocket.write(Buffer.from(msg));
    } else {
      // ArrayBuffer etc.
      tcpSocket.write(Buffer.from(msg));
    }
  });

  // TCP → WS
  tcpSocket.on("data", (chunk) => {
    ws.send(chunk);
  });
});

// ---- WEBSOCKET UPGRADE HANDLER ----
server.on("upgrade", (req, socket, head) => {
  const url = new URL(req.url, "http://localhost");

  // Terminal WebSocket
  if (url.pathname === "/ws/terminal") {
    const userId = url.searchParams.get("userId");
    const terminalId = url.searchParams.get("terminalId");

    if (!userId || !terminalId) {
      socket.destroy();
      return;
    }

    req.userId = userId;
    req.terminalId = terminalId;

    wss.handleUpgrade(req, socket, head, (ws) => {
      ws.userId = userId;
      ws.terminalId = terminalId;
      wss.emit("connection", ws, req);
    });
    return;
  }

  // VNC websockify WebSocket: /websockify/:userId
  if (url.pathname.startsWith("/websockify/")) {
    vncWss.handleUpgrade(req, socket, head, (ws) => {
      vncWss.emit("connection", ws, req);
    });
    return;
  }

  // Anything else: reject
  socket.destroy();
});

// ---- SECURE REVERSE PROXY (dev server preview) ----
app.use("/preview/:userId/:port", (req, res, next) => {
  const { userId, port } = req.params;
  const { token } = req.query;

  if (!token) {
    return res.status(403).send("Missing token");
  }

  if (!verifyPreviewToken(token, userId, port)) {
    return res.status(403).send("Invalid or expired preview token");
  }

  return createProxyMiddleware({
    target: `http://localhost:${port}`,
    changeOrigin: true,
    ws: true,
    pathRewrite: { [`^/preview/${userId}/${port}`]: "" },
  })(req, res, next);
});

// ---- START SERVER ----
server.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
  console.log(`Project root: ${PROJECT_ROOT}`);
});