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

const sessions = {};
const PROJECT_ROOT = path.join(__dirname, "projects", "sample");

// GUI CONFIG
const GUI_BASE_DISPLAY = 100;
const GUI_BASE_VNC_PORT = 5900;
let nextGuiIndex = 1;

// TOKEN GENERATION
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

function getUserSession(userId) {
  if (!sessions[userId]) {
    sessions[userId] = { 
      terminals: {}, 
      gui: null,
      detectedPorts: new Set() // Track detected ports to avoid duplicates
    };
  }
  return sessions[userId];
}

function ensureGuiSession(userId) {
  const session = getUserSession(userId);

  if (session.gui && session.gui.display && session.gui.vncPort) {
    return session.gui;
  }

  const index = nextGuiIndex++;
  const displayNum = GUI_BASE_DISPLAY + index;
  const display = `:${displayNum}`;
  const vncPort = GUI_BASE_VNC_PORT + index;

  const xvfb = spawn("Xvfb", [display, "-screen", "0", "1920x1080x24"], {
    stdio: "ignore",
    detached: false,
  });

  const wm = spawn("fluxbox", [], {
    stdio: "ignore",
    detached: false,
    env: {
      ...process.env,
      DISPLAY: display,
    },
  });

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
  console.log(`Started GUI for user=${userId} display=${display} vncPort=${vncPort}`);
  return guiSession;
}

// CORS
app.use(
  cors({
    origin: ["http://localhost:5173", "https://devsync-runner.onrender.com"],
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true,
  })
);
app.use(express.json());

// HEALTH CHECK
app.get("/health", (req, res) => {
  res.json({ status: "ok", projectRoot: PROJECT_ROOT });
});

// SAVE FILE
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

// SERVE noVNC STATIC FILES
app.use("/novnc", express.static("/usr/share/novnc"));

// GUI ENDPOINT
app.get("/gui/:userId", (req, res) => {
  const { userId } = req.params;
  const gui = ensureGuiSession(userId);
  const encodedUser = encodeURIComponent(userId);
  const url = `/novnc/vnc.html?path=websockify/${encodedUser}&autoconnect=true&resize=scale`;
  res.redirect(url);
});

// WEBSOCKET + PTY
const wss = new WebSocketServer({ noServer: true });
const vncWss = new WebSocketServer({ noServer: true });

wss.on("connection", (ws, req) => {
  const userId = req.userId;
  const terminalId = req.terminalId;

  console.log(`WS connected: user=${userId}, terminal=${terminalId}`);

  const session = getUserSession(userId);

  let env = { ...process.env };
  if (session.gui && session.gui.display) {
    env.DISPLAY = session.gui.display;
  }

  const ptyProcess = pty.spawn("bash", [], {
    name: "xterm-color",
    cols: 80,
    rows: 25,
    cwd: PROJECT_ROOT,
    env,
  });

  session.terminals[terminalId] = ptyProcess;

  // FIXED: Better port detection patterns
  const portPatterns = [
    // Python http.server: "Serving HTTP on 0.0.0.0 port 8000"
    /port\s+(\d{2,5})/i,
    
    // Node/Express: "Server listening on port 3000"
    /listening.*?(\d{2,5})/i,
    
    // URL formats: http://localhost:8000, http://127.0.0.1:8000, http://0.0.0.0:8000
    /https?:\/\/(?:localhost|127\.0\.0\.1|0\.0\.0\.0):(\d{2,5})/gi,
    
    // Generic: "on :8000" or "at :8000"
    /(?:on|at)\s+:(\d{2,5})/i,
    
    // Port with colon: ":8000"
    /:(\d{2,5})\b/
  ];

  ptyProcess.on("data", (data) => {
    ws.send(data);

    const dataStr = data.toString();
    
    // Try each pattern
    for (const pattern of portPatterns) {
      const matches = dataStr.matchAll(pattern);
      
      for (const match of matches) {
        const port = match[1];
        const portNum = parseInt(port, 10);
        
        // Validate port range and avoid duplicates
        if (portNum >= 1000 && portNum <= 65535 && !session.detectedPorts.has(port)) {
          session.detectedPorts.add(port);
          const token = generatePreviewToken(userId, port);
          ws.send(`PREVIEW:${port}:${token}`);
          console.log(`✓ Dev server detected: port=${port} for user=${userId}`);
        }
      }
    }
  });

  ws.on("message", (msg) => ptyProcess.write(msg));

  ws.on("close", () => {
    try {
      ptyProcess.kill();
    } catch (e) {}
    delete session.terminals[terminalId];
    console.log(`Terminal closed: user=${userId}, terminal=${terminalId}`);
  });
});

// VNC websockify bridge
vncWss.on("connection", (ws, req) => {
  const url = new URL(req.url, "http://localhost");
  const [, , encodedUserId] = url.pathname.split("/");
  const userId = decodeURIComponent(encodedUserId || "");

  const session = sessions[userId];
  const gui = session && session.gui;
  if (!gui || !gui.vncPort) {
    console.error("No GUI session for user:", userId);
    ws.close();
    return;
  }

  const vncPort = gui.vncPort;
  const tcpSocket = net.connect(vncPort, "127.0.0.1");

  tcpSocket.on("error", (err) => {
    console.error("VNC TCP error:", err);
    try { ws.close(); } catch {}
  });

  tcpSocket.on("close", () => {
    try { ws.close(); } catch {}
  });

  ws.on("close", () => {
    try { tcpSocket.end(); } catch {}
  });

  ws.on("message", (msg) => {
    if (Buffer.isBuffer(msg)) {
      tcpSocket.write(msg);
    } else if (typeof msg === "string") {
      tcpSocket.write(Buffer.from(msg));
    } else {
      tcpSocket.write(Buffer.from(msg));
    }
  });

  tcpSocket.on("data", (chunk) => {
    ws.send(chunk);
  });
});

// WEBSOCKET UPGRADE HANDLER
server.on("upgrade", (req, socket, head) => {
  const url = new URL(req.url, "http://localhost");

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

  if (url.pathname.startsWith("/websockify/")) {
    vncWss.handleUpgrade(req, socket, head, (ws) => {
      vncWss.emit("connection", ws, req);
    });
    return;
  }

  socket.destroy();
});

// FIXED: Preview proxy with WebSocket support
app.use("/preview/:userId/:port", (req, res, next) => {
  const { userId, port } = req.params;
  const { token } = req.query;

  if (!token) {
    return res.status(403).send("Missing token");
  }

  if (!verifyPreviewToken(token, userId, port)) {
    return res.status(403).send("Invalid token");
  }

  const proxy = createProxyMiddleware({
    target: `http://localhost:${port}`,
    changeOrigin: true,
    ws: true,
    pathRewrite: { [`^/preview/${userId}/${port}`]: "" },
    onError: (err, req, res) => {
      console.error(`Proxy error for port ${port}:`, err.message);
      res.status(502).send(`Cannot connect to port ${port}. Is the server running?`);
    },
    onProxyReq: (proxyReq, req, res) => {
      console.log(`Proxying: ${req.method} ${req.url} -> localhost:${port}`);
    }
  });

  return proxy(req, res, next);
});

// Handle WebSocket upgrades for preview proxy
server.on("upgrade", (req, socket, head) => {
  const url = new URL(req.url, "http://localhost");
  
  // Check if this is a preview WebSocket upgrade
  const previewMatch = url.pathname.match(/^\/preview\/([^\/]+)\/(\d+)/);
  if (previewMatch) {
    const [, userId, port] = previewMatch;
    const token = url.searchParams.get("token");
    
    if (token && verifyPreviewToken(token, userId, port)) {
      // Forward WebSocket upgrade to the dev server
      const proxy = createProxyMiddleware({
        target: `http://localhost:${port}`,
        changeOrigin: true,
        ws: true,
      });
      
      proxy.upgrade(req, socket, head);
      return;
    }
  }
});

// START SERVER
server.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
  console.log(`Project root: ${PROJECT_ROOT}`);
});