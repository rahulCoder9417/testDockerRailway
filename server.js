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
const app = express();
const server = http.createServer(app);
const PORT = process.env.PORT || 3000;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const sessions = {};

// ---- CONFIG ----
const PROJECT_ROOT = path.join(__dirname, "projects", "sample");

// ---- GUI CONFIG ----
const GUI_BASE_DISPLAY = 100;
const GUI_BASE_VNC_PORT = 5900;
let nextGuiIndex = 1;

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

  console.log(`🔐 Token verification: userId=${userId}, port=${port}`);
  console.log(`   Received token: ${token}`);
  console.log(`   Expected token: ${recalculated}`);
  console.log(`   Match: ${recalculated === token}`);

  return recalculated === token;
}

// Helper: get or create user session
function getUserSession(userId) {
  if (!sessions[userId]) {
    sessions[userId] = { terminals: {}, gui: null };
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
  console.log(
    `Started GUI session for user=${userId} display=${display} vncPort=${vncPort}`
  );

  return guiSession;
}

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
app.use("/novnc", express.static("/usr/share/novnc"));

// ---- /gui/:userId → redirects into noVNC with proper WS path ----
app.get("/gui/:userId", (req, res) => {
  const { userId } = req.params;
  const gui = ensureGuiSession(userId);
  const encodedUser = encodeURIComponent(userId);
  const url = `/novnc/vnc.html?path=websockify/${encodedUser}&autoconnect=true&resize=scale`;
  res.redirect(url);
});

// ---- SECURE REVERSE PROXY (dev server preview) ----
app.use("/preview/:userId/:port*", (req, res, next) => {
  const { userId, port } = req.params;
  const token = req.query.token;

  if (!token) return res.status(403).send("Missing token");
  if (!verifyPreviewToken(token, userId, port)) {
    return res.status(403).send("Invalid or expired preview token");
  }

  const proxy = createProxyMiddleware({
    target: `http://localhost:${port}`,
    changeOrigin: true,
    ws: true,
    selfHandleResponse: true,

    // 1️⃣ Normalize path → strip /preview/:userId/:port and strip ?token=...
    pathRewrite: (path, req) => {
      const { userId, port } = req.params;
      const prefix = `/preview/${userId}/${port}`;
      let newPath = path.replace(prefix, "");

      // strip token query manually from the path string
      newPath = newPath.replace(/[?&]token=[^&]+/, "").replace(/\?$/, "");

      if (!newPath) newPath = "/";
      console.log(`🔄 Path rewrite: ${path} → ${newPath}`);
      return newPath;
    },

    // 2️⃣ Make sure we always get a *real* body (no gzip, no 304)
    onProxyReq(proxyReq, req, res) {
      // disable gzip so we can read plain text
      proxyReq.removeHeader("accept-encoding");
      // disable cache validation → avoid 304 Not Modified (no body to rewrite)
      proxyReq.removeHeader("if-none-match");
      proxyReq.removeHeader("if-modified-since");
      console.log(`➡️  Proxying to: http://localhost:${port}${proxyReq.path}`);
    },

    // 3️⃣ Intercept responses and rewrite HTML + JS bodies
    onProxyRes(proxyRes, req, res) {
      const contentType = proxyRes.headers["content-type"] || "";
      console.log(
        `⬅️  Response received: ${proxyRes.statusCode} ${proxyRes.statusMessage}`
      );
      console.log(`📄 Content-Type: ${contentType}`);

      const isHtml = contentType.includes("text/html");
      const isJs =
        contentType.includes("application/javascript") ||
        contentType.includes("text/javascript") ||
        contentType.includes("javascript+module") ||
        contentType.includes("module");

      // If it's neither HTML nor JS → just stream it straight through
      if (!isHtml && !isJs) {
        res.writeHead(proxyRes.statusCode || 200, proxyRes.headers);
        proxyRes.pipe(res);
        return;
      }

      console.log(
        `✏️  Intercepting ${isHtml ? "HTML" : "JS"} response for rewrite`
      );

      let body = "";
      proxyRes.on("data", (chunk) => {
        body += chunk.toString("utf8");
      });

      proxyRes.on("end", () => {
        const { userId, port } = req.params;
        const token = req.query.token || "";
        const baseUrl = `/preview/${userId}/${port}`;

        // ---- HTML REWRITE ----
        if (isHtml) {
          // src="/..." or href="/..."
          body = body.replace(
            /((?:src|href))="\/([^"]*)"/g,
            `$1="${baseUrl}/$2?token=${token}"`
          );

          // modulepreload link tags
          body = body.replace(
            /<link\s+rel="modulepreload"\s+href="\/([^"]*)"/g,
            `<link rel="modulepreload" href="${baseUrl}/$1?token=${token}"`
          );

          console.log("✅ HTML URLs rewritten");
        }

        // ---- JS REWRITE ----
        if (isJs) {
          // import "/foo"
          body = body.replace(
            /import\s+(['"])\s*\/([^'"]*)\1/g,
            (_m, quote, spec) =>
              `import ${quote}${baseUrl}/${spec}?token=${token}${quote}`
          );

          // dynamic import("/foo")
          body = body.replace(
            /import\(\s*(['"])\s*\/([^'"]*)\1\s*\)/g,
            (_m, quote, spec) =>
              `import(${quote}${baseUrl}/${spec}?token=${token}${quote})`
          );

          // export ... from "/foo"
          body = body.replace(
            /export\s+([^'"]*?)\s+from\s+(['"])\s*\/([^'"]*)\2/g,
            (_m, what, quote, spec) =>
              `export ${what} from ${quote}${baseUrl}/${spec}?token=${token}${quote}`
          );

          // Very common in Vite client code: bare absolute HMR URL
          body = body.replace(
            /new WebSocket\(\s*(['"])ws:\/\/localhost:(\d+)\/([^'"]*)\1\s*\)/g,
            (_m, quote, devPort, hmrPath) =>
              `new WebSocket(${quote}ws://"+location.host+"${baseUrl}/${hmrPath}?token=${token}${quote})`
          );

          console.log("✅ JS import/export URLs rewritten");
        }

        // We changed the body → kill length & encoding so Node recalculates
        const headers = { ...proxyRes.headers };
        delete headers["content-length"];
        delete headers["Content-Length"];
        delete headers["content-encoding"];
        delete headers["Content-Encoding"];

        res.writeHead(proxyRes.statusCode || 200, headers);
        res.end(body);
      });
    },

    onError(err, req, res) {
      console.error("❌ PROXY ERROR:", err.message);
      if (!res.headersSent) {
        res
          .status(502)
          .send(`<h1>Proxy Error</h1><pre>${err.message}</pre>`);
      }
    },
  });

  return proxy(req, res, next);
});


// ---- WEBSOCKET + PTY (code runner) ----
const wss = new WebSocketServer({ noServer: true });
const vncWss = new WebSocketServer({ noServer: true });

wss.on("connection", (ws, req) => {
  const userId = req.userId;
  const terminalId = req.terminalId;

  console.log(`🖥️  Terminal WS connected: user=${userId}, terminal=${terminalId}`);

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

  ptyProcess.on("data", (data) => {
    ws.send(data);

    const regex = /https?:\/\/(localhost|127\.0\.0\.1)(?::(\d{1,5}))?/g;
    const serverReadyPatterns = [
      /compiled successfully/i,
      /vite v[\d.]+/i,
      /local:\s*https?:\/\/localhost/i,
      /ready/i,
      /listening/i,
    ];
    
    let match;
    data = data.replace(/\x1b\[[0-9;]*m/g, '')
    while ((match = regex.exec(data)) !== null) {
      console.log("🚀 Dev server detected:", match);
      const port = match[2];
      const token = generatePreviewToken(userId, port);

      ws.send(`PREVIEW:${port}:${token}`);
      console.log(`✅ Preview URL generated: port=${port} for user=${userId}`);
    }
  });

  ws.on("message", (msg) => ptyProcess.write(msg));

  ws.on("close", () => {
    try {
      ptyProcess.kill();
    } catch (e) {
      // ignore
    }
    delete session.terminals[terminalId];
    console.log(`🖥️  Terminal closed: user=${userId}, terminal=${terminalId}`);
  });
});

vncWss.on("connection", (ws, req) => {
  const url = new URL(req.url, "http://localhost");
  const [, , encodedUserId] = url.pathname.split("/");
  const userId = decodeURIComponent(encodedUserId || "");

  const session = sessions[userId];
  const gui = session && session.gui;
  if (!gui || !gui.vncPort) {
    console.error("No GUI session or VNC port for user:", userId);
    ws.close();
    return;
  }

  const vncPort = gui.vncPort;
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

// ---- WEBSOCKET UPGRADE HANDLER ----
server.on("upgrade", (req, socket, head) => {
  const url = new URL(req.url, "http://localhost");

  console.log('\n⬆️  ============ WEBSOCKET UPGRADE ============');
  console.log(`📍 URL: ${req.url}`);
  console.log(`📂 Pathname: ${url.pathname}`);
  console.log(`🔧 Headers:`, JSON.stringify(req.headers, null, 2));

  // Terminal WebSocket
  if (url.pathname === "/ws/terminal") {
    console.log('✅ Matched: Terminal WebSocket');
    const userId = url.searchParams.get("userId");
    const terminalId = url.searchParams.get("terminalId");

    if (!userId || !terminalId) {
      console.log('❌ Missing userId or terminalId');
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

  // VNC websockify WebSocket
  if (url.pathname.startsWith("/websockify/")) {
    console.log('✅ Matched: VNC WebSocket');
    vncWss.handleUpgrade(req, socket, head, (ws) => {
      vncWss.emit("connection", ws, req);
    });
    return;
  }

  // Preview WebSocket
  if (url.pathname.startsWith("/preview/")) {
    console.log('✅ Matched: Preview WebSocket');
    const pathParts = url.pathname.split("/");
    const userId = pathParts[2];
    const port = pathParts[3];
    const token = url.searchParams.get("token");

    console.log(`👤 UserId: ${userId}`);
    console.log(`🔌 Port: ${port}`);
    console.log(`🎫 Token: ${token ? token.substring(0, 20) + '...' : '❌ MISSING'}`);

    if (!token) {
      console.log('❌ No token provided for WebSocket upgrade');
      socket.destroy();
      return;
    }

    const isValid = verifyPreviewToken(token, userId, port);
    if (!isValid) {
      console.log('❌ Invalid token for WebSocket upgrade');
      socket.destroy();
      return;
    }

    console.log('✅ Token verified, creating WebSocket proxy...');

    const pathAfterPort = "/" + pathParts.slice(4).join("/");
    const rewrittenPath = (pathAfterPort === "/" ? "" : pathAfterPort) + url.search;
    
    console.log(`🔄 Path rewrite: ${url.pathname} → ${rewrittenPath || '/'}`);
    console.log(`➡️  Connecting to: localhost:${port}${rewrittenPath || '/'}`);

    const proxyReq = http.request({
      hostname: "localhost",
      port: parseInt(port),
      path: rewrittenPath || '/',
      headers: req.headers,
    });

    proxyReq.on("upgrade", (proxyRes, proxySocket, proxyHead) => {
      console.log('✅ Dev server accepted WebSocket upgrade');
      console.log(`📡 Response status: ${proxyRes.statusCode} ${proxyRes.statusMessage}`);
      console.log(`📨 Response headers:`, JSON.stringify(proxyRes.headers, null, 2));

      socket.write("HTTP/1.1 101 Switching Protocols\r\n");
      Object.keys(proxyRes.headers).forEach((key) => {
        socket.write(`${key}: ${proxyRes.headers[key]}\r\n`);
      });
      socket.write("\r\n");
      
      console.log('✅ Pipes established - WebSocket is live!');

      proxySocket.on("error", (err) => {
        console.error("❌ ProxySocket error:", err.message);
        try { socket.destroy(); } catch {}
      });
      
      socket.on("error", (err) => {
        console.error("❌ Client socket error:", err.message);
        try { proxySocket.destroy(); } catch {}
      });
      
      proxySocket.pipe(socket);
      socket.pipe(proxySocket);
    });

    proxyReq.on("error", (err) => {
      console.error('❌ ============ WEBSOCKET PROXY ERROR ============');
      console.error(`🔴 Error: ${err.message}`);
      console.error(`🔴 Code: ${err.code}`);
      console.error(`🔴 Target: localhost:${port}${rewrittenPath || '/'}`);
      console.error(`💡 Is dev server running on port ${port}?`);
      socket.destroy();
    });

    proxyReq.end();
    return;
  }

  console.log('❌ No matching WebSocket route');
  socket.destroy();
});

// ---- START SERVER ----
server.listen(PORT, () => {
  console.log(`\n🚀 ============ SERVER STARTED ============`);
  console.log(`📡 Port: ${PORT}`);
  console.log(`📂 Project root: ${PROJECT_ROOT}`);
  console.log(`🔐 Preview secret: ${process.env.PREVIEW_SECRET ? 'Set from env' : 'Using default "supersecret"'}`);
  console.log(`============================================\n`);
});