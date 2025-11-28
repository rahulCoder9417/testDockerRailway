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
    sessions[userId] = { terminals: {}, gui: null, previews: {} };
  }
  return sessions[userId];
}

function ensureGuiSession(userId) {
  const session = getUserSession(userId);

  if (session.gui && session.gui.display && session.gui.vncPort) {
    console.log(`♻️  Reusing existing GUI session: display=${session.gui.display}`);
    return session.gui;
  }

  const index = nextGuiIndex++;
  const displayNum = GUI_BASE_DISPLAY + index;
  const display = `:${displayNum}`;
  const vncPort = GUI_BASE_VNC_PORT + index;

  console.log(`🎬 Starting Xvfb on display ${display}...`);

  const xvfb = spawn("Xvfb", [display, "-screen", "0", "1920x1080x24", "-ac"], {
    stdio: ["ignore", "pipe", "pipe"],
    detached: false,
  });

  xvfb.stdout?.on("data", (data) => console.log(`[Xvfb ${display}] ${data}`));
  xvfb.stderr?.on("data", (data) => console.error(`[Xvfb ${display}] ${data}`));
  xvfb.on("error", (err) => console.error(`❌ Xvfb error on ${display}:`, err));
  xvfb.on("exit", (code) => console.log(`Xvfb ${display} exited with code ${code}`));

  // Wait for Xvfb to be ready
  const waitForDisplay = () => {
    return new Promise((resolve) => {
      const checkInterval = setInterval(() => {
        const testProcess = spawn("xdpyinfo", ["-display", display], {
          stdio: "ignore",
        });
        testProcess.on("exit", (code) => {
          if (code === 0) {
            clearInterval(checkInterval);
            console.log(`✅ Xvfb ${display} is ready!`);
            resolve();
          }
        });
      }, 100);

      // Timeout after 5 seconds
      setTimeout(() => {
        clearInterval(checkInterval);
        console.warn(`⚠️  Xvfb ${display} timeout, proceeding anyway...`);
        resolve();
      }, 5000);
    });
  };

  // Start window manager after Xvfb is ready
  waitForDisplay().then(() => {
    console.log(`🪟 Starting fluxbox on ${display}...`);
    const wm = spawn("fluxbox", [], {
      stdio: ["ignore", "pipe", "pipe"],
      detached: false,
      env: {
        ...process.env,
        DISPLAY: display,
      },
    });

    wm.stdout?.on("data", (data) => console.log(`[fluxbox ${display}] ${data}`));
    wm.stderr?.on("data", (data) => console.error(`[fluxbox ${display}] ${data}`));
    wm.on("error", (err) => console.error(`❌ fluxbox error on ${display}:`, err));

    console.log(`📡 Starting x11vnc on ${display} port ${vncPort}...`);
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
        stdio: ["ignore", "pipe", "pipe"],
        detached: false,
      }
    );

    x11vnc.stdout?.on("data", (data) => console.log(`[x11vnc ${display}] ${data}`));
    x11vnc.stderr?.on("data", (data) => console.error(`[x11vnc ${display}] ${data}`));
    x11vnc.on("error", (err) => console.error(`❌ x11vnc error on ${display}:`, err));

    if (session.gui && session.gui.processes) {
      session.gui.processes.wm = wm;
      session.gui.processes.x11vnc = x11vnc;
    }
  });

  const guiSession = {
    display,
    vncPort,
    index,
    processes: { xvfb },
    ready: false,
  };

  session.gui = guiSession;
  
  // Mark as ready after wait
  waitForDisplay().then(() => {
    guiSession.ready = true;
    console.log(`✅ GUI session fully initialized for user=${userId} display=${display} vncPort=${vncPort}`);
  });

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

// ---- SECURE REVERSE PROXY (PRODUCTION BUILD PREVIEW) ----
app.use("/preview/:userId/:port*", (req, res, next) => {
  const { userId, port } = req.params;
  const { token } = req.query;

  console.log('\n🌐 ============ HTTP PROXY REQUEST ============');
  console.log(`📍 Full URL: ${req.protocol}://${req.get('host')}${req.originalUrl}`);
  console.log(`📂 Path: ${req.path}`);
  console.log(`👤 UserId: ${userId}`);
  console.log(`🔌 Port: ${port}`);
  console.log(`🎫 Token: ${token ? token.substring(0, 20) + '...' : '❌ MISSING'}`);

  if (!token) {
    console.log('❌ FAILED: No token provided');
    return res.status(403).send("Missing token");
  }

  const isValid = verifyPreviewToken(token, userId, port);
  if (!isValid) {
    console.log('❌ FAILED: Invalid token');
    return res.status(403).send("Invalid or expired preview token");
  }

  console.log('✅ Token verified, creating proxy...');

  const proxy = createProxyMiddleware({
    target: `http://localhost:${port}`,
    changeOrigin: true,
    ws: true,
    selfHandleResponse: true,
    pathRewrite: (path, req) => {
      const { userId, port } = req.params;
      const prefix = `/preview/${userId}/${port}`;
      
      let newPath = path.replace(prefix, '').replace(/[?&]token=[^&]+/, '').replace(/\?$/, '') || '/';
      
      console.log(`🔄 Path rewrite: ${path} → ${newPath}`);
      return newPath;
    },
    onProxyReq: (proxyReq, req, res) => {
      console.log(`➡️  Proxying to: http://localhost:${port}${proxyReq.path}`);
    },
    onProxyRes: (proxyRes, req, res) => {
      console.log(`⬅️  Response received: ${proxyRes.statusCode} ${proxyRes.statusMessage}`);
      console.log(`📄 Content-Type: ${proxyRes.headers['content-type']}`);
      console.log(`📂 Request path: ${req.path}`);
      
      const contentType = proxyRes.headers['content-type'] || '';
      
      // Rewrite HTML
      if (contentType.includes('text/html')) {
        console.log('🔧 Modifying HTML response...');
        
        let body = '';
        proxyRes.on('data', (chunk) => {
          body += chunk.toString('utf8');
        });
        
        proxyRes.on('end', () => {
          const baseUrl = `/preview/${userId}/${port}`;
          
          console.log('📝 Original HTML length:', body.length);
          
          // Rewrite absolute URLs in HTML attributes
          body = body.replace(
            /((?:src|href))="\/([^"]*)"/g,
            `$1="${baseUrl}/$2?token=${token}"`
          );
          
         // Also rewrite relative URLs in CSS/JS that reference images
          body = body.replace(
            /(url\(['"]?)(\/[^'")]+)(['"]?\))/g,
            `$1${baseUrl}$2?token=${token}$3`
          );
          
          console.log('✅ HTML URLs rewritten');
          
          res.writeHead(proxyRes.statusCode, proxyRes.headers);
          res.end(body);
        });
      } 
      // Pass through everything else (images, JS, fonts, etc.)
      else {
        console.log('📦 Passing through:', contentType);
        res.writeHead(proxyRes.statusCode, proxyRes.headers);
        proxyRes.pipe(res);
      }
    },
    onError: (err, req, res) => {
      console.error('❌ ============ PROXY ERROR ============');
      console.error(`🔴 Error: ${err.message}`);
      console.error(`🔴 Code: ${err.code}`);
      console.error(`🔴 Target: http://localhost:${port}`);
      res.status(502).send(`<h1>Proxy Error</h1><p>${err.message}</p><p>Make sure your app is built and running with 'npm start'</p>`);
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

  // ✅ AUTO-ASSIGN GUI: Create GUI session when user opens any terminal
  const gui = ensureGuiSession(userId);
  console.log(`🖼️  GUI session assigned: DISPLAY=${gui.display} VNC=:${gui.vncPort} for user=${userId}`);

  // Set environment with DISPLAY variable
  let env = { ...process.env, DISPLAY: gui.display };

  const ptyProcess = pty.spawn("bash", [], {
    name: "xterm-color",
    cols: 80,
    rows: 25,
    cwd: PROJECT_ROOT,
    env,
  });

  session.terminals[terminalId] = ptyProcess;

  // Send GUI info to frontend on connection
  ws.send(`\r\n🖼️  GUI Display ready: ${gui.display} (VNC port: ${gui.vncPort})\r\n`);
  ws.send(`💡 Access GUI at: /gui/${userId}\r\n\r\n`);

  ptyProcess.on("data", (data) => {
    ws.send(data);

    // Clean ANSI codes for detection
    const cleanData = data.replace(/\x1b\[[0-9;]*m/g, '');
    
    // Detect production server patterns (Express, serve, http-server, etc.)
    const productionPatterns = [
      /listening on.*?(?:port\s*)?(\d{4,5})/i,
      /server.*?(?:running|started).*?(?:port\s*)?(\d{4,5})/i,
      /started.*?(?:on|at).*?:(\d{4,5})/i,
      /ready.*?(?:on|at).*?:(\d{4,5})/i,
      /serving.*?(?:on|at).*?:(\d{4,5})/i,
      /https?:\/\/(localhost|127\.0\.0\.1):(\d{4,5})/i,
    ];

    let detectedPort = null;
    for (const pattern of productionPatterns) {
      const match = cleanData.match(pattern);
      if (match) {
        // Get the port from either capture group 1 or 2 (depending on pattern)
        detectedPort = match[2] || match[1];
        break;
      }
    }

    // Only generate preview if we haven't already for this port
    if (detectedPort && !session.previews[detectedPort]) {
      console.log("🚀 Production server detected on port:", detectedPort);
      const token = generatePreviewToken(userId, detectedPort);
      
      // Store preview info
      session.previews[detectedPort] = {
        port: detectedPort,
        token,
        startedAt: new Date(),
      };

      ws.send(`\n\n✅ Preview ready! Your app is running on port ${detectedPort}\n`);
      ws.send(`PREVIEW:${detectedPort}:${token}\n`);
      console.log(`✅ Preview URL generated: port=${detectedPort} for user=${userId}`);
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
    
    // CLEANUP: If no more terminals for this user, stop GUI session after delay
    if (Object.keys(session.terminals).length === 0) {
      console.log(`⏳ Last terminal closed for user=${userId}, scheduling GUI cleanup in 60s...`);
      setTimeout(() => {
        // Double-check no new terminals were opened
        if (Object.keys(session.terminals).length === 0) {
          console.log(`🧹 Cleaning up GUI session for inactive user=${userId}`);
          stopGuiSession(userId);
        }
      }, 60000); // 60 second grace period
    }
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

  // Preview WebSocket (for Express apps with WebSocket support)
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
      console.log('✅ Server accepted WebSocket upgrade');

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
  console.log(`\n📝 USAGE INSTRUCTIONS:`);
  console.log(`   1. Build your app: npm run build`);
  console.log(`   2. Start production server: npm start`);
  console.log(`   3. Preview will be detected automatically`);
  console.log(`============================================\n`);
});