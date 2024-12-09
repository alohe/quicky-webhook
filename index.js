import express from "express";
import { createHmac, timingSafeEqual } from "node:crypto";
import { exec } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import rateLimit from 'express-rate-limit';
import util from 'node:util';
import session from 'express-session';
import bcrypt from 'bcrypt';
import WebSocket, { WebSocketServer } from 'ws';
import dotenv from 'dotenv';

dotenv.config();

const env = process.env.NODE_ENV || 'production';

const homeDir = os.homedir();
const defaultFolder = path.join(homeDir, ".quicky");
const configPath = path.join(defaultFolder, "config.json");
const logsPath = path.join(defaultFolder, "logs.json");
const viewsPath = env === 'development'
  ? path.join(process.cwd(), "views")
  : path.join(defaultFolder, "webhook", "views")



if (!fs.existsSync(configPath)) {
  throw new Error(
    "Configuration file not found. Please install and configure quicky first. Visit https://quicky.dev for more info."
  );
}

// Initialize logs file if it doesn't exist
if (!fs.existsSync(logsPath)) {
  fs.writeFileSync(logsPath, JSON.stringify([]));
}

// WebSocket clients array with heartbeat tracking
let wsClients = [];

// Add structured logging helper at the top after imports
const logger = {
  info: (message, meta = {}) => {
    const logEntry = { level: 'info', message, timestamp: new Date().toISOString(), ...meta };
    console.log(JSON.stringify(logEntry));
    const logs = JSON.parse(fs.readFileSync(logsPath, 'utf-8'));
    logs.push(logEntry);
    fs.writeFileSync(logsPath, JSON.stringify(logs));
    // Broadcast to all connected WebSocket clients
    for (const client of wsClients) {
      if (client.isAlive && client.readyState === WebSocket.OPEN) {
        client.send(JSON.stringify(logEntry));
      }
    }
  },
  error: (message, meta = {}) => {
    const logEntry = { level: 'error', message, timestamp: new Date().toISOString(), ...meta };
    console.error(JSON.stringify(logEntry));
    const logs = JSON.parse(fs.readFileSync(logsPath, 'utf-8'));
    logs.push(logEntry);
    fs.writeFileSync(logsPath, JSON.stringify(logs));
    // Broadcast to all connected WebSocket clients
    for (const client of wsClients) {
      if (client.isAlive && client.readyState === WebSocket.OPEN) {
        client.send(JSON.stringify(logEntry));
      }
    }
  }
};

function validateConfig(config) {
  const required = ['webhook.webhookPort', 'webhook.secret', 'projects', 'dashboard.username', 'dashboard.password'];
  for (const field of required) {
    const value = field.split('.').reduce((obj, key) => obj?.[key], config);
    if (!value) {
      throw new Error(`Missing required config field: ${field}`);
    }
  }
  if (!Array.isArray(config.projects) || config.projects.length === 0) {
    throw new Error('Projects array must not be empty');
  }
}

// Read configuration file once
const config = JSON.parse(fs.readFileSync(configPath, "utf-8"));
validateConfig(config);

const webhookPort = config.webhook.webhookPort;
const webhookSecret = config.webhook.secret;

console.log(webhookPort);
console.log(webhookSecret);

if (!webhookSecret) {
  throw new Error("WEBHOOK_SECRET environment variable is required");
}

if (!webhookPort) {
  throw new Error("WEBHOOK_PORT environment variable is required");
}

const app = express();
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));
app.set('view engine', 'ejs');
app.set('views', viewsPath);

// Session middleware
app.use(session({
  secret: webhookSecret,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false } // Set to true if using HTTPS
}));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});

app.use('/webhook', limiter);

function verifySignature(req) {
  const signature = req.headers["x-hub-signature"];
  if (!signature) return false;

  const payload = JSON.stringify(req.body);
  const hmac = createHmac("sha1", webhookSecret);
  hmac.update(payload, "utf-8");

  const calculatedSignature = `sha1=${hmac.digest("hex")}`;
  return timingSafeEqual(
    Buffer.from(signature),
    Buffer.from(calculatedSignature)
  );
}

// Authentication middleware
function requireAuth(req, res, next) {
  if (req.session.authenticated) {
    next();
  } else {
    res.redirect('/login');
  }
}

// Login routes
app.get('/login', (req, res) => {
  res.render('login');
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  if (username === config.dashboard.username &&
    await bcrypt.compare(password, config.dashboard.password)) {
    req.session.authenticated = true;
    res.redirect('/dashboard');
  } else {
    res.render('login', { error: 'Invalid credentials' });
  }
});

// Dashboard routes
app.get('/dashboard', requireAuth, (req, res) => {
  const logs = JSON.parse(fs.readFileSync(logsPath, 'utf-8'));
  res.render('dashboard', { logs });
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});

app.post("/webhook", async (req, res) => {
  try {
    const event = req.headers["x-github-event"];
    logger.info('Received webhook event', { event });

    if (!verifySignature(req)) {
      logger.error('Invalid signature');
      return res.status(401).send("Invalid signature");
    }

    if (event === "push") {
      // Extract branch name from the ref (e.g. "refs/heads/main" -> "main")
      const branch = req.body.ref.split("/").pop();
      const owner = req.body.repository.owner.name;
      const repository = req.body.repository.name;

      logger.info('Processing push event', { branch, owner, repository });

      const project = config.projects.find(
        (p) => p.owner === owner && p.repo === repository
      );

      if (!project) {
        logger.error('Project not found', { owner, repository });
        return res.status(404).send("Project not found");
      }

      // Only deploy if push is to the main/master branch
      if (branch !== 'main' && branch !== 'master') {
        logger.info('Skipping deployment - not main/master branch', { branch });
        return res.status(200).send(`Skipping deployment for branch: ${branch}`);
      }

      const { stdout, stderr } = await util.promisify(exec)(`quicky update ${project.pid}`);

      if (stderr) {
        logger.error('Deployment warning', { warning: stderr });
      }
      logger.info('Deployment successful', { log: stdout });
      return res.status(200).send("Deployment successful");
    }

    logger.info('Unhandled event type', { event });
    return res.status(200).send(`Unhandled event type: ${event}`);
  } catch (error) {
    logger.error('Webhook processing failed', { error: error.message });
    return res.status(500).send("Internal server error");
  }
});

const server = app.listen(webhookPort, () => {
  logger.info('Webhook server started', { port: webhookPort });
});

// Set up WebSocket server with heartbeat
const wss = new WebSocketServer({ server });

function heartbeat() {
  this.isAlive = true;
}

const interval = setInterval(() => {
  for (const ws of wsClients) {
    if (!ws.isAlive) {
      ws.terminate();
      wsClients = wsClients.filter(client => client !== ws);
      return;
    }
    ws.isAlive = false;
    ws.ping();
  }
}, 30000);

wss.on('connection', (ws) => {
  ws.isAlive = true;
  ws.on('pong', heartbeat);
  wsClients.push(ws);

  // Send initial logs on connection
  const logs = JSON.parse(fs.readFileSync(logsPath, 'utf-8'));
  ws.send(JSON.stringify({ type: 'initial', logs }));

  ws.on('error', (error) => {
    console.error('WebSocket error:', error);
  });

  ws.on('close', () => {
    wsClients = wsClients.filter(client => client !== ws);
  });
});

wss.on('close', () => {
  clearInterval(interval);
});
