import express from "express";
import { createHmac, timingSafeEqual } from "node:crypto";
import { exec } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import rateLimit from 'express-rate-limit';
import util from 'node:util';

const homeDir = os.homedir();
const defaultFolder = path.join(homeDir, ".quicky");
const configPath = path.join(defaultFolder, "config.json");

if (!fs.existsSync(configPath)) {
  throw new Error(
    "Configuration file not found. Please install and configure quicky first. Visit https://quicky.dev for more info."
  );
}

// Add structured logging helper at the top after imports
const logger = {
  info: (message, meta = {}) => console.log(JSON.stringify({ level: 'info', message, ...meta })),
  error: (message, meta = {}) => console.error(JSON.stringify({ level: 'error', message, ...meta })),
};

function validateConfig(config) {
  const required = ['webhook.webhookPort', 'webhook.secret', 'projects'];
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

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});

app.use(limiter);

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

app.post("/webhook", async (req, res) => {
  try {
    const event = req.headers["x-github-event"];
    logger.info('Received webhook event', { event });

    if (!verifySignature(req)) {
      logger.error('Invalid signature');
      return res.status(401).send("Invalid signature");
    }

    if (event === "push") {
      const branch = req.body.ref.split("/").pop();
      const owner = req.body.repository.owner.name;
      const repository = req.body.repository.name;

      const project = config.projects.find(
        (p) => p.owner === owner && p.repo === repository
      );

      if (!project) {
        logger.error('Project not found', { owner, repository });
        return res.status(404).send("Project not found");
      }

      const { stdout, stderr } = await util.promisify(exec)(`quicky update ${project.pid}`);
      
      if (stderr) {
        logger.error('Deployment warning', { stderr });
      }
      logger.info('Deployment successful', { stdout });
      return res.status(200).send("Deployment successful");
    }

    logger.info('Unhandled event type', { event });
    return res.status(200).send(`Unhandled event type: ${event}`);
  } catch (error) {
    logger.error('Webhook processing failed', { error: error.message });
    return res.status(500).send("Internal server error");
  }
});

function setupGracefulShutdown(server) {
  const shutdown = () => {
    logger.info('Received shutdown signal');
    server.close(() => {
      logger.info('Server shut down gracefully');
      process.exit(0);
    });
  };

  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

const server = app.listen(webhookPort, () => {
  logger.info('Webhook server started', { port: webhookPort });
});

setupGracefulShutdown(server);
