import express from "express";
import { createHmac, timingSafeEqual } from "crypto";
import { exec } from "child_process";
import dotenv from "dotenv";
import fs from "fs";
import path from "path";

dotenv.config();

const homeDir = os.homedir();
const defaultFolder = path.join(homeDir, ".quicky");
const configPath = path.join(defaultFolder, "config.json");

if (!fs.existsSync(configPath)) {
  throw new Error(
    "Configuration file not found. Please install and configure quicky first. Visit https://quicky.dev for more info."
  );
}

// Read configuration file once
const config = JSON.parse(fs.readFileSync(configPath, "utf-8"));

const webhookPort = process.env.WEBHOOK_PORT;
const webhookSecret = process.env.WEBHOOK_SECRET;

if (!webhookSecret) {
  throw new Error("WEBHOOK_SECRET environment variable is required");
}

if (!webhookPort) {
  throw new Error("WEBHOOK_PORT environment variable is required");
}

const app = express();
app.use(express.json());

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

app.post("/webhook", (req, res) => {
  const event = req.headers["x-github-event"];
  console.log(`Received event: ${event}`);

  if (!verifySignature(req)) {
    console.error("Invalid signature");
    return res.status(401).send("Invalid signature");
  }

  if (event === "push") {
    console.log("Push event detected, triggering deployment...");
    const branch = req.body.ref.split("/").pop();
    console.log(`Push to branch ${branch}`);

    const owner = req.body.repository.owner.name;
    const repository = req.body.repository.name;

    // Check if project exists in config
    const project = config.projects.find(
      (p) => p.owner === owner && p.repo === repository
    );

    if (!project) {
      console.error("Project not found in configuration");
      return res.status(404).send("Project not found");
    }

    exec(`quicky update ${project.pid}`, (error, stdout, stderr) => {
      if (error) {
        console.error(`Error updating project: ${error.message}`);
        return res.status(500).send("Deployment failed");
      }
      if (stderr) {
        console.error(`Deployment stderr: ${stderr}`);
      }
      console.log(`Deployment stdout: ${stdout}`);
      res.status(200).send("Deployment successful");
    });
  } else {
    console.log(`Unhandled event type: ${event}`);
    res.status(200).send(`Unhandled event type: ${event}`);
  }
});

app.listen(webhookPort, () => {
  console.log(`Listening for GitHub webhook events on port ${webhookPort}`);
});
