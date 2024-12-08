# Quicky Dashboard

A web dashboard for managing GitHub webhook deployments using [Quicky](https://quicky.dev).

## Features

- Secure webhook endpoint for GitHub push events
- Real-time log streaming via WebSocket
- Authentication protected dashboard
- Deployment status monitoring
- Rate limiting for webhook requests
- Graceful shutdown handling

## Configuration

The dashboard requires a config file at `~/.quicky/config.json` with the following structure:

```json
{
  "webhook": {
    "webhookUrl": "https://webhook.example.com/webhook",
    "webhookPort": 3000,
    "secret": "your-webhook-secret",
    "pm2Name": "quicky-webhook-server"
  },
  "dashboard": {
    "username": "admin", 
    "password": "hashed-password"
  },
  "projects": [
    {
      "owner": "github-username",
      "repo": "repository-name",
      "pid": "project-id"
    }
  ]
}
```

Setting up this webhook is handled by the [Quicky CLI](https://quicky.dev/docs/getting-started/installation).

## Running the dashboard

```bash
npm install
npm start
```
