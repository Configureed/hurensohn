# Discord Server Cloner Web App

A web-based Discord server cloner that allows you to copy entire servers (channels, roles, emojis, etc.) from one server to another.

## Prerequisites

1. Node.js (v16 or higher)
2. npm or yarn

## Installation

1. Install dependencies:
```bash
npm install
```

## How to Use

1. Start the server:
```bash
npm start
```

2. Open your browser and go to `http://localhost:3002`

3. Enter your Discord token (bot or user token) and click "Login"

4. Select the source server (the one you want to copy) and the target server (the one you want to copy to)

5. Click "Clone Server" and wait for the process to complete

## Important Notes

- You need to have appropriate permissions (Manage Server, Manage Channels, Manage Roles, etc.) on both servers
- The cloning process may take some time depending on the size of the server
- This tool uses `discord.js-selfbot-v13`, which is against Discord's Terms of Service. Use at your own risk.
