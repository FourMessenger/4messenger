#!/usr/bin/env node
/**
 * 4 Messenger Server Startup Script
 * Run this from the root directory: node start-server.js
 */

const path = require('path');
const { spawn } = require('child_process');
const fs = require('fs');

const serverDir = path.join(__dirname, 'server');
const serverFile = path.join(serverDir, 'server.js');

// Check if server directory exists
if (!fs.existsSync(serverDir)) {
  console.error('\x1b[31m[Error]\x1b[0m Server directory not found!');
  console.log('Expected directory:', serverDir);
  process.exit(1);
}

// Check if server.js exists
if (!fs.existsSync(serverFile)) {
  console.error('\x1b[31m[Error]\x1b[0m server.js not found!');
  console.log('Expected file:', serverFile);
  process.exit(1);
}

// Check if node_modules exists in server directory
const nodeModulesDir = path.join(serverDir, 'node_modules');
if (!fs.existsSync(nodeModulesDir)) {
  console.log('\x1b[33m[Setup]\x1b[0m Installing server dependencies...');
  const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
  const install = spawn(npm, ['install'], { cwd: serverDir, stdio: 'inherit' });
  
  install.on('close', (code) => {
    if (code !== 0) {
      console.error('\x1b[31m[Error]\x1b[0m Failed to install dependencies');
      process.exit(1);
    }
    startServer();
  });
} else {
  startServer();
}

function startServer() {
  console.log('\x1b[36m[4 Messenger]\x1b[0m Starting server...\n');
  
  const server = spawn('node', ['server.js'], { 
    cwd: serverDir, 
    stdio: 'inherit',
    env: { ...process.env }
  });

  server.on('error', (err) => {
    console.error('\x1b[31m[Error]\x1b[0m Failed to start server:', err.message);
    process.exit(1);
  });

  server.on('close', (code) => {
    console.log(`\n\x1b[36m[4 Messenger]\x1b[0m Server exited with code ${code}`);
    process.exit(code);
  });

  // Handle Ctrl+C
  process.on('SIGINT', () => {
    console.log('\n\x1b[36m[4 Messenger]\x1b[0m Shutting down...');
    server.kill('SIGINT');
  });
}
