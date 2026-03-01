# 4 Messenger

A secure, self-hosted messenger with end-to-end encryption, group chats, voice/video calls, file sharing, and full admin controls.

![4 Messenger](https://img.shields.io/badge/4-Messenger-4F46E5?style=for-the-badge)

## Features

- 🔒 **End-to-end Encryption** - AES-256-GCM message encryption
- 👥 **Group Chats** - Create groups with admin controls
- 📞 **Voice & Video Calls** - WebRTC-based calling
- 📎 **File Sharing** - Upload and share files
- 👤 **Role System** - Admin, Moderator, User, Banned
- 🛡️ **Admin Panel** - Full server management dashboard
- ✉️ **Email Verification** - Optional email verification
- 🔑 **Server Password** - Password-protect your server
- 🤖 **CAPTCHA** - Bot protection
- 💾 **SQLite Database** - Zero-config database
- 🔐 **JWT Authentication** - Secure token-based auth
- ⚡ **Real-time** - WebSocket for instant messaging
- 📱 **Responsive** - Works on desktop and mobile

## Quick Start

### 1. Build the Client

```bash
# In root directory
npm install
npm run build
```

### 2. Setup the Server

```bash
cd server
npm install
```

### 3. Configure

Edit `server/config.json` to customize:
- Server password
- Email verification (SMTP settings)
- CAPTCHA on/off
- File upload limits
- Encryption settings
- Default admin credentials

### 4. Run

**Option 1: From root directory (recommended)**
```bash
node start-server.js
```
This will automatically install dependencies if needed and start the server.

**Option 2: From server directory**
```bash
cd server
npm start
```

Open `http://localhost:3000` in your browser.

## Configuration

### `server/config.json`

| Section | Key | Description |
|---------|-----|-------------|
| `server` | `port` | Server port (default: 3000) |
| `security` | `serverPassword` | Password to access the server |
| `security` | `jwtSecret` | Secret for JWT tokens (**change this!**) |
| `security` | `encryptionEnabled` | Enable message encryption |
| `captcha` | `enabled` | Enable CAPTCHA verification |
| `email` | `verificationEnabled` | Require email verification |
| `email.smtp` | `host`, `port`, etc. | SMTP server settings |
| `registration` | `enabled` | Allow new registrations |
| `files` | `maxSize` | Max file upload size (bytes) |
| `admin` | `defaultAdminPassword` | Default admin password |

### Environment Variables

```bash
PORT=3000        # Override server port
HOST=0.0.0.0    # Override bind address
```

## Default Credentials

- **Server Password:** `changeme123`
- **Admin Username:** `admin`
- **Admin Password:** `admin123`

⚠️ **Change these immediately in production!**

## Setting Up Cloudflare Turnstile (CAPTCHA)

4 Messenger uses Cloudflare Turnstile for CAPTCHA protection. Follow these steps to set it up:

### 1. Create a Cloudflare Account

If you don't have one, create a free account at [cloudflare.com](https://cloudflare.com).

### 2. Add Turnstile Widget

1. Go to the [Cloudflare Dashboard](https://dash.cloudflare.com)
2. Navigate to **Turnstile** in the sidebar
3. Click **Add Widget**
4. Enter a name for your widget (e.g., "4 Messenger")
5. Add your domain(s) where the messenger will be hosted
   - For local development, add `localhost`
6. Choose widget type:
   - **Managed** (recommended) - Cloudflare decides when to show challenges
   - **Non-interactive** - Invisible verification
   - **Invisible** - Completely invisible
7. Click **Create**

### 3. Get Your Keys

After creating the widget, you'll see:
- **Site Key** (public) - Goes in the frontend
- **Secret Key** (private) - Goes in the server config

### 4. Configure the Server

Edit `server/config.json`:

```json
{
  "captcha": {
    "enabled": true,
    "type": "cloudflare",
    "cloudflare": {
      "siteKey": "0x4AAAAAAXXXXXXXXXXXXXXXXX",
      "secretKey": "0x4AAAAAAXXXXXXXXXXXXXXXXX"
    }
  }
}
```

Replace the placeholder keys with your actual keys from the Cloudflare dashboard.

### 5. Test It

1. Restart the server
2. Connect to your messenger
3. You should see the Cloudflare Turnstile widget on the auth screen

### Troubleshooting

- **Widget not showing**: Check that the site key is correct and the domain is whitelisted
- **Verification failing**: Check that the secret key is correct in config.json
- **Console errors**: Ensure CORS is properly configured for your domain

## Security Checklist

Before deploying to production:

1. ✅ Change `jwtSecret` in config.json
2. ✅ Change default admin password
3. ✅ Change server password
4. ✅ Enable HTTPS (use reverse proxy like nginx)
5. ✅ Configure CORS origins
6. ✅ Enable email verification if needed
7. ✅ Set appropriate rate limits
8. ✅ Review file upload settings
9. ✅ Set up Cloudflare Turnstile (CAPTCHA)

## API Endpoints

### Authentication
- `POST /api/register` - Register new user
- `POST /api/login` - Login
- `POST /api/logout` - Logout
- `GET /api/me` - Get current user
- `GET /api/verify-email?token=...` - Verify email

### Server
- `GET /api/server-info` - Get server configuration
- `POST /api/verify-password` - Verify server password
- `GET /api/captcha` - Get CAPTCHA challenge
- `POST /api/captcha/verify` - Verify CAPTCHA answer

### Users
- `GET /api/users` - List all users
- `PUT /api/users/:id/role` - Update user role (admin)
- `POST /api/users/:id/ban` - Ban user (mod+)
- `POST /api/users/:id/unban` - Unban user (mod+)
- `DELETE /api/users/:id` - Delete user (admin)

### Chats
- `GET /api/chats` - Get user's chats
- `POST /api/chats/direct` - Create direct chat
- `POST /api/chats/group` - Create group chat
- `POST /api/chats/:id/members` - Add member
- `DELETE /api/chats/:id/members/:userId` - Remove member
- `POST /api/chats/:id/leave` - Leave group

### Messages
- `GET /api/chats/:id/messages` - Get messages
- `POST /api/chats/:id/messages` - Send message
- `PUT /api/messages/:id` - Edit message
- `DELETE /api/messages/:id` - Delete message

### Files
- `POST /api/upload` - Upload file

### Admin
- `GET /api/admin/stats` - Dashboard statistics
- `GET /api/admin/config` - Get server config
- `PUT /api/admin/config` - Update server config

### WebSocket Events
- `auth` - Authenticate WebSocket connection
- `typing` - Typing indicator
- `mark_read` - Mark messages as read
- `call_start` - Initiate call
- `call_offer` / `call_answer` - WebRTC signaling
- `ice_candidate` - ICE candidate exchange
- `call_end` - End call

## Tech Stack

### Client
- React 19 + TypeScript
- Vite
- Tailwind CSS 4
- Zustand (state management)
- Lucide React (icons)

### Server
- Node.js + Express
- WebSocket (ws)
- SQLite (sql.js - no native dependencies)
- JWT authentication
- bcryptjs (password hashing)
- AES-256-GCM encryption

## License

MIT
