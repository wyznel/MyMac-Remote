# MyMac Remote

A Node.js web application that turns any phone or browser on the same local network into a remote control for your Mac. Provides volume control, a mouse trackpad, keyboard input, and real-time state sync — served over HTTPS with PIN-based authentication.

---

## Features

**Volume**
- Slider with live feedback
- Mute toggle
- Step buttons (+5 / -5)
- Real-time sync via Server-Sent Events — volume changes made on the Mac appear on the phone within one second

**Trackpad and mouse**
- Drag to move the cursor
- Tap to left-click
- Double-tap and hold to enter drag mode (hold mouse button down for dragging windows, selecting text, etc.)
- Left click, right click, and double-click buttons
- Scroll up / scroll down

**Keyboard**
- Type arbitrary text (sent to the focused application)
- Special keys: Return, Backspace, Escape, Tab

**Authentication and security**
- Random 6-digit PIN generated on every server start, or a persistent passphrase via environment variable
- Session cookies: `HttpOnly`, `Secure`, `SameSite=Strict`
- Sliding session expiry — sessions remain active as long as you are using the app, and expire after one hour of inactivity
- Single-device enforcement — logging in from a new device immediately invalidates all existing sessions
- Rate limiting — five failed login attempts triggers a sixty-second IP lockout
- HTTPS — a self-signed TLS certificate is generated automatically on first run

---

## Requirements

| Dependency | Version | Install |
|---|---|---|
| Homebrew | latest version | [brew.sh](https://brew.sh) |
| Node.js | 16 or later | [nodejs.org](https://nodejs.org) |
| cliclick | any | `brew install cliclick` |
| openssl | any | Included with macOS |

`cliclick` is a small command-line utility that drives the mouse cursor. It is required for all trackpad and click functionality. The openssl binary bundled with macOS (LibreSSL) is used to generate the TLS certificate on first run.

---

## Setup

### 1. Install cliclick

```
brew install cliclick
```

### 2. Install Node dependencies

```
cd "MyMac Remote"
npm install
```

### 3. Start the server

```
npm start
```

On first run, the server generates a self-signed TLS certificate and saves it to `certs/`. This takes about one second. Subsequent starts skip this step.

The terminal output will look similar to the following:

```
              MyMac Remote
  -----------------------------------------

      PIN:  4  8  2  9  1  7
      Sessions expire after 1 hour of inactivity.

      Local:    https://localhost:45212
      Network:  https://192.168.1.42:45212

  First visit: accept the self-signed certificate in your browser.
```

---

## Accessing from a phone

1. Connect the phone to the same Wi-Fi network as the Mac.
2. Open Safari and navigate to the Network URL shown in the terminal (the `https://` address).
3. Accept the self-signed certificate warning (see the section below).
4. Enter the 6-digit PIN displayed in the terminal.
5. Optionally, tap Share > Add to Home Screen to create an app-like shortcut.

### Accepting the self-signed certificate

Because the certificate is self-signed rather than issued by a public certificate authority, browsers will show a security warning on the first visit. This is expected. The connection is still encrypted.

**Safari on iPhone**
Tap Show Details, then tap "visit this website".

**Safari on Mac**
Click Show Details, then click "visit this website".

**Chrome on Mac or Android**
Click Advanced, then click "Proceed to [address] (unsafe)". If Chrome shows no Advanced option, type `thisisunsafe` directly on the warning page (no input box — the text is typed into the page itself).

### Using a .local hostname

If your Mac's hostname is `macbook.local`, you can access the server at `https://macbook.local:45212` from any device on the network without needing to look up the IP address. The generated certificate includes a wildcard `*.local` Subject Alternative Name so this works without an additional certificate warning.

Your Mac's local hostname can be found or changed in System Settings > General > Sharing.

---

## macOS permissions

Two permissions are required. macOS will prompt for each on first use.

| Permission | Used for | Where to grant |
|---|---|---|
| Automation > System Events | Volume control, keyboard input, scrolling | System Settings > Privacy & Security > Automation > Terminal > System Events |
| Accessibility | Mouse movement and clicks | System Settings > Privacy & Security > Accessibility > Terminal |

If you run the server from a terminal other than Terminal.app (for example iTerm2 or VS Code's integrated terminal), grant the permissions to that application instead.

---

## Configuration

All configuration is done via environment variables. There is no configuration file.

| Variable | Default | Description |
|---|---|---|
| `PORT` | `45212` | Port the HTTPS server binds to |
| `PASSWORD` | _(not set)_ | If set, this value replaces the random PIN as the login credential. Useful when you want a persistent passphrase that survives server restarts. |

### Setting a persistent password

```
PASSWORD=mypassphrase npm start
```

When `PASSWORD` is set, the terminal will show `Password: set via PASSWORD env var` instead of printing a PIN.

### Changing the port

```
PORT=3000 npm start
```

---

## Trackpad gestures

| Gesture | Action |
|---|---|
| Single tap | Left click at current cursor position |
| Single finger drag | Move cursor |
| Double-tap and hold (hold for ~180 ms) | Enter drag mode — mouse button is held down |
| Move finger while in drag mode | Move cursor with button held (drag windows, select text, etc.) |
| Lift finger while in drag mode | Release mouse button, exit drag mode |

When drag mode is active, the trackpad surface glows red and a "Dragging" badge appears. Moving to another page or closing the browser while in drag mode automatically releases the mouse button.

---

## API reference

All endpoints except `/login`, `POST /auth/login`, and `POST /auth/logout` require a valid `rvc_session` cookie. Unauthenticated requests to `/api/*` receive a `401` JSON response. Unauthenticated page requests are redirected to `/login`.

### Authentication

| Method | Path | Body | Response |
|---|---|---|---|
| `GET` | `/login` | — | Login page HTML |
| `POST` | `/auth/login` | `{ pin: string }` | `{ ok: true }` and sets session cookie |
| `POST` | `/auth/logout` | — | `{ ok: true }` and clears session cookie |

### Volume

| Method | Path | Body | Response |
|---|---|---|---|
| `GET` | `/api/volume` | — | `{ volume: number, muted: boolean }` |
| `POST` | `/api/volume` | `{ volume: number }` (0–100) | `{ volume, muted }` |
| `POST` | `/api/volume/up` | `{ step?: number }` (default 5, max 20) | `{ volume, muted }` |
| `POST` | `/api/volume/down` | `{ step?: number }` (default 5, max 20) | `{ volume, muted }` |
| `POST` | `/api/mute` | `{ muted: boolean }` | `{ volume, muted }` |

### Real-time events

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/events` | Server-Sent Events stream. Sends `{ volume, muted }` immediately on connect, then pushes updates whenever the system volume changes (polled every one second server-side). |

### Mouse

| Method | Path | Body | Response |
|---|---|---|---|
| `GET` | `/api/screen` | — | `{ width, height }` screen resolution |
| `GET` | `/api/mouse` | — | `{ x, y }` current cursor position |
| `POST` | `/api/mouse/move` | `{ dx: number, dy: number }` | `{ x, y }` updated position |
| `POST` | `/api/mouse/click` | `{ button: "left" \| "right" \| "double" }` | `{ ok: true, button }` |
| `POST` | `/api/mouse/down` | — | `{ ok: true }` — presses and holds the left mouse button |
| `POST` | `/api/mouse/up` | — | `{ ok: true }` — releases the left mouse button |
| `POST` | `/api/mouse/scroll` | `{ direction: "up" \| "down", amount?: number }` (default 3, max 20) | `{ ok, direction, amount }` |

### Keyboard

| Method | Path | Body | Response |
|---|---|---|---|
| `POST` | `/api/keyboard/type` | `{ text: string }` (max 500 characters) | `{ ok: true, length: number }` |
| `POST` | `/api/keyboard/key` | `{ key: "backspace" \| "return" \| "escape" \| "tab" }` | `{ ok: true, key }` |

---

## Troubleshooting

**"Connection refused" or page does not load**
Ensure you are using `https://` not `http://`. The server does not serve plain HTTP.

**Certificate warning does not have an "Advanced" or "visit this website" option**
On iOS, if the option is missing, try navigating directly to the URL (not via a link) and waiting a moment before tapping the warning details.

**Volume control works but mouse or keyboard does not**
Grant the Accessibility permission to your terminal application in System Settings > Privacy & Security > Accessibility.

**"osascript failed" errors in the terminal**
Grant the Automation permission in System Settings > Privacy & Security > Automation and ensure System Events is checked under your terminal application.

**PIN is not accepted**
Check that you are typing the digits shown in the terminal for the current server session. The PIN changes every time the server restarts. If you have set a `PASSWORD` environment variable, use that value instead.

**Drag mode does not release after closing the browser**
Open a new browser tab and navigate to the trackpad page, then tap anywhere to ensure the page loads and the safety release fires. Alternatively, press the Escape key or click the mouse on the Mac to interrupt the drag.
