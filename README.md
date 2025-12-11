# Secure Authentication System Project

This is a complete "Defense in Depth" secure authentication system. It features a premium UI, a Security Console for live demonstrations, and a built-in presentation deck.

## Project Overview

### 1. The Application (`app.py`)
A Flask-based application implementing:
- **Bot Prevention (The Moat)**: Hidden Honeypot field in registration.
- **Input Validation (The Gate)**: SQLAlchemy ORM and WTForms validation.
- **Password Security (The Vault)**: Bcrypt hashing.
- **Brute Force Protection (The Guard)**: Flask-Limiter for rate limiting.

### 2. Premium UI
- **Design**: Glassmorphism aesthetic with animated backgrounds.
- **Technology**: Vanilla CSS (`static/style.css`).
- **Templates**: `base`, `home`, `register`, `login`, `dashboard`, `live_demo`, `429`.

### 3. Key Features
- **Security Console (`/live-demo`)**: A "Hacker Terminal" UI to run live attacks (Bot, Brute Force) and see them get blocked in real-time.
- **Presentation Deck (`/presentation`)**: Built-in slides explaining the architecture.
- **Public Sharing**: `share.bat` script to create a public URL for the running app.

## File Structure
```text
/project login
  ├── app.py                # Main Application
  ├── security_proof.py     # Terminal-based verification script
  ├── DEMO_SCRIPT.md        # Script for the presenter
  ├── release.bat           # (Optional) Sharing script
  ├── requirements.txt      # Dependencies
  ├── static/               # CSS and Assets
  └── templates/            # HTML Templates
```

## How to Run

### Prerequisite
Install dependencies:
```bash
pip install -r requirements.txt
```

### Start the App
1.  **Run the application**:
    ```bash
    python app.py
    ```
2.  **Open Browser**: Go to `http://127.0.0.1:5000`.

### Presentation Flow
1.  **Start Presentation**: Navigate to "Presentation" in the navbar.
2.  **Live Demo**:
    - Go to **Security Console** (navbar).
    - Use the buttons to simulate attacks.
    - Show the **Security Alert** page (Brute Force block).
    - Use **Inspect Vault** to show hashed passwords.
3.  **Terminal Proof** (Optional):
    - Run `python security_proof.py` in a terminal for a "Matrix-style" verification.

## Public Sharing
To allow others to access your local server:
1.  Run `share.bat`.
2.  Share the `https://....pinggy.io` link provided.
