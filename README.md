# VirusTotal Telegram Bot

A high-performance Telegram bot powered by **Pyrogram** (MTProto) and the **VirusTotal v3 API**. This bot is designed to handle massive files, seamlessly querying VirusTotal to provide you with rich, interactive threat analysis reports directly in Telegram.

## Features

- **Massive File Support (2GB)**: Bypasses the standard 20MB bot limit. Because it uses Pyrogram and MTProto, you can upload files up to **2GB** (VirusTotal supports up to 650MB natively).
- **Interactive Analysis**: Reports feature inline buttons (`🧪 Detections`, `💉 Signatures`) that instantly pull up detailed lists of what each antivirus engine found without hitting rate limits.
- **URL & Hash Scanning**: Send any `http(s)://` URL or file hash (MD5/SHA1/SHA256) for instant reports.
- **Smart Uploads**: Automatically handles VirusTotal's `upload_url` flow for files over 32MB.
- **Local Hashing**: Computes SHA-256 hashes locally to check if a file has already been analyzed by VirusTotal, preventing unnecessary bandwidth usage and `409 ConflictErrors`.

## Prerequisites

- Python 3.7+
- **Telegram Bot Token**: Get one from [@BotFather](https://t.me/BotFather).
- **Telegram API ID & Hash**: Required for Pyrogram to use MTProto. Get them for free at [my.telegram.org](https://my.telegram.org).
- **VirusTotal API Key**: Get a free API key from the [VirusTotal website](https://www.virustotal.com/).

## Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/yourusername/virusscan-bot.git
    cd virusscan-bot
    ```

2.  **Set up a Python virtual environment:**
    ```bash
    python3 -m venv .venv
    source .venv/bin/activate
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## Configuration

Create a `.env` file in the root directory:
```bash
touch .env
```

Add your credentials to the `.env` file:
```env
TELEGRAM_BOT_TOKEN="YOUR_BOT_TOKEN_HERE"
VIRUSTOTAL_API_KEY="YOUR_VIRUSTOTAL_API_KEY_HERE"
TELEGRAM_API_ID="YOUR_API_ID"
TELEGRAM_API_HASH="YOUR_API_HASH"
```

> **Warning:** Never share your `TELEGRAM_API_ID` or `.session` files. The included `.gitignore` will ensure your `vt_bot.session` file is kept out of version control.

## Usage

1.  **Run the bot:**
    ```bash
    python bot.py
    ```

2.  **Interact on Telegram:**
    - Find your bot and send `/start`.
    - **Scan File**: Send any document, photo, video, or audio file.
    - **Scan URL**: Paste any URL.
    - **Lookup Hash**: Send an MD5, SHA1, or SHA256 string.
    - Use the inline buttons on the resulting report to explore detailed threat signatures.
