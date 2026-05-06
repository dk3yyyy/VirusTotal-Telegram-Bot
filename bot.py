#!/usr/bin/env python3
"""
Telegram bot that scans URLs, files and hashes using VirusTotal v3 API.

Features:
 - Scan URLs (/api/v3/urls -> /api/v3/analyses/{id})
 - Upload files (direct for <=32MB or via upload_url for larger)
 - Lookup file reports by hash (md5/sha1/sha256)
 - Exponential backoff on 429 responses
 - Clean, user-friendly formatted result matching the requested layout
 - Powered by Pyrogram for MTProto 2GB+ downloads
 - Inline buttons for Detailed Detections and Malware Signatures
"""

import os
import re
import asyncio
import logging
import aiohttp
import tempfile
import hashlib
import base64
import uuid
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv
from collections import OrderedDict
from pyrogram import Client, filters
from pyrogram.enums import ParseMode
from pyrogram.types import InlineKeyboardMarkup, InlineKeyboardButton

# Load environment
load_dotenv()
TELEGRAM_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
API_ID = os.getenv("TELEGRAM_API_ID")
API_HASH = os.getenv("TELEGRAM_API_HASH")
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

if not TELEGRAM_TOKEN or not VT_API_KEY:
    raise RuntimeError("Set TELEGRAM_BOT_TOKEN and VIRUSTOTAL_API_KEY in environment (or .env)")

if not API_ID or not API_HASH:
    raise RuntimeError("TELEGRAM_API_ID and TELEGRAM_API_HASH are not set in environment (or .env). Pyrogram requires them.")

# Logging to both file and console
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler("bot.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)
logging.getLogger("pyrogram").setLevel(logging.WARNING)


class TTLCache:
    """Simple TTL-based LRU cache with max size limit."""
    def __init__(self, maxsize: int = 128, ttl_seconds: int = 300):
        self._cache: OrderedDict = OrderedDict()
        self._timestamps: dict = {}
        self._maxsize = maxsize
        self._ttl = timedelta(seconds=ttl_seconds)

    def get(self, key: str):
        if key not in self._cache:
            return None
        if datetime.now() - self._timestamps[key] > self._ttl:
            self._evict(key)
            return None
        self._cache.move_to_end(key)
        return self._cache[key]

    def put(self, key: str, value) -> None:
        if key not in self._cache and len(self._cache) >= self._maxsize:
            oldest_key = next(iter(self._cache))
            self._evict(oldest_key)
        self._cache[key] = value
        self._cache.move_to_end(key)
        self._timestamps[key] = datetime.now()

    def _evict(self, key: str) -> None:
        self._cache.pop(key, None)
        self._timestamps.pop(key, None)

    def __contains__(self, key: str) -> bool:
        return self.get(key) is not None

# Caches
lookup_cache = TTLCache(maxsize=256, ttl_seconds=600)  # Hash/URL -> cache_id
report_cache = TTLCache(maxsize=512, ttl_seconds=3600) # cache_id -> file_obj

LANGS = {
    'en': {
        'error': "An error occurred. Please try again later.",
    }
}

VT_BASE = "https://www.virustotal.com/api/v3"
HEADERS = {"x-apikey": VT_API_KEY}

def epoch_to_utc(ts):
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return "N/A"

async def vt_request(session: aiohttp.ClientSession, method: str, path: str, **kwargs):
    """Wrapper for VirusTotal HTTP requests with basic retry/backoff for 429."""
    url = f"{VT_BASE}{path}"
    backoff = 1.0
    for attempt in range(8):
        async with session.request(method, url, headers=HEADERS, **kwargs) as resp:
            text = await resp.text()
            if resp.status in (200, 201, 202):
                try:
                    return await resp.json()
                except Exception:
                    return {"status": resp.status, "raw_text": text}
            elif resp.status == 429:
                logger.warning("VirusTotal rate-limited, sleeping %s s (attempt %d)", backoff, attempt + 1)
                await asyncio.sleep(backoff)
                backoff *= 2
                continue
            elif resp.status == 409:
                logger.warning("VirusTotal API 409 ConflictError: %s", text)
                raise RuntimeError(f"ConflictError: {text}")
            else:
                logger.error("VirusTotal API error %s: %s", resp.status, text)
                raise RuntimeError(f"VT API {resp.status}: {text}")
    raise RuntimeError("Exceeded retries to VirusTotal API due to rate limiting or server error")

def format_detection_stats(stats: dict):
    if not stats:
        return "N/A", "N/A"
    malicious = stats.get("malicious", 0)
    total = sum(stats.get(k, 0) for k in stats.keys())
    return f"{malicious} / {total}", (malicious, total)

def safe_get(dct, *keys, default="N/A"):
    for k in keys:
        if isinstance(dct, dict) and k in dct:
            dct = dct[k]
        else:
            return default
    return dct

def extract_hash_from_analysis_id(analysis_id: str) -> str:
    if not analysis_id:
        return ""
    if analysis_id.startswith(("u-", "analysis-")):
        return analysis_id
    try:
        padded = analysis_id + '=' * (-len(analysis_id) % 4)
        decoded = base64.b64decode(padded).decode('utf-8')
        if ':' in decoded:
            return decoded.split(':')[0]
    except Exception:
        pass
    return analysis_id

def build_report_from_file_object(file_obj, cache_id=None, is_url=False):
    attributes = file_obj.get("attributes", {})
    last_stats = attributes.get("last_analysis_stats") or {}
    detections_text, _ = format_detection_stats(last_stats)

    file_name = attributes.get("meaningful_name") or attributes.get("names", [""])[0] if attributes.get("names") else "N/A"
    file_type = attributes.get("type_description") or attributes.get("type") or "N/A"
    
    file_size_str = "N/A"
    if not is_url:
        file_size = attributes.get("size") or attributes.get("size_in_bytes")
        if isinstance(file_size, int):
            if file_size >= 1024*1024:
                file_size_str = f"{round(file_size/(1024*1024), 2)} MB"
            elif file_size >= 1024:
                file_size_str = f"{round(file_size/1024, 2)} KB"
            else:
                file_size_str = f"{file_size} B"
        else:
            file_size_str = str(file_size)

    created = attributes.get("first_submission_date") or attributes.get("created_at") or attributes.get("submission_date")
    last_analysis = attributes.get("last_analysis_date") or attributes.get("last_submission_date")
    first_analysis_text = epoch_to_utc(created) if created else "N/A"
    last_analysis_text = epoch_to_utc(last_analysis) if last_analysis else "N/A"

    sha256 = attributes.get("sha256") or file_obj.get("id")
    
    if is_url:
        target_url = attributes.get("url") or "N/A"
        vt_link = file_obj.get("links", {}).get("self") or f"https://www.virustotal.com/gui/url/{sha256}/detection"
        message = (
            f"🧬 Detections: {detections_text}\n\n"
            f"🔖 URL: {target_url}\n\n"
            f"🔬 First analysis\n• {first_analysis_text}\n\n"
            f"🔭 Last analysis\n• {last_analysis_text}\n\n"
            f"⚜️ Link to VirusTotal\n{vt_link}"
        )
    else:
        magic = attributes.get("magic", None) or attributes.get("pe_info", {}).get("machine_type") or attributes.get("meaningful_name") or attributes.get("file_type_description") or attributes.get("type_description") or "N/A"
        vt_link = f"https://www.virustotal.com/gui/file/{sha256}/detection" if sha256 else "N/A"
        message = (
            f"🧬 Detections: {detections_text}\n\n"
            f"🔖 File name: {file_name}\n"
            f"🔒 File type: {file_type}\n"
            f"📁 File size: {file_size_str}\n\n"
            f"🔬 First analysis\n• {first_analysis_text}\n\n"
            f"🔭 Last analysis\n• {last_analysis_text}\n\n"
            f"🎉 Magic\n• {magic}\n\n"
            f"⚜️ Link to VirusTotal\n{vt_link}"
        )

    if not cache_id:
        cache_id = uuid.uuid4().hex[:16]
        
    # Always update the object in cache to reset TTL
    report_cache.put(cache_id, {"obj": file_obj, "is_url": is_url})

    reply_markup = InlineKeyboardMarkup([
        [
            InlineKeyboardButton("🧪 Detections", callback_data=f"det_{cache_id}"),
            InlineKeyboardButton("💉 Signatures", callback_data=f"sig_{cache_id}")
        ],
        [
            InlineKeyboardButton("❌ Close", callback_data="close")
        ]
    ])
    
    return message, reply_markup, cache_id

def format_detailed_detections(file_obj, show_signatures=False):
    attributes = file_obj.get("attributes", {})
    results = attributes.get("last_analysis_results", {})
    
    lines = []
    
    # Sort engines: malicious first, then undetected
    sorted_engines = sorted(results.values(), key=lambda x: (x.get("category") != "malicious", x.get("engine_name", "")))
    
    for res in sorted_engines:
        cat = res.get("category", "")
        name = res.get("engine_name", "Unknown")
        result_text = res.get("result", "")
        
        if show_signatures:
            if cat in ("malicious", "suspicious"):
                lines.append(f"⛔ {name}")
                if result_text:
                    lines.append(f" ╰ `{result_text}`")
        else:
            if cat in ("malicious", "suspicious"):
                lines.append(f"⛔ {name}")
            elif cat == "undetected":
                lines.append(f"✅ {name}")
            elif cat == "type-unsupported":
                lines.append(f"⚪ {name}")
            else:
                lines.append(f"❓ {name}")

    if not lines:
        return "No engine data available."
        
    text = "\n".join(lines)
    # Telegram message limit is 4096. Truncate if needed.
    if len(text) > 4000:
        text = text[:3900] + "\n\n... (truncated due to Telegram limits)"
    return text

# Setup Pyrogram app
app = Client(
    "vt_bot",
    api_id=int(API_ID) if API_ID else None,
    api_hash=API_HASH,
    bot_token=TELEGRAM_TOKEN
)

@app.on_message(filters.command(["start", "help"]))
async def start_cmd(client, message):
    await message.reply_text(
        "Hi — send me a file (up to 2GB!), a hash (MD5/SHA1/SHA256) or a URL and I'll scan it using VirusTotal and return a compact report."
    )

def extract_hash_if_message_text_is_hash(text: str) -> str | None:
    t = text.strip().lower()
    if all(c in "0123456789abcdef" for c in t) and len(t) in (32, 40, 64):
        return t
    return None

@app.on_message(filters.text & ~filters.command(["start", "help"]))
async def handle_text(client, message):
    text = message.text.strip()
    if len(text) > 2048:
        await message.reply_text("❌ Message too long.")
        return
        
    if text.startswith("http://") or text.startswith("https://"):
        await message.reply_text("🌐 Scanning URL with VirusTotal...")
        
        cached_id = lookup_cache.get(text)
        if cached_id and cached_id in report_cache:
            cache_data = report_cache.get(cached_id)
            msg, markup, _ = build_report_from_file_object(cache_data["obj"], cache_id=cached_id, is_url=cache_data["is_url"])
            await message.reply_text(msg, parse_mode=ParseMode.MARKDOWN, disable_web_page_preview=True, reply_markup=markup)
            return
            
        await scan_url_flow(message, text)
        return
        
    maybe_hash = extract_hash_if_message_text_is_hash(text)
    if maybe_hash:
        await message.reply_text("🔍 Looking up hash on VirusTotal...")
        cached_id = lookup_cache.get(maybe_hash)
        if cached_id and cached_id in report_cache:
            cache_data = report_cache.get(cached_id)
            msg, markup, _ = build_report_from_file_object(cache_data["obj"], cache_id=cached_id, is_url=cache_data["is_url"])
            await message.reply_text(msg, parse_mode=ParseMode.MARKDOWN, disable_web_page_preview=True, reply_markup=markup)
            return
            
        await lookup_hash_flow(message, maybe_hash)
        return
        
    await message.reply_text("🤖 I didn't detect a URL or a valid hash. Send a URL starting with http(s) or a MD5/SHA1/SHA256 hash, or attach a file.")

@app.on_message(filters.document | filters.video | filters.audio | filters.photo)
async def handle_document(client, message):
    media = message.document or message.video or message.audio or message.photo
    if not media:
        return
        
    file_name = getattr(media, "file_name", "file")
    file_size = getattr(media, "file_size", 0)
    
    safe_display_name = re.sub(r'[^a-zA-Z0-9_.-]', '_', file_name)
    status_msg = await message.reply_text(f"📦 File received: **{safe_display_name}** ({file_size} bytes)\nDownloading via MTProto...", parse_mode=ParseMode.MARKDOWN)
    
    with tempfile.NamedTemporaryFile(delete=False, prefix="vt_", suffix=".tmp") as tmp_file:
        tmp_path = tmp_file.name
        
    try:
        # Pyrogram native fast download
        await message.download(file_name=tmp_path)
    except Exception as e:
        await status_msg.edit_text(f"Error downloading file: {e}")
        return
        
    try:
        # Compute SHA256 locally to check if VT already has it
        sha256_hash = hashlib.sha256()
        with open(tmp_path, "rb") as f:
            for byte_block in iter(lambda: f.read(65536), b""):
                sha256_hash.update(byte_block)
        file_hash = sha256_hash.hexdigest()

        # Check if file already exists in VT
        async with aiohttp.ClientSession() as session:
            try:
                report = await vt_request(session, "GET", f"/files/{file_hash}")
                if report and "data" in report:
                    await status_msg.edit_text("✅ Found existing analysis for this file in VirusTotal!")
                    msg, markup, cache_id = build_report_from_file_object(report["data"])
                    lookup_cache.put(file_hash, cache_id)
                    await message.reply_text(msg, parse_mode=ParseMode.MARKDOWN, disable_web_page_preview=True, reply_markup=markup)
                    return
            except Exception as e:
                pass

        await status_msg.edit_text("🚀 Uploading to VirusTotal cloud... Please wait.")
        await upload_file_flow(message, tmp_path, safe_display_name, file_size)
    except Exception as e:
        if "AlreadySubmittedError" in str(e):
            await message.reply_text(
                "⏳ File is currently being processed by VirusTotal from a recent submission.\n"
                "Please wait a few minutes and try again, or check manually at:\n"
                f"https://www.virustotal.com/gui/file/{file_hash}/detection",
                parse_mode=ParseMode.MARKDOWN
            )
        else:
            await message.reply_text(f"Error uploading file to VirusTotal: {e}")
            logger.exception("Upload error")
    finally:
        try:
            os.remove(tmp_path)
        except Exception as e:
            logger.warning(f"Failed to remove temp file {tmp_path}: {e}")

async def scan_url_flow(message, url: str):
    async with aiohttp.ClientSession() as session:
        data = {"url": url}
        resp = await vt_request(session, "POST", "/urls", data=data)
        
        analysis_id = None
        if isinstance(resp, dict):
            analysis_id = safe_get(resp, "data", "id", default=None)
            if not analysis_id:
                analysis_id = safe_get(resp, "meta", "analysis_id", default=None)

        if not analysis_id:
            await message.reply_text("Couldn't create URL analysis on VirusTotal (unexpected response).")
            logger.error("URL scan response: %s", resp)
            return

        status_msg = await message.reply_text("Analysis submitted — waiting for results (may take a few seconds)...")
        delays = [2, 2, 3, 3, 5, 5, 10, 10, 15, 15, 20, 20]
        for delay in delays:
            await asyncio.sleep(delay)
            analysis = await vt_request(session, "GET", f"/analyses/{analysis_id}")
            status = safe_get(analysis, "data", "attributes", "status", default="queued")
            if status in ("completed", "succeeded", "completed_with_errors"):
                item = None
                try:
                    item_resp = await vt_request(session, "GET", f"/analyses/{analysis_id}/item")
                    item = item_resp.get("data")
                except Exception:
                    item = None
                if item:
                    msg, markup, cache_id = build_report_from_file_object(item, is_url=True)
                    lookup_cache.put(url, cache_id)
                    await message.reply_text(msg, parse_mode=ParseMode.MARKDOWN, disable_web_page_preview=True, reply_markup=markup)
                    return
                else:
                    stats = safe_get(analysis, "data", "attributes", "stats", default={})
                    det_text, _ = format_detection_stats(stats)
                    await message.reply_text(f"🧬 Detections: {det_text}\n\n⚜️ Link to VirusTotal (analysis): https://www.virustotal.com/gui/url/{analysis_id}/detection", disable_web_page_preview=True)
                    return
        await message.reply_text(
            "⏳ URL analysis is taking longer than expected.\n"
            f"Analysis ID: `{analysis_id}`\n"
            "Check back at:\n"
            f"https://www.virustotal.com/gui/url/{analysis_id}/detection",
            parse_mode=ParseMode.MARKDOWN,
            disable_web_page_preview=True
        )

async def upload_file_flow(message, path: str, filename: str, filesize: int):
    async with aiohttp.ClientSession() as session:
        if filesize and filesize > 32 * 1024 * 1024:
            up_resp = await vt_request(session, "GET", "/files/upload_url")
            upload_url = safe_get(up_resp, "data", "attributes", "upload_url", default=None) or safe_get(up_resp, "upload_url", default=None)
            if not upload_url:
                await message.reply_text("Could not obtain upload URL from VirusTotal.")
                logger.error("Unexpected upload_url response: %s", up_resp)
                return
            with open(path, "rb") as fh:
                upload_data = aiohttp.FormData()
                upload_data.add_field("file", fh, filename=filename, content_type="application/octet-stream")
                async with session.post(upload_url, data=upload_data, headers=HEADERS) as upload_resp:
                    if upload_resp.status not in (200, 201, 202):
                        text = await upload_resp.text()
                        await message.reply_text(f"Upload failed: {upload_resp.status}")
                        logger.error("Large upload failed: %s", text)
                        return
                    upload_json = await upload_resp.json()
                    analysis_id = safe_get(upload_json, "data", "id", default=None)
                    resp = upload_json
        else:
            with open(path, "rb") as fh:
                data = aiohttp.FormData()
                data.add_field("file", fh, filename=filename, content_type="application/octet-stream")
                resp = await vt_request(session, "POST", "/files", data=data)
                analysis_id = safe_get(resp, "data", "id", default=None)

        if not analysis_id:
            await message.reply_text("Failed to create an analysis for the file on VirusTotal.")
            logger.error("No analysis_id after upload: upload response snippet: %s", resp)
            return

        resp_type = safe_get(resp, "data", "type", default="")
        if resp_type in ("file", "file_info"):
            msg, markup, _ = build_report_from_file_object(resp.get("data", {}))
            await message.reply_text(msg, parse_mode=ParseMode.MARKDOWN, disable_web_page_preview=True, reply_markup=markup)
            return

        resp_attributes = safe_get(resp, "data", "attributes", default={})
        resp_status = resp_attributes.get("status") if isinstance(resp_attributes, dict) else None
        if resp_status in ("completed", "succeeded"):
            try:
                item_resp = await vt_request(session, "GET", f"/analyses/{analysis_id}/item")
                if item_resp and "data" in item_resp:
                    msg, markup, _ = build_report_from_file_object(item_resp["data"])
                    await message.reply_text(msg, parse_mode=ParseMode.MARKDOWN, disable_web_page_preview=True, reply_markup=markup)
                    return
            except Exception:
                pass
            stats = resp_attributes.get("stats", {})
            if stats:
                det_text, _ = format_detection_stats(stats)
                gui_hash = extract_hash_from_analysis_id(analysis_id)
                await message.reply_text(f"🧬 Detections: {det_text}\n\n⚜️ https://www.virustotal.com/gui/file/{gui_hash}/detection", disable_web_page_preview=True)
                return

        status_msg = await message.reply_text("🔎 File uploaded! Running advanced threat analysis...", parse_mode=ParseMode.MARKDOWN)
        delays = [2, 2, 3, 3, 5, 5, 10, 10, 15, 15, 20, 20, 30, 30, 30, 30]
        for delay in delays:
            await asyncio.sleep(delay)
            analysis = await vt_request(session, "GET", f"/analyses/{analysis_id}")
            status = safe_get(analysis, "data", "attributes", "status", default=None)
            if status in ("completed", "succeeded", "completed_with_errors"):
                try:
                    item_resp = await vt_request(session, "GET", f"/analyses/{analysis_id}/item")
                    if item_resp and "data" in item_resp:
                        file_obj = item_resp["data"]
                        msg, markup, cache_id = build_report_from_file_object(file_obj)
                        
                        sha256 = safe_get(analysis, "meta", "file_info", "sha256", default=None) or safe_get(analysis, "data", "relationships", "file", "data", "id", default=None)
                        if not sha256:
                            sha256 = safe_get(analysis, "data", "relationships", "file", "data", "id", default=None)
                        if sha256:
                            lookup_cache.put(sha256, cache_id)
                            
                        await message.reply_text(msg, parse_mode=ParseMode.MARKDOWN, disable_web_page_preview=True, reply_markup=markup)
                        return
                except Exception:
                    pass

                sha256 = safe_get(analysis, "meta", "file_info", "sha256", default=None) or safe_get(analysis, "data", "relationships", "file", "data", "id", default=None)
                if not sha256:
                    sha256 = safe_get(analysis, "data", "relationships", "file", "data", "id", default=None)
                if sha256:
                    file_report = await vt_request(session, "GET", f"/files/{sha256}")
                    if file_report and "data" in file_report:
                        msg, markup, cache_id = build_report_from_file_object(file_report["data"])
                        lookup_cache.put(sha256, cache_id)
                        await message.reply_text(msg, parse_mode=ParseMode.MARKDOWN, disable_web_page_preview=True, reply_markup=markup)
                        return

                await message.reply_text(f"Analysis finished but final report could not be parsed. Analysis id: {analysis_id}")
                return

        gui_hash = extract_hash_from_analysis_id(analysis_id)
        await message.reply_text(
            "⏳ Analysis is taking longer than expected. VirusTotal might still be processing your file.\n"
            f"Analysis ID: `{analysis_id}`\n"
            "You can check back manually at:\n"
            f"https://www.virustotal.com/gui/file/{gui_hash}/detection",
            parse_mode=ParseMode.MARKDOWN,
            disable_web_page_preview=True
        )

async def lookup_hash_flow(message, the_hash: str):
    async with aiohttp.ClientSession() as session:
        try:
            file_report = await vt_request(session, "GET", f"/files/{the_hash}")
        except Exception as e:
            await message.reply_text(f"Error querying VirusTotal: {e}")
            return
        if not file_report or "data" not in file_report:
            await message.reply_text("No report found for that hash on VirusTotal.")
            return
            
        msg, markup, cache_id = build_report_from_file_object(file_report["data"])
        lookup_cache.put(the_hash, cache_id)
        await message.reply_text(msg, parse_mode=ParseMode.MARKDOWN, disable_web_page_preview=True, reply_markup=markup)


@app.on_callback_query()
async def handle_callback(client, query):
    data = query.data
    if data == "close":
        await query.message.delete()
        return
        
    try:
        action, cache_id = data.split("_", 1)
    except ValueError:
        await query.answer("Invalid button data.", show_alert=True)
        return

    cache_data = report_cache.get(cache_id)
    if not cache_data:
        await query.answer("Report expired from bot memory. Please rescan the file/URL.", show_alert=True)
        return
        
    file_obj = cache_data["obj"]
    is_url = cache_data["is_url"]
    
    if action == "sum":
        msg, markup, _ = build_report_from_file_object(file_obj, cache_id=cache_id, is_url=is_url)
        await query.message.edit_text(msg, parse_mode=ParseMode.MARKDOWN, disable_web_page_preview=True, reply_markup=markup)
        
    elif action == "det":
        text = format_detailed_detections(file_obj, show_signatures=False)
        full_text = "🧪 **Detailed Detections:**\n\n" + text
        markup = InlineKeyboardMarkup([
            [
                InlineKeyboardButton("🔙 Back", callback_data=f"sum_{cache_id}"),
                InlineKeyboardButton("💉 Signatures", callback_data=f"sig_{cache_id}")
            ],
            [
                InlineKeyboardButton("❌ Close", callback_data="close")
            ]
        ])
        await query.message.edit_text(full_text, parse_mode=ParseMode.MARKDOWN, disable_web_page_preview=True, reply_markup=markup)
        
    elif action == "sig":
        text = format_detailed_detections(file_obj, show_signatures=True)
        full_text = "💉 **Malware Signatures:**\n\n" + text
        markup = InlineKeyboardMarkup([
            [
                InlineKeyboardButton("🔙 Back", callback_data=f"sum_{cache_id}"),
                InlineKeyboardButton("🧪 Detections", callback_data=f"det_{cache_id}")
            ],
            [
                InlineKeyboardButton("❌ Close", callback_data="close")
            ]
        ])
        await query.message.edit_text(full_text, parse_mode=ParseMode.MARKDOWN, disable_web_page_preview=True, reply_markup=markup)

    try:
        await query.answer()
    except Exception:
        pass


if __name__ == "__main__":
    logger.info("Starting Pyrogram bot...")
    app.run()
