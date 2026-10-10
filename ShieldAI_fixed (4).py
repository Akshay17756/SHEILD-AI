import re
import os
import json
import base64
import threading
import subprocess
import sys
import urllib.request
import urllib.error
import sqlite3
import hashlib
import secrets
import math

import tkinter as tk

from tkinter import messagebox, ttk

from datetime import datetime

from urllib.parse import urlparse

APP_NAME = "ShieldAI"

DB_FILE = "shieldai_history.db"

DARK = {

    "bg": "#0B1020", "panel": "#111A2E", "panel2": "#16213A",

    "card": "#121D33", "text": "#EAF2FF", "muted": "#93A4C3",

    "accent": "#48D7FF", "accent2": "#8B7CFF", "border": "#263653",

    "input": "#0D1629", "good": "#37D99A", "warn": "#FFC857",

    "bad": "#FF617C", "button_text": "#06111E"

}

LIGHT = {

    "bg": "#F3F7FC", "panel": "#FFFFFF", "panel2": "#EAF0FA",

    "card": "#FFFFFF", "text": "#18243B", "muted": "#60708C",

    "accent": "#087EA4", "accent2": "#6554C0", "border": "#D5DFEF",

    "input": "#F8FAFE", "good": "#07885A", "warn": "#A96800",

    "bad": "#C52C4A", "button_text": "#FFFFFF"

}

# Explainable, heuristic-only indicators. This is not a machine-learning model

# and cannot guarantee that a message is safe or fraudulent.

INDICATORS = [

    (r"\b(otp|one[- ]time password|verification code|security code)\b", 20,

     "Mentions an OTP or verification code"),

    (r"\b(password|pin|passcode|cvv|card number|bank details)\b", 24,

     "Requests sensitive credentials or payment details"),

    (r"\b(urgent|immediately|act now|within \d+ minutes|account.*(block|suspend|freeze))\b", 16,

     "Uses urgency or account-threat pressure"),

    (r"\b(prize|won|winner|lottery|reward|free gift|cashback)\b", 16,

     "Promises a prize, reward, or unexpected benefit"),

    (r"\b(click here|tap here|verify now|claim now|update kyc|reactivate)\b", 14,

     "Pushes you to click, claim, or verify"),

    (r"\b(send money|transfer|pay now|upi|refund fee|processing fee)\b", 18,

     "Mentions a payment or money transfer"),

    (r"\b(police|arrest|legal action|digital arrest|case registered)\b", 22,

     "Uses intimidation or legal-threat language"),

    (r"\b(job offer|work from home|daily income|earn \d+|investment guaranteed)\b", 12,

     "May involve a job or guaranteed-income lure"),

    (r"\b(share|tell me|send).{0,18}\b(otp|pin|password)\b", 24,

     "Explicitly asks for a secret code or password"),

    (r"(.)\1{5,}", 4, "Contains an unusual repeated-character pattern"),

]

URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy", "shorturl.at"}

SUSPICIOUS_TLDS = {".zip", ".mov", ".click", ".top", ".xyz", ".work", ".support"}

BRAND_WORDS = ("bank", "paypal", "google", "microsoft", "amazon", "apple", "upi", "sbi", "hdfc", "icici")

def clamp(value, low=0, high=100):

    return max(low, min(high, int(value)))

def scan_text(text):

    raw = text.strip()

    if not raw:

        return {"score": 0, "level": "NO INPUT", "reasons": ["Enter a message to scan."],

                "advice": "Paste a message, then select Scan message.", "category": "Empty input"}

    score, reasons = 0, []

    lower = raw.lower()

    for pattern, points, explanation in INDICATORS:

        if re.search(pattern, lower, re.I):

            score += points

            reasons.append(explanation)

    urls = re.findall(r"(?:https?://|www\.)[^\s<>\]\[()]+", raw, re.I)

    if urls:

        score += min(18, 7 * len(urls))

        reasons.append(f"Contains {len(urls)} web link(s); inspect each link before opening")

    if re.search(r"\b(official|support|customer care|kyc)\b", lower) and urls:

        score += 8

        reasons.append("Combines official-sounding language with a link")

    score = clamp(score)

    level = "HIGH RISK" if score >= 70 else "SUSPICIOUS" if score >= 35 else "LOW SIGNAL"

    category = "Credential theft" if re.search(r"\b(otp|password|pin|cvv|kyc)\b", lower) else (

        "Payment / reward lure" if re.search(r"\b(prize|reward|pay|transfer|upi|refund)\b", lower) else

        "Social engineering" if reasons else "No strong indicators found")

    if not reasons:

        reasons.append("No configured high-risk patterns were detected")

    advice = ("Do not click links, reply, pay, or share codes. Verify through the organisation's official app or a number you find independently."

              if score >= 35 else

              "No strong configured warning signs were found. Still verify the sender and destination independently; a low score is not proof of safety.")

    return {"score": score, "level": level, "reasons": reasons, "advice": advice, "category": category}

def scan_url(value):

    raw = value.strip()

    if not raw:

        return {"score": 0, "level": "NO INPUT", "reasons": ["Enter a URL to scan."],

                "advice": "Paste a complete URL or domain.", "category": "Empty input"}

    candidate = raw if "://" in raw else "https://" + raw

    try:

        parsed = urlparse(candidate)

        host = (parsed.hostname or "").lower().rstrip(".")

    except Exception:

        host = ""

        parsed = None

    score, reasons = 0, []

    if not host or "." not in host:

        score += 30

        reasons.append("URL could not be parsed as a normal domain")

    if parsed and parsed.scheme.lower() != "https":

        score += 12

        reasons.append("Does not use HTTPS")

    if host and (host in URL_SHORTENERS or any(host.endswith("." + s) for s in URL_SHORTENERS)):

        score += 22

        reasons.append("Uses a URL-shortening service that hides the final destination")

    if host and (host.startswith("xn--") or ".xn--" in host):

        score += 22

        reasons.append("Contains an internationalised domain label that may disguise characters")

    if re.search(r"@|%40", raw):

        score += 25

        reasons.append("Contains @-style URL syntax that can obscure the real destination")

    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host):

        score += 22

        reasons.append("Uses an IP address instead of a conventional domain name")

    if host and any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):

        score += 12

        reasons.append("Uses a less-common top-level domain often seen in low-trust campaigns")

    if host and host.count("-") >= 3:

        score += 10

        reasons.append("Domain contains several hyphens")

    if host and len(host) > 35:

        score += 8

        reasons.append("Domain name is unusually long")

    if parsed and parsed.username:

        score += 20

        reasons.append("URL includes user-info before the host")

    if host and any(brand in host for brand in BRAND_WORDS):

        if not any(host == b or host.endswith("." + b) for b in BRAND_WORDS):

            score += 12

            reasons.append("Brand-like wording appears in a domain that may not belong to that brand")

    score = clamp(score)

    level = "HIGH RISK" if score >= 60 else "SUSPICIOUS" if score >= 30 else "LOW SIGNAL"

    if not reasons:

        reasons.append("No configured URL warning patterns were detected")

    advice = ("Avoid opening this URL. Visit the service by typing its official address yourself and do not enter passwords or payment details."

              if score >= 30 else

              "No strong configured URL warning signs were found. This is not a reputation or malware check; verify the domain before entering information.")

    return {"score": score, "level": level, "reasons": reasons, "advice": advice,

            "category": "URL / domain analysis", "host": host or "Unrecognised host"}

def lookup_virustotal(url):
    """Look up an existing VirusTotal URL report. Requires SHIELDAI_VT_API_KEY.

    This sends the submitted URL to VirusTotal. It does not upload or submit a
    new scan; if VirusTotal has no report, it returns a clear unavailable status.
    """
    api_key = os.environ.get("SHIELDAI_VT_API_KEY", "").strip()
    if not api_key:
        return {"available": False, "message": "Live reputation lookup is off. Set SHIELDAI_VT_API_KEY to enable VirusTotal."}
    normalized = url.strip()
    if not re.match(r"^https?://", normalized, re.I):
        normalized = "https://" + normalized
    url_id = base64.urlsafe_b64encode(normalized.encode("utf-8")).decode("ascii").rstrip("=")
    request = urllib.request.Request(
        "https://www.virustotal.com/api/v3/urls/" + url_id,
        headers={"x-apikey": api_key, "Accept": "application/json"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            payload = json.loads(response.read().decode("utf-8"))
        attrs = payload.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        harmless = int(stats.get("harmless", 0))
        undetected = int(stats.get("undetected", 0))
        return {
            "available": True,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "message": f"VirusTotal: {malicious} malicious, {suspicious} suspicious, {harmless} harmless, {undetected} undetected.",
        }
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {"available": False, "message": "VirusTotal has no existing report for this URL."}
        if exc.code == 429:
            return {"available": False, "message": "VirusTotal rate limit reached. Try again later."}
        return {"available": False, "message": f"VirusTotal lookup failed (HTTP {exc.code})."}
    except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
        return {"available": False, "message": "VirusTotal lookup could not connect or parse a response."}


class ShieldAI:

    def __init__(self, root):

        self.root = root

        self.root.title("ShieldAI | Digital Bodyguard")

        self.root.geometry("1180x780")

        self.root.minsize(920, 650)

        self.theme_name = "dark"

        self.colors = DARK.copy()

        self.protection_on = True

        self.student_mode = True

        self.current_page = "Dashboard"

        self.last_result = None
        self._scan_generation = 0
        self.assistant_history = []
        self._voice_process = None
        self._voice_busy = False

        self.message_draft = ""

        self.url_draft = ""

        self.email_draft = ""

        self.db = sqlite3.connect(DB_FILE)

        self.db.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            password_salt TEXT NOT NULL,
            created_at TEXT NOT NULL
        )""")
        self.db.execute("""CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL, scan_type TEXT NOT NULL,
            subject TEXT NOT NULL, score INTEGER NOT NULL,
            level TEXT NOT NULL, category TEXT NOT NULL, reasons TEXT NOT NULL
        )""")
        # Add account ownership to existing databases without deleting old records.
        scan_columns = {row[1] for row in self.db.execute("PRAGMA table_info(scans)").fetchall()}
        if "user_id" not in scan_columns:
            self.db.execute("ALTER TABLE scans ADD COLUMN user_id INTEGER")
        self.db.commit()
        self.current_user_id = None
        self.current_username = None
        self.auth_mode = "login"

        self.style = ttk.Style()

        try:

            self.style.theme_use("clam")

        except tk.TclError:

            pass

        self.root.protocol("WM_DELETE_WINDOW", self.close)
        self.show_auth_screen()
        self.root.after(250, self.pulse)

    @staticmethod
    def _password_digest(password, salt):
        return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 240000).hex()

    def show_auth_screen(self):
        for child in self.root.winfo_children():
            child.destroy()
        self.root.configure(bg=self.c("bg"))
        shell = tk.Frame(self.root, bg=self.c("bg"))
        shell.pack(fill="both", expand=True)

        # Animated, anime-inspired cyber guardian artwork drawn with Tkinter only.
        visual = tk.Frame(shell, bg=self.c("bg"))
        visual.pack(side="left", fill="both", expand=True, padx=(28, 10), pady=24)
        art = tk.Canvas(visual, height=410, bg=self.c("bg"), highlightthickness=0)
        art.pack(fill="both", expand=True)
        self.draw_guardian(art)
        art.bind("<Configure>", lambda _event: self.draw_guardian(art))
        self.animate_guardian(art)
        tk.Label(visual, text="YOUR DIGITAL BODYGUARD", bg=self.c("bg"),
                 fg=self.c("accent"), font=("Helvetica", 10, "bold")).pack(anchor="w", padx=22, pady=(8, 5))
        tk.Label(visual, text="Stay sharp.\nStay protected.", bg=self.c("bg"),
                 fg=self.c("text"), font=("Helvetica", 25, "bold"), justify="left").pack(anchor="w", padx=22)
        tk.Label(visual, text="A smarter first line of defence against digital scams.",
                 bg=self.c("bg"), fg=self.c("muted"), font=("Helvetica", 10),
                 wraplength=390, justify="left").pack(anchor="w", padx=22, pady=(8, 0))

        card = tk.Frame(shell, bg=self.c("panel"), padx=38, pady=32,
                        highlightthickness=1, highlightbackground=self.c("border"))
        card.pack(side="right", fill="y", padx=(10, 36), pady=26)
        card.configure(width=440)
        card.pack_propagate(False)

        tk.Label(card, text="⬡", font=("Helvetica", 34, "bold"),
                 bg=self.c("panel"), fg=self.c("accent")).pack()
        tk.Label(card, text="ShieldAI", font=("Helvetica", 24, "bold"),
                 bg=self.c("panel"), fg=self.c("text")).pack(pady=(2, 4))
        tk.Label(card, text="YOUR DIGITAL BODYGUARD", font=("Helvetica", 9, "bold"),
                 bg=self.c("panel"), fg=self.c("muted")).pack(pady=(0, 22))

        heading = "Create your account" if self.auth_mode == "signup" else "Welcome back"
        tk.Label(card, text=heading, font=("Helvetica", 17, "bold"),
                 bg=self.c("panel"), fg=self.c("text")).pack(anchor="w")
        tk.Label(card, text="Sign in to access your personal scan history." if self.auth_mode == "login"
                 else "Create an account to keep your scan history separate.",
                 font=("Helvetica", 9), bg=self.c("panel"), fg=self.c("muted"),
                 wraplength=340, justify="left").pack(anchor="w", pady=(5, 18))

        tk.Label(card, text="USERNAME", font=("Helvetica", 8, "bold"),
                 bg=self.c("panel"), fg=self.c("muted")).pack(anchor="w", pady=(0, 5))
        username = tk.Entry(card, font=("Helvetica", 11), relief="flat", bd=0,
                            bg=self.c("input"), fg=self.c("text"), insertbackground=self.c("text"))
        username.pack(fill="x", ipady=11, pady=(0, 14))

        tk.Label(card, text="PASSWORD", font=("Helvetica", 8, "bold"),
                 bg=self.c("panel"), fg=self.c("muted")).pack(anchor="w", pady=(0, 5))
        password = tk.Entry(card, show="•", font=("Helvetica", 11), relief="flat", bd=0,
                            bg=self.c("input"), fg=self.c("text"), insertbackground=self.c("text"))
        password.pack(fill="x", ipady=11, pady=(0, 18))

        def submit(_event=None):
            user = username.get().strip()
            secret = password.get()
            if not user or not secret:
                messagebox.showwarning("ShieldAI", "Enter both username and password.")
                return
            if len(user) < 3 or len(user) > 40 or any(ch.isspace() for ch in user):
                messagebox.showwarning("ShieldAI", "Username must be 3–40 characters with no spaces.")
                return
            if self.auth_mode == "signup":
                if len(secret) < 8:
                    messagebox.showwarning("ShieldAI", "Use a password with at least 8 characters.")
                    return
                salt = secrets.token_hex(16)
                digest = self._password_digest(secret, salt)
                try:
                    cur = self.db.execute(
                        "INSERT INTO users (username,password_hash,password_salt,created_at) VALUES (?,?,?,?)",
                        (user, digest, salt, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
                    self.db.commit()
                    self.current_user_id = cur.lastrowid
                    self.current_username = user
                    self.open_application()
                except sqlite3.IntegrityError:
                    messagebox.showerror("Account exists", "That username is already registered. Choose another.")
            else:
                row = self.db.execute(
                    "SELECT id,username,password_hash,password_salt FROM users WHERE username=? COLLATE NOCASE",
                    (user,)).fetchone()
                if not row or not secrets.compare_digest(self._password_digest(secret, row[3]), row[2]):
                    messagebox.showerror("Sign-in failed", "Incorrect username or password.")
                    return
                self.current_user_id, self.current_username = row[0], row[1]
                self.open_application()

        primary = tk.Button(card, text="Create account" if self.auth_mode == "signup" else "Sign in",
                            command=submit, bg=self.c("accent"), fg=self.c("button_text"),
                            activebackground=self.c("accent2"), activeforeground="#FFFFFF",
                            relief="flat", bd=0, font=("Helvetica", 10, "bold"), cursor="hand2")
        primary.pack(fill="x", ipady=10)
        switch_text = "Already have an account? Sign in" if self.auth_mode == "signup" else "New here? Create an account"
        switch = tk.Button(card, text=switch_text, command=self.toggle_auth_mode,
                           bg=self.c("panel"), fg=self.c("accent"), activebackground=self.c("panel"),
                           activeforeground=self.c("accent2"), relief="flat", bd=0,
                           font=("Helvetica", 9), cursor="hand2")
        switch.pack(pady=(14, 0))
        password.bind("<Return>", submit)
        username.bind("<Return>", lambda _event: password.focus_set())
        username.focus_set()

    def draw_guardian(self, canvas):
        """Draw a friendly anime-inspired cyber guardian using native Canvas shapes."""
        canvas.delete("all")
        canvas.update_idletasks()
        w = max(canvas.winfo_width(), 420)
        h = max(canvas.winfo_height(), 360)
        cx, cy = w * 0.50, h * 0.48
        # Halo and HUD rings
        for radius in (100, 128, 154):
            canvas.create_oval(cx-radius, cy-radius, cx+radius, cy+radius,
                               outline=self.c("border"), width=1)
        canvas.create_oval(cx-76, cy-76, cx+76, cy+76,
                           fill=self.c("panel"), outline=self.c("accent"), width=2)
        # Shoulders / futuristic jacket
        canvas.create_polygon(cx-38, cy+54, cx-93, cy+92, cx-111, cy+151,
                              cx+111, cy+151, cx+93, cy+92, cx+38, cy+54,
                              fill=self.c("panel2"), outline=self.c("accent"), width=2)
        canvas.create_polygon(cx-38, cy+58, cx, cy+103, cx+38, cy+58,
                              cx+25, cy+139, cx-25, cy+139,
                              fill=self.c("bg"), outline=self.c("border"), width=2)
        # Face and hair, with stylised anime silhouette
        canvas.create_oval(cx-48, cy-62, cx+48, cy+54,
                           fill="#F2C9B5", outline="#E7A98F", width=2)
        canvas.create_polygon(cx-51, cy-17, cx-61, cy-61, cx-30, cy-91,
                              cx+9, cy-96, cx+51, cy-62, cx+57, cy-15,
                              cx+34, cy-39, cx+10, cy-28, cx-13, cy-45,
                              cx-34, cy-27, fill="#18243B", outline="#48D7FF", width=2)
        # Eyes, brows and face details
        canvas.create_line(cx-32, cy-20, cx-12, cy-24, fill="#18243B", width=3)
        canvas.create_line(cx+12, cy-24, cx+32, cy-20, fill="#18243B", width=3)
        canvas.create_oval(cx-29, cy-15, cx-10, cy+1, fill="#48D7FF", outline="#18243B", width=2)
        canvas.create_oval(cx+10, cy-15, cx+29, cy+1, fill="#48D7FF", outline="#18243B", width=2)
        canvas.create_oval(cx-22, cy-12, cx-16, cy-4, fill="#FFFFFF", outline="")
        canvas.create_oval(cx+17, cy-12, cx+23, cy-4, fill="#FFFFFF", outline="")
        canvas.create_line(cx-8, cy+24, cx+8, cy+24, fill="#B86D75", width=2)
        # Chest shield insignia
        canvas.create_polygon(cx, cy+76, cx+20, cy+84, cx+17, cy+108,
                              cx, cy+121, cx-17, cy+108, cx-20, cy+84,
                              fill=self.c("accent"), outline="")
        canvas.create_text(cx, cy+96, text="S", fill=self.c("button_text"),
                           font=("Helvetica", 17, "bold"))
        canvas.create_text(cx, cy+177, text="SHIELD // ACTIVE DEFENCE", fill=self.c("muted"),
                           font=("Menlo", 9, "bold"))
        # Corner HUD marks
        for x, y, sx, sy in [(24, 28, 1, 1), (w-24, 28, -1, 1),
                             (24, h-25, 1, -1), (w-24, h-25, -1, -1)]:
            canvas.create_line(x, y, x+sx*22, y, fill=self.c("accent"), width=2)
            canvas.create_line(x, y, x, y+sy*22, fill=self.c("accent"), width=2)

    def animate_guardian(self, canvas, frame=0):
        """Add drifting HUD particles without blocking the Tkinter event loop."""
        try:
            if not canvas.winfo_exists():
                return
            canvas.delete("particle")
            w, h = max(canvas.winfo_width(), 420), max(canvas.winfo_height(), 360)
            accent = self.c("accent")
            for i in range(9):
                x = 22 + ((i * 47 + frame * (1 + i % 3)) % max(w - 44, 1))
                y = 24 + ((i * 61 + frame * (1 + i % 2)) % max(h - 48, 1))
                r = 2 + (i % 3)
                canvas.create_oval(x-r, y-r, x+r, y+r, outline=accent, width=1, tags="particle")
            canvas.after(100, lambda: self.animate_guardian(canvas, frame + 1))
        except tk.TclError:
            return

    def draw_radar(self, canvas):
        """Draw a richer cyber-security illustration using Tkinter only."""
        canvas.delete("all")
        canvas.update_idletasks()
        w = max(canvas.winfo_width(), 300)
        h = max(canvas.winfo_height(), 170)
        bg = self.c("panel")
        accent = self.c("accent")
        purple = self.c("accent2")
        muted = self.c("border")
        canvas.configure(bg=bg)

        # Low-contrast circuit grid and corner framing.
        for x in range(0, w, 24):
            canvas.create_line(x, 0, x, h, fill=muted, width=1)
        for y in range(0, h, 24):
            canvas.create_line(0, y, w, y, fill=muted, width=1)
        canvas.create_line(8, 18, 8, 8, fill=accent, width=2)
        canvas.create_line(8, 8, 25, 8, fill=accent, width=2)
        canvas.create_line(w-8, h-18, w-8, h-8, fill=accent, width=2)
        canvas.create_line(w-8, h-8, w-25, h-8, fill=accent, width=2)

        # Digital globe on the right.
        gx, gy = w * 0.78, h * 0.49
        gr = min(49, h * 0.29)
        canvas.create_oval(gx-gr, gy-gr, gx+gr, gy+gr, outline=purple, width=2)
        canvas.create_oval(gx-gr*0.65, gy-gr, gx+gr*0.65, gy+gr, outline=muted, width=1)
        canvas.create_oval(gx-gr*0.28, gy-gr, gx+gr*0.28, gy+gr, outline=muted, width=1)
        canvas.create_arc(gx-gr, gy-gr*0.55, gx+gr, gy+gr*0.55,
                          start=0, extent=180, style="arc", outline=accent)
        canvas.create_arc(gx-gr, gy-gr*0.55, gx+gr, gy+gr*0.55,
                          start=180, extent=180, style="arc", outline=accent)
        for i in range(22):
            px = gx - gr + (i * 17 % int(max(gr*2, 1)))
            py = gy - gr + (i * 29 % int(max(gr*2, 1)))
            if (px-gx)**2 + (py-gy)**2 < gr**2:
                canvas.create_oval(px-1.5, py-1.5, px+1.5, py+1.5,
                                   fill=accent if i % 3 else purple, outline="")

        # Hooded guardian silhouette behind a holographic shield.
        cx, cy = w * 0.43, h * 0.43
        canvas.create_polygon(cx-33, cy+5, cx-49, cy-24, cx-27, cy-53,
                              cx+7, cy-60, cx+37, cy-34, cx+42, cy+8,
                              cx+28, cy-9, cx-20, cy-8,
                              fill="#101B31", outline=accent, width=2)
        canvas.create_oval(cx-21, cy-25, cx+22, cy+22,
                           fill="#0B1325", outline=muted, width=1)
        canvas.create_line(cx-15, cy-2, cx-4, cy-5, fill=accent, width=3)
        canvas.create_line(cx+5, cy-5, cx+16, cy-2, fill=accent, width=3)
        canvas.create_polygon(cx-24, cy+25, cx-57, cy+42, cx-68, h-13,
                              cx+67, h-13, cx+53, cy+42, cx+24, cy+25,
                              fill="#111D34", outline=muted, width=2)
        # Shield and orbital rings.
        sx, sy = cx, cy + 25
        for r in (30, 39, 49):
            canvas.create_oval(sx-r, sy-r, sx+r, sy+r, outline=muted, width=1)
        canvas.create_polygon(sx, sy-29, sx+24, sy-19, sx+20, sy+10,
                              sx, sy+30, sx-20, sy+10, sx-24, sy-19,
                              fill="#102D4B", outline=accent, width=3)
        canvas.create_text(sx, sy, text="S", fill=accent,
                           font=("Helvetica", 22, "bold"))

        # Animated scan ray and status labels are redrawn every frame.
        canvas.create_line(15, h-26, w-15, h-26, fill=muted, width=1)
        canvas.create_text(18, h-13, text="THREAT MAP  /  LIVE ANALYSIS",
                           anchor="w", fill=accent, font=("Menlo", 7, "bold"))
        canvas.create_text(w-16, 14, text="DEFENCE: ACTIVE", anchor="e",
                           fill=self.c("good"), font=("Menlo", 7, "bold"))
        canvas.create_line(0, 0, 0, h, fill=accent, width=2, tags="scan_ray")
        canvas.create_oval(0, 0, 0, 0, fill=accent, outline="", tags="pulse_dot")

    def animate_radar(self, canvas, angle=0):
        try:
            if not canvas.winfo_exists():
                return
            import math
            w = max(canvas.winfo_width(), 300)
            h = max(canvas.winfo_height(), 170)
            x = (angle * 4) % w
            canvas.coords("scan_ray", x, 0, x, h)
            y = h * 0.45 + math.sin(math.radians(angle * 2)) * 12
            canvas.coords("pulse_dot", x-3, y-3, x+3, y+3)
            canvas.after(55, lambda: self.animate_radar(canvas, angle + 1))
        except tk.TclError:
            return

    def toggle_auth_mode(self):
        self.auth_mode = "signup" if self.auth_mode == "login" else "login"
        self.show_auth_screen()

    def open_application(self):
        self.build_shell()
        self.show_page("Dashboard")

    def logout(self):
        self.current_user_id = None
        self.current_username = None
        self.last_result = None
        self.auth_mode = "login"
        self.show_auth_screen()

    def close(self):

        try:

            self.db.close()

        finally:

            self.root.destroy()

    def c(self, key):

        return self.colors[key]

    def build_shell(self):

        for child in self.root.winfo_children():

            child.destroy()

        self.root.configure(bg=self.c("bg"))

        self.outer = tk.Frame(self.root, bg=self.c("bg"))

        self.outer.pack(fill="both", expand=True)

        self.sidebar = tk.Frame(self.outer, bg=self.c("panel"), width=220)

        self.sidebar.pack(side="left", fill="y")

        self.sidebar.pack_propagate(False)

        brand = tk.Frame(self.sidebar, bg=self.c("panel"))

        brand.pack(fill="x", padx=18, pady=(22, 24))

        emblem = tk.Canvas(brand, width=42, height=42, bg=self.c("panel"), highlightthickness=0)

        emblem.pack(side="left")

        emblem.create_polygon(21, 2, 38, 9, 36, 27, 21, 40, 6, 27, 4, 9,

                              fill=self.c("accent"), outline="")

        emblem.create_text(21, 20, text="S", fill=self.c("button_text"), font=("Helvetica", 16, "bold"))

        words = tk.Frame(brand, bg=self.c("panel"))

        words.pack(side="left", padx=9)

        self.label(words, "ShieldAI", 17, "bold", self.c("text")).pack(anchor="w")

        self.label(words, "DIGITAL BODYGUARD", 7, "bold", self.c("muted")).pack(anchor="w", pady=(2, 0))

        self.label(self.sidebar, "WORKSPACE", 8, "bold", self.c("muted")).pack(anchor="w", padx=20, pady=(0, 8))

        self.nav_buttons = {}

        for name, glyph in [("Dashboard", "◈"), ("Message Scanner", "▤"), ("URL Scanner", "⌁"),

                            ("Email Analyzer", "✉"), ("AI Assistant", "✦"), ("Scan History", "◷"), ("Test Lab", "⌘"), ("Settings", "⚙")]:

            b = tk.Button(self.sidebar, text=f"  {glyph}   {name}", anchor="w", relief="flat",

                          bd=0, cursor="hand2", padx=15, pady=11,

                          font=("Helvetica", 10), command=lambda n=name: self.show_page(n))

            b.pack(fill="x", padx=10, pady=2)

            self.nav_buttons[name] = b

        tk.Frame(self.sidebar, bg=self.c("border"), height=1).pack(fill="x", padx=16, pady=(20, 14))

        self.protection_card = tk.Frame(self.sidebar, bg=self.c("panel2"), highlightthickness=1,

                                        highlightbackground=self.c("border"))

        self.protection_card.pack(fill="x", padx=13, pady=4, side="bottom")

        self.protection_dot = tk.Canvas(self.protection_card, width=16, height=16,

                                        bg=self.c("panel2"), highlightthickness=0)

        self.protection_dot.pack(anchor="w", padx=13, pady=(13, 0))

        self.protection_text = self.label(self.protection_card, "", 10, "bold", self.c("text"))

        self.protection_text.pack(anchor="w", padx=13, pady=(3, 0))

        self.protection_sub = self.label(self.protection_card, "", 8, "normal", self.c("muted"))

        self.protection_sub.pack(anchor="w", padx=13, pady=(2, 12))

        self.main = tk.Frame(self.outer, bg=self.c("bg"))

        self.main.pack(side="left", fill="both", expand=True)

        self.topbar = tk.Frame(self.main, bg=self.c("bg"))

        self.topbar.pack(fill="x", padx=28, pady=(20, 10))

        self.page_title = self.label(self.topbar, "Dashboard", 22, "bold", self.c("text"))

        self.page_title.pack(side="left")

        self.top_right = tk.Frame(self.topbar, bg=self.c("bg"))

        self.top_right.pack(side="right")

        self.account_label = self.label(self.top_right, f"Signed in: {self.current_username}", 9, "bold", self.c("muted"))

        self.account_label.pack(side="left", padx=(0, 10))

        self.logout_button = tk.Button(self.top_right, text="Log out", command=self.logout,
                                       relief="flat", bd=0, padx=10, pady=8, cursor="hand2",
                                       font=("Helvetica", 9, "bold"), bg=self.c("panel2"), fg=self.c("text"))

        self.logout_button.pack(side="left", padx=(0, 8))

        self.theme_button = tk.Button(self.top_right, text="☼  Light mode", command=self.toggle_theme,

                                      relief="flat", bd=0, padx=12, pady=8, cursor="hand2",

                                      font=("Helvetica", 9, "bold"))

        self.theme_button.pack(side="left", padx=(0, 8))

        self.protect_button = tk.Button(self.top_right, text="Protection: ON", command=self.toggle_protection,

                                        relief="flat", bd=0, padx=12, pady=8, cursor="hand2",

                                        font=("Helvetica", 9, "bold"))

        self.protect_button.pack(side="left")

        # Scrollable page viewport: keeps dashboard cards and actions reachable on smaller screens.
        self.content_host = tk.Frame(self.main, bg=self.c("bg"))
        self.content_host.pack(fill="both", expand=True, padx=22, pady=(8, 12))

        self.content_canvas = tk.Canvas(
            self.content_host, bg=self.c("bg"), highlightthickness=0, borderwidth=0
        )
        self.content_scrollbar = ttk.Scrollbar(
            self.content_host, orient="vertical", command=self.content_canvas.yview
        )
        self.content_canvas.configure(yscrollcommand=self.content_scrollbar.set)
        self.content_scrollbar.pack(side="right", fill="y")
        self.content_canvas.pack(side="left", fill="both", expand=True)

        self.content = tk.Frame(self.content_canvas, bg=self.c("bg"))
        self.content_window = self.content_canvas.create_window(
            (0, 0), window=self.content, anchor="nw"
        )

        def update_scroll_region(_event=None):
            try:
                self.content_canvas.configure(scrollregion=self.content_canvas.bbox("all"))
            except tk.TclError:
                pass

        def fit_content_width(event):
            try:
                self.content_canvas.itemconfigure(self.content_window, width=event.width)
            except tk.TclError:
                pass

        def scroll_content(event):
            # macOS uses small deltas; Windows commonly uses multiples of 120.
            if not self.content_canvas.winfo_exists():
                return
            delta = event.delta
            if not delta:
                return
            units = -1 if delta > 0 else 1
            if abs(delta) >= 120:
                units = int(-delta / 120)
            self.content_canvas.yview_scroll(units, "units")

        self.content.bind("<Configure>", update_scroll_region)
        self.content_canvas.bind("<Configure>", fit_content_width)
        # Bind once only; theme changes rebuild the shell, but not the root.
        # The callback reads self.content_canvas dynamically, so it always targets
        # the newest canvas after a theme switch.
        if not getattr(self, "_wheel_binding_installed", False):
            self.root.bind_all("<MouseWheel>", scroll_content)
            self._wheel_binding_installed = True


        self.update_protection_ui()

        self.style.configure("Treeview", background=self.c("panel"), fieldbackground=self.c("panel"),

                             foreground=self.c("text"), rowheight=30, borderwidth=0)

        self.style.configure("Treeview.Heading", background=self.c("panel2"), foreground=self.c("text"),

                             font=("Helvetica", 9, "bold"), relief="flat")

        self.style.map("Treeview", background=[("selected", self.c("accent2"))],

                       foreground=[("selected", "#FFFFFF")])

    def label(self, parent, text, size=10, weight="normal", color=None):

        return tk.Label(parent, text=text, bg=parent.cget("bg"), fg=color or self.c("text"),

                        font=("Helvetica", size, weight), anchor="w", justify="left")

    def card(self, parent, bg=None, padx=18, pady=16):

        return tk.Frame(parent, bg=bg or self.c("card"), highlightthickness=1,

                        highlightbackground=self.c("border"), padx=padx, pady=pady)

    def button(self, parent, text, command, primary=False):

        bg = self.c("accent") if primary else self.c("panel2")

        fg = self.c("button_text") if primary else self.c("text")

        b = tk.Button(parent, text=text, command=command, bg=bg, fg=fg,
                      activebackground=self.c("accent2"), activeforeground="#FFFFFF",
                      relief="flat", bd=0, padx=15, pady=10, cursor="hand2",
                      font=("Helvetica", 10, "bold"), takefocus=True)
        hover_bg = self.c("accent2") if not primary else self.c("good")
        hover_fg = "#FFFFFF" if not primary else "#06111E"
        b.bind("<Enter>", lambda _e, widget=b, color=hover_bg, ink=hover_fg:
               widget.configure(bg=color, fg=ink))
        b.bind("<Leave>", lambda _e, widget=b, color=bg, ink=fg:
               widget.configure(bg=color, fg=ink))
        return b

    def input_box(self, parent, height=7):

        return tk.Text(parent, height=height, wrap="word", undo=True,

                       bg=self.c("input"), fg=self.c("text"), insertbackground=self.c("text"),

                       selectbackground=self.c("accent2"), relief="flat", bd=0,

                       font=("Menlo", 10), padx=12, pady=12,

                       highlightthickness=1, highlightbackground=self.c("border"),

                       highlightcolor=self.c("accent"))

    def _read_widget_text(self, attribute, fallback):
        widget = getattr(self, attribute, None)
        if widget is None:
            return fallback
        try:
            if widget.winfo_exists():
                return widget.get("1.0", "end-1c")
        except tk.TclError:
            pass
        return fallback

    def toggle_theme(self):
        # Preserve text typed into scanner fields when the shell is rebuilt.
        self.message_draft = self._read_widget_text("message_box", self.message_draft)
        self.url_draft = self._read_widget_text("url_box", self.url_draft)
        self.email_draft = self._read_widget_text("email_box", self.email_draft)

        # Keep the selected page instead of falling back to a scanner page.
        page = self.current_page or "Dashboard"
        self.theme_name = "light" if self.theme_name == "dark" else "dark"
        self.colors = (LIGHT if self.theme_name == "light" else DARK).copy()
        self.build_shell()
        self.show_page(page)

    def toggle_protection(self):

        self.protection_on = not self.protection_on

        self.update_protection_ui()

        self.show_toast("Local in-app protection enabled." if self.protection_on else

                        "Local in-app protection paused. Manual scans remain available.")

    def update_protection_ui(self):

        if not hasattr(self, "protect_button"):

            return

        active = self.protection_on

        self.protect_button.configure(text="Protection: ON" if active else "Protection: OFF",

                                      bg=self.c("good") if active else self.c("panel2"),

                                      fg="#06111E" if active else self.c("text"))

        self.protection_text.configure(text="Protection active" if active else "Protection paused")

        self.protection_sub.configure(text="Local app monitoring state" if active else "Manual scans still work")

        self.protection_dot.delete("all")

        self.protection_dot.create_oval(3, 3, 13, 13, fill=self.c("good") if active else self.c("warn"), outline="")

        for name, b in self.nav_buttons.items():

            selected = name == self.current_page

            b.configure(bg=self.c("panel2") if selected else self.c("panel"),

                        fg=self.c("accent") if selected else self.c("muted"),

                        activebackground=self.c("panel2"), activeforeground=self.c("accent"))

        self.theme_button.configure(text="☾  Dark mode" if self.theme_name == "light" else "☼  Light mode",

                                    bg=self.c("panel2"), fg=self.c("text"),

                                    activebackground=self.c("accent2"), activeforeground="#FFFFFF")

    def show_toast(self, message):

        self.status_message.configure(text=message) if hasattr(self, "status_message") and self.status_message.winfo_exists() else None

    def show_page(self, page):

        self.current_page = page

        if hasattr(self, "content_canvas"):
            try:
                self.content_canvas.yview_moveto(0)
            except tk.TclError:
                pass

        self.update_protection_ui()

        for child in self.content.winfo_children():

            child.destroy()

        self.page_title.configure(text=page)

        pages = {

            "Dashboard": self.page_dashboard, "Message Scanner": self.page_message,

            "URL Scanner": self.page_url, "Email Analyzer": self.page_email, "AI Assistant": self.page_ai_assistant,
            "Scan History": self.page_history, "Test Lab": self.page_test_lab, "Settings": self.page_settings

        }

        renderer = pages.get(page, self.page_dashboard)
        renderer()
        self.update_protection_ui()

    def page_dashboard(self):
        """Dashboard-only redesign inspired by a professional security operations center.
        Other workspace pages and their scanning logic are intentionally unchanged.
        """
        bg = self.c("bg")
        panel = self.c("panel")
        card_bg = self.c("card")
        border = self.c("border")
        text = self.c("text")
        muted = self.c("muted")
        accent = self.c("accent")
        good = self.c("good")
        warn = self.c("warn")
        bad = self.c("bad")

        # Header status row: system state, threat level, and local protection state.
        overview = tk.Frame(self.content, bg=bg)
        overview.pack(fill="x", pady=(0, 12))

        protected = self.card(overview, bg=panel, padx=15, pady=13)
        protected.pack(side="left", fill="both", expand=True, padx=(0, 6))
        hero_row = tk.Frame(protected, bg=panel)
        hero_row.pack(fill="x")
        shield = tk.Canvas(hero_row, width=78, height=82, bg=panel, highlightthickness=0)
        shield.pack(side="left", padx=(0, 12))
        shield.create_oval(5, 5, 73, 73, outline=border, width=2)
        shield.create_oval(11, 11, 67, 67, outline=accent, width=1)
        shield.create_polygon(39, 13, 59, 21, 56, 47, 39, 64, 22, 47, 19, 21,
                              fill=panel, outline=accent, width=3)
        shield.create_line(29, 38, 36, 45, 49, 30, fill=good if self.protection_on else warn, width=4)
        details = tk.Frame(hero_row, bg=panel)
        details.pack(side="left", fill="x", expand=True)
        self.label(details, "YOUR SYSTEM IS", 8, "bold", muted).pack(anchor="w")
        self.label(details, "PROTECTED" if self.protection_on else "PROTECTION PAUSED",
                   17, "bold", good if self.protection_on else warn).pack(anchor="w", pady=(2, 0))
        self.label(details, "Local scan engine ready" if self.protection_on else "Manual scans remain available",
                   8, "normal", muted).pack(anchor="w", pady=(2, 7))
        self.button(details, "Run smart scan", lambda: self.show_page("Message Scanner"), True).pack(anchor="w")

        threat = self.card(overview, bg=panel, padx=13, pady=13)
        threat.pack(side="left", fill="both", expand=True, padx=6)
        self.label(threat, "THREAT LEVEL", 8, "bold", muted).pack(anchor="w")
        count, high, today = self.get_stats()
        level_text = "HIGH" if high else ("WATCH" if count and today else "LOW")
        level_color = bad if high else (warn if count and today else good)
        self.label(threat, level_text, 17, "bold", level_color).pack(anchor="w", pady=(6, 2))
        self.label(threat, f"{high} high-risk scan(s) recorded", 8, "normal", muted).pack(anchor="w")
        globe = tk.Canvas(threat, height=65, bg=panel, highlightthickness=0)
        globe.pack(fill="x", pady=(3, 0))
        gx, gy, gr = 62, 33, 26
        globe.create_oval(gx-gr, gy-gr, gx+gr, gy+gr, outline=accent, width=2)
        globe.create_oval(gx-gr*.55, gy-gr, gx+gr*.55, gy+gr, outline=border)
        globe.create_arc(gx-gr, gy-gr*.45, gx+gr, gy+gr*.45, start=0, extent=180,
                         style="arc", outline=border)
        globe.create_arc(gx-gr, gy-gr*.45, gx+gr, gy+gr*.45, start=180, extent=180,
                         style="arc", outline=border)
        globe.create_oval(gx-5, gy-5, gx+5, gy+5, fill=level_color, outline="")

        live = self.card(overview, bg=panel, padx=13, pady=13)
        live.pack(side="left", fill="both", expand=True, padx=(6, 0))
        self.label(live, "LOCAL PROTECTION", 8, "bold", muted).pack(anchor="w", pady=(0, 7))
        for name, detail in [
            ("Message checks", "Rule-based signals"),
            ("URL inspection", "Domain structure"),
            ("Scan history", "Saved on device"),
            ("Theme controls", "Dark / light UI"),
        ]:
            line = tk.Frame(live, bg=panel)
            line.pack(fill="x", pady=3)
            tk.Canvas(line, width=12, height=14, bg=panel, highlightthickness=0).pack(side="left", padx=(0, 6))
            dot = line.winfo_children()[0]
            dot.create_oval(3, 4, 9, 10, fill=good if self.protection_on else warn, outline="")
            self.label(line, name, 8, "normal", text).pack(side="left", fill="x", expand=True)
            self.label(line, "ON" if self.protection_on else "PAUSED", 7, "bold",
                       good if self.protection_on else warn).pack(side="right")

        # Protection layers row: real, transparent app capabilities, not claims of OS-level protection.
        layers = self.card(self.content, bg=panel, padx=13, pady=11)
        layers.pack(fill="x", pady=(0, 12))
        self.label(layers, "PROTECTION LAYERS", 9, "bold", muted).pack(anchor="w", pady=(0, 9))
        layer_row = tk.Frame(layers, bg=panel)
        layer_row.pack(fill="x")
        layer_items = [
            ("✦", "Message scan", "Scam indicators", accent),
            ("↗", "URL analysis", "Link structure", self.c("accent2")),
            ("✉", "Email review", "Urgency & requests", good),
            ("◷", "Local history", "Saved scan records", warn),
            ("⚙", "Privacy first", "Local database", accent),
        ]
        for i, (symbol, title, sub, tint) in enumerate(layer_items):
            item = tk.Frame(layer_row, bg=card_bg, highlightthickness=1, highlightbackground=border,
                            padx=7, pady=8)
            item.pack(side="left", fill="both", expand=True, padx=(0 if i == 0 else 4, 0))
            self.label(item, symbol, 16, "bold", tint).pack(anchor="w")
            self.label(item, title, 8, "bold", text).pack(anchor="w", pady=(4, 1))
            self.label(item, sub, 7, "normal", muted).pack(anchor="w")

        # Main analytics area.
        body = tk.Frame(self.content, bg=bg)
        body.pack(fill="both", expand=True, pady=(0, 12))

        activity = self.card(body, bg=panel, padx=14, pady=13)
        activity.pack(side="left", fill="both", expand=True, padx=(0, 6))
        activity_header = tk.Frame(activity, bg=panel)
        activity_header.pack(fill="x")
        self.label(activity_header, "SECURITY ACTIVITY", 10, "bold", text).pack(side="left")
        self.label(activity_header, "RECENT SCAN SCORES", 7, "bold", accent).pack(side="right")
        chart = tk.Canvas(activity, height=180, bg=panel, highlightthickness=0)
        chart.pack(fill="both", expand=True, pady=(8, 0))
        self.draw_dashboard_activity(chart)
        chart.bind("<Configure>", lambda _event, c=chart: self.draw_dashboard_activity(c))

        side = tk.Frame(body, bg=bg)
        side.pack(side="left", fill="both", expand=True, padx=(6, 0))

        recent = self.card(side, bg=panel, padx=12, pady=12)
        recent.pack(fill="both", expand=True, pady=(0, 8))
        recent_head = tk.Frame(recent, bg=panel)
        recent_head.pack(fill="x", pady=(0, 7))
        self.label(recent_head, "RECENT ACTIVITY", 10, "bold", text).pack(side="left")
        self.button(recent_head, "View all", lambda: self.show_page("Scan History")).pack(side="right")
        rows = self.db.execute(
            "SELECT created_at,scan_type,subject,score,level FROM scans "
            "WHERE user_id=? ORDER BY id DESC LIMIT 4", (self.current_user_id,)
        ).fetchall()
        if not rows:
            self.label(recent, "No activity yet. Run a message or URL scan to populate this panel.",
                       8, "normal", muted).pack(anchor="w", pady=10)
        else:
            for dt, kind, subject, score, level in rows:
                row = tk.Frame(recent, bg=card_bg, padx=8, pady=7,
                               highlightthickness=1, highlightbackground=border)
                row.pack(fill="x", pady=3)
                top_line = tk.Frame(row, bg=card_bg)
                top_line.pack(fill="x")
                self.label(top_line, f"{kind.upper()}  ·  {dt[11:16]}", 8, "bold", text).pack(side="left")
                self.label(top_line, f"{score}/100", 8, "bold", self.risk_color(score)).pack(side="right")
                preview = (subject or "").replace("\n", " ").strip()
                if len(preview) > 54:
                    preview = preview[:51] + "..."
                self.label(row, preview or "Scan completed", 7, "normal", muted).pack(anchor="w", pady=(3, 0))

        quick = self.card(side, bg=panel, padx=12, pady=11)
        quick.pack(fill="x")
        self.label(quick, "QUICK ACTIONS", 9, "bold", text).pack(anchor="w", pady=(0, 6))
        actions = tk.Frame(quick, bg=panel)
        actions.pack(fill="x")
        for title, page in [
            ("▤ Message", "Message Scanner"),
            ("↗ URL", "URL Scanner"),
            ("✉ Email", "Email Analyzer"),
            ("◷ History", "Scan History"),
        ]:
            self.button(actions, title, lambda p=page: self.show_page(p)).pack(
                side="left", fill="x", expand=True, padx=2, pady=2
            )

        footer = tk.Frame(self.content, bg=bg)
        footer.pack(fill="x", pady=(0, 2))
        self.label(footer, "SHIELDAI  /  PRIVACY-FIRST SCANNING  /  VERIFY BEFORE YOU TRUST",
                   7, "bold", muted).pack(anchor="w")

    def draw_dashboard_activity(self, canvas):
        """Draw dashboard-only activity graph from the current user's latest scans."""
        try:
            if not canvas.winfo_exists():
                return
            canvas.delete("all")
            w = max(canvas.winfo_width(), 300)
            h = max(canvas.winfo_height(), 150)
            bg = self.c("panel")
            grid = self.c("border")
            accent = self.c("accent")
            purple = self.c("accent2")
            muted = self.c("muted")
            left, right, top, bottom = 28, w - 12, 12, h - 28
            for i in range(5):
                y = top + (bottom - top) * i / 4
                canvas.create_line(left, y, right, y, fill=grid, dash=(2, 4))
                canvas.create_text(3, y, text=str(100 - i * 25), anchor="w",
                                  fill=muted, font=("Helvetica", 7))
            scores = self.db.execute(
                "SELECT score FROM scans WHERE user_id=? ORDER BY id DESC LIMIT 12",
                (self.current_user_id,)
            ).fetchall()
            values = [int(r[0]) for r in reversed(scores)]
            if not values:
                values = [8, 12, 10, 18, 14, 22, 17, 12, 16, 9]
                canvas.create_text(w / 2, h / 2, text="Demo trend • no scans saved yet",
                                   fill=muted, font=("Helvetica", 8))
            if len(values) == 1:
                values = [values[0], values[0]]
            points = []
            span = max(len(values) - 1, 1)
            for i, value in enumerate(values):
                x = left + (right - left) * i / span
                y = bottom - (bottom - top) * max(0, min(100, value)) / 100
                points.extend((x, y))
            if len(points) >= 4:
                canvas.create_line(*points, fill=accent, width=2, smooth=True)
                for i in range(0, len(points), 2):
                    x, y = points[i], points[i + 1]
                    canvas.create_oval(x-3, y-3, x+3, y+3, fill=purple, outline=accent, width=1)
            canvas.create_text(left, h - 10, text="OLDER", anchor="w",
                               fill=muted, font=("Helvetica", 7, "bold"))
            canvas.create_text(right, h - 10, text="LATEST", anchor="e",
                               fill=muted, font=("Helvetica", 7, "bold"))
        except (tk.TclError, sqlite3.Error):
            return

    def stat_card(self, parent, title, value, sub, accent):

        frame = self.card(parent, padx=16, pady=14)

        self.label(frame, title, 8, "bold", self.c("muted")).pack(anchor="w")

        self.label(frame, value, 24, "bold", accent).pack(anchor="w", pady=(5, 1))

        self.label(frame, sub, 8, "normal", self.c("muted")).pack(anchor="w")

        return frame

    def page_message(self):

        self.scanner_page("Message Scanner", "Paste SMS, chat, or social messages. ShieldAI checks for configured social-engineering indicators.",

                          "Example: Your account will be blocked. Verify KYC now at http://example.invalid and share your OTP.",

                          "Scan message", self.message_draft, "message")

    def page_url(self):

        self.scanner_page("URL Scanner", "Inspect a URL for suspicious structure. This does not query live threat-intelligence services.",

                          "https://secure-account.example.invalid/verify", "Scan URL", self.url_draft, "url", compact=True)

    def page_email(self):

        self.scanner_page("Email Analyzer", "Paste the email subject and body. ShieldAI applies the same explainable text checks.",

                          "Subject: Urgent account verification required\n\nDear customer, click here to avoid account suspension and enter your password.",

                          "Analyze email", self.email_draft, "email")

    def add_cyber_banner(self, parent, title, subtitle):
        """Add an animated cyber-security HUD banner to interior pages."""
        shell = tk.Frame(parent, bg=self.c("panel"), highlightthickness=1,
                         highlightbackground=self.c("border"))
        shell.pack(fill="x", pady=(0, 12))
        canvas = tk.Canvas(shell, height=92, bg=self.c("panel"), highlightthickness=0)
        canvas.pack(fill="x", expand=True)

        def draw(frame=0, schedule=True):
            try:
                if not canvas.winfo_exists():
                    return
                canvas.delete("all")
                w = max(canvas.winfo_width(), 500)
                h = max(canvas.winfo_height(), 92)
                accent, border = self.c("accent"), self.c("border")
                # Subtle technical grid and animated scanning line.
                for x in range(0, w, 28):
                    canvas.create_line(x, 0, x, h, fill=border, width=1)
                for y in range(0, h, 18):
                    canvas.create_line(0, y, w, y, fill=border, width=1)
                scan_x = (frame * 7) % max(w, 1)
                canvas.create_rectangle(scan_x - 20, 0, scan_x + 20, h,
                                        fill=self.c("panel2"), outline="")
                # Holographic shield emblem on the right.
                cx, cy = w - 78, h / 2
                for r in (25, 34, 43):
                    canvas.create_oval(cx-r, cy-r, cx+r, cy+r,
                                       outline=border, width=1)
                canvas.create_polygon(cx, cy-25, cx+21, cy-16, cx+17, cy+10,
                                      cx, cy+27, cx-17, cy+10, cx-21, cy-16,
                                      fill=self.c("panel2"), outline=accent, width=2)
                canvas.create_text(cx, cy, text="S", fill=accent,
                                   font=("Helvetica", 16, "bold"))
                # Moving signal nodes.
                for i in range(8):
                    x = (frame * (2 + i % 3) + i * 73) % max(w - 150, 1)
                    y = 14 + (i * 17) % 62
                    canvas.create_oval(x-2, y-2, x+2, y+2,
                                       fill=accent if i % 2 == 0 else self.c("accent2"), outline="")
                canvas.create_text(22, 28, text=title.upper(), anchor="w",
                                   fill=accent, font=("Helvetica", 10, "bold"))
                canvas.create_text(22, 53, text=subtitle, anchor="w",
                                   fill=self.c("text"), font=("Helvetica", 10))
                canvas.create_text(w-140, h-10, text="SHIELD // ACTIVE DEFENCE",
                                   fill=self.c("muted"), font=("Menlo", 7, "bold"))
                if schedule:
                    canvas.after(110, lambda: draw(frame + 1))
            except tk.TclError:
                return
        canvas.bind("<Configure>", lambda _event: draw(schedule=False))
        canvas.after_idle(draw)
        return shell

    def add_page_visual(self, parent, visual_kind, title, subtitle):
        """Add a unique animated cybersecurity graphic inside each workspace page."""
        shell = tk.Frame(parent, bg=self.c("panel"), highlightthickness=1,
                         highlightbackground=self.c("border"))
        shell.pack(fill="x", pady=(0, 12))
        canvas = tk.Canvas(shell, height=106, bg=self.c("panel"), highlightthickness=0)
        canvas.pack(fill="x", expand=True)

        def draw(frame=0, schedule=True):
            try:
                if not canvas.winfo_exists():
                    return
                canvas.delete("all")
                w = max(canvas.winfo_width(), 480)
                h = max(canvas.winfo_height(), 106)
                accent, accent2 = self.c("accent"), self.c("accent2")
                border, muted = self.c("border"), self.c("muted")
                # Circuit-board grid and a slowly moving scan beam.
                for x in range(0, w, 24):
                    canvas.create_line(x, 0, x, h, fill=border)
                for y in range(0, h, 18):
                    canvas.create_line(0, y, w, y, fill=border)
                beam_x = (frame * 5) % (w + 80) - 40
                canvas.create_rectangle(beam_x - 12, 0, beam_x + 12, h,
                                        fill=self.c("panel2"), outline="")
                canvas.create_text(18, 21, text=title.upper(), anchor="w",
                                   fill=accent, font=("Helvetica", 10, "bold"))
                canvas.create_text(18, 43, text=subtitle, anchor="w",
                                   fill=self.c("text"), font=("Helvetica", 9))
                # Draw a different animated visual for each page.
                cx, cy = w - 92, h // 2 + 2
                if visual_kind == "message":
                    # Chat bubble + moving waveform.
                    canvas.create_rectangle(cx-32, cy-24, cx+30, cy+17,
                                            outline=accent, width=2)
                    canvas.create_polygon(cx-16, cy+17, cx-23, cy+27, cx-5, cy+17,
                                          fill=accent, outline=accent)
                    for i in range(9):
                        x = cx - 24 + i * 6
                        amp = 4 + abs(((frame + i * 7) % 18) - 9) * 1.1
                        canvas.create_line(x, cy-amp/2, x, cy+amp/2,
                                           fill=accent2 if i % 3 == 0 else accent, width=2)
                elif visual_kind == "url":
                    # Network nodes connected by animated pulses.
                    nodes = [(cx-38, cy+10), (cx-14, cy-20), (cx+14, cy+18), (cx+39, cy-13)]
                    for a, b in zip(nodes, nodes[1:]):
                        canvas.create_line(a[0], a[1], b[0], b[1], fill=accent, width=2)
                    for i, (x, y) in enumerate(nodes):
                        r = 5 + ((frame // 3 + i) % 3)
                        canvas.create_oval(x-r, y-r, x+r, y+r,
                                           fill=self.c("panel2"), outline=accent2 if i % 2 else accent, width=2)
                    px = cx - 38 + ((frame * 2) % 77)
                    canvas.create_oval(px-3, cy-3, px+3, cy+3, fill=accent, outline="")
                elif visual_kind == "email":
                    canvas.create_rectangle(cx-39, cy-25, cx+39, cy+25, outline=accent, width=2)
                    canvas.create_line(cx-39, cy-25, cx, cy+4, cx+39, cy-25,
                                       fill=accent2, width=2)
                    canvas.create_line(cx-39, cy+25, cx-8, cy-1, fill=accent, width=1)
                    canvas.create_line(cx+39, cy+25, cx+8, cy-1, fill=accent, width=1)
                    for i in range(3):
                        xx = cx - 27 + i * 27
                        yy = cy + 35 + (frame + i * 5) % 7
                        canvas.create_oval(xx-2, yy-2, xx+2, yy+2, fill=accent2, outline="")
                elif visual_kind == "history":
                    # Animated activity bars and timeline.
                    canvas.create_line(cx-46, cy+27, cx+46, cy+27, fill=muted)
                    for i in range(9):
                        bh = 10 + ((frame * (i+2) + i*13) % 34)
                        x = cx - 39 + i * 10
                        canvas.create_rectangle(x, cy+25-bh, x+5, cy+25,
                                                fill=accent if i % 2 else accent2, outline="")
                    canvas.create_line(cx-42, cy-28, cx+42, cy-28, fill=border, dash=(3, 3))
                elif visual_kind == "lab":
                    # Scanner target with rotating sweep and pulse rings.
                    for r in (15, 27, 39):
                        canvas.create_oval(cx-r, cy-r, cx+r, cy+r, outline=border, width=1)
                    angle = math.radians((frame * 8) % 360)
                    ex, ey = cx + 38 * math.cos(angle), cy + 38 * math.sin(angle)
                    canvas.create_line(cx, cy, ex, ey, fill=accent, width=2)
                    canvas.create_oval(cx-4, cy-4, cx+4, cy+4, fill=accent2, outline="")
                else:  # settings / security controls
                    # Lock and orbiting status indicators.
                    canvas.create_arc(cx-19, cy-29, cx+19, cy+12, start=0, extent=180,
                                      style="arc", outline=accent, width=3)
                    canvas.create_rectangle(cx-27, cy-8, cx+27, cy+29,
                                            outline=accent2, width=2)
                    canvas.create_oval(cx-4, cy+1, cx+4, cy+9, fill=accent, outline="")
                    canvas.create_line(cx, cy+8, cx, cy+17, fill=accent, width=2)
                    for i in range(4):
                        ang = math.radians(frame * 4 + i * 90)
                        ox, oy = cx + 43 * math.cos(ang), cy + 43 * math.sin(ang)
                        canvas.create_oval(ox-2, oy-2, ox+2, oy+2,
                                           fill=accent if i % 2 == 0 else accent2, outline="")
                # Small live status strip gives the panel an animated HUD feel.
                status = "SIGNAL LOCKED" if frame % 80 < 55 else "ANALYZING SIGNAL"
                canvas.create_text(w-18, h-9, text=status, anchor="e",
                                   fill=accent if frame % 80 < 55 else accent2,
                                   font=("Menlo", 7, "bold"))
                if schedule:
                    canvas.after(110, lambda: draw(frame + 1))
            except tk.TclError:
                return

        canvas.bind("<Configure>", lambda _event: draw(schedule=False))
        canvas.after_idle(draw)
        return shell

    def scanner_page(self, title, description, placeholder, action, draft, kind, compact=False):

        self.add_cyber_banner(self.content, title, "LOCAL THREAT INTELLIGENCE  •  ANALYZE BEFORE YOU ACT")

        head = self.card(self.content, bg=self.c("panel"), padx=18, pady=15)

        head.pack(fill="x", pady=(0, 12))

        self.label(head, "LOCAL HEURISTIC SCAN", 8, "bold", self.c("accent")).pack(anchor="w")

        self.label(head, description, 10, "normal", self.c("muted")).pack(anchor="w", pady=(5, 0))

        visual_titles = {
            "message": ("Message threat radar", "CHAT SIGNALS  •  SOCIAL ENGINEERING  •  OTP BAIT"),
            "url": ("Link intelligence network", "DOMAIN STRUCTURE  •  REDIRECTS  •  TRUST SIGNALS"),
            "email": ("Email inspection bay", "SENDER CONTEXT  •  URGENCY  •  CREDENTIAL REQUESTS"),
        }
        visual_title, visual_subtitle = visual_titles.get(kind, ("Threat analysis", "LOCAL SIGNAL ANALYSIS"))
        self.add_page_visual(self.content, kind, visual_title, visual_subtitle)

        area = self.card(self.content)

        area.pack(fill="x", pady=(0, 12))

        self.label(area, "INPUT PAYLOAD", 9, "bold", self.c("muted")).pack(anchor="w", pady=(0, 8))

        box = self.input_box(area, height=4 if compact else 8)

        box.pack(fill="x")

        if draft:

            box.insert("1.0", draft)

        elif placeholder:

            box.insert("1.0", placeholder)

            box.configure(fg=self.c("muted"))

            def clear_hint(event):

                if box.get("1.0", "end-1c") == placeholder:

                    box.delete("1.0", "end")

                    box.configure(fg=self.c("text"))

            box.bind("<FocusIn>", clear_hint)

        if kind == "message":

            self.message_box = box

        elif kind == "url":

            self.url_box = box

        else:

            self.email_box = box

        controls = tk.Frame(area, bg=self.c("card"))

        controls.pack(fill="x", pady=(10, 0))

        self.button(controls, "⌕  " + action, lambda: self.run_scan(kind, box, placeholder), True).pack(side="left")

        self.button(controls, "Clear input", lambda: self.clear_box(box)).pack(side="left", padx=8)

        self.label(controls, "Runs locally · no cloud upload", 8, "normal", self.c("muted")).pack(side="right", pady=8)

        result_card = self.card(self.content, padx=18, pady=14)

        result_card.pack(fill="both", expand=True)

        self.label(result_card, "SCAN RESULT", 9, "bold", self.c("muted")).pack(anchor="w")

        self.result_area = tk.Frame(result_card, bg=self.c("card"))

        self.result_area.pack(fill="both", expand=True, pady=(8, 0))

        if self.last_result and self.last_result.get("kind") == kind:

            self.render_result(self.last_result["result"], self.result_area)

        else:

            self.label(self.result_area, "Your risk score and explanation will stay here after scanning.", 10, "normal", self.c("muted")).pack(anchor="w", pady=12)

    def clear_box(self, box):

        box.delete("1.0", "end")

        box.focus_set()

    def run_scan(self, kind, box, placeholder):
        try:
            raw = box.get("1.0", "end-1c").strip()
        except tk.TclError:
            return
        if raw == placeholder:
            raw = ""
        if not raw:
            messagebox.showinfo("ShieldAI", "Enter some content to scan first.")
            return

        # Invalidate any older pending scan so rapid clicks cannot race each other.
        self._scan_generation += 1
        generation = self._scan_generation
        target_page = self.current_page

        target_area = getattr(self, "result_area", None)
        if target_area is not None:
            try:
                if target_area.winfo_exists():
                    for child in target_area.winfo_children():
                        child.destroy()
                    self.show_scan_animation(target_area, kind, raw)
            except tk.TclError:
                target_area = None

        self.root.after(
            1100,
            lambda: self.finish_scan(kind, raw, generation, target_page)
        )

    def show_scan_animation(self, parent, kind, raw):
        """Render a lightweight radar/progress animation using Tkinter only."""
        panel = tk.Frame(parent, bg=self.c("card"))
        panel.pack(fill="both", expand=True, pady=8)

        radar = tk.Canvas(panel, width=150, height=150, bg=self.c("card"),
                          highlightthickness=0)
        radar.pack(side="left", padx=(8, 22))
        radar.create_oval(15, 15, 135, 135, outline=self.c("border"), width=2)
        radar.create_oval(35, 35, 115, 115, outline=self.c("border"), width=1)
        radar.create_oval(55, 55, 95, 95, outline=self.c("border"), width=1)
        radar.create_line(75, 15, 75, 135, fill=self.c("border"))
        radar.create_line(15, 75, 135, 75, fill=self.c("border"))
        sweep = radar.create_line(75, 75, 75, 18, fill=self.c("accent"), width=3)
        radar.create_oval(70, 70, 80, 80, fill=self.c("accent"), outline="")

        info = tk.Frame(panel, bg=self.c("card"))
        info.pack(side="left", fill="both", expand=True, padx=(0, 10))
        title = self.label(info, "SCANNING IN PROGRESS", 13, "bold", self.c("accent"))
        title.pack(anchor="w", pady=(10, 6))
        status = self.label(info, "Preparing local detection rules…", 10, "normal", self.c("muted"))
        status.pack(anchor="w", pady=(0, 12))
        bar = tk.Canvas(info, height=10, bg=self.c("panel2"), highlightthickness=0)
        bar.pack(fill="x", pady=(0, 10))
        fill = bar.create_rectangle(0, 0, 0, 10, fill=self.c("accent"), outline="")
        self.label(info, f"Analyzing {kind.upper()} · checking indicators · saving locally",
                   8, "normal", self.c("muted")).pack(anchor="w")

        self._scan_animation = {"parent": parent, "radar": radar, "sweep": sweep,
                                "status": status, "bar": bar, "fill": fill,
                                "step": 0, "kind": kind, "raw": raw}
        self.animate_scan_step()

    def animate_scan_step(self):
        anim = getattr(self, "_scan_animation", None)
        if not anim:
            return
        try:
            if not anim["parent"].winfo_exists():
                return
            step = anim["step"] + 1
            anim["step"] = step
            angle = (step * 22) % 360
            import math
            x = 75 + 57 * math.sin(math.radians(angle))
            y = 75 - 57 * math.cos(math.radians(angle))
            anim["radar"].coords(anim["sweep"], 75, 75, x, y)
            width = max(anim["bar"].winfo_width(), 1)
            progress = min(0.96, step / 14)
            anim["bar"].coords(anim["fill"], 0, 0, width * progress, 10)
            messages = ["Preparing local detection rules…", "Checking suspicious phrases…",
                        "Inspecting links and urgency signals…", "Calculating risk score…",
                        "Preparing explanation and safety advice…"]
            anim["status"].configure(text=messages[min((step - 1) // 3, len(messages) - 1)])
            self.root.after(70, self.animate_scan_step)
        except tk.TclError:
            return

    def finish_scan(self, kind, raw, generation=None, target_page=None):
        # Ignore an obsolete callback if the user has started a newer scan.
        if generation is not None and generation != self._scan_generation:
            return
        self._scan_animation = None
        result = scan_url(raw) if kind == "url" else scan_text(raw)
        self.last_result = {"kind": kind, "result": result}

        if kind == "message":
            self.message_draft = raw
        elif kind == "url":
            self.url_draft = raw
        else:
            self.email_draft = raw

        cursor = self.db.execute(
            "INSERT INTO scans (created_at,scan_type,subject,score,level,category,reasons,user_id) VALUES (?,?,?,?,?,?,?,?)",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), kind.upper(), raw[:500],
             result["score"], result["level"], result["category"],
             " | ".join(result["reasons"]), self.current_user_id))
        self.last_scan_id = cursor.lastrowid
        self.db.commit()

        # Only render into the matching page. Navigating during a scan must not
        # put a message result inside the URL or email scanner.
        if target_page is None or self.current_page == target_page:
            area = getattr(self, "result_area", None)
            try:
                if area is not None and area.winfo_exists():
                    for child in area.winfo_children():
                        child.destroy()
                    self.render_result(result, area)
            except tk.TclError:
                pass
        self.update_protection_ui()
        if kind == "url":
            self.start_live_lookup(raw, result, self.last_scan_id)

    def start_live_lookup(self, raw, result, scan_id):
        """Perform optional VirusTotal lookup off the Tkinter UI thread."""
        if not os.environ.get("SHIELDAI_VT_API_KEY", "").strip():
            return
        def worker():
            live = lookup_virustotal(raw)
            def update_ui():
                if not self.root.winfo_exists():
                    return
                if live.get("available"):
                    live_text = live["message"]
                    # Recalculate a conservative combined score from local score and reputation.
                    if live.get("malicious", 0) > 0:
                        result["score"] = max(result["score"], min(100, 60 + 5 * live["malicious"]))
                        result["level"] = "HIGH RISK" if result["score"] >= 60 else result["level"]
                        result["reasons"].append("VirusTotal reports one or more malicious detections")
                        result["advice"] = "Avoid opening this URL. Do not enter credentials or payment details."
                    elif live.get("suspicious", 0) > 0:
                        result["score"] = max(result["score"], 40)
                        result["level"] = "SUSPICIOUS"
                        result["reasons"].append("VirusTotal reports suspicious detections")
                    result["live_reputation"] = live_text
                    self.db.execute("UPDATE scans SET score=?, level=?, reasons=? WHERE id=?", (result["score"], result["level"], " | ".join(result["reasons"]), scan_id))
                    self.db.commit()
                else:
                    result["live_reputation"] = live.get("message", "Live lookup unavailable.")
                if hasattr(self, "result_area") and self.result_area.winfo_exists():
                    for child in self.result_area.winfo_children():
                        child.destroy()
                    self.render_result(result, self.result_area)
                self.update_protection_ui()
            self.root.after(0, update_ui)
        threading.Thread(target=worker, daemon=True).start()

    def risk_color(self, score):

        return self.c("bad") if score >= 70 else self.c("warn") if score >= 35 else self.c("good")

    def render_result(self, result, parent):

        wrap = tk.Frame(parent, bg=self.c("card"))

        wrap.pack(fill="both", expand=True)

        gauge = tk.Canvas(wrap, width=164, height=164, bg=self.c("card"), highlightthickness=0)
        gauge.pack(side="left", padx=(0, 20), pady=2)

        score = clamp(result["score"])
        color = self.risk_color(score)

        # Full track plus a score-proportional coloured arc.
        # Avoid exactly 360 degrees because Tk Canvas may omit a full arc.
        x1, y1, x2, y2 = 12, 12, 152, 152
        gauge.create_oval(x1, y1, x2, y2, outline=self.c("border"), width=12)
        extent = min(359.5, 3.6 * score)
        if score > 0:
            gauge.create_arc(x1, y1, x2, y2, start=90, extent=-extent,
                             style="arc", outline=color, width=12)
            import math
            angle = math.radians(90 - extent)
            cx, cy, radius = 82, 82, 64
            px = cx + radius * math.cos(angle)
            py = cy - radius * math.sin(angle)
            gauge.create_oval(px-5, py-5, px+5, py+5, fill=color, outline=color)

        gauge.create_text(82, 70, text=str(score), fill=color,
                          font=("Helvetica", 29, "bold"))
        gauge.create_text(82, 98, text="/ 100 RISK", fill=self.c("muted"),
                          font=("Helvetica", 8, "bold"))

        info = tk.Frame(wrap, bg=self.c("card"))

        info.pack(side="left", fill="both", expand=True)

        self.label(info, result["level"], 15, "bold", color).pack(anchor="w")

        self.label(info, result.get("category", "Content analysis"), 10, "bold").pack(anchor="w", pady=(4, 8))

        self.label(info, "Why it was flagged", 9, "bold", self.c("muted")).pack(anchor="w")

        for reason in result["reasons"]:

            self.label(info, "• " + reason, 9, "normal").pack(anchor="w", pady=2)

        self.label(info, "Recommended action", 9, "bold", self.c("muted")).pack(anchor="w", pady=(8, 2))

        self.label(info, result["advice"], 9, "normal").pack(anchor="w")

        if result.get("live_reputation"):
            self.label(info, result["live_reputation"], 9, "bold", self.c("accent")).pack(anchor="w", pady=(7, 0))

        self.label(info, "Heuristic result only — never proof that content is safe.", 8, "normal", self.c("muted")).pack(anchor="w", pady=(8, 0))

    def get_stats(self):

        total = self.db.execute("SELECT COUNT(*) FROM scans WHERE user_id=?", (self.current_user_id,)).fetchone()[0]

        high = self.db.execute("SELECT COUNT(*) FROM scans WHERE score >= 70 AND user_id=?", (self.current_user_id,)).fetchone()[0]

        today = self.db.execute("SELECT COUNT(*) FROM scans WHERE created_at LIKE ? AND user_id=?",

                                (datetime.now().strftime("%Y-%m-%d") + "%", self.current_user_id)).fetchone()[0]

        return total, high, today

    def page_history(self):

        self.add_cyber_banner(self.content, "Threat activity archive", "YOUR SCAN HISTORY  •  STORED LOCALLY ON THIS DEVICE")
        self.add_page_visual(self.content, "history", "Threat timeline", "SCAN EVENTS  •  RISK SIGNALS  •  LOCAL ACTIVITY")

        wrap = self.card(self.content, padx=14, pady=14)

        wrap.pack(fill="both", expand=True)

        bar = tk.Frame(wrap, bg=self.c("card"))

        bar.pack(fill="x", pady=(0, 10))

        self.label(bar, "Saved locally in shieldai_history.db", 9, "normal", self.c("muted")).pack(side="left")

        self.button(bar, "Refresh", lambda: self.show_page("Scan History")).pack(side="right", padx=4)

        self.button(bar, "Clear history", self.clear_history).pack(side="right", padx=4)

        cols = ("date", "type", "score", "risk", "category")
        row_ids = {}

        tree = ttk.Treeview(wrap, columns=cols, show="headings")

        for col, heading, width in [("date","DATE / TIME",155),("type","TYPE",100),("score","SCORE",70),

                                     ("risk","RISK LEVEL",110),("category","CATEGORY",220)]:

            tree.heading(col, text=heading)

            tree.column(col, width=width, anchor="w")

        tree.pack(fill="both", expand=True)

        rows = self.db.execute("SELECT id,created_at,scan_type,score,level,category FROM scans WHERE user_id=? ORDER BY id DESC", (self.current_user_id,)).fetchall()

        for scan_id, created_at, scan_type, score, level, category in rows:
            iid = tree.insert("", "end", values=(created_at, scan_type, score, level, category))
            row_ids[iid] = scan_id

        self.label(wrap, f"{len(rows)} saved scan(s). Select a row to view its details.", 8, "normal", self.c("muted")).pack(anchor="w", pady=(8, 0))

        def details(_event):

            selected = tree.selection()

            if not selected:

                return

            scan_id = row_ids.get(selected[0])
            if scan_id is None:
                return
            row = self.db.execute(
                "SELECT subject,reasons FROM scans WHERE id=? AND user_id=?",
                (scan_id, self.current_user_id)
            ).fetchone()

            if row:

                messagebox.showinfo("Scan details", f"Input preview:\n{row[0][:800]}\n\nIndicators:\n{row[1]}")

        tree.bind("<TreeviewSelect>", details)

    def clear_history(self):

        if messagebox.askyesno("Clear history", "Delete all locally saved ShieldAI scan history?"):

            self.db.execute("DELETE FROM scans WHERE user_id=?", (self.current_user_id,))

            self.db.commit()

            self.show_page("Scan History")

    def page_test_lab(self):

        self.add_cyber_banner(self.content, "Cyber simulation lab", "TEST FICTIONAL THREATS  •  IMPROVE YOUR DETECTION RULES")
        self.add_page_visual(self.content, "lab", "Detection simulation", "SAFE PAYLOADS  •  RULE TESTING  •  EXPLAINABLE RESULTS")

        intro = self.card(self.content, bg=self.c("panel"))

        intro.pack(fill="x", pady=(0, 12))

        self.label(intro, "SAFE TEST LAB", 9, "bold", self.c("accent")).pack(anchor="w")

        self.label(intro, "Use sample payloads to test the scanner. These are fictional examples.", 10, "normal", self.c("muted")).pack(anchor="w", pady=(5, 0))

        samples = [

            ("High-risk SMS", "URGENT: Your bank account will be blocked today. Update KYC now at http://sbi-secure-check.example.invalid and share your OTP."),

            ("Reward scam", "Congratulations! You won a free gift reward. Click here and pay a processing fee to claim your prize."),

            ("Suspicious URL", "http://secure-account-login.example.invalid/verify"),

            ("Lower-signal message", "Hi, our meeting is at 4 PM. Please bring the project notes.")

        ]

        for title, payload in samples:

            row = self.card(self.content, padx=14, pady=12)

            row.pack(fill="x", pady=5)

            self.label(row, title, 10, "bold").pack(side="left")

            self.button(row, "Test message", lambda p=payload: self.load_sample("message", p)).pack(side="right")

            self.label(row, payload, 8, "normal", self.c("muted")).pack(anchor="w", pady=(7, 0))

    def load_sample(self, kind, payload):

        if kind == "message":

            self.show_page("Message Scanner")

            self.message_box.delete("1.0", "end")

            self.message_box.insert("1.0", payload)

            self.run_scan("message", self.message_box, "")

        else:

            self.show_page("URL Scanner")

            self.url_box.delete("1.0", "end")

            self.url_box.insert("1.0", payload)

            self.run_scan("url", self.url_box, "")

    def assistant_reply(self, question):
        """Offline cyber-safety helper; this is rule-based, not a cloud AI model."""
        q = question.strip().lower()
        result = self.last_result or {}
        if not q:
            return "Ask about your latest scan, phishing links, OTPs, UPI payments, suspicious jobs, or reporting fraud."
        if any(x in q for x in ("latest scan", "last scan", "my result", "explain score", "explain result")):
            if "score" not in result:
                return "No scan result is available in this session. Run a message, URL, or email scan first, then ask me again."
            reasons = "\n".join("• " + str(x) for x in result.get("reasons", [])[:6])
            return (f"Latest result: {result.get('level', 'UNKNOWN')} — {result['score']}/100.\n\n"
                    f"Why it was flagged:\n{reasons or 'No configured warning pattern found.'}\n\n"
                    f"Recommended action: {result.get('advice', 'Verify independently.')}\n\n"
                    "This is a rule-based score, not a probability or a guarantee.")
        if any(x in q for x in ("otp", "verification code", "one time password")):
            return ("Never share an OTP or verification code with a caller, chat account, or anyone claiming to be support. "
                    "If you already shared it, contact the service through its official app/site immediately and secure your account.")
        if any(x in q for x in ("upi", "payment", "money", "transfer", "qr code", "collect request")):
            return ("Receiving money normally does not require entering your UPI PIN. Never enter your PIN to receive a refund, "
                    "approve an unexpected collect request, or scan a QR code sent by a stranger. Check the recipient and amount.")
        if any(x in q for x in ("link", "url", "website", "domain", "phishing")):
            return ("Avoid unexpected links. Check the exact domain spelling and beware of shortened links and look-alike brands. "
                    "Visit the service by typing its known official address. ShieldAI's URL checks inspect structure; they don't "
                    "prove a site is safe or perform live reputation checks by default.")
        if any(x in q for x in ("kyc", "bank", "account blocked", "account suspended")):
            return ("Treat urgent KYC or account-blocking messages with suspicion. Don't use the message's link or phone number. "
                    "Open your bank's official app or call the number printed on your card or official statement.")
        if any(x in q for x in ("job", "work from home", "investment", "prize", "reward", "lottery")):
            return ("Be cautious of guaranteed income, unexpected prizes, and requests for registration or processing fees. "
                    "Do not pay to unlock a job or prize. Verify the company independently.")
        if any(x in q for x in ("report", "complaint", "cybercrime", "1930", "india")):
            return ("If money was lost in India, contact your bank/payment provider immediately and call cyber fraud helpline 1930 "
                    "as soon as possible. You can also report at https://cybercrime.gov.in. Preserve transaction IDs and screenshots.")
        if any(x in q for x in ("safe", "low score", "score meaning", "risk score")):
            return ("The score is a heuristic warning score, not the probability that something is fraudulent. A low score only "
                    "means fewer configured rules matched; new scams can evade checks. Verify the sender independently.")
        if any(x in q for x in ("privacy", "data", "upload", "stored", "cloud")):
            return (f"Scan history is stored in the local SQLite file {DB_FILE}. This assistant answers locally and doesn't send "
                    "your question to an AI service. Optional VirusTotal lookup sends the submitted URL to VirusTotal.")
        if any(x in q for x in ("hello", "hi", "hey", "help")):
            return ("Hi! I'm ShieldAI Cyber Assistant. Try 'Explain my latest scan', 'What should I do about an OTP scam?', "
                    "'Is this link safe?', or 'How do I report cyber fraud in India?'")
        return ("I can explain scan results and help with OTP/UPI safety, phishing links, KYC messages, job/prize scams, privacy, "
                "and reporting cyber fraud in India. I'm an offline rule-based assistant in this version, so I may not understand every question.")

    def page_ai_assistant(self):
        self.add_cyber_banner(self.content, "ShieldAI Cyber Assistant",
                              "ASK • UNDERSTAND • ACT SAFELY  /  OFFLINE GUIDANCE")
        self.add_page_visual(self.content, "assistant", "Cyber safety companion",
                             "LOCAL RESPONSES  •  SCAN EXPLANATIONS  •  PRACTICAL NEXT STEPS")
        intro = self.card(self.content, bg=self.c("panel"))
        intro.pack(fill="x", pady=(0, 12))
        self.label(intro, "Your cybersecurity helper", 14, "bold", self.c("text")).pack(anchor="w")
        self.label(intro, "Ask in plain language about phishing, OTPs, UPI, suspicious links, reporting fraud, or your latest scan.",
                   9, "normal", self.c("muted")).pack(anchor="w", pady=(5, 0))
        self.label(intro, "Privacy: answers use local rules. This is not a cloud generative AI model.",
                   8, "bold", self.c("accent")).pack(anchor="w", pady=(8, 0))

        quick = self.card(self.content, bg=self.c("panel"), padx=14, pady=12)
        quick.pack(fill="x", pady=(0, 12))
        self.label(quick, "QUICK QUESTIONS", 9, "bold", self.c("muted")).pack(anchor="w", pady=(0, 8))
        quick_row = tk.Frame(quick, bg=self.c("panel"))
        quick_row.pack(fill="x")
        for prompt in ("Explain my latest scan", "What should I do about an OTP scam?",
                       "Is this link safe?", "How do I report cyber fraud in India?"):
            self.button(quick_row, prompt, lambda p=prompt: self._assistant_send(p)).pack(
                side="left", fill="x", expand=True, padx=3, pady=2)

        chat = self.card(self.content, bg=self.c("panel"))
        chat.pack(fill="both", expand=True, pady=(0, 12))
        self.label(chat, "CONVERSATION", 9, "bold", self.c("muted")).pack(anchor="w", pady=(0, 8))
        transcript = tk.Text(chat, height=14, wrap="word", state="disabled",
                             bg=self.c("input"), fg=self.c("text"), insertbackground=self.c("text"),
                             relief="flat", bd=0, font=("Helvetica", 10), padx=12, pady=12)
        transcript.pack(fill="both", expand=True)
        transcript.tag_configure("user", foreground=self.c("accent"), font=("Helvetica", 10, "bold"))
        transcript.tag_configure("assistant", foreground=self.c("good"), font=("Helvetica", 10, "bold"))
        transcript.tag_configure("body", foreground=self.c("text"))
        self.assistant_transcript = transcript
        if not self.assistant_history:
            self.assistant_history.append(("assistant",
                "Welcome to ShieldAI Cyber Assistant. Ask me to explain your latest scan or choose a quick question."))
        self._assistant_render_history()

        row = tk.Frame(chat, bg=self.c("panel"))
        row.pack(fill="x", pady=(10, 0))
        entry = tk.Entry(row, font=("Helvetica", 10), relief="flat", bg=self.c("input"),
                         fg=self.c("text"), insertbackground=self.c("text"))
        entry.pack(side="left", fill="x", expand=True, ipady=10, padx=(0, 8))
        entry.insert(0, "Ask a cyber-safety question...")
        entry.bind("<FocusIn>", lambda _e: entry.delete(0, "end")
                   if entry.get() == "Ask a cyber-safety question..." else None)
        entry.bind("<Return>", lambda _e: self._assistant_send(entry.get(), entry))
        self.assistant_entry = entry
        self.button(row, "Ask", lambda: self._assistant_send(entry.get(), entry), True).pack(side="right")
        voice_row = tk.Frame(chat, bg=self.c("panel"))
        voice_row.pack(fill="x", pady=(8, 0))
        self.button(voice_row, "🔊 Speak last reply", self._assistant_speak_last).pack(side="left", padx=(0, 6))
        self.button(voice_row, "🎙 Voice input", lambda: self._assistant_voice_input(entry)).pack(side="left", padx=(0, 6))
        self.button(voice_row, "■ Stop voice", self._assistant_stop_speech).pack(side="left")
        self.label(chat, "Voice output uses the built-in macOS speech engine. Microphone input needs the optional SpeechRecognition and PyAudio packages.",
                   8, "normal", self.c("muted")).pack(anchor="w", pady=(8, 0))
        self.label(chat, "If money was lost, contact your bank/payment provider immediately.",
                   8, "normal", self.c("muted")).pack(anchor="w", pady=(4, 0))

    def _assistant_render_history(self):
        widget = getattr(self, "assistant_transcript", None)
        if widget is None:
            return
        try:
            if not widget.winfo_exists():
                return
            widget.configure(state="normal")
            widget.delete("1.0", "end")
            for role, message in self.assistant_history[-30:]:
                widget.insert("end", "YOU\n" if role == "user" else "SHIELDAI ASSISTANT\n",
                              "user" if role == "user" else "assistant")
                widget.insert("end", message + "\n\n", "body")
            widget.configure(state="disabled")
            widget.see("end")
        except tk.TclError:
            return

    def _assistant_send(self, question, entry_widget=None):
        question = (question or "").strip()
        if not question or question == "Ask a cyber-safety question...":
            return
        self.assistant_history.append(("user", question))
        self.assistant_history.append(("assistant", self.assistant_reply(question)))
        self._assistant_render_history()
        if entry_widget is not None:
            try:
                entry_widget.delete(0, "end")
                entry_widget.focus_set()
            except tk.TclError:
                pass

    def _assistant_speak(self, text_to_speak):
        """Speak text using macOS's built-in `say` command without blocking Tkinter."""
        text_to_speak = (text_to_speak or "").strip()
        if not text_to_speak:
            self.show_toast("There is no assistant reply to speak yet.")
            return
        if sys.platform != "darwin":
            messagebox.showinfo(
                "Voice output",
                "Built-in voice output in this version uses the macOS 'say' command."
            )
            return

        def worker():
            try:
                # Stop an older speech process before starting another.
                old = self._voice_process
                if old is not None and old.poll() is None:
                    old.terminate()
                process = subprocess.Popen(
                    ["say", "-r", "190", text_to_speak],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                self._voice_process = process
                process.wait()
            except Exception:
                pass
            finally:
                self._voice_process = None

        threading.Thread(target=worker, daemon=True).start()
        self.show_toast("Speaking assistant reply…")

    def _assistant_speak_last(self):
        for role, message in reversed(self.assistant_history):
            if role == "assistant":
                self._assistant_speak(message)
                return
        self.show_toast("Ask a question first to get an assistant reply.")

    def _assistant_stop_speech(self):
        process = self._voice_process
        if process is not None and process.poll() is None:
            try:
                process.terminate()
            except Exception:
                pass
        self._voice_process = None
        self.show_toast("Voice playback stopped.")

    def _assistant_voice_input(self, entry_widget):
        """Optional microphone input. Recognition runs off the Tkinter main thread."""
        try:
            import speech_recognition as sr
        except ImportError:
            messagebox.showinfo(
                "Enable voice input",
                "Microphone input is optional and is not part of Python's standard library.\n\n"
                "In the VS Code terminal, install it with:\n"
                "python3 -m pip install SpeechRecognition pyaudio\n\n"
                "Then allow microphone access for your terminal/VS Code in macOS System Settings. "
                "Speech recognition may use an online recognition service."
            )
            return

        if self._voice_busy:
            self.show_toast("Voice input is already listening.")
            return
        self._voice_busy = True
        self.show_toast("Listening… speak clearly after the prompt.")

        def worker():
            recognized = None
            error = None
            try:
                recognizer = sr.Recognizer()
                with sr.Microphone() as source:
                    recognizer.adjust_for_ambient_noise(source, duration=0.5)
                    audio = recognizer.listen(source, timeout=5, phrase_time_limit=12)
                recognized = recognizer.recognize_google(audio)
            except sr.WaitTimeoutError:
                error = "I didn't hear anything. Try Voice input again."
            except sr.UnknownValueError:
                error = "I couldn't understand that audio. Please try again."
            except Exception as exc:
                error = f"Voice input failed: {exc}"

            def finish():
                self._voice_busy = False
                if recognized:
                    try:
                        entry_widget.delete(0, "end")
                        entry_widget.insert(0, recognized)
                        self._assistant_send(recognized, entry_widget)
                    except tk.TclError:
                        self.show_toast("Voice text was recognised, but the input field is no longer available.")
                elif error:
                    messagebox.showinfo("Voice input", error)
            try:
                self.root.after(0, finish)
            except tk.TclError:
                self._voice_busy = False

        threading.Thread(target=worker, daemon=True).start()

    def page_settings(self):

        self.add_cyber_banner(self.content, "Security control center", "CONFIGURE LOCAL PROTECTION  •  PRIVACY AND APP CONTROLS")
        self.add_page_visual(self.content, "settings", "Security systems", "LOCAL PROTECTION  •  DATA PRIVACY  •  ACCOUNT CONTROLS")

        panel = self.card(self.content, bg=self.c("panel"))

        panel.pack(fill="x", pady=(0, 12))

        self.label(panel, "Protection controls", 13, "bold").pack(anchor="w")

        self.label(panel, "This switch controls ShieldAI's in-app protection state. It does not monitor other apps or all device traffic.", 10, "normal", self.c("muted")).pack(anchor="w", pady=(5, 12))

        self.button(panel, "Turn local protection " + ("OFF" if self.protection_on else "ON"), self.toggle_protection, True).pack(anchor="w")

        student = self.card(self.content)

        student.pack(fill="x", pady=8)

        self.label(student, "Student-friendly explanations", 12, "bold").pack(anchor="w")

        self.label(student, "Scans list the rules contributing to each score. Optional VirusTotal reputation lookup requires an API key and sends the URL to that service. Results are not a guarantee or a trained AI verdict.", 10, "normal", self.c("muted")).pack(anchor="w", pady=(5, 0))

        data = self.card(self.content)

        data.pack(fill="x", pady=8)

        self.label(data, "Privacy & local data", 12, "bold").pack(anchor="w")

        self.label(data, f"Scan history is stored in {DB_FILE} in the app's current working folder. No network requests are made unless optional VirusTotal lookup is enabled with SHIELDAI_VT_API_KEY.", 10, "normal", self.c("muted")).pack(anchor="w", pady=(5, 0))

        self.button(data, "Open scan history", lambda: self.show_page("Scan History")).pack(anchor="w", pady=(12, 0))

    def pulse(self):

        # Subtle, non-destructive accent pulse. Never rebuilds or clears scan results.

        if not self.root.winfo_exists():

            return

        if hasattr(self, "protection_dot") and self.protection_dot.winfo_exists():

            self.protection_dot.configure(bg=self.c("panel2"))

        self.root.after(1800, self.pulse)

if __name__ == "__main__":

    try:
        root = tk.Tk()
        app = ShieldAI(root)
        root.mainloop()
    except tk.TclError as exc:
        print("ShieldAI could not start its desktop interface.")
        print("Check that Python was installed with Tkinter support and that a desktop display is available.")
        print(f"Details: {exc}")

