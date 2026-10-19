#!/usr/bin/env python3
"""
SKULL VAULT (GUI) - Password Manager, Generator & Checker
Coded by Cerbah and Faouzi

Requires:  py -m pip install cryptography
Run:       py skull_vault_gui.py        (or rename to .pyw to hide the console)

AI password coach (optional):
    Set an Anthropic API key either with the ANTHROPIC_API_KEY environment
    variable or from the "API key..." button in the Checker tab.
    Your password is NEVER sent - only a statistical profile of it.
"""

import base64
import json
import math
import os
import re
import secrets
import string
import sys
import threading
import time
import tkinter as tk
import urllib.error
import urllib.request
from datetime import datetime
from tkinter import messagebox, ttk

try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except ImportError:
    _r = tk.Tk()
    _r.withdraw()
    messagebox.showerror(
        "Missing dependency",
        "The 'cryptography' package is missing for this Python.\n\n"
        "Open cmd and run:\n    py -m pip install cryptography")
    sys.exit(1)

APP_DIR = os.path.dirname(os.path.abspath(__file__))
VAULT_FILE = os.path.join(APP_DIR, "vault.dat")
KDF_ITERATIONS = 600_000
SALT_SIZE = 16
AUTO_LOCK_SECONDS = 300
CLIPBOARD_CLEAR_MS = 20_000

# AI coach settings (change MODEL if you want a different Claude model)
AI_MODEL = "claude-sonnet-5-5"
AI_URL = "https://api.anthropic.com/v1/messages"
AI_VERSION = "2023-06-01"

# ----------------------------------------------------------------------------
# Theme
# ----------------------------------------------------------------------------
BG = "#0d0d0f"
PANEL = "#17171c"
PANEL2 = "#1f1f26"
FG = "#e8e8ea"
DIM = "#8b8b96"
RED = "#e11d2e"
RED_DARK = "#9b111e"
GREEN = "#22c55e"
YELLOW = "#eab308"
FONT = ("Segoe UI", 10)
FONT_B = ("Segoe UI", 10, "bold")
MONO = ("Consolas", 11)

SKULL = r"""
        _____________
     .-'             '-.
   .'                   '.
  /    .-~~~-.   .-~~~-.  \
 |    /  ___  \ /  ___  \  |
 |   |  (   )  |  (   )  | |
 |    \  '-'  / \  '-'  /  |
  \    '-...-'   '-...-'  /
   \        /\ /\        /
    '.     /  V  \     .'
      \    \_____/    /
       '-.  |_|_|_| .-'
          | |_|_|_| |
          '---------'
""".strip("\n")

LEVEL_COLORS = {"bad": RED, "mid": YELLOW, "good": GREEN}

# ----------------------------------------------------------------------------
# Generator
# ----------------------------------------------------------------------------
AMBIGUOUS = set("Il1O0o")
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?/"


def generate_password(length=16, lower=True, upper=True, digits=True,
                      symbols=True, avoid_ambiguous=False):
    pools = []
    if lower:
        pools.append(string.ascii_lowercase)
    if upper:
        pools.append(string.ascii_uppercase)
    if digits:
        pools.append(string.digits)
    if symbols:
        pools.append(SYMBOLS)
    if not pools:
        raise ValueError("Select at least one character type.")
    if avoid_ambiguous:
        pools = ["".join(c for c in p if c not in AMBIGUOUS) for p in pools]
    if length < len(pools):
        raise ValueError(f"Length must be at least {len(pools)}.")
    alphabet = "".join(pools)
    chars = [secrets.choice(p) for p in pools]
    chars += [secrets.choice(alphabet) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


WORDS = [
    "anchor", "badger", "candle", "dragon", "ember", "falcon", "garden",
    "harbor", "island", "jungle", "kettle", "lantern", "meadow", "nebula",
    "orchid", "pepper", "quartz", "rocket", "saddle", "thunder", "umbra",
    "velvet", "willow", "yonder", "zephyr", "bishop", "copper", "dagger",
    "eclipse", "forest", "glacier", "hollow", "ivory", "jackal", "knight",
    "lizard", "marble", "nickel", "oyster", "phantom", "raven", "shadow",
    "tundra", "violet", "walnut", "crimson", "obsidian", "cobalt",
    "scarab", "mirage", "summit", "tempest", "voyage", "cipher",
]


def generate_passphrase(words=5):
    return "-".join(secrets.choice(WORDS) for _ in range(words)) + \
        "-" + str(secrets.randbelow(100))


# ----------------------------------------------------------------------------
# Checker
# ----------------------------------------------------------------------------
COMMON_PASSWORDS = {
    "password", "123456", "123456789", "qwerty", "abc123", "password1",
    "111111", "123123", "admin", "letmein", "welcome", "iloveyou", "monkey",
    "dragon", "football", "baseball", "master", "sunshine", "princess",
    "login", "passw0rd", "starwars", "123321", "qwerty123", "1q2w3e4r",
    "azerty", "000000", "zaq12wsx", "trustno1", "superman", "batman",
}
SEQUENCES = ["abcdefghijklmnopqrstuvwxyz", "0123456789", "qwertyuiop",
             "asdfghjkl", "zxcvbnm", "azertyuiop", "qsdfghjklm"]


def entropy_bits(pw):
    pool = 0
    if any(c.islower() for c in pw):
        pool += 26
    if any(c.isupper() for c in pw):
        pool += 26
    if any(c.isdigit() for c in pw):
        pool += 10
    if any(not c.isalnum() for c in pw):
        pool += 32
    return len(pw) * math.log2(pool) if pool else 0.0


def has_sequence(pw, n=4):
    p = pw.lower()
    for seq in SEQUENCES:
        for s in (seq, seq[::-1]):
            for i in range(len(s) - n + 1):
                if s[i:i + n] in p:
                    return True
    return False


def has_repeats(pw, n=3):
    return any(len(set(pw[i:i + n])) == 1 for i in range(len(pw) - n + 1))


def check_password(pw):
    """Returns (score 0-100, label, level, feedback list)."""
    if not pw:
        return 0, "EMPTY", "bad", ["Type a password to test it."]
    if pw.lower() in COMMON_PASSWORDS:
        return 1, "TERRIBLE", "bad", ["One of the most common passwords!"]

    bits = entropy_bits(pw)
    score = min(bits, 100)
    fb = []
    if len(pw) < 8:
        fb.append("Too short - use at least 12 characters.")
    elif len(pw) < 12:
        fb.append("Better with 12+ characters.")
    if not any(c.islower() for c in pw):
        fb.append("Add lowercase letters.")
    if not any(c.isupper() for c in pw):
        fb.append("Add uppercase letters.")
    if not any(c.isdigit() for c in pw):
        fb.append("Add digits.")
    if not any(not c.isalnum() for c in pw):
        fb.append("Add symbols (!@#$...).")
    if has_sequence(pw):
        fb.append("Contains a keyboard / alphabet / number sequence.")
        score -= 15
    if has_repeats(pw):
        fb.append("Contains repeated characters (aaa, 111...).")
        score -= 10
    if len(set(pw)) < len(pw) * 0.6:
        fb.append("Too many repeated characters overall.")
        score -= 10
    if any(w in pw.lower() for w in COMMON_PASSWORDS if len(w) >= 5):
        fb.append("Contains a common password / word.")
        score -= 20
    flags = pattern_flags(pw)
    if flags["leet"]:
        score -= 35
    if flags["year"]:
        score -= 20
    if flags["classic"]:
        score -= 15
    if any(flags.values()):
        fb.append("Predictable patterns detected (see smart insights).")

    score = max(0, min(100, int(score)))
    if score < 25:
        label, level = "VERY WEAK", "bad"
    elif score < 45:
        label, level = "WEAK", "bad"
    elif score < 65:
        label, level = "FAIR", "mid"
    elif score < 85:
        label, level = "STRONG", "good"
    else:
        label, level = "EXCELLENT", "good"
    if not fb:
        fb.append("Looks great. Keep it unique per site!")
    fb.append(f"Estimated entropy: {bits:.0f} bits")
    return score, label, level, fb


# ----------------------------------------------------------------------------
# Smart insights (offline) + AI coach
# ----------------------------------------------------------------------------
LEET = {"@": "a", "4": "a", "3": "e", "1": "i", "!": "i", "0": "o",
        "$": "s", "5": "s", "7": "t"}


def pattern_mask(pw):
    """Structure only: U=upper l=lower d=digit s=symbol (never the real chars)."""
    out = []
    for c in pw:
        if c.isupper():
            out.append("U")
        elif c.islower():
            out.append("l")
        elif c.isdigit():
            out.append("d")
        else:
            out.append("s")
    return "".join(out)


def human_time(seconds):
    if seconds < 1:
        return "instantly"
    units = [("second", 60), ("minute", 60), ("hour", 24), ("day", 365),
             ("year", 1000), ("thousand years", 1000),
             ("million years", 1000)]
    value = seconds
    for name, step in units:
        if value < step:
            n = int(value)
            return f"{n} {name}{'' if n == 1 or 'years' in name else 's'}"
        value /= step
    return "billions of years"


def crack_time(bits):
    """Rough offline-attack estimate: 10 billion guesses per second."""
    return human_time((2 ** bits) / 2 / 1e10)


def pattern_flags(pw):
    """Detects predictable habits that make a password easier to guess."""
    low = pw.lower()
    deleet = "".join(LEET.get(c, c) for c in low)
    words = [w for w in (COMMON_PASSWORDS | set(WORDS)) if len(w) >= 4]
    return {
        "leet": deleet != low and any(w in deleet for w in words),
        "year": bool(re.search(r"(19|20)\d{2}[^\w]?$", pw)),
        "classic": bool(re.fullmatch(r"[A-Z][a-z]+\d{1,4}[^\w]?", pw)),
    }


def effective_bits(pw):
    """Entropy after subtracting what predictable patterns give away."""
    bits = entropy_bits(pw)
    f = pattern_flags(pw)
    if f["leet"]:
        bits -= 35
    if f["year"]:
        bits -= 20
    if f["classic"]:
        bits -= 15
    return max(bits, 10.0)


def smart_insights(pw):
    """Offline pattern analysis. Returns a list of human-readable findings."""
    if not pw:
        return []
    found = []
    f = pattern_flags(pw)
    if f["leet"]:
        found.append("Uses a common word with symbol/number swaps (leet "
                     "speak like p@ssw0rd). Attackers try these first.")
    if f["year"]:
        found.append("Ends with a year - a very predictable habit.")
    if f["classic"]:
        found.append("Follows the classic 'Capital + word + digits + symbol' "
                     "pattern that cracking tools target.")
    if pw.isalpha():
        found.append("Letters only - mixing in digits and symbols helps.")
    elif pw.isdigit():
        found.append("Digits only - extremely quick to brute-force.")
    if len(pw) >= 4 and pw == pw[::-1]:
        found.append("It is a palindrome.")
    found.append(f"Estimated time to crack offline: {crack_time(effective_bits(pw))}")
    return found


def build_ai_profile(pw, include_mask=True):
    """Statistical profile of the password. The password itself is NOT included."""
    score, label, level, _ = check_password(pw)
    bits = entropy_bits(pw)
    lines = [
        f"length: {len(pw)}",
        f"lowercase letters: {sum(c.islower() for c in pw)}",
        f"uppercase letters: {sum(c.isupper() for c in pw)}",
        f"digits: {sum(c.isdigit() for c in pw)}",
        f"symbols: {sum(not c.isalnum() for c in pw)}",
        f"unique characters: {len(set(pw))}",
        f"estimated entropy: {bits:.0f} bits",
        f"local score: {score}/100 ({label})",
        f"is a known common password: {pw.lower() in COMMON_PASSWORDS}",
        f"contains keyboard/alphabet/number sequence: {has_sequence(pw)}",
        f"contains repeated characters (aaa): {has_repeats(pw)}",
    ]
    for note in smart_insights(pw):
        if not note.startswith("Estimated time"):
            lines.append(f"pattern finding: {note}")
    if include_mask:
        lines.append(f"character-type structure (U=upper l=lower d=digit "
                     f"s=symbol): {pattern_mask(pw)}")
    return "\n".join(lines)


AI_SYSTEM = (
    "You are a friendly password security coach inside a password manager. "
    "You receive ONLY a statistical profile of a password, never the password "
    "itself, so never ask for it. Reply in plain text (no markdown) in under "
    "130 words with: a one-line verdict, the 2-3 most important specific "
    "weaknesses, and concrete advice for building a stronger one (for example "
    "a long random passphrase or a password manager generated string). Do not "
    "invent or suggest a specific password."
)


def ai_review(profile, api_key, timeout=40):
    """Calls the Anthropic Messages API. Returns text or raises RuntimeError."""
    body = json.dumps({
        "model": AI_MODEL,
        "max_tokens": 450,
        "system": AI_SYSTEM,
        "messages": [{"role": "user",
                      "content": "Password profile:\n" + profile}],
    }).encode()
    req = urllib.request.Request(AI_URL, data=body, method="POST", headers={
        "content-type": "application/json",
        "x-api-key": api_key,
        "anthropic-version": AI_VERSION,
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())
    except urllib.error.HTTPError as ex:
        try:
            msg = json.loads(ex.read().decode()).get("error", {}).get("message", "")
        except Exception:
            msg = ""
        if ex.code == 401:
            raise RuntimeError("Invalid API key.")
        raise RuntimeError(f"API error {ex.code}: {msg or ex.reason}")
    except (urllib.error.URLError, TimeoutError, OSError):
        raise RuntimeError("Could not reach the API. Check your internet connection.")
    text = "".join(b.get("text", "") for b in data.get("content", [])
                   if b.get("type") == "text").strip()
    if not text:
        raise RuntimeError("The AI returned an empty response.")
    return text



# ----------------------------------------------------------------------------
# Encrypted vault
# ----------------------------------------------------------------------------
def derive_key(master, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                     iterations=KDF_ITERATIONS)
    return base64.urlsafe_b64encode(kdf.derive(master.encode()))


class Vault:
    def __init__(self, path=VAULT_FILE):
        self.path = path
        self.salt = None
        self.fernet = None
        self.entries = {}

    def exists(self):
        return os.path.exists(self.path)

    def create(self, master):
        self.salt = os.urandom(SALT_SIZE)
        self.fernet = Fernet(derive_key(master, self.salt))
        self.entries = {}
        self.save()

    def unlock(self, master):
        with open(self.path, "rb") as f:
            data = f.read()
        self.salt, token = data[:SALT_SIZE], data[SALT_SIZE:]
        self.fernet = Fernet(derive_key(master, self.salt))
        try:
            self.entries = json.loads(self.fernet.decrypt(token).decode())
        except InvalidToken:
            self.fernet = None
            return False
        return True

    def lock(self):
        self.fernet = None
        self.entries = {}

    def save(self):
        token = self.fernet.encrypt(json.dumps(self.entries).encode())
        tmp = self.path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(self.salt + token)
        os.replace(tmp, self.path)

    def change_master(self, new_master):
        self.salt = os.urandom(SALT_SIZE)
        self.fernet = Fernet(derive_key(new_master, self.salt))
        self.save()

    def put(self, site, username, password, notes=""):
        self.entries[site] = {
            "username": username, "password": password, "notes": notes,
            "updated": datetime.now().strftime("%Y-%m-%d %H:%M"),
        }
        self.save()

    def delete(self, site):
        if site in self.entries:
            del self.entries[site]
            self.save()


# ----------------------------------------------------------------------------
# GUI helpers
# ----------------------------------------------------------------------------
def style_app(root):
    s = ttk.Style(root)
    s.theme_use("clam")
    s.configure(".", background=BG, foreground=FG, font=FONT,
                fieldbackground=PANEL2, bordercolor=PANEL2,
                lightcolor=PANEL2, darkcolor=PANEL2, focuscolor=BG)
    s.configure("TFrame", background=BG)
    s.configure("Panel.TFrame", background=PANEL)
    s.configure("TLabel", background=BG, foreground=FG)
    s.configure("Panel.TLabel", background=PANEL, foreground=FG)
    s.configure("Dim.TLabel", background=BG, foreground=DIM)
    s.configure("Title.TLabel", background=BG, foreground=FG,
                font=("Segoe UI", 20, "bold"))
    s.configure("Credit.TLabel", background=BG, foreground=RED,
                font=("Segoe UI", 9, "bold"))
    s.configure("TButton", background=PANEL2, foreground=FG, padding=(12, 7),
                borderwidth=0, font=FONT_B)
    s.map("TButton", background=[("active", "#2b2b35")])
    s.configure("Accent.TButton", background=RED, foreground="white")
    s.map("Accent.TButton", background=[("active", RED_DARK)])
    s.configure("TEntry", fieldbackground=PANEL2, foreground=FG,
                insertcolor=FG, padding=6)
    s.configure("TCheckbutton", background=PANEL, foreground=FG)
    s.map("TCheckbutton", background=[("active", PANEL)])
    s.configure("TNotebook", background=BG, borderwidth=0)
    s.configure("TNotebook.Tab", background=PANEL, foreground=DIM,
                padding=(18, 8), font=FONT_B, borderwidth=0)
    s.map("TNotebook.Tab",
          background=[("selected", RED)],
          foreground=[("selected", "white")])
    s.configure("Treeview", background=PANEL, fieldbackground=PANEL,
                foreground=FG, rowheight=28, borderwidth=0)
    s.configure("Treeview.Heading", background=PANEL2, foreground=FG,
                font=FONT_B, padding=6)
    s.map("Treeview", background=[("selected", RED_DARK)],
          foreground=[("selected", "white")])
    s.configure("Horizontal.TScale", background=PANEL, troughcolor=PANEL2)
    for lvl, col in LEVEL_COLORS.items():
        s.configure(f"{lvl}.Horizontal.TProgressbar", background=col,
                    troughcolor=PANEL2, borderwidth=0, thickness=14)


class StrengthMeter(ttk.Frame):
    """Progress bar + label used in several places."""

    def __init__(self, parent, bg_style="TFrame"):
        super().__init__(parent, style=bg_style)
        self.bar = ttk.Progressbar(self, maximum=100, length=300,
                                   style="bad.Horizontal.TProgressbar")
        self.bar.pack(side="left", fill="x", expand=True)
        self.lbl = tk.Label(self, text="", width=11, anchor="e", font=FONT_B,
                            bg=PANEL if bg_style == "Panel.TFrame" else BG, fg=DIM)
        self.lbl.pack(side="left", padx=(10, 0))

    def update_for(self, pw):
        score, label, level, fb = check_password(pw)
        self.bar.configure(style=f"{level}.Horizontal.TProgressbar")
        self.bar["value"] = score
        self.lbl.configure(text=f"{label}", fg=LEVEL_COLORS[level])
        return score, label, level, fb


class ModalDialog(tk.Toplevel):
    def __init__(self, parent, title, width=460, height=None):
        super().__init__(parent)
        self.title(title)
        self.configure(bg=BG)
        self.transient(parent)
        self.resizable(False, False)
        self.body = ttk.Frame(self, padding=20)
        self.body.pack(fill="both", expand=True)
        self.after(10, self._center, parent)

    def _center(self, parent):
        self.update_idletasks()
        x = parent.winfo_rootx() + (parent.winfo_width() - self.winfo_width()) // 2
        y = parent.winfo_rooty() + (parent.winfo_height() - self.winfo_height()) // 3
        self.geometry(f"+{max(x, 0)}+{max(y, 0)}")
        self.grab_set()


# ----------------------------------------------------------------------------
# Main app
# ----------------------------------------------------------------------------
class SkullVaultApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Skull Vault  -  coded by Cerbah and Faouzi")
        self.configure(bg=BG)
        self.geometry("980x860")
        self.minsize(880, 720)
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass
        style_app(self)

        self.vault = Vault()
        self.last_activity = time.time()
        self._clip_token = None
        self.api_key = os.environ.get("ANTHROPIC_API_KEY", "")

        self._build_header()
        self.content = ttk.Frame(self)
        self.content.pack(fill="both", expand=True, padx=24, pady=(0, 8))

        self.status = tk.StringVar(value="")
        self.status_lbl = tk.Label(self, textvariable=self.status, bg=PANEL, fg=DIM,
                                   anchor="w", padx=14, pady=6, font=("Segoe UI", 9))
        self.status_lbl.pack(fill="x", side="bottom")

        self.bind_all("<Any-KeyPress>", self._touch)
        self.bind_all("<Motion>", self._touch)
        self.bind_all("<Button>", self._touch)
        self.after(5000, self._auto_lock_check)

        self.show_login()

    # ---------------- header ----------------
    def _build_header(self):
        header = ttk.Frame(self, padding=(24, 16, 24, 8))
        header.pack(fill="x")
        tk.Label(header, text=SKULL, font=("Consolas", 8), fg=RED, bg=BG,
                 justify="left").pack(side="left")
        txt = ttk.Frame(header)
        txt.pack(side="left", padx=24)
        ttk.Label(txt, text="SKULL VAULT", style="Title.TLabel").pack(anchor="w")
        ttk.Label(txt, text="password manager  |  generator  |  checker",
                  style="Dim.TLabel").pack(anchor="w")
        ttk.Label(txt, text="C O D E D   B Y   C E R B A H   A N D   F A O U Z I",
                  style="Credit.TLabel").pack(anchor="w", pady=(10, 0))

    # ---------------- helpers ----------------
    def clear_content(self):
        for w in self.content.winfo_children():
            w.destroy()

    def set_status(self, msg, color=DIM):
        self.status.set(msg)
        self.status_lbl.configure(fg=color)

    def copy_secret(self, text, what="Password"):
        self.clipboard_clear()
        self.clipboard_append(text)
        self._clip_token = text
        self.set_status(f"{what} copied. Clipboard clears in "
                        f"{CLIPBOARD_CLEAR_MS // 1000}s.", GREEN)
        self.after(CLIPBOARD_CLEAR_MS, self._clear_clip, text)

    def _clear_clip(self, text):
        if self._clip_token == text:
            try:
                self.clipboard_clear()
                self.clipboard_append("")
            except tk.TclError:
                pass
            self._clip_token = None
            self.set_status("Clipboard cleared.")

    def _touch(self, _e=None):
        self.last_activity = time.time()

    def _auto_lock_check(self):
        if self.vault.fernet and time.time() - self.last_activity > AUTO_LOCK_SECONDS:
            self.lock()
            self.set_status("Vault auto-locked after inactivity.", YELLOW)
        self.after(5000, self._auto_lock_check)

    # ---------------- login ----------------
    def show_login(self):
        self.clear_content()
        creating = not self.vault.exists()
        card = ttk.Frame(self.content, style="Panel.TFrame", padding=30)
        card.place(relx=0.5, rely=0.42, anchor="center")

        title = "Create your vault" if creating else "Unlock your vault"
        tk.Label(card, text=title, font=("Segoe UI", 15, "bold"), bg=PANEL,
                 fg=FG).pack(anchor="w")
        sub = ("Choose a strong master password. It cannot be recovered "
               "if you forget it." if creating else
               "Enter your master password.")
        tk.Label(card, text=sub, bg=PANEL, fg=DIM, wraplength=380,
                 justify="left").pack(anchor="w", pady=(2, 16))

        self.pw1 = tk.StringVar()
        self.pw2 = tk.StringVar()
        e1 = ttk.Entry(card, textvariable=self.pw1, show="*", width=40)
        e1.pack(fill="x")
        e1.focus_set()

        meter = None
        e2 = None
        if creating:
            meter = StrengthMeter(card, "Panel.TFrame")
            meter.pack(fill="x", pady=8)
            self.pw1.trace_add("write", lambda *_: meter.update_for(self.pw1.get()))
            tk.Label(card, text="Confirm password", bg=PANEL, fg=DIM).pack(anchor="w")
            e2 = ttk.Entry(card, textvariable=self.pw2, show="*", width=40)
            e2.pack(fill="x", pady=(2, 0))

        self.login_msg = tk.Label(card, text="", bg=PANEL, fg=RED)
        self.login_msg.pack(anchor="w", pady=(10, 0))

        def submit(_e=None):
            m = self.pw1.get()
            if creating:
                if len(m) < 8:
                    self.login_msg.config(text="Use at least 8 characters.")
                    return
                if m != self.pw2.get():
                    self.login_msg.config(text="Passwords do not match.")
                    return
                self.vault.create(m)
                self.build_main()
            else:
                self.login_msg.config(text="Unlocking...")
                self.update_idletasks()
                if self.vault.unlock(m):
                    self.build_main()
                else:
                    self.login_msg.config(text="Wrong master password.")
                    self.pw1.set("")

        ttk.Button(card, text="Create vault" if creating else "Unlock",
                   style="Accent.TButton", command=submit).pack(fill="x", pady=(12, 0))
        for e in (e1, e2):
            if e:
                e.bind("<Return>", submit)

        # Allow generator / checker even before unlocking
        ttk.Button(card, text="Open generator / checker without vault",
                   command=self.build_tools_only).pack(fill="x", pady=(8, 0))

    def lock(self):
        self.vault.lock()
        self.show_login()

    # ---------------- main layout ----------------
    def build_main(self):
        self.clear_content()
        self.set_status("Vault unlocked.", GREEN)
        nb = ttk.Notebook(self.content)
        nb.pack(fill="both", expand=True)
        self.tab_vault = ttk.Frame(nb, padding=12)
        self.tab_gen = ttk.Frame(nb, padding=12)
        self.tab_chk = ttk.Frame(nb, padding=12)
        nb.add(self.tab_vault, text="  Vault  ")
        nb.add(self.tab_gen, text="  Generator  ")
        nb.add(self.tab_chk, text="  Checker  ")
        self._build_vault_tab()
        self._build_generator_tab(self.tab_gen)
        self._build_checker_tab(self.tab_chk)

    def build_tools_only(self):
        self.clear_content()
        self.set_status("Vault locked - generator and checker only.")
        top = ttk.Frame(self.content)
        top.pack(fill="x", pady=(0, 6))
        ttk.Button(top, text="< Back to login", command=self.show_login).pack(side="left")
        nb = ttk.Notebook(self.content)
        nb.pack(fill="both", expand=True)
        g = ttk.Frame(nb, padding=12)
        c = ttk.Frame(nb, padding=12)
        nb.add(g, text="  Generator  ")
        nb.add(c, text="  Checker  ")
        self._build_generator_tab(g)
        self._build_checker_tab(c)

    # ---------------- vault tab ----------------
    def _build_vault_tab(self):
        t = self.tab_vault
        bar = ttk.Frame(t)
        bar.pack(fill="x", pady=(0, 10))
        ttk.Button(bar, text="+ Add", style="Accent.TButton",
                   command=self.add_entry).pack(side="left")
        ttk.Button(bar, text="View", command=self.view_entry).pack(side="left", padx=6)
        ttk.Button(bar, text="Copy password", command=self.copy_selected).pack(side="left")
        ttk.Button(bar, text="Edit", command=self.edit_entry).pack(side="left", padx=6)
        ttk.Button(bar, text="Delete", command=self.delete_entry).pack(side="left")
        ttk.Button(bar, text="Lock", command=self.lock).pack(side="right")
        ttk.Button(bar, text="Master pw", command=self.change_master).pack(side="right", padx=6)
        ttk.Button(bar, text="Audit", command=self.audit).pack(side="right")

        sbar = ttk.Frame(t)
        sbar.pack(fill="x", pady=(0, 8))
        ttk.Label(sbar, text="Search:", style="Dim.TLabel").pack(side="left")
        self.search = tk.StringVar()
        self.search.trace_add("write", lambda *_: self.refresh())
        ttk.Entry(sbar, textvariable=self.search, width=34).pack(side="left", padx=8)

        cols = ("site", "username", "updated")
        self.tree = ttk.Treeview(t, columns=cols, show="headings", selectmode="browse")
        for c, w, name in (("site", 300, "Site / Service"),
                           ("username", 300, "Username"),
                           ("updated", 160, "Updated")):
            self.tree.heading(c, text=name)
            self.tree.column(c, width=w, anchor="w")
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<Double-1>", lambda e: self.view_entry())
        self.refresh()

    def refresh(self):
        q = self.search.get().lower().strip()
        self.tree.delete(*self.tree.get_children())
        for site, e in sorted(self.vault.entries.items(), key=lambda x: x[0].lower()):
            if q and q not in site.lower() and q not in e["username"].lower():
                continue
            self.tree.insert("", "end", iid=site,
                             values=(site, e["username"], e["updated"]))

    def selected(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Skull Vault", "Select an entry first.", parent=self)
            return None
        return sel[0]

    def add_entry(self):
        self.entry_dialog()

    def edit_entry(self):
        site = self.selected()
        if site:
            self.entry_dialog(site)

    def entry_dialog(self, site=None):
        existing = self.vault.entries.get(site) if site else None
        d = ModalDialog(self, "Edit entry" if existing else "Add entry")
        b = d.body
        site_v = tk.StringVar(value=site or "")
        user_v = tk.StringVar(value=existing["username"] if existing else "")
        pass_v = tk.StringVar(value=existing["password"] if existing else "")

        def row(label, var, show=None):
            ttk.Label(b, text=label, style="Dim.TLabel").pack(anchor="w", pady=(8, 2))
            e = ttk.Entry(b, textvariable=var, width=46, show=show or "")
            e.pack(fill="x")
            return e

        row("Site / Service", site_v)
        row("Username / Email", user_v)
        ttk.Label(b, text="Password", style="Dim.TLabel").pack(anchor="w", pady=(8, 2))
        prow = ttk.Frame(b)
        prow.pack(fill="x")
        pe = ttk.Entry(prow, textvariable=pass_v, show="*")
        pe.pack(side="left", fill="x", expand=True)
        show = tk.BooleanVar(value=False)
        ttk.Checkbutton(prow, text="Show", variable=show, style="TCheckbutton",
                        command=lambda: pe.config(show="" if show.get() else "*")
                        ).pack(side="left", padx=6)
        ttk.Button(prow, text="Generate",
                   command=lambda: pass_v.set(generate_password(20))).pack(side="left")
        meter = StrengthMeter(b)
        meter.pack(fill="x", pady=8)
        pass_v.trace_add("write", lambda *_: meter.update_for(pass_v.get()))
        meter.update_for(pass_v.get())

        ttk.Label(b, text="Notes", style="Dim.TLabel").pack(anchor="w", pady=(4, 2))
        notes = tk.Text(b, height=4, width=46, bg=PANEL2, fg=FG, relief="flat",
                        insertbackground=FG, font=FONT, padx=6, pady=6)
        notes.pack(fill="x")
        if existing:
            notes.insert("1.0", existing.get("notes", ""))

        def save():
            s = site_v.get().strip()
            if not s:
                messagebox.showwarning("Skull Vault", "Site name is required.", parent=d)
                return
            if s != site and s in self.vault.entries and not messagebox.askyesno(
                    "Overwrite?", f"'{s}' already exists. Overwrite?", parent=d):
                return
            if site and s != site:
                self.vault.delete(site)
            self.vault.put(s, user_v.get().strip(), pass_v.get(),
                           notes.get("1.0", "end").strip())
            d.destroy()
            self.refresh()
            self.set_status(f"Saved '{s}'.", GREEN)

        btns = ttk.Frame(b)
        btns.pack(fill="x", pady=(16, 0))
        ttk.Button(btns, text="Cancel", command=d.destroy).pack(side="right")
        ttk.Button(btns, text="Save", style="Accent.TButton",
                   command=save).pack(side="right", padx=8)

    def view_entry(self):
        site = self.selected()
        if not site:
            return
        e = self.vault.entries[site]
        d = ModalDialog(self, site)
        b = d.body

        def field(label, value, secret=False, copy=True):
            ttk.Label(b, text=label, style="Dim.TLabel").pack(anchor="w", pady=(8, 2))
            r = ttk.Frame(b)
            r.pack(fill="x")
            v = tk.StringVar(value=value)
            ent = ttk.Entry(r, textvariable=v, width=42, show="*" if secret else "",
                            state="readonly")
            ent.pack(side="left", fill="x", expand=True)
            if secret:
                state = {"on": False}

                def toggle():
                    state["on"] = not state["on"]
                    ent.config(show="" if state["on"] else "*")
                ttk.Button(r, text="Show", command=toggle).pack(side="left", padx=6)
            if copy and value:
                ttk.Button(r, text="Copy", command=lambda: self.copy_secret(
                    value, label)).pack(side="left")

        field("Username", e["username"])
        field("Password", e["password"], secret=True)
        if e.get("notes"):
            field("Notes", e["notes"], copy=False)
        ttk.Label(b, text=f"Updated {e['updated']}", style="Dim.TLabel").pack(
            anchor="w", pady=(12, 0))
        ttk.Button(b, text="Close", command=d.destroy).pack(anchor="e", pady=(12, 0))

    def copy_selected(self):
        site = self.selected()
        if site:
            self.copy_secret(self.vault.entries[site]["password"])

    def delete_entry(self):
        site = self.selected()
        if site and messagebox.askyesno("Delete", f"Delete '{site}' permanently?",
                                        parent=self):
            self.vault.delete(site)
            self.refresh()
            self.set_status(f"Deleted '{site}'.", YELLOW)

    def audit(self):
        d = ModalDialog(self, "Vault audit")
        b = d.body
        txt = tk.Text(b, width=64, height=18, bg=PANEL, fg=FG, relief="flat",
                      font=("Consolas", 10), padx=10, pady=10)
        txt.pack(fill="both", expand=True)
        txt.tag_configure("bad", foreground=RED)
        txt.tag_configure("mid", foreground=YELLOW)
        txt.tag_configure("good", foreground=GREEN)
        seen = {}
        if not self.vault.entries:
            txt.insert("end", "Vault is empty.")
        for site, e in sorted(self.vault.entries.items()):
            seen.setdefault(e["password"], []).append(site)
            score, label, level, _ = check_password(e["password"])
            txt.insert("end", f"{site[:30]:<32}")
            txt.insert("end", f"{label:<11}", level)
            txt.insert("end", f"{score}/100\n")
        reused = [v for v in seen.values() if len(v) > 1]
        if reused:
            txt.insert("end", "\nReused passwords:\n", "bad")
            for g in reused:
                txt.insert("end", "  - " + ", ".join(g) + "\n")
        elif self.vault.entries:
            txt.insert("end", "\nNo reused passwords found.\n", "good")
        txt.config(state="disabled")
        ttk.Button(b, text="Close", command=d.destroy).pack(anchor="e", pady=(10, 0))

    def change_master(self):
        d = ModalDialog(self, "Change master password")
        b = d.body
        n1, n2 = tk.StringVar(), tk.StringVar()
        ttk.Label(b, text="New master password", style="Dim.TLabel").pack(anchor="w")
        ttk.Entry(b, textvariable=n1, show="*", width=40).pack(fill="x", pady=(2, 6))
        meter = StrengthMeter(b)
        meter.pack(fill="x")
        n1.trace_add("write", lambda *_: meter.update_for(n1.get()))
        ttk.Label(b, text="Confirm", style="Dim.TLabel").pack(anchor="w", pady=(8, 0))
        ttk.Entry(b, textvariable=n2, show="*", width=40).pack(fill="x", pady=(2, 0))

        def go():
            if len(n1.get()) < 8:
                messagebox.showwarning("Skull Vault", "Use at least 8 characters.", parent=d)
            elif n1.get() != n2.get():
                messagebox.showwarning("Skull Vault", "Passwords do not match.", parent=d)
            else:
                self.vault.change_master(n1.get())
                d.destroy()
                self.set_status("Master password changed.", GREEN)

        ttk.Button(b, text="Change", style="Accent.TButton", command=go).pack(
            anchor="e", pady=(14, 0))

    # ---------------- generator tab ----------------
    def _build_generator_tab(self, parent):
        card = ttk.Frame(parent, style="Panel.TFrame", padding=22)
        card.pack(fill="both", expand=True)

        out = tk.StringVar()
        tk.Label(card, text="Generated password", bg=PANEL, fg=DIM).pack(anchor="w")
        ent = tk.Entry(card, textvariable=out, font=("Consolas", 16, "bold"),
                       bg=PANEL2, fg=GREEN, relief="flat", insertbackground=FG,
                       readonlybackground=PANEL2, state="readonly")
        ent.pack(fill="x", ipady=10, pady=(4, 8))
        meter = StrengthMeter(card, "Panel.TFrame")
        meter.pack(fill="x", pady=(0, 14))

        length = tk.IntVar(value=18)
        row = ttk.Frame(card, style="Panel.TFrame")
        row.pack(fill="x")
        tk.Label(row, text="Length", bg=PANEL, fg=FG).pack(side="left")
        len_lbl = tk.Label(row, text="18", bg=PANEL, fg=RED, font=FONT_B, width=3)
        len_lbl.pack(side="right")
        ttk.Scale(row, from_=6, to=64, orient="horizontal", variable=length,
                  command=lambda v: (length.set(int(float(v))),
                                     len_lbl.config(text=str(int(float(v)))))
                  ).pack(side="left", fill="x", expand=True, padx=12)

        opts = {}
        orow = ttk.Frame(card, style="Panel.TFrame")
        orow.pack(fill="x", pady=12)
        for key, label, default in (("lower", "a-z", True), ("upper", "A-Z", True),
                                    ("digits", "0-9", True), ("symbols", "!@#$", True),
                                    ("ambig", "No look-alikes", False)):
            opts[key] = tk.BooleanVar(value=default)
            ttk.Checkbutton(orow, text=label, variable=opts[key]).pack(
                side="left", padx=(0, 16))

        def gen():
            try:
                pw = generate_password(
                    length.get(), opts["lower"].get(), opts["upper"].get(),
                    opts["digits"].get(), opts["symbols"].get(), opts["ambig"].get())
            except ValueError as ex:
                messagebox.showwarning("Skull Vault", str(ex), parent=self)
                return
            out.set(pw)
            meter.update_for(pw)

        def phrase():
            pw = generate_passphrase(5)
            out.set(pw)
            meter.update_for(pw)

        btns = ttk.Frame(card, style="Panel.TFrame")
        btns.pack(fill="x", pady=(6, 0))
        ttk.Button(btns, text="Generate", style="Accent.TButton",
                   command=gen).pack(side="left")
        ttk.Button(btns, text="Passphrase", command=phrase).pack(side="left", padx=8)
        ttk.Button(btns, text="Copy", command=lambda: out.get() and
                   self.copy_secret(out.get())).pack(side="left")
        gen()

    # ---------------- checker tab ----------------
    def ask_api_key(self, on_done=None):
        d = ModalDialog(self, "Anthropic API key")
        b = d.body
        ttk.Label(b, text="Paste your Anthropic API key. It is kept in memory "
                          "for this session only and is never saved to disk.",
                  style="Dim.TLabel", wraplength=400).pack(anchor="w")
        v = tk.StringVar(value=self.api_key)
        e = ttk.Entry(b, textvariable=v, show="*", width=48)
        e.pack(fill="x", pady=10)
        e.focus_set()

        def save(_e=None):
            self.api_key = v.get().strip()
            d.destroy()
            if on_done:
                on_done()

        e.bind("<Return>", save)
        ttk.Button(b, text="Use key", style="Accent.TButton", command=save).pack(anchor="e")

    def _build_checker_tab(self, parent):
        card = ttk.Frame(parent, style="Panel.TFrame", padding=22)
        card.pack(fill="both", expand=True)
        tk.Label(card, text="Type a password to test its strength", bg=PANEL,
                 fg=DIM).pack(anchor="w")
        pw = tk.StringVar()
        r = ttk.Frame(card, style="Panel.TFrame")
        r.pack(fill="x", pady=(4, 12))
        e = ttk.Entry(r, textvariable=pw, show="*", font=("Consolas", 14))
        e.pack(side="left", fill="x", expand=True, ipady=4)
        show = tk.BooleanVar(value=False)
        ttk.Checkbutton(r, text="Show", variable=show,
                        command=lambda: e.config(show="" if show.get() else "*")
                        ).pack(side="left", padx=10)
        meter = StrengthMeter(card, "Panel.TFrame")
        meter.pack(fill="x")
        score_lbl = tk.Label(card, text="", bg=PANEL, fg=FG,
                             font=("Segoe UI", 26, "bold"))
        score_lbl.pack(anchor="w", pady=(8, 0))
        fb = tk.Label(card, text="", bg=PANEL, fg=FG, justify="left",
                      anchor="nw", font=FONT, wraplength=780)
        fb.pack(fill="x", pady=(4, 0))
        insights = tk.Label(card, text="", bg=PANEL, fg=YELLOW, justify="left",
                            anchor="nw", font=FONT, wraplength=780)
        insights.pack(fill="x", pady=(6, 0))

        # ---------------- AI coach panel ----------------
        tk.Frame(card, bg=PANEL2, height=1).pack(fill="x", pady=14)
        head = ttk.Frame(card, style="Panel.TFrame")
        head.pack(fill="x")
        tk.Label(head, text="AI password coach", font=("Segoe UI", 12, "bold"),
                 bg=PANEL, fg=FG).pack(side="left")
        key_lbl = tk.Label(head, text="", bg=PANEL, font=("Segoe UI", 9))
        key_lbl.pack(side="right")
        tk.Label(card, text="Your password is never sent - only a statistical "
                            "profile (length, character counts, patterns).",
                 bg=PANEL, fg=DIM, font=("Segoe UI", 9)).pack(anchor="w", pady=(2, 8))

        arow = ttk.Frame(card, style="Panel.TFrame")
        arow.pack(fill="x")
        include_mask = tk.BooleanVar(value=True)
        busy = {"on": False}

        out = tk.Text(card, height=8, bg=PANEL2, fg=FG, relief="flat",
                      font=FONT, padx=10, pady=8, wrap="word", state="disabled")

        def set_out(text, color=FG):
            out.config(state="normal", fg=color)
            out.delete("1.0", "end")
            out.insert("1.0", text)
            out.config(state="disabled")

        def refresh_key():
            key_lbl.config(text="API key: set" if self.api_key else "API key: not set",
                           fg=GREEN if self.api_key else YELLOW)

        def analyze():
            if busy["on"]:
                return
            if not pw.get():
                set_out("Type a password above first.", DIM)
                return
            if not self.api_key:
                set_out("No API key yet. Click 'API key...' (or set the "
                        "ANTHROPIC_API_KEY environment variable). The offline "
                        "insights above still work without it.", YELLOW)
                return
            profile = build_ai_profile(pw.get(), include_mask.get())
            result = {}
            busy["on"] = True
            ai_btn.config(state="disabled", text="Thinking...")
            set_out("Asking the AI coach...", DIM)

            def worker():
                try:
                    result["text"] = ai_review(profile, self.api_key)
                except RuntimeError as ex:
                    result["error"] = str(ex)
                except Exception as ex:  # unexpected
                    result["error"] = f"Unexpected error: {ex}"

            threading.Thread(target=worker, daemon=True).start()

            def poll():
                if not result:
                    self.after(150, poll)
                    return
                busy["on"] = False
                try:
                    ai_btn.config(state="normal", text="Analyze with AI")
                    if "error" in result:
                        set_out(result["error"], RED)
                    else:
                        set_out(result["text"])
                except tk.TclError:
                    pass  # window was closed

            self.after(150, poll)

        ai_btn = ttk.Button(arow, text="Analyze with AI", style="Accent.TButton",
                            command=analyze)
        ai_btn.pack(side="left")
        ttk.Button(arow, text="API key...",
                   command=lambda: self.ask_api_key(refresh_key)).pack(side="left", padx=8)
        ttk.Checkbutton(arow, text="Include structure pattern (e.g. Ulllld!)",
                        variable=include_mask).pack(side="left", padx=8)
        out.pack(fill="both", expand=True, pady=(10, 0))
        set_out("Press 'Analyze with AI' for personalised advice.", DIM)
        refresh_key()

        def update(*_):
            score, label, level, tips = meter.update_for(pw.get())
            score_lbl.config(text=f"{score}/100", fg=LEVEL_COLORS[level])
            fb.config(text="\n".join("  -  " + t for t in tips))
            smart = smart_insights(pw.get())
            insights.config(text=("Smart insights (offline):\n" +
                                  "\n".join("  *  " + t for t in smart)) if smart else "")

        pw.trace_add("write", update)
        update()


if __name__ == "__main__":
    SkullVaultApp().mainloop()
