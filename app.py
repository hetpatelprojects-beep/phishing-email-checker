import json
import re
import html as htmllib
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from urllib.parse import urlparse

import joblib
import streamlit as st
from sklearn.feature_extraction.text import ENGLISH_STOP_WORDS

st.set_page_config(page_title="Phishing Email Checker")

# ---------- load the trained files ----------
@st.cache_resource
def load_files():
    model = joblib.load("model_v3.joblib")
    vec = joblib.load("vectorizer_v3.joblib")
    with open("cutoffs_v3.json") as f:
        cutoffs = json.load(f)
    return model, vec, cutoffs

model, vec, cutoffs = load_files()
HIGH_CUTOFF = cutoffs["0.02"]        # about 2% false alarms in our tests
SUSPICIOUS_CUTOFF = cutoffs["0.1"]   # about 10% false alarms in our tests

# ---------- text helpers (same cleaning as in training) ----------
TAG_RE = re.compile(r"<[^>]+>")
STYLE_RE = re.compile(r"<(style|script|head)\b.*?</\1>", re.I | re.S)
COMMENT_RE = re.compile(r"<!--.*?-->", re.S)
ANCHOR_RE = re.compile(r'<a\s[^>]*?href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', re.I | re.S)
URL_RE = re.compile(r"https?://[^\s<>\"')]+", re.I)
TEXT_DOMAIN_RE = re.compile(r"\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b", re.I)
IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at"}

def clean_space(s):
    return re.sub(r"\s+", " ", s).strip()

def strip_html(t):
    t = COMMENT_RE.sub(" ", str(t))
    t = STYLE_RE.sub(" ", t)
    return htmllib.unescape(TAG_RE.sub(" ", t))

def sanitize(t):
    t = str(t).lower()
    t = re.sub(r"https?://\S+", " ", t)
    t = re.sub(r"\S+@\S+", " ", t)
    t = re.sub(r"\d+", " ", t)
    return " ".join(re.findall(r"[a-z']+", t))

def looks_english(t):
    tokens = re.findall(r"[a-z]+", str(t).lower())
    if len(tokens) < 8:
        return True
    stop_share = sum(w in ENGLISH_STOP_WORDS for w in tokens) / len(tokens)
    letters = [c for c in str(t) if c.isalpha()]
    accent_share = sum(ord(c) > 127 for c in letters) / max(len(letters), 1)
    return stop_share >= 0.2 and accent_share < 0.02

def base_domain(host):
    parts = host.lower().strip(".").split(".")
    if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "net", "gov", "ac") and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])

# ---------- warning flags (shown to the user, not part of the score) ----------
def link_flags(hrefs, anchors):
    flags = []
    for href, text in anchors:
        m = TEXT_DOMAIN_RE.search(text)
        if not m or not href.lower().startswith(("http://", "https://")):
            continue
        try:
            real = urlparse(href).hostname or ""
        except ValueError:
            continue
        if real and base_domain(m.group(1)) != base_domain(real):
            flags.append(f"A link's visible text shows {m.group(1)} but it really goes to {real}.")
    for h in hrefs:
        if not h.lower().startswith(("http://", "https://")):
            continue
        try:
            p = urlparse(h)
            host = (p.hostname or "").lower()
        except ValueError:
            continue
        if IP_RE.match(host):
            flags.append(f"A link uses a numeric address instead of a website name ({host}).")
        if host in SHORTENERS:
            flags.append(f"A link is hidden behind a link shortener ({host}).")
        if p.username:
            flags.append("A link contains a name@ trick before the real address.")
        if "xn--" in host:
            flags.append(f"A link uses lookalike characters in its web address ({host}).")
    return list(dict.fromkeys(flags))[:8]

def header_flags(msg):
    flags = []
    frm = parseaddr(str(msg.get("From", "")))[1]
    reply = parseaddr(str(msg.get("Reply-To", "")))[1]
    dom = lambda a: a.rsplit("@", 1)[-1].lower() if "@" in a else ""
    if reply and dom(reply) != dom(frm):
        flags.append(f"Replies go to a different domain ({dom(reply)}) than the sender ({dom(frm)}).")
    auth = str(msg.get("Authentication-Results", "")).lower()
    for name in ("spf", "dkim", "dmarc"):
        if f"{name}=fail" in auth:
            flags.append(f"The {name.upper()} sender check failed.")
    return flags

def analyze_eml(raw):
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    html, plain = "", ""
    try:
        part = msg.get_body(preferencelist=("html",))
        if part is not None:
            html = part.get_content()[:300000]
    except Exception:
        pass
    try:
        part = msg.get_body(preferencelist=("plain",))
        if part is not None:
            plain = part.get_content()[:300000]
    except Exception:
        pass
    body = plain if plain.strip() else strip_html(html)
    text = clean_space(str(msg.get("Subject", "")) + " " + body)[:5000]
    anchors = [(h, clean_space(TAG_RE.sub(" ", t))[:100]) for h, t in ANCHOR_RE.findall(html)][:50]
    hrefs = list(dict.fromkeys([h for h, _ in anchors] + URL_RE.findall(plain)))[:50]
    return text, header_flags(msg) + link_flags(hrefs, anchors)

def analyze_pasted(subject, body):
    text = clean_space(subject + " " + strip_html(body))[:5000]
    return text, link_flags(URL_RE.findall(body), [])

# ---------- scoring and display ----------
def show_result(text, flags):
    if not text.strip():
        st.warning("There is no text to check.")
        return
    if not looks_english(text):
        st.warning("This email does not look like English. The model was trained on English emails only, so the result is unreliable.")
    score = float(model.decision_function(vec.transform([sanitize(text)]))[0])

    if score >= HIGH_CUTOFF:
        st.error("HIGH RISK: this email looks a lot like the phishing and scam emails the model learned from.")
    elif score >= SUSPICIOUS_CUTOFF:
        st.warning("SUSPICIOUS: some features resemble phishing, but legitimate emails can look like this too.")
    else:
        st.success("No strong warning signs in the text. This does not prove the email is safe.")
    st.caption(f"Model score: {score:.2f}  (suspicious from {SUSPICIOUS_CUTOFF:.2f}, high risk from {HIGH_CUTOFF:.2f})")

    st.subheader("Other warning signs")
    if flags:
        for f in flags:
            st.write("- " + f)
        st.caption("These flags are shown as evidence only. They are not part of the score, because they were not reliable enough in our tests.")
    else:
        st.write("None found.")

# ---------- the page ----------
st.title("Phishing Email Checker")
st.caption("Educational prototype. Your email is checked in memory and is not stored by this app. Even so, please do not upload private or sensitive emails to this public demo; run it locally instead.")

tab_file, tab_paste = st.tabs(["Upload an .eml file", "Paste text"])

with tab_file:
    uploaded = st.file_uploader("Choose an .eml file", type=["eml"])
    if uploaded is not None:
        text, flags = analyze_eml(uploaded.getvalue())
        show_result(text, flags)

with tab_paste:
    subject = st.text_input("Subject")
    body = st.text_area("Email body", height=220)
    if st.button("Check pasted email"):
        text, flags = analyze_pasted(subject, body)
        show_result(text, flags)

with st.expander("How reliable is this?"):
    st.write(
        "In our tests on emails from senders the model had never seen, the HIGH RISK level caught about half of phishing "
        "emails (with about 2% false alarms), and the SUSPICIOUS level caught about 80% (with about 10% false alarms). "
        "Because real email is mostly legitimate, many alerts will still be false alarms. "
        "The model works on English emails only, and it is weakest on credential phishing. "
        "Never rely on it alone, and never click links in emails you do not trust."
    )