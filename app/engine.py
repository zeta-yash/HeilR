"""Deterministic scam-analysis engine. No network, no LLM. Offsets always refer to the ORIGINAL text."""
import re
from typing import Literal
from pydantic import BaseModel

Stage = Literal["hook", "trust", "pressure", "extraction"]

class Flag(BaseModel):
    id: str; stage: Stage; weight: int; title: str; why: str
    spans: list[tuple[int, int]] = []; evidence: list[str] = []

class Result(BaseModel):
    level: Literal["low", "medium", "high"]; score: int
    stages: list[Stage]; flags: list[Flag]; counter: list[str]
    links: list[str]; scam_type: str; steps: list[str]
    ambiguous: dict[str, str] = {}      # brand -> text window the LLM may disambiguate
    summary: str = ""; llm_used: bool = False

# 1:1 character mapping so offsets never shift
_MAP = {ord(c): " " for c in "\u200b\u200c\u200d\u2060\ufeff"}
_MAP.update(str.maketrans("аеорсхуі", "aeopcxyi"))
def normalise(t: str) -> str:
    return t.translate(_MAP)

BRANDS = {"TCS": ["tcs.com"], "Infosys": ["infosys.com"], "Wipro": ["wipro.com"], "Google": ["google.com"],
  "Amazon": ["amazon.in", "amazon.com"], "Flipkart": ["flipkart.com"], "SBI": ["sbi.co.in", "onlinesbi.sbi"],
  "HDFC": ["hdfcbank.com"], "Paytm": ["paytm.com"], "NTA": ["nta.ac.in"], "UGC": ["ugc.gov.in"],
  "Microsoft": ["microsoft.com"], "Naukri": ["naukri.com"], "LinkedIn": ["linkedin.com"]}
TOOL = r"(?:forms?|meet|drive|docs?|sheets?|slides|classroom|calendar|colab|maps|translate|teams|pay|account|learn)"
ROLE = r"(?:hr|team|careers?|recruit\w*|hiring|is hiring|support|bank|yono|customer\w*|official|internship|talent|pvt|ltd|private limited|kyc)"
SHORT = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "cutt.ly", "rb.gy", "is.gd", "shorturl.at", "ow.ly", "tiny.cc", "wa.link"}
BADTLD = {"xyz", "top", "click", "icu", "live", "site", "online", "buzz", "work", "loan", "monster", "rest", "cfd", "sbs", "vip"}
HOSTED = {"forms.gle", "linktr.ee", "t.me", "wa.me", "wa.link"}   # real domains, attacker-controlled content
FREEMAIL = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "rediffmail.com", "proton.me", "protonmail.com"}

def reg(h: str) -> str:
    p = h.lower().strip(".").split(".")
    if len(p) >= 3 and p[-2] in {"co", "ac", "gov", "nic", "edu", "org", "com"} and len(p[-1]) == 2:
        return ".".join(p[-3:])
    return ".".join(p[-2:])
def official(h: str, doms) -> bool:
    return reg(h) in {reg(d) for d in doms}
def gov_ac(h: str) -> bool:
    return reg(h).endswith((".gov.in", ".ac.in", ".nic.in", ".edu.in"))

# (id, stage, weight, title, why, regex)
RULES = [
 ("urgency", "pressure", 16, "Pressure to hurry", "Scammers rush you so you do not stop to verify. Real organisations publish deadlines on their official site.",
  r"\b(?:urgent(?:ly)?|immediately|right now|act now|hurry|last chance|final (?:notice|warning)|within (?:the next )?\d+ ?(?:hours?|hrs|minutes?|mins)|today only|limited (?:seats|slots)|account (?:will be )?(?:blocked|suspended|closed))\b"),
 ("fee", "extraction", 30, "Asks you to pay money", "Genuine internships and scholarships never charge a registration, kit, security or processing fee.",
  r"\b(?:registration fee|processing fee|security (?:deposit|amount)|refundable (?:deposit|amount)|training fee|kit charges?|verification (?:fee|charge)|token amount|joining fee|pay (?:a )?(?:small )?(?:fee|amount)|(?:pay|send|transfer|deposit)\W+(?:rs\.?|inr|₹)\s?\d[\d,]*)"),
 ("cred", "extraction", 30, "Asks for OTP, PIN, password or card details", "No bank, company or government office needs your OTP, UPI PIN, CVV or password.",
  r"\b(?:share|send|enter|tell|provide|confirm|verify|give)\b[^.\n]{0,40}\b(?:otp|upi pin|pin|cvv|password|card number|bank details|account number|aadhaar|aadhar|pan (?:card|number))\b"),
 ("prize", "hook", 26, "Prize you never applied for", "You cannot win a contest you did not enter. The 'claiming fee' is the scam.",
  r"\b(?:congratulations|you (?:have )?won|lucky (?:draw|winner|user)|lottery|prize money|claim your (?:prize|reward|gift|cashback)|free (?:iphone|laptop|gift))\b"),
 ("refund", "extraction", 24, "Refund or 'sent by mistake' story", "Fake refunds push you to approve a collect request, scan a QR or install a remote-access app. Receiving money never needs a PIN.",
  r"\b(?:refund (?:is )?(?:pending|initiated|approved|processing)|claim (?:your )?refund|(?:sent|credited|transferred) (?:\w+ ){0,3}by mistake|wrongly (?:sent|transferred)|collect request|scan (?:this|the) qr|anydesk|teamviewer|quicksupport)\b"),
 ("offer", "hook", 20, "Too-good-to-be-true job offer", "Real companies do not hire without any interview or pay big money for simple tasks.",
  r"\b(?:no interview|selected without|selected directly|directly selected|without (?:any )?interview|work from home (?:and )?earn|earn (?:up to )?(?:rs\.?|₹)?\s?\d[\d,]*\s?(?:per|a|/) ?(?:day|week|hour)|like (?:and|&) subscribe|guaranteed (?:job|placement))\b"),
 ("offplat", "trust", 12, "Moves you to WhatsApp or Telegram", "Official recruiters use company email and portals; personal chat apps avoid a paper trail.",
  r"\b(?:contact|message|text|ping|join)\b[^.\n]{0,40}\b(?:whatsapp|telegram)\b"),
 ("apk", "extraction", 22, "Asks you to install an app or file", "An unknown .apk can read your SMS and steal OTPs. Install only from official stores.",
  r"\b\S+\.apk\b"),
 ("scholar", "hook", 10, "Verification link for a scholarship/KYC", "Scholarship portals do not send verify links by chat. Type the official address yourself.",
  r"\bkyc (?:update|pending|expired)\b|\bscholarship\b[^.\n]{0,60}\b(?:click|verify|apply now)\b"),
]
NEG = re.compile(r"(?:do not|don't|never|not|won't|will not|n't)\W+(?:\w+\W+){0,3}$", re.I)
URL = re.compile(r"(?<![@\w.-])(?:https?://|www\.)[^\s<>\"')]+|(?<![@\w.-])\b\d{1,3}(?:\.\d{1,3}){3}(?:/[^\s<>\"')]*)?"
  r"|(?<![@\w.-])\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|in|net|org|xyz|top|click|icu|live|site|online|buzz|co|ly|gl|me|info|cc|vip|cfd|gle)\b(?:/[^\s<>\"')]*)?", re.I)

def host_of(u: str) -> str:
    return re.sub(r":\d+$", "", re.sub(r"^.*@", "", re.split(r"[/?#]", re.sub(r"^[a-z]+://", "", u, flags=re.I))[0])).lower()

STEPS = {
 "high": ["Do not pay, reply, click or call any number in the message.", "Never share an OTP, PIN, CVV or password with anyone.",
          "Verify on the official site: type its address yourself, do not use the link you were given.",
          "Report at cybercrime.gov.in. If you already paid or shared details, call 1930 immediately and tell your bank.", "Block the sender and warn your class group."],
 "medium": ["Pause: do not pay or share details yet.", "Check the sender on the organisation's official website or the number printed there.",
            "Read the full link address before tapping; if unsure, do not open it.", "Ask a senior or your placement cell.", "If it turns out fake, report at cybercrime.gov.in or call 1930."],
 "low": ["No strong warning signs were found, which is not a guarantee.", "Never pay a fee or share an OTP/PIN for any offer.",
         "If money, documents or logins are involved, confirm on the official website.", "If something feels off later, report at cybercrime.gov.in or call 1930."]}
TYPES = {"fee": "Fake internship / fee", "cred": "OTP or credential theft", "prize": "Prize or lottery", "refund": "Fake refund",
         "offer": "Fake job offer", "scholar": "Scholarship / KYC link", "apk": "Malicious app"}

def analyze(raw: str, forced: frozenset = frozenset()) -> Result:
    t = normalise(raw)
    flags: list[Flag] = []
    def add(id, stage, w, title, why, spans=(), ev=()):
        flags.append(Flag(id=id, stage=stage, weight=w, title=title, why=why, spans=list(spans), evidence=list(dict.fromkeys(ev))[:4]))

    for id, stage, w, title, why, rx in RULES:
        ms = [m for m in re.finditer(rx, t, re.I) if not (id in ("cred", "fee") and NEG.search(t[max(0, m.start() - 30):m.start()]))]
        if ms:
            if id == "urgency" and len(ms) == 1 and len(t) > 200: w = 8   # a lone deadline in a long notice is weak evidence
            add(id, stage, w, title, why, [m.span() for m in ms], [m.group(0).strip() for m in ms])

    sm = re.search(r"^\s*(?:from|sender)\s*:(.*)$", t, re.I | re.M)
    sdom = ""
    if sm:
        e = re.search(r"@([a-z0-9.-]+\.[a-z]{2,})", sm.group(1), re.I)
        sdom = e.group(1).lower() if e else ""
    links = []
    for m in URL.finditer(t):
        if sm and sm.start() <= m.start() < sm.end(): continue
        raw_u = m.group(0).rstrip(".,;:)"); h = host_of(raw_u); links.append(raw_u)
        sp = [(m.start(), m.start() + len(raw_u))]
        if h in SHORT: add("short", "trust", 20, "Shortened link hides the real address", "You cannot see where it leads. Do not tap it; search for the organisation yourself.", sp, [raw_u])
        elif re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", h): add("ip", "trust", 25, "Link uses a raw IP address", "Real organisations use their own name in links, not numbers.", sp, [raw_u])
        elif h.rsplit(".", 1)[-1] in BADTLD: add("tld", "trust", 18, "Link ends in a cheap, scam-prone domain", "Endings like .xyz, .top or .click cost almost nothing and are common in throwaway scam sites.", sp, [raw_u])
        if "xn--" in h: add("puny", "trust", 25, "Look-alike (punycode) domain", "The address may use special characters that imitate normal letters.", sp, [raw_u])
        if h.count("-") >= 2: add("hyphen", "trust", 10, "Link has many hyphens", "Addresses like secure-login-verify-now typically copy a brand.", sp, [raw_u])
        for b, doms in BRANDS.items():
            if b.lower() in re.split(r"[-.]", h) and not official(h, doms):
                add("lookalike", "trust", 22, f"Link uses {b}'s name but is not {b}'s site", f"Official {b} domains end in {', '.join(doms)}.", sp, [raw_u])

    ambiguous = {}
    for b, doms in BRANDS.items():
        bm = list(re.finditer(rf"\b{b}\b", t, re.I))
        if not bm: continue
        ident = re.search(rf"\b(?:from|by|behalf of|we are|we're|this is|team of)\s+(?:the\s+)?{b}\b|\b{b}\s+{ROLE}\b|\b(?:internship|job|offer|scholarship)\s+(?:at|with|from|by)\s+{b}\b", t, re.I) or b in forced
        tool = re.search(rf"\b{b}\s+{TOOL}\b", t, re.I)
        if ident and not (tool and b not in forced):
            bad = [l for l in links if not official(host_of(l), doms) and host_of(l) not in SHORT]
            free = sdom in FREEMAIL
            if bad or free or (sdom and not official(sdom, doms)):
                add("impersonation", "trust", 24 if free else 26, f"Claims to be {b} but does not match",
                    f"The message names {b}, yet " + ("it was sent from a free email service" if free else "the sender or link does not belong to them") + f". Official {b} domains: {', '.join(doms)}.",
                    [x.span() for x in bm], bad[:3] or [f"sender @{sdom}"])
        elif not ident and not tool:
            ambiguous[b] = t[max(0, bm[0].start() - 150): bm[0].end() + 150]

    if sdom and not any(f.id == "impersonation" for f in flags) and sdom.rsplit(".", 1)[-1] in BADTLD:
        add("sender", "trust", 20, "Sender uses a scam-prone domain", "The email comes from a throwaway-style domain.", [], [f"@{sdom}"])
    if any(f.stage == "extraction" for f in flags):   # hosted pages only matter next to a money/credential ask
        for l in links:
            if host_of(l) in HOSTED or "docs.google.com/forms" in l:
                add("hosted", "trust", 12, "Form or chat link anyone can create", "The domain is real but the content is controlled by whoever made it, and this message also asks for money or details.", [], [l])
    counter = []
    sc = sum(f.weight for f in flags)
    if not any(f.stage == "extraction" for f in flags):
        if links and all(gov_ac(host_of(l)) for l in links): counter.append("Every link goes to an official government or college domain"); sc -= 10
        if re.search(r"\b(?:never ask|do not share|don't share|never share)\b", t, re.I): counter.append("The message warns you not to share OTPs or PINs"); sc -= 8
        if not flags: counter.append("No payment, credential or pressure language found")
    sc = max(0, min(100, sc))
    level = "high" if sc >= 50 else "medium" if sc >= 22 else "low"
    flags.sort(key=lambda f: -f.weight)
    stype = TYPES.get(next((f.id for f in flags if f.id in TYPES), ""), "Suspicious link" if flags else "None found")
    return Result(level=level, score=sc, stages=[s for s in ("hook", "trust", "pressure", "extraction") if any(f.stage == s for f in flags)],
                  flags=flags, counter=counter, links=links, scam_type=stype, steps=STEPS[level], ambiguous=ambiguous)
