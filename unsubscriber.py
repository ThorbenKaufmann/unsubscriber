#!/usr/bin/env python3
"""unsubscriber - find newsletters in a notmuch database and leave them.

  scan         read-only overview of all senders with a List-Unsubscribe header
  unsubscribe  pick senders by number to unsubscribe from, or to block as spam
  purge        move their mail to the trash on the IMAP server

Unsubscribe methods found in the List-Unsubscribe header:

  one-click  RFC 8058: HTTPS POST, done automatically
  mailto     a mail is sent from the address that receives the newsletter
             (needs an [smtp] section in the config file)
  https      link only, usually needs a click on a web page (listed)
  none       header present but no usable URI

Only senders with a DKIM or DMARC pass (as recorded by your own mail server in
the topmost Authentication-Results header) aligned with the From domain are
offered for unsubscribing. A valid signature does not make a sender honest,
though: phishers sign mails for their own throwaway domains. Senders whose
display name does not appear in their domain are flagged with '!' - check
those and rather block them. Never unsubscribe from spam: it only confirms
that your address is alive.

Blocked senders go to a blocklist file and their existing mails are tagged as
spam right away. Your own tagging script can apply the list to new mail.

Requires only Python 3.9+ and the notmuch command line tool.
"""

import argparse
import collections
import configparser
import datetime
import email.message
import email.parser
import email.policy
import email.utils
import json
import os
import re
import shlex
import smtplib
import ssl
import subprocess
import sys
import unicodedata
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_QUERY = "date:6months.."
DEFAULT_SPAM_TAGS = "+spam -inbox"
USER_AGENT = "unsubscriber/0.3 (RFC 8058 one-click)"
STATE_DIR = os.path.join(os.environ.get("XDG_STATE_HOME")
                         or os.path.expanduser("~/.local/state"), "unsubscriber")
CONFIG_DIR = os.path.join(os.environ.get("XDG_CONFIG_HOME")
                          or os.path.expanduser("~/.config"), "unsubscriber")
LOG_FILE = os.path.join(STATE_DIR, "log.jsonl")
BLOCKLIST = os.path.join(CONFIG_DIR, "blocklist.txt")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.ini")

# Shared mail domains: block the single address, never the whole domain.
FREEMAIL = {"gmail.com", "googlemail.com", "outlook.com", "hotmail.com",
            "live.com", "yahoo.com", "icloud.com", "gmx.de", "gmx.net",
            "web.de", "t-online.de", "aol.com", "proton.me", "protonmail.com"}

# Words in display names that say nothing about the brand.
NAME_NOISE = {"news", "newsletter", "team", "info", "service", "support",
              "noreply", "reply", "mail", "from", "von", "shop", "online",
              "deutschland", "germany", "via", "the", "und", "and", "gmbh"}

# Platforms that send on behalf of people or other companies: the display
# name legitimately differs from their domain.
PLATFORMS = {"linkedin.com", "github.com", "xing.com", "wordpress.com",
             "quora.com", "trustedshops.com", "brevosend.com", "steadyhq.com",
             "qemailserver.com", "substack.com", "facebookmail.com"}

HOSTNAME = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")
ADDRESS = re.compile(r"^[^@\s,;<>]+@[a-z0-9.-]+\.[a-z]+$", re.I)

# Headers naming the recipient, most reliable first.
RECIPIENT_HEADERS = ("Delivered-To", "X-Original-To", "To", "Cc")


def notmuch(args, config=None):
    cmd = ["notmuch"]
    if config:
        cmd.append("--config=" + os.path.expanduser(config))
    return subprocess.run(cmd + args, check=True, capture_output=True).stdout


def load_config():
    """Settings from config.ini; a missing file means defaults."""
    cp = configparser.ConfigParser(interpolation=None)
    cp.read(CONFIG_FILE)
    return cp


def own_addresses(config):
    """Addresses of the mailbox owner, taken from the notmuch config."""
    addrs = set()
    for key in ("user.primary_email", "user.other_email"):
        try:
            out = notmuch(["config", "get", key], config).decode()
        except subprocess.CalledProcessError:
            continue
        for a in re.split(r"[;\n]", out):
            if a.strip():
                addrs.add(a.strip().lower())
    return addrs


def message_files(query, config):
    """One file per message (duplicates from several folders skipped)."""
    out = notmuch(["search", "--output=files", "--duplicate=1",
                   "--format=text0", query], config)
    return [p.decode("utf-8", "surrogateescape") for p in out.split(b"\0") if p]


def parse_unsubscribe(value):
    """Split a List-Unsubscribe header into (mailto, https) URIs."""
    mailto = https = None
    for uri in re.findall(r"<([^>]+)>", value or ""):
        uri = re.sub(r"\s+", "", uri)
        low = uri.lower()
        if low.startswith("mailto:") and not mailto:
            if parse_mailto(uri):
                mailto = uri
        elif low.startswith("https://") and not https:
            # Broken templates produce URLs like "https://String does not..."
            host = urllib.parse.urlsplit(uri).hostname or ""
            if HOSTNAME.match(host):
                https = uri
    return mailto, https


def parse_mailto(uri):
    """'mailto:a@b?subject=x' -> ('a@b', subject, body), None if unusable."""
    parts = urllib.parse.urlsplit(uri)
    to = urllib.parse.unquote(parts.path)
    if not ADDRESS.match(to):
        return None
    q = urllib.parse.parse_qs(parts.query)
    subject = q.get("subject", ["unsubscribe"])[0] or "unsubscribe"
    body = q.get("body", ["unsubscribe"])[0] or "unsubscribe"
    return to, subject, body


def domain_of(addr):
    return addr.rpartition("@")[2].lower()


def aligned(d1, d2):
    """Relaxed DMARC-style alignment: one domain is the other or a subdomain."""
    return d1 == d2 or d1.endswith("." + d2) or d2.endswith("." + d1)


def dkim_status(msg, from_domain, authserv_id):
    """'pass' if the receiving server saw a DKIM or DMARC pass aligned with
    From, 'unaligned' for a pass of a foreign domain only, else
    'fail'/'unknown'."""
    results = msg.get_all("Authentication-Results") or []
    if not results:
        return "unknown"
    # The topmost header was added by our own server; anything below may be
    # forged by the sender.
    top = str(results[0])
    if authserv_id and not top.strip().lower().startswith(authserv_id.lower()):
        return "unknown"
    passed = re.findall(r"dkim=pass[^;]*?header\.[di]=\"?@?([\w.-]+)", top, re.I)
    dmarc = re.findall(r"dmarc=pass[^;]*?header\.from=\"?([\w.-]+)", top, re.I)
    if any(aligned(d.lower(), from_domain) for d in passed + dmarc):
        return "pass"
    if passed:
        return "unaligned"
    if re.search(r"dkim=(fail|none|neutral|permerror|temperror)", top, re.I):
        return "fail"
    return "unknown"


def name_mismatch(name, addr):
    """True if no word of the display name shows up in the sender domain.

    Catches '1Password <no-reply@jxtgotfunded.com>', but also flags shops
    mailing from an unrelated domain - it is a hint for a human, not a
    verdict."""
    domain = domain_of(addr)
    if any(aligned(domain, p) for p in PLATFORMS):
        return False
    domain = re.sub(r"[^a-z0-9]", "", domain)
    words = set()
    for variant in transliterations(name.lower()):
        words.update(w for w in re.findall(r"[a-z0-9]+", variant)
                     if len(w) >= 3 and w not in NAME_NOISE)
    return bool(words) and not any(w in domain for w in words)


def transliterations(text):
    """'böttcher' -> {'bottcher', 'boettcher'}: domains spell umlauts both ways."""
    german = text.translate(str.maketrans({"ä": "ae", "ö": "oe", "ü": "ue",
                                           "ß": "ss", "ø": "oe", "æ": "ae"}))
    plain = unicodedata.normalize("NFKD", text.replace("ø", "o").replace("ß", "ss"))
    return {german, plain.encode("ascii", "ignore").decode()}


def recipient(msg, me, account):
    """Which of our own addresses received this message ('' if unknown).

    Unsubscribing must happen for exactly this address."""
    for h in RECIPIENT_HEADERS:
        values = [str(v) for v in msg.get_all(h) or []]
        for _, a in email.utils.getaddresses(values):
            if a.lower() in me:
                return a.lower()
    return account.lower() if account.lower() in me else ""


def collect(query, config, authserv_id):
    """Group all messages with a List-Unsubscribe header by sender.

    Within a group, the newest unsubscribe data is kept per recipient
    address: each subscription has its own token."""
    me = own_addresses(config)
    root = notmuch(["config", "get", "database.mail_root"], config).decode().strip()
    parser = email.parser.BytesHeaderParser(policy=email.policy.default)

    groups = {}
    stats = collections.Counter()
    for path in message_files(query, config):
        try:
            with open(path, "rb") as fh:
                msg = parser.parse(fh)
        except OSError:
            stats["unreadable"] += 1
            continue
        stats["messages"] += 1

        try:
            name, addr = email.utils.parseaddr(str(msg.get("From", "")))
        except Exception:
            name, addr = "", ""
        addr = addr.lower()
        if addr in me:
            stats["own"] += 1
            continue

        lu = msg.get("List-Unsubscribe")
        if not lu:
            stats["no_header"] += 1
            continue
        stats["with_header"] += 1

        mailto, https = parse_unsubscribe(str(lu))
        post = "one-click" in str(msg.get("List-Unsubscribe-Post", "")).lower()
        if https and post:
            method = "one-click"
        elif mailto:
            method = "mailto"
        elif https:
            method = "https"
        else:
            method = "none"

        # Group by sender address and display name: some senders use a new
        # List-Id per mailing, others send several lists from one address.
        key = f"{name.strip()} <{addr}>".lower()

        try:
            date = email.utils.parsedate_to_datetime(str(msg.get("Date")))
            date = date.date().isoformat()
        except Exception:
            date = ""

        account = os.path.relpath(path, root).split(os.sep)[0]
        rcpt = recipient(msg, me, account)
        g = groups.setdefault(key, {
            "key": key, "name": name, "from": addr, "count": 0, "last": "",
            "accounts": set(), "dkim": collections.Counter(), "targets": {},
        })
        g["count"] += 1
        g["accounts"].add(account)
        g["dkim"][dkim_status(msg, domain_of(addr), authserv_id)] += 1
        if date >= g["last"]:
            g["last"], g["name"], g["from"] = date, name or g["name"], addr
        t = g["targets"].get(rcpt)
        # Keep the newest unsubscribe data: older tokens may have expired.
        if t is None or date >= t["last"]:
            g["targets"][rcpt] = {"rcpt": rcpt, "last": date, "method": method,
                                  "mailto": mailto, "https": https}

    rows = []
    for g in groups.values():
        g["trusted"] = g["dkim"]["pass"] == g["count"]
        g["suspect"] = name_mismatch(g["name"], g["from"])
        g["accounts"] = sorted(g["accounts"])
        g["dkim"] = dict(g["dkim"])
        g["targets"] = sorted(g["targets"].values(), key=lambda t: t["last"], reverse=True)
        g["method"] = g["targets"][0]["method"]
        rows.append(g)
    rows.sort(key=lambda g: (-g["count"], g["key"]))
    return rows, stats


# ── state: log of past actions and the blocklist ──────────────────────

def read_log():
    """Latest logged action per (sender key, recipient)."""
    done = {}
    try:
        with open(LOG_FILE) as fh:
            for line in fh:
                try:
                    e = json.loads(line)
                    done[(e["key"], e.get("rcpt", ""))] = e
                except (ValueError, KeyError):
                    pass
    except FileNotFoundError:
        pass
    return done


def write_log(entry):
    os.makedirs(STATE_DIR, exist_ok=True)
    with open(LOG_FILE, "a") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")


def block_entry(addr):
    """What goes on the blocklist: the domain, or the address for freemail."""
    d = domain_of(addr)
    return addr if d in FREEMAIL else d


def read_blocklist():
    try:
        with open(BLOCKLIST) as fh:
            return {l.strip().lower() for l in fh if l.strip() and not l.startswith("#")}
    except FileNotFoundError:
        return set()


def add_to_blocklist(entries):
    known = read_blocklist()
    new = sorted(set(entries) - known)
    if not new:
        return []
    os.makedirs(CONFIG_DIR, exist_ok=True)
    fresh = not os.path.exists(BLOCKLIST)
    with open(BLOCKLIST, "a") as fh:
        if fresh:
            fh.write("# Sender domains/addresses treated as spam, one per line.\n"
                     "# Written by unsubscriber, edit freely.\n")
        for e in new:
            fh.write(e + "\n")
    return new


def tag_as_spam(entries, configs, tags):
    """Tag existing mail from blocked senders in every given database.

    Returns [(config, number of newly tagged messages)]."""
    query = " or ".join(f'from:"{e}"' for e in entries)
    first_tag = tags.split()[0].lstrip("+")
    result = []
    for cfg in configs:
        n = int(notmuch(["count", "--exclude=false",
                         f"( {query} ) and not tag:{first_tag}"], cfg))
        notmuch(["tag"] + tags.split() + ["--", f"( {query} )"], cfg)
        result.append((cfg or "default", n))
    return result


def target_state(g, t, log):
    """'done', 'still' (mail arrived after unsubscribing) or ''."""
    e = log.get((g["key"], t["rcpt"]))
    if not e or not e.get("ok"):
        return ""
    # Allow a few days for the sender to process the request.
    grace = (datetime.date.fromisoformat(e["date"][:10])
             + datetime.timedelta(days=3)).isoformat()
    return "still" if t["last"] > grace else "done"


def status_of(g, log, blocked):
    """'blocked', 'done', 'still', 'partial' or ''."""
    if g["from"] in blocked or domain_of(g["from"]) in blocked:
        return "blocked"
    states = [target_state(g, t, log) for t in g["targets"]]
    if "still" in states:
        return "still"
    if all(s == "done" for s in states):
        return "done"
    return "partial" if "done" in states else ""


# ── output ────────────────────────────────────────────────────────────

def print_table(rows, numbered=False, log=None, blocked=None):
    print(f"{'nr':>4}  " if numbered else "", end="")
    print(f"{'#':>4}  {'last':10}  {'method':11}  {'auth':4}  {'state':7}  sender")
    print("-" * 92)
    for i, g in enumerate(rows, 1):
        auth = ("ok" if g["trusted"] else "--") + ("!" if g["suspect"] else "")
        method = g["method"] + (f" x{len(g['targets'])}" if len(g["targets"]) > 1 else "")
        state = status_of(g, log or {}, blocked or set())
        sender = f"{g['name']} <{g['from']}>" if g["name"] else g["from"]
        if numbered:
            print(f"{i:>4}  ", end="")
        print(f"{g['count']:>4}  {g['last']:10}  {method:11}  {auth:4}  "
              f"{state:7}  {sender[:52]}")


def summary(rows, stats, query):
    print(f"Query: {query}")
    print(f"{stats['messages']} messages, {stats['with_header']} with List-Unsubscribe "
          f"from {len(rows)} senders ({stats['own']} own, "
          f"{stats['no_header']} without header)\n")


def legend():
    print("\nmethod: x2 = sent to two of your addresses, both get unsubscribed\n"
          "auth: ok = DKIM/DMARC pass aligned with sender, -- = not verified,\n"
          "      ! = display name not found in sender domain (possible fake)\n"
          "state: done = unsubscribed, still = mails arrived after unsubscribing,\n"
          "       partial = not all addresses done, blocked = on the blocklist")


def scan(args):
    rows, stats = collect(args.query, args.config, args.authserv_id)
    summary(rows, stats, args.query)
    print_table(rows, log=read_log(), blocked=read_blocklist())
    legend()

    by_method = collections.Counter(g["method"] for g in rows)
    trusted = [g for g in rows if g["trusted"]]
    print("\nMethods:  " + ", ".join(f"{m} {n}" for m, n in by_method.most_common()))
    print(f"Verified: {len(trusted)} of {len(rows)} senders, "
          f"{sum(g['count'] for g in trusted)} messages; "
          f"{sum(g['suspect'] for g in rows)} flagged with '!'")
    if args.json:
        save_json(rows, args.json)


def save_json(rows, path):
    # Unsubscribe URLs contain personal tokens: keep the file private.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(rows, fh, indent=2, ensure_ascii=False)
    print(f"Details written to {path}")


# ── unsubscribe ───────────────────────────────────────────────────────

def parse_selection(text, n):
    """'1,3, 5-8' -> {1, 3, 5, 6, 7, 8}; raises ValueError on bad input."""
    picked = set()
    for part in re.split(r"[,\s]+", text.strip()):
        if not part:
            continue
        lo, _, hi = part.partition("-")
        lo, hi = int(lo), int(hi or lo)
        if not 1 <= lo <= hi <= n:
            raise ValueError(f"out of range: {part}")
        picked.update(range(lo, hi + 1))
    return picked


def read_line(prompt):
    try:
        return input(prompt)
    except EOFError:
        return ""


def ask(prompt, n):
    while True:
        try:
            return parse_selection(read_line(prompt), n)
        except ValueError as e:
            print(f"  {e} - use numbers like 1,3,5-8 (empty for none)")


def ascii_url(url):
    """Percent-encode non-ASCII characters, keeping everything else as is.

    Some senders put raw UTF-8 into the header, which arrives here decoded
    as Latin-1 ('TRACE32Â®'). If the text round-trips that way, the
    original bytes are used, otherwise its UTF-8 encoding."""
    if url.isascii():
        return url
    try:
        raw = url.encode("latin-1")
        raw.decode("utf-8")
    except UnicodeError:
        raw = url.encode("utf-8")
    return urllib.parse.quote(raw, safe="%/:=&?~#+!$,;'@()*[]")


def one_click(url, timeout):
    """RFC 8058 one-click POST. Returns (ok, detail)."""
    req = urllib.request.Request(
        ascii_url(url), data=b"List-Unsubscribe=One-Click", method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded",
                 "User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status < 400, f"HTTP {resp.status}"
    except urllib.error.HTTPError as e:
        return False, f"HTTP {e.code}"
    except (urllib.error.URLError, OSError) as e:
        return False, str(getattr(e, "reason", e))
    except Exception as e:
        # Malformed URLs or odd server replies must not end the whole run.
        return False, f"{type(e).__name__}: {e}"


def get_password(passcmd, address):
    """Run the configured password command for one of our addresses."""
    cmd = passcmd.format(sender=address, account=address)
    out = subprocess.run(shlex.split(cmd), check=True, capture_output=True)
    return out.stdout.decode().splitlines()[0]


def send_mail(sender, uri, smtp, timeout):
    """Send the unsubscribe mail for a mailto: URI from our own address.

    The [smtp] config section either names a 'sendmail' command, or 'host',
    'port', 'user' and 'passcmd'; '{sender}' in user and passcmd is replaced
    by the sending address. Returns (ok, detail)."""
    to, subject, body = parse_mailto(uri)
    msg = email.message.EmailMessage()
    msg["From"] = sender
    msg["To"] = to
    msg["Subject"] = subject
    msg["Date"] = email.utils.formatdate(localtime=True)
    msg["Message-ID"] = email.utils.make_msgid(domain=domain_of(sender))
    msg.set_content(body)
    try:
        if smtp.get("sendmail"):
            subprocess.run(shlex.split(smtp["sendmail"]) + ["-f", sender, to],
                           input=msg.as_bytes(), check=True, capture_output=True,
                           timeout=timeout)
            return True, "sendmail"
        host = smtp["host"]
        port = int(smtp.get("port", "465"))
        password = get_password(smtp["passcmd"], sender)
        ctx = ssl.create_default_context()
        if port == 465:
            server = smtplib.SMTP_SSL(host, port, timeout=timeout, context=ctx)
        else:
            server = smtplib.SMTP(host, port, timeout=timeout)
            server.starttls(context=ctx)
        with server:
            server.login(smtp.get("user", "{sender}").format(sender=sender), password)
            server.send_message(msg)
        return True, f"via {host}"
    except KeyError as e:
        return False, f"[smtp] setting missing: {e}"
    except subprocess.CalledProcessError as e:
        return False, f"command failed: {e.cmd[0]} (exit {e.returncode})"
    except (smtplib.SMTPException, OSError, IndexError, subprocess.TimeoutExpired) as e:
        return False, f"{type(e).__name__}: {e}"


def unsubscribe(args):
    cfg = load_config()
    smtp = dict(cfg["smtp"]) if cfg.has_section("smtp") else {}
    rows, stats = collect(args.query, args.config, args.authserv_id)
    log, blocked = read_log(), read_blocklist()
    # Hide what is settled, unless it keeps coming.
    rows = [g for g in rows if status_of(g, log, blocked) not in ("done", "blocked")]
    if not rows:
        print("Nothing left to do.")
        return
    summary(rows, stats, args.query)
    print_table(rows, numbered=True, log=log, blocked=blocked)
    legend()
    print()

    unsub = ask("Unsubscribe (e.g. 1,3,5-8): ", len(rows))
    spam = ask("Block as spam:              ", len(rows))
    both = unsub & spam
    if both:
        print(f"  {sorted(both)} chosen twice - treated as spam only")
        unsub -= both

    chosen = []
    for i in sorted(unsub):
        g = rows[i - 1]
        if not g["trusted"] and not args.force:
            print(f"  skip {i}: sender not verified (use --force to override)")
            continue
        chosen.append((i, g))

    # Unsubscribing from a fake confirms the address: ask once more.
    suspects = [i for i, g in chosen if g["suspect"]]
    if suspects:
        answer = read_line(f"  {suspects} are flagged '!' - unsubscribe anyway? [y/N] ")
        if answer.strip().lower() not in ("y", "yes", "j", "ja"):
            chosen = [(i, g) for i, g in chosen if not g["suspect"]]
            print("  flagged ones skipped")

    print("\nDry run, nothing sent:" if args.dry_run else "")

    # Blocking first: it is local and quick, and must not be lost if
    # something goes wrong on the network afterwards.
    spam_rows = [rows[i - 1] for i in sorted(spam)]
    entries = sorted({block_entry(g["from"]) for g in spam_rows})
    if entries:
        configs = [args.config] + [c.strip() for c in
                                   cfg.get("unsubscriber", "extra_configs", fallback="").split(",")
                                   if c.strip()]
        tags = cfg.get("unsubscriber", "spam_tags", fallback=DEFAULT_SPAM_TAGS)
        if args.dry_run:
            print(f"  would block: {', '.join(entries)}  (tags {tags})")
        else:
            new = add_to_blocklist(entries)
            print(f"  blocklist +{len(new)}: " + ", ".join(new or ["(all known)"]))
            for db, n in tag_as_spam(entries, configs, tags):
                print(f"  tagged {tags} in {db}: {n} messages")

    manual = []
    for _, g in chosen:
        label = g["name"] or g["from"]
        for t in g["targets"]:
            if target_state(g, t, log) == "done":
                continue
            rcpt = t["rcpt"] or "?"
            if t["method"] == "one-click":
                host = urllib.parse.urlsplit(t["https"]).hostname
                what = f"POST to {host}"
                run = lambda t=t: one_click(t["https"], args.timeout)
            elif t["method"] == "mailto" and t["rcpt"] and smtp:
                to = parse_mailto(t["mailto"])[0]
                what = f"mail to {to}"
                run = lambda t=t: send_mail(t["rcpt"], t["mailto"], smtp, args.timeout)
            else:
                manual.append((g, t))
                continue
            if args.dry_run:
                print(f"  would {what}  ({label} -> {rcpt})")
                continue
            try:
                ok, detail = run()
            except Exception as e:
                ok, detail = False, f"{type(e).__name__}: {e}"
            print(f"  {'ok  ' if ok else 'FAIL'}  {label} -> {rcpt}  ({what}, {detail})")
            write_log({"date": datetime.datetime.now().isoformat(timespec="seconds"),
                       "key": g["key"], "from": g["from"], "rcpt": t["rcpt"],
                       "method": t["method"], "target": what, "ok": ok,
                       "detail": detail})

    if manual:
        print("\nNot automatable, please handle by hand:")
        for g, t in manual:
            if t["method"] == "mailto" and not smtp:
                hint = "  (no [smtp] section in config)"
            elif t["method"] == "mailto":
                hint = "  (receiving address unknown)"
            else:
                hint = ""
            target = t["mailto"] if t["method"] == "mailto" else t["https"]
            print(f"  {g['name'] or g['from']} -> {t['rcpt'] or '?'}: "
                  f"{target or '(no link)'}{hint}")


# ── purge: clean up the server ────────────────────────────────────────

def purge_rules(only):
    """What to remove: blocked domains/addresses and unsubscribed senders.

    Returns [(label, imap search term, match function on (name, addr))]."""
    rules = []
    if only in (None, "blocked"):
        for e in sorted(read_blocklist()):
            if "@" in e:
                match = lambda name, addr, e=e: addr == e
            else:
                match = lambda name, addr, e=e: aligned_sub(domain_of(addr), e)
            rules.append((f"blocked {e}", e, match))
    if only in (None, "unsubscribed"):
        senders = {}
        for (key, _), entry in read_log().items():
            if entry.get("ok"):
                senders[key] = entry["from"]
        for key, addr in sorted(senders.items()):
            # Same grouping key as in collect(): display name plus address,
            # so leaving one newsletter of a shared sender address does not
            # remove the others.
            match = lambda name, a, key=key: f"{name.strip()} <{a}>".lower() == key
            rules.append((f"unsubscribed {key}", addr, match))
    return rules


def aligned_sub(domain, blocked):
    """A blocked domain also covers its subdomains, never the other way."""
    return domain == blocked or domain.endswith("." + blocked)


def imap_quote(mailbox):
    return '"' + mailbox.replace("\\", "\\\\").replace('"', '\\"') + '"'


def imap_connect(account, imap, timeout):
    import imaplib
    host = imap["host"]
    port = int(imap.get("port", "993"))
    conn = imaplib.IMAP4_SSL(host, port, timeout=timeout,
                             ssl_context=ssl.create_default_context())
    conn.login(imap.get("user", "{sender}").format(sender=account, account=account),
               get_password(imap["passcmd"], account))
    return conn


def find_trash(conn, imap):
    """The mailbox flagged \\Trash (RFC 6154), else the configured name."""
    typ, data = conn.list()
    for line in data if typ == "OK" else []:
        if not isinstance(line, bytes):
            continue
        m = re.match(rb'\((?P<flags>[^)]*)\) (?:"[^"]*"|NIL) (?P<name>.+)$', line)
        if m and b"\\trash" in m.group("flags").lower():
            return m.group("name").decode().strip().strip('"')
    return imap.get("trash", "Trash")


def search_mailbox(conn, folder, rules):
    """UIDs in folder matching a rule: {uid: (label, from)}. Read-only."""
    typ, _ = conn.select(imap_quote(folder), readonly=True)
    if typ != "OK":
        return None
    candidates = set()
    for _, term, _ in rules:
        # FROM is a substring search on the server; the exact check follows.
        typ, data = conn.uid("SEARCH", "UNFLAGGED", "FROM", imap_quote(term))
        if typ == "OK" and data and data[0]:
            candidates.update(data[0].split())
    found = {}
    uids = sorted(candidates, key=int)
    for i in range(0, len(uids), 200):
        chunk = b",".join(uids[i:i + 200]).decode()
        typ, data = conn.uid("FETCH", chunk, "(BODY.PEEK[HEADER.FIELDS (FROM)])")
        for item in data if typ == "OK" else []:
            if not isinstance(item, tuple):
                continue
            m = re.search(rb"UID (\d+)", item[0])
            if not m:
                continue
            msg = email.parser.BytesHeaderParser(policy=email.policy.default).parsebytes(item[1])
            try:
                name, addr = email.utils.parseaddr(str(msg.get("From", "")))
            except Exception:
                continue
            addr = addr.lower()
            for label, _, match in rules:
                if match(name, addr):
                    found[m.group(1)] = (label, addr)
                    break
    return found


def move_to_trash(conn, folder, uids, trash):
    """Move UIDs to the trash; returns the number moved."""
    conn.select(imap_quote(folder))
    moved = 0
    for i in range(0, len(uids), 200):
        chunk = b",".join(uids[i:i + 200]).decode()
        if "MOVE" in conn.capabilities:
            typ, _ = conn.uid("MOVE", chunk, imap_quote(trash))
        else:
            typ, _ = conn.uid("COPY", chunk, imap_quote(trash))
            if typ == "OK":
                conn.uid("STORE", chunk, "+FLAGS.SILENT", r"(\Deleted)")
                # Without UIDPLUS a plain EXPUNGE could hit other messages
                # marked deleted, so leave them flagged in that case.
                if "UIDPLUS" in conn.capabilities:
                    conn.uid("EXPUNGE", chunk)
        if typ == "OK":
            moved += len(uids[i:i + 200])
    return moved


def purge(args):
    cfg = load_config()
    if not cfg.has_section("imap"):
        sys.exit(f"purge needs an [imap] section in {CONFIG_FILE}")
    imap = dict(cfg["imap"])
    accounts = [a.strip() for a in imap.get("accounts", "").split(",") if a.strip()] \
        or sorted(own_addresses(args.config))
    folders = args.folder or [f.strip() for f in imap.get("folders", "INBOX").split(",")]

    rules = purge_rules(args.only)
    if args.sender:
        rules = [r for r in rules if args.sender.lower() in r[0]]
    if not rules:
        print("Nothing to purge: no blocked or unsubscribed senders"
              + (f" matching {args.sender!r}" if args.sender else "") + ".")
        return
    print(f"{len(rules)} senders, folders {', '.join(folders)}, "
          f"accounts {', '.join(accounts)}\n(flagged messages are never touched)\n")

    plan = []
    for account in accounts:
        try:
            conn = imap_connect(account, imap, args.timeout)
        except Exception as e:
            print(f"  {account}: cannot log in ({type(e).__name__}: {e})")
            continue
        with conn:
            trash = find_trash(conn, imap)
            for folder in folders:
                found = search_mailbox(conn, folder, rules)
                if found is None:
                    print(f"  {account}/{folder}: no such folder")
                    continue
                if not found:
                    continue
                per_rule = collections.Counter(label for label, _ in found.values())
                print(f"  {account}/{folder}: {len(found)} messages -> {trash}")
                for label, n in per_rule.most_common():
                    print(f"    {n:>5}  {label}")
                plan.append((account, folder, trash, sorted(found, key=int), per_rule))

    total = sum(len(p[3]) for p in plan)
    if not total:
        print("Nothing found on the server.")
        return
    if args.dry_run:
        print(f"\nDry run: {total} messages would be moved to the trash.")
        return
    answer = read_line(f"\nMove {total} messages to the trash? [y/N] ")
    if answer.strip().lower() not in ("y", "yes", "j", "ja"):
        print("Nothing changed.")
        return

    for account, folder, trash, uids, per_rule in plan:
        try:
            conn = imap_connect(account, imap, args.timeout)
            with conn:
                moved = move_to_trash(conn, folder, uids, trash)
        except Exception as e:
            moved, error = 0, f"{type(e).__name__}: {e}"
        else:
            error = ""
        print(f"  {account}/{folder}: {moved} of {len(uids)} moved"
              + (f"  ({error})" if error else ""))
        write_purge_log({"date": datetime.datetime.now().isoformat(timespec="seconds"),
                         "account": account, "folder": folder, "trash": trash,
                         "moved": moved, "planned": len(uids),
                         "senders": dict(per_rule), "error": error})


def write_purge_log(entry):
    os.makedirs(STATE_DIR, exist_ok=True)
    with open(os.path.join(STATE_DIR, "purge.jsonl"), "a") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")


def main():
    cfg = load_config()
    ap = argparse.ArgumentParser(
        description=__doc__.split("\n\n")[0],
        epilog=f"Settings: {CONFIG_FILE}, see config.example.ini")
    ap.add_argument("--config", default=cfg.get("unsubscriber", "notmuch_config", fallback=None),
                    help="notmuch config file (default: notmuch's own)")
    ap.add_argument("-q", "--query", default=DEFAULT_QUERY,
                    help=f"notmuch query (default: {DEFAULT_QUERY!r})")
    ap.add_argument("--authserv-id", default=cfg.get("unsubscriber", "authserv_id", fallback=None),
                    help="only trust Authentication-Results from this server, e.g. mail.example.com")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="list newsletters (read-only)")
    s.add_argument("--json", metavar="FILE", help="write details incl. URLs to FILE (mode 600)")
    s.set_defaults(func=scan)

    u = sub.add_parser("unsubscribe", help="pick senders to unsubscribe or block")
    u.add_argument("-n", "--dry-run", action="store_true", help="show what would happen")
    u.add_argument("--force", action="store_true", help="also unsubscribe unverified senders")
    u.add_argument("--timeout", type=float, default=20, help="network timeout in s (default 20)")
    u.set_defaults(func=unsubscribe)

    p = sub.add_parser("purge", help="move mail of blocked/unsubscribed senders "
                                     "to the trash on the IMAP server")
    p.add_argument("-n", "--dry-run", action="store_true", help="only count, change nothing")
    p.add_argument("--only", choices=("blocked", "unsubscribed"), help="limit to one kind")
    p.add_argument("--sender", metavar="TEXT", help="limit to senders containing TEXT")
    p.add_argument("--folder", action="append",
                   help="IMAP folder to clean, repeatable (default: INBOX or [imap] folders)")
    p.add_argument("--timeout", type=float, default=30, help="network timeout in s (default 30)")
    p.set_defaults(func=purge)

    args = ap.parse_args()
    try:
        args.func(args)
    except subprocess.CalledProcessError as e:
        sys.exit(f"notmuch failed: {e.stderr.decode(errors='replace').strip()}")
    except KeyboardInterrupt:
        sys.exit("\naborted")


if __name__ == "__main__":
    main()
