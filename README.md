# unsubscriber

Leave newsletters in bulk, straight from your local mail archive.

`unsubscriber` reads a [notmuch](https://notmuchmail.org) database, groups all
mail carrying a `List-Unsubscribe` header by sender, and lets you pick by number
which ones to leave. Senders turning out to be fakes go on a blocklist instead,
and their mail is tagged as spam.

No dependencies besides Python 3.8+ and the `notmuch` command line tool.

```
  nr     #  last        method       auth  state    sender
--------------------------------------------------------------------------------------------
   1   115  2026-11-13  one-click    ok             Daily Briefing <newsletter@example-news.com>
   2    63  2026-11-13  one-click    ok             Vendor Updates <updates@contact.vendor.example>
  21     9  2026-11-09  one-click x2  ok            Some Service <noreply@service.example>
  98     1  2026-09-23  one-click    ok!            1Password <no-reply@jxtgotfunded.example>
 106     1  2026-10-21  mailto       ok             Appliances <info@mails.appliance.example>

Unsubscribe (e.g. 1,3,5-8): 1,2,21,106
Block as spam:              98
```

## How it works

Most newsletters announce how to leave them in a `List-Unsubscribe` header,
so there is no need to dig for links in the mail body. Three variants exist:

| Method | Header | What unsubscriber does |
|---|---|---|
| **one-click** | `List-Unsubscribe-Post: List-Unsubscribe=One-Click` plus an https URL ([RFC 8058](https://www.rfc-editor.org/rfc/rfc8058)) | sends the POST itself |
| **mailto** | `<mailto:…>` | sends the mail from the address that received the newsletter |
| **https** | URL without the post header | lists the link; it usually opens a page with a button |

Each subscription carries its own token. If a newsletter reaches several of your
addresses (`x2` in the list), each one is unsubscribed separately.

Every action is logged. A sender who keeps mailing more than three days after
you left shows up again with state `still`.

## Safety

**Never unsubscribe from spam.** It only tells the sender that your address is
read. unsubscriber guards against that in two ways:

- **Signature check.** Only senders whose mail passed DKIM or DMARC for their
  own From domain are offered. The result is taken from the topmost
  `Authentication-Results` header, the one your provider adds on delivery; set
  `authserv_id` so headers forged further down are ignored. Unverified senders
  need `--force`.
- **Fake hint.** A valid signature proves the domain, not the brand: a phisher
  signs `1Password <no-reply@jxtgotfunded.example>` just fine. Senders whose
  display name does not appear in their domain are flagged with `!`, and
  picking one asks for confirmation. The hint also fires for shops mailing
  from unrelated domains. It is a prompt to look, not a verdict.

Block suspicious senders instead. That adds their domain to
`~/.config/unsubscriber/blocklist.txt` (or only the address, for freemail
providers) and tags their existing mail `+spam -inbox`.

Use `-n` for a dry run first.

## Usage

```
./unsubscriber.py scan                  # read-only overview
./unsubscriber.py scan --json out.json  # details incl. unsubscribe URLs
./unsubscriber.py unsubscribe -n        # dry run: show what would happen
./unsubscriber.py unsubscribe           # do it
```

Global options go before the command:

| Option | Meaning |
|---|---|
| `-q QUERY` | notmuch query to look at, default `date:6months..` |
| `--config FILE` | notmuch config file |
| `--authserv-id ID` | trust only `Authentication-Results` from this server |

`unsubscribe` also takes `--force` (allow unverified senders) and `--timeout`.

## Configuration

Optional, in `~/.config/unsubscriber/config.ini`. See
[`config.example.ini`](config.example.ini):

```ini
[unsubscriber]
authserv_id = mail.example.com
extra_configs = ~/.notmuch-config-old   ; also tag blocked senders here
spam_tags = +spam -inbox

[smtp]                                  ; needed for mailto: only
host = smtp.example.com
port = 465
user = {sender}
passcmd = pass show mail/{sender}
```

`{sender}` is replaced by the address that received the newsletter. That
address must send the unsubscribe mail, otherwise the list cannot tell whom to
remove. Instead of SMTP you can set `sendmail = /usr/sbin/sendmail -oi`, but only
if your MTA relays through your provider: mail sent directly from a home
connection fails SPF/DMARC.

## Blocking new mail too

Tagging existing mail happens right away. For mail arriving later, read the
blocklist in your tagging script, e.g. in a notmuch `post-new` hook:

```bash
BL="$HOME/.config/unsubscriber/blocklist.txt"
if [[ -s "$BL" ]]; then
    q=$(grep -v -e '^#' -e '^[[:space:]]*$' "$BL" | sed 's/.*/from:"&"/' \
        | paste -sd'|' | sed 's/|/ or /g')
    [[ -n "$q" ]] && notmuch tag +spam -inbox -- "tag:new and ( $q )"
fi
```

This only acts locally. On the server, and on your phone, the mail stays in
the inbox.

## Files

| Path | Content |
|---|---|
| `~/.config/unsubscriber/config.ini` | settings |
| `~/.config/unsubscriber/blocklist.txt` | blocked domains/addresses, one per line |
| `~/.local/state/unsubscriber/log.jsonl` | one line per unsubscribe attempt |

`XDG_CONFIG_HOME` and `XDG_STATE_HOME` are honoured. The `--json` output
contains personal unsubscribe tokens and is written with mode 600.

## Limits

- https-only links are listed, not followed: they need a human on a web page.
- A sender's grouping key is display name plus address. A newsletter that
  changes its display name appears twice.
- The fake hint is a heuristic. Platforms that mail on behalf of others
  (LinkedIn, GitHub, …) are exempt via a list in the source.

## License

MIT, see [LICENSE](LICENSE).
