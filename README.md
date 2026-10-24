# server-scripts

## server-audit.sh

`server-audit.sh` is a read-only security, health and capacity audit for a **Linux server that hosts Laravel apps**. It reads logs and config files, makes a few HTTPS requests to your own domains, and prints a report. It never changes, deletes, blocks or installs anything.

The output is built for a nightly email. Checks that pass are counted but not printed, so the report lists only problems and useful info.

### What it checks

| Section | What it looks at |
|---|---|
| **1. Laravel applications** | Each app found under `/home`:<br>• Laravel log errors, and secrets written into logs<br>• `.env` settings: `APP_DEBUG`, `APP_ENV`, `APP_KEY`, file permissions, database user, database host, TLS, secure cookies<br>• Document root pointing at the app root instead of `public/`<br>• World-writable files, and stray PHP files in `storage/` or `public/`<br>• Upload folders that can run PHP, and backups or dumps inside `public/`<br>• Backdoor-style code<br>• Files that differ from the last `git pull`<br>• `composer audit` |
| **2. Web access logs** | • Requests per domain<br>• SQL injection, path traversal, XSS, secret/backup probes, exploit and webshell paths, remote command attempts and scanner tools<br>• Probes that actually got **HTTP 200**<br>• Login brute force<br>• Most active scanners<br>• 5xx errors by URL |
| **3. Exposure checks** | For each domain:<br>• Probes `.env`, `.git/config`, `laravel.log`, `composer.lock`, `vendor/`, `phpinfo`, Telescope, Horizon and Ignition. A domain is reported only when the real content is served, not a 200 error page.<br>• Security headers, the HTTP→HTTPS redirect and TLS certificate expiry |
| **4. Login activity** | Failed and successful SSH logins; failed control panel and webmail logins |
| **5. Server hardening** | • Firewall, brute-force protection and ModSecurity<br>• SSH password and root login<br>• Database and cache ports listening publicly<br>• PHP version and settings, and shell functions left enabled in PHP-FPM pools<br>• Pending OS security updates<br>• Backups: enabled, recent, copied off the server, and not excluding app files<br>• Managed database reminders |
| **6. Capacity and peaks** | • Disk and swap<br>• CPU, memory and load peaks (from sysstat)<br>• Out-of-memory kills<br>• PHP-FPM `max_children` and Apache worker limits<br>• Database "too many connections" errors and PHP memory exhaustion<br>• Busiest hours |

### Requirements

- Linux
- bash, curl, and the standard GNU tools
- Run as **root**. A normal user can run it but sees far less.
- Optional: `sysstat` for past CPU and memory peaks, and `composer` for the package audit.

### Usage

```bash
bash server-audit.sh                  # last 7 days (today counts as day 1)
DAYS=2 bash server-audit.sh           # yesterday + today (use this for a nightly run)
DAYS=all bash server-audit.sh         # every log file, no date filter
VERBOSE=1 bash server-audit.sh        # also print the checks that passed
```

### Options

All options are environment variables.

| Variable | Default | Meaning |
|---|---|---|
| `DAYS` | `7` | Days of history to analyse, or `all` |
| `APPS` | auto-find under `/home` | Laravel app folders, space separated |
| `DOMAINS` | all hosted domains | Domains to probe, space separated |
| `MAILTO` | none | Email the report to this address |
| `MAIL_ENV` | none | Path to a Laravel `.env`, used to send the email with that app's mail settings (see below) |
| `MAIL_FROM` | the app's `MAIL_FROM_ADDRESS` | Sender address |
| `SKIP_HTTP=1` | off | Skip the HTTPS probes |
| `SKIP_UPDATES=1` | off | Skip the OS security-update check |
| `VERBOSE=1` | off | Also print passed checks |
| `LOGIN_THRESHOLD` | `30` | Login POSTs from one IP before it is flagged |
| `INCLUDE_DOWN=1` | off | Also audit sites in Laravel maintenance mode. They are skipped by default, except for the backdoor scan |
| `DISK_SNAPSHOTS=1` | off | The cloud provider snapshots the whole disk, so skip the control-panel backup check |
| `IGNORE_FILE` | `/root/server-audit.ignore` | Known-good file paths, one text fragment per line. Lines starting with `#` are comments. Ignored files are still scanned for backdoor code |

### Emailing the report

Many cloud providers block outgoing port 25, so the server's own mailer often can't deliver. Set `MAIL_ENV` to send through a Laravel app's mail settings instead. The script tries these in order:

1. The mail provider's HTTP API, if the `.env` holds its domain and secret.
2. SMTP login on port 465 or 587, using `MAIL_HOST`, `MAIL_PORT`, `MAIL_USERNAME` and `MAIL_PASSWORD`.
3. The server's own `mail` or `sendmail`.

Credentials are passed to curl on stdin, so they never appear in the process list.

### Nightly run

Add this to root's crontab with `crontab -e`:

```cron
15 3 * * * DAYS=2 MAILTO=you@example.com MAIL_ENV=/home/user/app/.env nice -n 19 ionice -c3 /root/server-audit.sh > /root/audit-last.txt 2>&1
```

`nice` and `ionice` keep the audit from slowing down the websites.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Clean |
| `1` | Warnings only |
| `2` | At least one FAIL |
| `3` | Bad option or setup error |

### Reading the report

- **FAIL:** fix first.
- **WARN:** worth a look.
- **info:** context only.
- Attack attempts in section 2 are normal background noise for any public server. A `403` or `404` means the request was refused. Act on the **"Probes that SUCCEEDED (HTTP 200)"** list and on login floods.
