#!/usr/bin/env bash
# =============================================================================
# server-audit.sh  -  read-only log, security and capacity audit
# For: WHM/cPanel cloud server hosting several Laravel apps,
#      database on a managed cloud database service.
#
# It only READS files and makes a few HTTPS requests to your own domains.
# It never changes, deletes, blocks or installs anything.
#
# Run as root:
#     bash server-audit.sh                  # last 7 days (today counts as day 1)
#     DAYS=2 bash server-audit.sh           # yesterday + today so far (use this for the nightly run)
#     DAYS=all bash server-audit.sh         # every log file, no date filter
#
# Optional settings (environment variables):
#     DAYS=7                 days of history to analyse, or "all"
#     APPS="/home/u1/app1 /home/u2/app2"   Laravel app folders (default: auto-find under /home)
#     DOMAINS="a.example.com b.example.com" domains to probe (default: all cPanel domains)
#     MAILTO=you@example.com email the report
#     MAIL_ENV=/home/user/app/.env   send through the mail account of that Laravel app:
#                            mail provider HTTP API if the .env has its API domain + secret,
#                            otherwise SMTP login from MAIL_HOST / MAIL_PORT / MAIL_USERNAME / MAIL_PASSWORD.
#                            Without MAIL_ENV the server's own mailer is used (often blocked on port 25 by cloud providers).
#     MAIL_FROM=audit@yourdomain.com  sender address (default: the app's MAIL_FROM_ADDRESS)
#     SKIP_HTTP=1            skip the outside-in HTTPS probes
#     SKIP_UPDATES=1         skip the pending-security-updates check
#     VERBOSE=1              also print the checks that passed (default: only problems and info are printed)
#     LOGIN_THRESHOLD=30     login POSTs from one IP before it is flagged
#     INCLUDE_DOWN=1         also audit sites in Laravel maintenance mode (default: they are skipped,
#                            except for the backdoor-code scan)
#     IGNORE_FILE=/root/server-audit.ignore   known-good file paths, one text fragment per line
#                            (/public/landing-page/ is already built in). Lines starting with # are comments.
#                            Ignored files are still scanned for backdoor code.
#
# Nightly schedule, low priority (add with: crontab -e   as root):
#     15 3 * * * DAYS=2 MAILTO=you@example.com MAIL_ENV=/home/user/app/.env nice -n 19 ionice -c3 /root/server-audit.sh > /root/audit-last.txt 2>&1
#
# Exit code: 0 = clean, 1 = warnings, 2 = at least one FAIL.
# =============================================================================
set -u
export LC_ALL=C
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/cpanel/bin:$PATH

DAYS="${DAYS:-7}"
APP_ROOTS="${APP_ROOTS:-/home}"
LOGIN_THRESHOLD="${LOGIN_THRESHOLD:-30}"
UA="server-audit-selfcheck/1.0"
TMP="$(mktemp -d /tmp/server-audit.XXXXXX)" || exit 3
REPORT="$TMP/report.txt"
trap 'rm -rf "$TMP"' EXIT
NPASS=0; NWARN=0; NFAIL=0
IS_ROOT=0; [ "$(id -u)" -eq 0 ] && IS_ROOT=1

# ---------- output helpers ---------------------------------------------------
if [ -t 1 ]; then R=$'\e[31m'; Y=$'\e[33m'; G=$'\e[32m'; B=$'\e[1m'; N=$'\e[0m'; else R=; Y=; G=; B=; N=; fi
WHERE=""; : > "$TMP/pending"
# a sub-heading prints only once something is listed under it (kept in a file so pipelines/subshells see it too)
flush()   { [ -s "$TMP/pending" ] || return 0; local p; p=$(cat "$TMP/pending"); : > "$TMP/pending"; out ""; out "$p"; }
out()     { flush; printf '%s\n' "$*" | tee -a "$REPORT"; }
section() { : > "$TMP/pending"; WHERE="${*#[0-9]. }"; out ""; out "${B}=== $* ===${N}"; }
sub()     { printf '%s' "${B}--- $* ---${N}" > "$TMP/pending"; case "$*" in App:*) WHERE="${*##*/}";; esac; }
ok()      { NPASS=$((NPASS+1)); [ "${VERBOSE:-0}" = 1 ] && out "  ${G}[ OK ]${N} $*"; return 0; }   # passed checks are counted, shown only with VERBOSE=1
warn()    { NWARN=$((NWARN+1)); out "  ${Y}[WARN]${N} $*"; echo "WARN  $WHERE: $*" >> "$TMP/actions"; }   # also collected for the to-do list
bad()     { NFAIL=$((NFAIL+1)); out "  ${R}[FAIL]${N} $*"; echo "FAIL  $WHERE: $*" >> "$TMP/actions"; }
note()    { out "  [info] $*"; }
indent()  { flush; sed 's/^/         /' | tee -a "$REPORT"; }
top()     { sort | uniq -c | sort -rn | head -n "${1:-5}"; }
cnt()     { grep -ciE -- "$1" "$2" 2>/dev/null || true; }
have()    { command -v "$1" >/dev/null 2>&1; }

# ---------- date filters -----------------------------------------------------
: > "$TMP/d_apache"; : > "$TMP/d_iso"; : > "$TMP/d_sys"; : > "$TMP/d_fpm"; : > "$TMP/d_aperr"
if [ "$DAYS" != "all" ]; then
  case "$DAYS" in ''|*[!0-9]*) echo "DAYS must be a number or 'all'"; exit 3;; esac
  for i in $(seq 0 $((DAYS-1))); do
    date -d "-$i day" +'%d/%b/%Y' >> "$TMP/d_apache"
    date -d "-$i day" +'[%Y-%m-%d' >> "$TMP/d_iso"
    date -d "-$i day" +'%b %e ' >> "$TMP/d_sys"; date -d "-$i day" +'%Y-%m-%dT' >> "$TMP/d_sys"   # syslog, old and new style
    date -d "-$i day" +'[%d-%b-%Y ' >> "$TMP/d_fpm"       # PHP-FPM error log
    date -d "-$i day" +'[%a %b %d ' >> "$TMP/d_aperr"     # Apache error log
  done
fi
# files last written before the window started cannot hold entries from it, so they are never opened
NEWER=()
[ "$DAYS" != "all" ] && NEWER=(-newermt "$(date -d "-$((DAYS-1)) day" +%Y-%m-%d) 00:00:00")
datefilter() {  # $1 = pattern file ; passes everything when DAYS=all
  if [ "$DAYS" = "all" ]; then cat; else grep -F -f "$1" || true; fi
}

# windowed SRC PATTERNS OUT DATE_REGEX : keep only lines inside the window.
# Sets WLABEL. If the file's date format is not recognised, uses the whole file and says so.
windowed() {
  WLABEL="last $DAYS day(s)"
  if [ "$DAYS" = all ]; then WLABEL="whole file"; cat "$1" > "$3"; return; fi
  if head -n 200 "$1" | grep -qaE -- "$4"; then grep -aF -f "$2" "$1" > "$3" || true
  else WLABEL="whole file - date format not recognised"; cat "$1" > "$3"; fi
}

# ignore list for known-good files
IGN="$TMP/ign"; : > "$IGN"
IGNORE_FILE="${IGNORE_FILE:-/root/server-audit.ignore}"
[ -r "$IGNORE_FILE" ] && grep -vE '^[[:space:]]*(#|$)' "$IGNORE_FILE" | sed 's/[[:space:]]*$//' > "$IGN"
echo '/public/landing-page/' >> "$IGN"    # built-in: landing-page template files are known-good
apply_ignore() {  # FILE (list of paths) - drops ignored paths and says how many
  [ -s "$IGN" ] && [ -s "$1" ] || return 0
  local b a; b=$(wc -l < "$1"); grep -vF -f "$IGN" "$1" > "$1.keep"; mv "$1.keep" "$1"; a=$(wc -l < "$1")
  [ "$b" -gt "$a" ] && note "$((b-a)) known-good file(s) skipped (landing-page or ignore list)"
  return 0
}

out "${B}Server audit report${N}  -  $(hostname)  -  $(date '+%Y-%m-%d %H:%M %Z')"
out "Window: last $DAYS day(s).  Read-only run."
[ $IS_ROOT -eq 1 ] || out "NOTE: not running as root - server log and config checks will be skipped or partial."

# =============================================================================
# 1. LARAVEL APPS: errors, attack traces, configuration
# =============================================================================
section "1. Laravel applications"

if [ -n "${APPS:-}" ]; then
  read -r -a APP_LIST <<< "$APPS"
else
  # shellcheck disable=SC2086
  mapfile -t APP_LIST < <(find $APP_ROOTS -maxdepth 5 -type f -name artisan \
      -not -path '*/vendor/*' -not -path '*/node_modules/*' 2>/dev/null | sed 's|/artisan$||' | sort -u)
fi
note "Laravel apps found: ${#APP_LIST[@]}"
: > "$TMP/lv_all"   # all filtered Laravel log header lines, for the capacity section

envget() { grep -E "^[[:space:]]*$2=" "$1" 2>/dev/null | tail -n1 | cut -d= -f2- | tr -d "\"'\r" | sed 's/[[:space:]]*$//'; }

DOWN_APPS=()
scan_backdoor() {  # APP - runs for every app, including ones in maintenance mode
  local app="$1"
  # obfuscated / backdoor code signatures (app code only, vendor excluded)
  grep -rIlE --include='*.php' --include='*.phtml' --exclude-dir=vendor --exclude-dir=node_modules --exclude-dir=framework \
    'eval[[:space:]]*\([[:space:]]*(base64_decode|gzinflate|gzuncompress|str_rot13)|\$_(POST|GET|REQUEST|COOKIE)\[[^]]+\][[:space:]]*\(|assert[[:space:]]*\([[:space:]]*\$_|(system|passthru|shell_exec)[[:space:]]*\([[:space:]]*\$_(POST|GET|REQUEST|COOKIE)' \
    "$app" 2>/dev/null > "$TMP/f2"
  if [ -s "$TMP/f2" ]; then
    bad "$(wc -l < "$TMP/f2") file(s) contain backdoor-style code patterns:"; head -n 15 "$TMP/f2" | indent
  else ok "no backdoor-style code patterns"; fi
}

audit_app() {
  local app="$1" envf="$1/.env" lv="$TMP/lv" n
  sub "App: $app"

  # Laravel maintenance mode (php artisan down) leaves storage/framework/down
  if [ "${INCLUDE_DOWN:-0}" != 1 ] && [ -e "$app/storage/framework/down" ]; then
    DOWN_APPS+=("$app")
    note "in maintenance mode - skipped (only the backdoor-code scan still runs)"
    scan_backdoor "$app"
    return
  fi

  # ---- 1a. log files --------------------------------------------------------
  local logdir="$app/storage/logs"
  if [ -d "$logdir" ]; then
    local nfiles size nread
    nfiles=$(find "$logdir" -type f -name '*.log' 2>/dev/null | wc -l)
    nread=$(find "$logdir" -type f -name '*.log' "${NEWER[@]}" 2>/dev/null | wc -l)
    size=$(du -sm "$logdir" 2>/dev/null | awk '{print $1}')
    note "storage/logs: $nfiles log file(s), ${size:-0} MB - $nread written to in the window and read, $((nfiles-nread)) older file(s) not opened"

    # header lines only: "[2026-10-10 13:55:01] production.ERROR: message ..."
    find "$logdir" -type f -name '*.log' "${NEWER[@]}" -print0 2>/dev/null \
      | xargs -0 -r grep -ahE '^\[[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9:.+-]+\] [A-Za-z0-9_-]+\.[A-Z]+:' 2>/dev/null \
      | datefilter "$TMP/d_iso" > "$lv"
    cat "$lv" >> "$TMP/lv_all"

    local nerr ncrit
    nerr=$(cnt '^\[[^]]+\] [A-Za-z0-9_-]+\.ERROR:' "$lv")
    ncrit=$(cnt '^\[[^]]+\] [A-Za-z0-9_-]+\.(CRITICAL|ALERT|EMERGENCY):' "$lv")
    if [ "$ncrit" -gt 0 ]; then bad "$ncrit CRITICAL/ALERT/EMERGENCY entries"
    elif [ "$nerr" -gt 0 ]; then warn "$nerr ERROR entries"
    else ok "no ERROR or CRITICAL entries in the window"; fi

    if [ $((nerr+ncrit)) -gt 0 ]; then
      out "         Most frequent errors:"
      grep -aE '\.(ERROR|CRITICAL|ALERT|EMERGENCY):' "$lv" | sed -E 's/^\[[^]]+\] [^:]+: //; s/[0-9]{3,}/#/g' \
        | cut -c1-140 | top 8 | indent
      out "         (numbers of 3+ digits shown as # so one error with different IDs counts together)"
      out "         Errors per day:"
      grep -aE '\.(ERROR|CRITICAL|ALERT|EMERGENCY):' "$lv" | cut -c2-11 | sort | uniq -c | tail -n 14 | indent
    fi

    # ---- 1b. attack and abuse traces inside the Laravel logs ----------------
    sig() {  # label, regex, level(warn|note)
      n=$(cnt "$2" "$lv")
      [ "$n" -gt 0 ] || return 0
      if [ "$3" = warn ]; then warn "$1: $n"; else note "$1: $n"; fi
    }
    sig "SQL-injection strings reaching the database layer" 'union.{1,30}select|information_schema|sleep\([0-9]|benchmark\(|or 1=1|xp_cmdshell' warn
    sig "Tampered cookies / encrypted payloads (DecryptException, invalid MAC)" 'DecryptException|MAC is invalid|payload is invalid' warn
    sig "Tampered signed URLs (InvalidSignatureException)" 'InvalidSignatureException' warn
    sig "Path traversal strings" '\.\./\.\./|/etc/passwd|php://(input|filter)' warn
    sig "Unsafe unserialize activity" 'unserialize\(\)|__PHP_Incomplete_Class' warn
    sig "Untrusted host / suspicious request" 'SuspiciousOperationException|Untrusted Host' warn
    sig "Rate limiter hits (Too Many Attempts) - possible brute force" 'ThrottleRequestsException|Too Many (Attempts|Requests)' note
    sig "CSRF token mismatches" 'TokenMismatchException|CSRF token mismatch' note
    sig "Authorization denials" 'AuthorizationException|action is unauthorized|AccessDeniedHttpException' note
    sig "Database connection failures (database unreachable / too many connections)" 'SQLSTATE\[HY000\] \[(1040|1045|2002|2006)\]|Too many connections|server has gone away|Connection (refused|timed out)' warn
    sig "PHP memory or time limit exhausted" 'Allowed memory size|Maximum execution time' warn
    sig "Disk full / write failures" 'No space left on device|failed to open stream: Permission denied' warn

    # secrets written into logs (count only, values are never printed); api_log* is skipped (it logs generated initial passwords on purpose)
    n=$(find "$logdir" -type f -name '*.log' ! -name 'api_log*' "${NEWER[@]}" -print0 2>/dev/null \
      | xargs -0 -r grep -ahE '^\[[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9:.+-]+\] [A-Za-z0-9_-]+\.[A-Z]+:' 2>/dev/null | datefilter "$TMP/d_iso" \
      | grep -aciE "(password|passwd|secret|api[_-]?key|access[_-]?token|authorization)[\"']?[[:space:]]*(=>|[:=])[[:space:]]*[\"']?[^]\"'[:space:],}]{6,}" || true)
    [ "$n" -gt 0 ] && warn "$n log line(s) appear to contain passwords, tokens or keys - stop logging request data with credentials"
  else
    note "no storage/logs folder"
  fi

  # ---- 1c. configuration ----------------------------------------------------
  if [ -r "$envf" ]; then
    local v perm
    v=$(envget "$envf" APP_DEBUG)
    case "${v,,}" in true|1) bad "APP_DEBUG=true in production - error pages can leak .env contents, queries and paths";; *) ok "APP_DEBUG is off";; esac
    v=$(envget "$envf" APP_ENV)
    [ "$v" = production ] && ok "APP_ENV=production" || warn "APP_ENV is '${v:-unset}', expected 'production'"
    [ -n "$(envget "$envf" APP_KEY)" ] && ok "APP_KEY is set" || bad "APP_KEY is empty"
    perm=$(stat -c '%a' "$envf" 2>/dev/null)
    case "$perm" in *0) ok ".env permissions $perm";; *) warn ".env permissions are $perm - readable by other server users; use 640 or 600";; esac
    v=$(envget "$envf" DB_USERNAME)
    [ "$v" = root ] && warn "DB_USERNAME is 'root' - use a dedicated account limited to this app's database"
    v=$(envget "$envf" DB_HOST)
    if [ -n "$v" ]; then
      local ip="$v"
      echo "$v" | grep -qE '^[0-9.]+$' || ip=$(getent hosts "$v" 2>/dev/null | awk '{print $1; exit}')
      if echo "${ip:-}" | grep -qE '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.|127\.)'; then
        ok "DB_HOST resolves to a private/intranet address"
      elif [ -n "${ip:-}" ]; then
        warn "DB_HOST resolves to a PUBLIC address - use the database private (VPC) endpoint, or require SSL"
        grep -qE '^[[:space:]]*MYSQL_ATTR_SSL_CA=.+' "$envf" || warn "no MYSQL_ATTR_SSL_CA set - database traffic over a public endpoint is unencrypted"
      else
        note "DB_HOST could not be resolved from this server"
      fi
    fi
    v=$(envget "$envf" SESSION_SECURE_COOKIE)
    case "${v,,}" in true|1) ok "SESSION_SECURE_COOKIE=true";; *) warn "SESSION_SECURE_COOKIE is not true - session cookie can travel over plain HTTP";; esac
  else
    warn "no readable .env in $app"
  fi

  # document root should be public/, never the app root
  if [ -r /etc/userdatadomains ]; then
    local exposed
    exposed=$(awk -F'==' -v a="$app" '$5==a {split($1,p,":"); print p[1]}' /etc/userdatadomains | tr '\n' ' ')
    [ -n "$exposed" ] && bad "document root is the Laravel root (not public/) for: $exposed- .env, storage and vendor may be downloadable"
  fi

  # ---- 1d. files ------------------------------------------------------------
  n=$(find "$app" -xdev \( -path "$app/vendor" -o -path "$app/node_modules" \) -prune -o -perm -0002 ! -type l -print 2>/dev/null | wc -l)
  [ "$n" -gt 0 ] && warn "$n world-writable files/folders (777-style) - use 755 folders / 644 files" || ok "no world-writable files"

  # PHP where PHP should not be (classic webshell locations)
  find "$app/storage" -type f -name '*.ph*' -not -path '*/framework/*' 2>/dev/null > "$TMP/f1"
  [ -d "$app/public" ] && find "$app/public" -type f \( -name '*.php' -o -name '*.phtml' -o -name '*.phar' -o -name '*.php[0-9]' \) \
      -not -name index.php 2>/dev/null >> "$TMP/f1"
  apply_ignore "$TMP/f1"
  if [ -s "$TMP/f1" ]; then
    bad "$(wc -l < "$TMP/f1") PHP file(s) in storage/ or public/ (other than index.php) - review, possible webshell:"
    head -n 15 "$TMP/f1" | indent
  else ok "no stray PHP files in storage/ or public/"; fi

  # upload folders must refuse to run PHP, so an uploaded webshell returns 403 instead of executing
  if [ -d "$app/public" ]; then
    { [ -d "$app/public/storage" ] && echo "$app/public/storage"
      find "$app/public" -mindepth 1 -maxdepth 2 -type d -regextype posix-extended \
        -iregex '.*/(uploads?|files|media|attachments)' 2>/dev/null; } > "$TMP/f5"
    : > "$TMP/f6"
    while IFS= read -r d; do
      grep -qiE 'engine[[:space:]]+off|FilesMatch[^>]*ph' "$d/.htaccess" 2>/dev/null || echo "$d" >> "$TMP/f6"
    done < "$TMP/f5"
    if [ -s "$TMP/f6" ]; then
      warn "upload folder(s) can run PHP - add a .htaccess with: <FilesMatch \"\\.(php|phtml|phar)\$\"> Require all denied </FilesMatch>"
      indent < "$TMP/f6"
    elif [ -s "$TMP/f5" ]; then ok "upload folders block PHP"; fi
  fi

  scan_backdoor "$app"

  # things that should never sit in the web root
  if [ -d "$app/public" ]; then
    find "$app/public" -maxdepth 3 \( -name '*.sql' -o -name '*.sql.gz' -o -name '*.bak' -o -name '*.zip' -o -name '*.tar.gz' \
        -o -name '.env*' -o -name '.git' -o -name 'phpinfo.php' -o -name 'adminer*.php' -o -name '*.log' \) 2>/dev/null > "$TMP/f3"
    apply_ignore "$TMP/f3"
    if [ -s "$TMP/f3" ]; then
      warn "backups, dumps or sensitive files inside public/:"; head -n 15 "$TMP/f3" | indent
    else ok "no dumps/backups/secrets in public/"; fi
  fi

  # recently changed code (deployments explain these; anything else is suspicious)
  if [ "$DAYS" != all ] && [ ! -d "$app/.git" ]; then   # git checkouts: the git check below compares content instead
    find "$app" -xdev \( -path "$app/vendor" -o -path "$app/node_modules" -o -path "$app/storage" -o -path "$app/bootstrap/cache" \) -prune \
      -o -type f -name '*.php' -mtime "-$DAYS" -print 2>/dev/null > "$TMP/f4"
    n=$(wc -l < "$TMP/f4")
    if [ "$n" -gt 0 ]; then
      note "$n PHP file(s) modified in the last $DAYS day(s) - confirm these match your deployments:"; head -n 10 "$TMP/f4" | indent
    fi
  fi

  # files that differ from the last git pull (git compares content, so a faked file date does not hide a change)
  # GIT_OPTIONAL_LOCKS=0 stops git status from rewriting .git/index, keeping the run read-only
  if have git && [ -d "$app/.git" ]; then
    GIT_OPTIONAL_LOCKS=0 git -c safe.directory="$app" -C "$app" status --porcelain 2>/dev/null > "$TMP/f7"
    apply_ignore "$TMP/f7"
    if [ -s "$TMP/f7" ]; then
      warn "$(wc -l < "$TMP/f7") file(s) differ from the last git pull (M = edited on the server, ?? = not in git) - commit them or remove them:"
      head -n 20 "$TMP/f7" | indent
    else ok "code matches the last git pull"; fi
    # a token in the remote URL lets anyone who reads .git/config into the repo (value never printed)
    if grep -qE '^\s*url\s*=\s*https?://[^/@[:space:]]+@' "$app/.git/config" 2>/dev/null; then
      bad "git remote URL contains a token/password in .git/config - remove it (git remote set-url origin https://github.com/OWNER/REPO.git) and revoke the token"
    else ok "no credentials in git remote URL"; fi
  else note "not a git checkout - change detection skipped"; fi

  # known-vulnerable packages
  if have composer && [ -f "$app/composer.lock" ]; then
    if COMPOSER_ALLOW_SUPERUSER=1 timeout 60 composer audit --locked --no-interaction -d "$app" > "$TMP/ca" 2>&1; then
      ok "composer audit: no known vulnerable packages"
    elif grep -qiE 'advisor|CVE-|abandoned' "$TMP/ca"; then
      warn "composer audit reports issues:"; grep -iE 'Package|CVE|Title|abandoned' "$TMP/ca" | head -n 20 | indent
    else
      note "composer audit could not run (old Composer or no network)"
    fi
  fi
}

for app in "${APP_LIST[@]}"; do [ -d "$app" ] && audit_app "$app"; done

# domains served by apps in maintenance mode: left out of sections 2 and 3
DOWN_DOMAINS=""
if [ ${#DOWN_APPS[@]} -gt 0 ] && [ -r /etc/userdatadomains ]; then
  for a in "${DOWN_APPS[@]}"; do
    DOWN_DOMAINS="$DOWN_DOMAINS $(awk -F'==' -v a="$a" '$5==a || index($5, a"/")==1 {split($1,p,":"); print p[1]}' /etc/userdatadomains | tr '\n' ' ')"
  done
fi
is_down() { case " $DOWN_DOMAINS " in *" $1 "*) return 0;; esac; return 1; }

# =============================================================================
# 2. WEB ACCESS LOGS (Apache domlogs): attacks against every domain/subdomain
# =============================================================================
section "2. Web access logs - attack traffic"

ACC="$TMP/acc"; : > "$ACC"
LOGDIR="${ACCESS_LOG_DIR:-}"
if [ -z "$LOGDIR" ]; then
  for d in /usr/local/apache/domlogs /etc/apache2/logs/domlogs /var/log/apache2/domlogs "$HOME/access-logs"; do
    [ -d "$d" ] && [ -r "$d" ] && { LOGDIR="$d"; break; }
  done
fi

if [ -n "$LOGDIR" ] && [ -r "$LOGDIR" ]; then
  while IFS= read -r f; do
    b=$(basename "$f")
    case "$b" in *bytes_log*|*.offset|*ftp*|*.bkup*|*.gz) continue;; esac
    v=${b%-ssl_log}
    is_down "$v" && continue
    datefilter "$TMP/d_apache" < "$f" | grep -avF -- "$UA" | sed "s|^|$v |" >> "$ACC"
  done < <(find -L "$LOGDIR" -maxdepth 1 -type f 2>/dev/null)
  # line layout now:  vhost ip - - [date tz] "METHOD path proto" status size "ref" "ua"
  #                   $1    $2      $5       $7      $8          $10
  TOTAL=$(wc -l < "$ACC")
  note "access log folder: $LOGDIR  -  $TOTAL requests in window"
else
  note "no readable Apache domlogs folder found - skipping (set ACCESS_LOG_DIR to override)"
  TOTAL=0
fi

if [ "$TOTAL" -gt 0 ]; then
  sub "Requests per domain"
  out "$(printf '         %-42s %9s %8s %8s' DOMAIN REQUESTS 4xx 5xx)"
  awk '{r[$1]++; if($10>=500)e5[$1]++; else if($10>=400)e4[$1]++}
       END{for(v in r) printf "%-42s %9d %8d %8d\n", v, r[v], e4[v]+0, e5[v]+0}' "$ACC" | sort -k2,2 -rn | head -n 40 | indent

  sub "Attack attempts (requests made, not necessarily successful)"
  P_SQLI='union(\+|%20| )+(all(\+|%20| )+)?select|information_schema|sleep\(|benchmark\(|%27(\+|%20)*(or|and)(\+|%20)|waitfor(\+|%20)delay'
  P_LFI='\.\./\.\.|\.\.%2f|%2e%2e%2f|/etc/passwd|php://|proc/self/environ'
  P_XSS='<script|%3Cscript|onerror(=|%3D)|javascript:'
  P_FILES='/\.env|/\.git/|/\.aws/|/\.ssh/|/storage/logs/|composer\.(json|lock)|phpinfo|\.sql( |\?|\.gz)|\.bak( |\?)|/backup'
  P_EXPL='eval-stdin\.php|_ignition/execute-solution|wp-login\.php|xmlrpc\.php|/wp-admin|/phpmyadmin|/cgi-bin/|(shell|c99|r57|wso|alfa|adminer)[0-9]*\.php'
  P_RCE='base64_decode|eval\(|system\(|(\?|&)cmd=|wget(\+|%20)|curl(\+|%20)|\$\{jndi|/bin/(ba)?sh'
  P_SCAN='sqlmap|nikto|nuclei|masscan|zgrab|wpscan|acunetix|nessus|dirbuster|gobuster|ffuf|nmap'
  scan() {
    local n; n=$(cnt "$2" "$ACC")
    if [ "$n" -gt 0 ]; then
      note "$1: $n request(s). Top source IPs:"
      grep -aiE -- "$2" "$ACC" | awk '{print $2}' | top 5 | indent
    else ok "$1: none"; fi
  }
  scan "SQL injection"                    "$P_SQLI"
  scan "Path traversal / file inclusion"  "$P_LFI"
  scan "Cross-site scripting"             "$P_XSS"
  scan "Probes for secrets and backups"   "$P_FILES"
  scan "Known exploit and webshell paths" "$P_EXPL"
  scan "Remote command execution"         "$P_RCE"
  scan "Scanner tools (by user agent)"    "$P_SCAN"

  sub "Probes that SUCCEEDED (HTTP 200)"
  awk '$10==200 && tolower($8) ~ /\/\.env|\/\.git\/|eval-stdin\.php|_ignition\/execute-solution|\/storage\/logs\/|\.sql($|\?|\.gz)|phpinfo|composer\.lock|(shell|c99|r57|wso|alfa)[0-9]*\.php/ {print $1, $8}' "$ACC" \
    | top 20 > "$TMP/hit200"
  if [ -s "$TMP/hit200" ]; then
    bad "sensitive paths were served with HTTP 200 - check each one (count, domain, path):"; indent < "$TMP/hit200"
    out "         (an app with a catch-all route returns 200 for anything; section 3 checks the real content)"
  else ok "no sensitive path returned HTTP 200"; fi

  sub "Login brute force"
  awk -v q='"POST' '$7==q && tolower($8) ~ /login|signin|sign-in|password|auth/ {print $2, $1}' "$ACC" \
    | sort | uniq -c | sort -rn | awk -v t="$LOGIN_THRESHOLD" '$1>=t' | head -n 15 > "$TMP/bf"
  if [ -s "$TMP/bf" ]; then
    warn "IPs with $LOGIN_THRESHOLD+ login POSTs (count, IP, domain) - an office or carrier NAT can be legitimate:"; indent < "$TMP/bf"
  else ok "no IP exceeded $LOGIN_THRESHOLD login POSTs"; fi

  sub "Most active scanners (403/404 = already blocked, no action needed; act only on 200 or login floods)"
  grep -aiE -- "$P_SQLI|$P_LFI|$P_EXPL|$P_RCE|$P_SCAN|/\.env|/\.git/" "$ACC" > "$TMP/offl"
  awk '{print $2}' "$TMP/offl" | top 15 > "$TMP/off"
  # list scanners only when some request was not refused
  if [ "${VERBOSE:-0}" != 1 ] && ! awk '$10 !~ /^(30[1278]|40[034]|429)$/ {f=1} END {exit !f}' "$TMP/offl"; then
    [ -s "$TMP/off" ] && note "$(wc -l < "$TMP/off") scanner IP(s), every request refused (403/404/301) - nothing to do (VERBOSE=1 lists them)"
    : > "$TMP/off"
  fi
  [ -s "$TMP/off" ] && out "         (requests, IP - then what it tried: count, HTTP status, domain+path, first 100 chars)"
  while read -r n ip; do
    out "$(printf '         %6s  %s  %s' "$n" "$ip" "$(awk -v ip="$ip" '$2==ip {p[$1 $8]; s[$10]++}
      END {for (k in s) st = st " " k ":" s[k]; printf "(%d different paths; status%s)", length(p), st}' "$TMP/offl")")"
    awk -v ip="$ip" '$2==ip {print $10, $1 substr($8,1,100)}' "$TMP/offl" | top 5 | sed 's/^/        /' | indent
  done < "$TMP/off"

  sub "Server errors (5xx) by URL"
  awk '$10>=500 {sub(/\?.*/,"",$8); print $10, $1, $8}' "$ACC" | top 10 > "$TMP/e5"
  if [ -s "$TMP/e5" ]; then warn "URLs returning 5xx (count, status, domain, path):"; indent < "$TMP/e5"; else ok "no 5xx responses"; fi
fi

# =============================================================================
# 3. OUTSIDE-IN CHECKS: what a visitor can actually reach on each domain
# =============================================================================
section "3. Exposure checks on each domain"

if [ "${SKIP_HTTP:-0}" = 1 ] || ! have curl; then
  note "skipped"
else
  if [ -n "${DOMAINS:-}" ]; then read -r -a DOM_LIST <<< "$DOMAINS"
  elif [ -r /etc/userdatadomains ]; then mapfile -t DOM_LIST < <(cut -d: -f1 /etc/userdatadomains | grep -v '^\*' | sort -u)
  elif [ "$TOTAL" -gt 0 ]; then mapfile -t DOM_LIST < <(awk '{print $1}' "$ACC" | grep -F . | sort -u)
  else DOM_LIST=(); fi
  note "domains to check: ${#DOM_LIST[@]}"
  [ -n "${DOWN_DOMAINS// /}" ] && note "skipped (maintenance mode):$(echo " $DOWN_DOMAINS" | tr -s ' ')"

  probe() {  # domain path content-regex  -> true only when the real thing is served
    local code
    code=$(curl -sk -m 8 -A "$UA" -o "$TMP/body" -w '%{http_code}' "https://$1/$2" 2>/dev/null)
    [ "$code" = 200 ] && grep -qaE -- "$3" "$TMP/body"
  }
  PROBES=(
    ".env~APP_KEY=|DB_PASSWORD=~.env file (database password and app key are public)"
    ".git/config~\[core\]~Git repository (source code downloadable)"
    "storage/logs/laravel.log~\.(ERROR|INFO|DEBUG|WARNING):~Laravel log file"
    "composer.lock~\"packages\"~composer.lock (document root is probably not public/)"
    "vendor/composer/installed.json~\"packages\"~vendor/ folder"
    "phpinfo.php~PHP Version~phpinfo() page"
    "telescope/requests~[Tt]elescope~Laravel Telescope without a login"
    "horizon~Horizon~Laravel Horizon without a login"
    "_ignition/health-check~can_execute_commands~Ignition debug endpoint (debug mode is on)"
  )
  CDN_SKIP=""
  for d in "${DOM_LIST[@]}"; do
    is_down "$d" && continue
    code=$(curl -sk -m 8 -A "$UA" -D "$TMP/hdr" -o /dev/null -w '%{http_code}' "https://$d/" 2>/dev/null)
    if [ -z "$code" ] || [ "$code" = 000 ]; then note "$d: not reachable over HTTPS, skipped"; continue; fi
    if grep -qi '^cf-mitigated:' "$TMP/hdr"; then CDN_SKIP="$CDN_SKIP $d"; continue; fi
    found=0
    for p in "${PROBES[@]}"; do
      IFS='~' read -r path rx desc <<< "$p"
      if probe "$d" "$path" "$rx"; then bad "$d/$path is PUBLIC: $desc"; found=1; fi
    done
    [ $found -eq 0 ] && ok "$d: no sensitive files or debug tools exposed"

    miss=""
    grep -qi '^strict-transport-security:' "$TMP/hdr" || miss="$miss HSTS,"
    grep -qi '^x-content-type-options:' "$TMP/hdr"    || miss="$miss X-Content-Type-Options,"
    grep -qiE '^x-frame-options:|^content-security-policy:.*frame-ancestors' "$TMP/hdr" || miss="$miss X-Frame-Options,"
    grep -qi '^x-powered-by:' "$TMP/hdr" && miss="$miss (X-Powered-By reveals the PHP version),"
    grep -i '^set-cookie:.*session' "$TMP/hdr" | grep -qvi 'secure' && miss="$miss session cookie lacks Secure,"
    [ -n "$miss" ] && warn "$d: missing security headers:${miss%,}"

    hcode=$(curl -s -m 8 -A "$UA" -o /dev/null -w '%{http_code}' "http://$d/" 2>/dev/null)
    case "$hcode" in 301|302|307|308|000|"") ;; *) warn "$d: plain HTTP answers $hcode instead of redirecting to HTTPS";; esac

    if have openssl; then
      end=$(echo | timeout 8 openssl s_client -servername "$d" -connect "$d:443" 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
      if [ -n "$end" ]; then
        left=$(( ( $(date -d "$end" +%s) - $(date +%s) ) / 86400 ))
        if [ "$left" -lt 0 ]; then bad "$d: TLS certificate EXPIRED"
        elif [ "$left" -lt 14 ]; then warn "$d: TLS certificate expires in $left day(s)"; fi
      fi
    fi
  done
  [ -n "$CDN_SKIP" ] && note "CDN bot protection challenged the check, skipped (allow this server's IP in the CDN firewall):$CDN_SKIP"
fi

# =============================================================================
# 4. SERVER LOGINS: SSH, cPanel/WHM, firewall
# =============================================================================
section "4. Server login activity"

if [ $IS_ROOT -eq 1 ]; then
  SEC=""; for f in /var/log/secure /var/log/auth.log; do [ -r "$f" ] && SEC="$f"; done
  if [ -n "$SEC" ]; then
    windowed "$SEC" "$TMP/d_sys" "$TMP/sec" '^([A-Z][a-z]{2} [ 0-9][0-9] |[0-9]{4}-[0-9]{2}-[0-9]{2}T)'
    n=$(grep -acE 'Failed password|Invalid user|authentication failure' "$TMP/sec" || true)
    if [ "$n" -gt 0 ]; then
      note "SSH: $n failed login attempts ($WLABEL). Top source IPs:"
      grep -aE 'Failed password|Invalid user' "$TMP/sec" | grep -oE 'from [0-9a-fA-F:.]+' | awk '{print $2}' | top 5 | indent
    else ok "SSH: no failed logins ($WLABEL)"; fi
    grep -aE 'sshd.*Accepted (password|publickey)' "$TMP/sec" | awk '{for(i=1;i<=NF;i++) if($i=="for") print $(i+1), "from", $(i+3), "via", $(i-1)}' | top 10 > "$TMP/acc_ssh"
    if [ -s "$TMP/acc_ssh" ]; then
      warn "SUCCESSFUL SSH logins ($WLABEL) - confirm every user and IP is yours (count, user, IP, method):"; indent < "$TMP/acc_ssh"
    fi
  else note "SSH auth log not found (journal-only system: journalctl -u sshd)"; fi

  CPL=/usr/local/cpanel/logs/login_log
  if [ -r "$CPL" ]; then
    windowed "$CPL" "$TMP/d_iso" "$TMP/cpl" '^\[[0-9]{4}-[0-9]{2}-[0-9]{2} '
    grep -a 'FAILED LOGIN' "$TMP/cpl" > "$TMP/cplf" || true
    n=$(wc -l < "$TMP/cplf")
    if [ "$n" -gt 0 ]; then
      note "cPanel/WHM/webmail: $n failed logins ($WLABEL). By service:"
      grep -aoE '\[(cpaneld|whostmgrd|webmaild|cpdavd)\]' "$TMP/cplf" \
        | sed -e 's/\[cpaneld\]/cPanel (2083)/' -e 's/\[whostmgrd\]/WHM (2087)/' -e 's/\[webmaild\]/Webmail (2096)/' -e 's/\[cpdavd\]/Calendar-contacts (2080)/' | top 5 | indent
      out "         Top source IPs:"
      grep -aoE '[0-9]{1,3}(\.[0-9]{1,3}){3}' "$TMP/cplf" | top 5 | indent
      out "         Per day:"
      cut -c2-11 "$TMP/cplf" | grep -E '^[0-9]{4}-' | sort | uniq -c | tail -n 7 | indent
      grep -aq '127\.0\.0\.1' "$TMP/cplf" && out "         (127.0.0.1 = logins through cpanel./webmail. addresses on port 443, or a script on this server)"
    else ok "cPanel/WHM/webmail: no failed logins ($WLABEL)"; fi
    SL=/usr/local/cpanel/logs/session_log
    if [ -r "$SL" ]; then
      windowed "$SL" "$TMP/d_iso" "$TMP/sl" '^\[[0-9]{4}-[0-9]{2}-[0-9]{2} '
      grep -a 'whostmgrd' "$TMP/sl" | awk '{for(i=2;i<NF;i++) if($i=="NEW"){split($(i+1),u,":"); print u[1], "from", $(i-1)}}' | top 10 > "$TMP/whm"
      [ -s "$TMP/whm" ] && { note "WHM sessions opened ($WLABEL) - confirm they are yours (count, user, IP):"; indent < "$TMP/whm"; }
    fi
  fi
  [ -r /var/log/lfd.log ] && note "CSF/LFD blocks logged: $(grep -ac 'Blocked in csf' /var/log/lfd.log || true)"
  for m in /usr/local/apache/logs/modsec_audit.log /etc/apache2/logs/modsec_audit.log; do
    [ -r "$m" ] && { note "ModSecurity rule hits logged: $(grep -ac -- '-H--' "$m" || true)"; break; }
  done
else
  note "skipped (needs root)"
fi

# =============================================================================
# 5. SERVER HARDENING
# =============================================================================
section "5. Server hardening"

if [ $IS_ROOT -eq 1 ]; then
  IM360=0
  if have imunify360-agent; then
    if systemctl is-active --quiet imunify360 2>/dev/null; then
      IM360=1; ok "Imunify360 is active (firewall, web application firewall and brute-force protection)"
    else warn "Imunify360 is installed but its service is not running"; fi
  fi
  if have sshd; then
    sshd -T 2>/dev/null > "$TMP/sshd"
    grep -qi '^passwordauthentication yes' "$TMP/sshd" && warn "SSH allows password logins - switch to key-only (PasswordAuthentication no)" || ok "SSH password logins disabled"
    grep -qi '^permitrootlogin yes' "$TMP/sshd" && warn "SSH allows direct root login with a password - use 'prohibit-password'" || ok "SSH root password login disabled"
    grep -qi '^port 22$' "$TMP/sshd" && note "SSH is on port 22 - restrict it to your IPs in the cloud security group"
  fi

  # services that must never listen on a public interface (one line per port)
  ss -tlnH 2>/dev/null | awk '{print $4}' | sort -u > "$TMP/ports"
  # Imunify360 in DENY mode only lets in the listed TCP ports, so a public listener outside that list is closed by the firewall
  fwin=""
  if [ $IM360 -eq 1 ]; then
    fwcfg=$(imunify360-agent config show 2>/dev/null)
    echo "$fwcfg" | grep -q '"port_blocking_mode": "DENY"' &&
      fwin=$(echo "$fwcfg" | grep -oE '"TCP_IN_IPv[46]": \[[^]]*\]' | sed 's/.*: //' | grep -oE '[0-9]+(-[0-9]+)?' | tr '\n' ' ')
  fi
  fw_open() { [ -z "$fwin" ] && return 0; for r in $fwin; do [ "${r%-*}" -le "$1" ] && [ "$1" -le "${r#*-}" ] && return 0; done; return 1; }
  for port in 3306 6379 11211 27017 5432 9200; do
    all=$(grep -E ":$port\$" "$TMP/ports"); [ -n "$all" ] || continue
    pub=$(echo "$all" | grep -vE '^(127\.|\[::1\]|localhost)' | tr '\n' ' ')
    if [ -n "$pub" ] && ! fw_open "$port"; then
      ok "port $port listens publicly but Imunify360 (DENY mode) does not allow it in"
    elif [ -n "$pub" ]; then
      chk="the cloud security group"; [ $IM360 -eq 1 ] && chk="$chk or Imunify360's blocked-ports list"
      bad "port $port (database/cache) listens on all interfaces (${pub% }) - bind it to 127.0.0.1, or confirm $chk closes it"
    else ok "port $port bound to localhost only"; fi
  done
  if have redis-cli && timeout 3 redis-cli -h 127.0.0.1 ping 2>/dev/null | grep -q PONG; then
    note "Redis answers without a password on localhost - fine only while it stays bound to 127.0.0.1"
  fi

  if [ $IM360 -eq 0 ]; then
    if [ -x /usr/sbin/csf ]; then
      grep -q '^TESTING = "1"' /etc/csf/csf.conf 2>/dev/null && warn "CSF firewall is in TESTING mode (rules are cleared every few minutes)" || ok "CSF firewall installed and not in testing mode"
    else note "CSF firewall not installed - the cloud security group is then your only firewall"; fi
    if have whmapi1; then
      whmapi1 cphulk_status 2>/dev/null | grep -q 'is_enabled: 1' && ok "cPHulk brute-force protection is on" || warn "cPHulk brute-force protection is off (WHM > Security Center)"
    fi
  fi
  if have httpd; then
    httpd -M 2>/dev/null | grep -q security2 && ok "ModSecurity is loaded" || warn "ModSecurity (web application firewall) is not loaded"
  fi

  if have php; then
    pv=$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;' 2>/dev/null)
    case "$pv" in 5.*|7.*|8.0|8.1) warn "default PHP is $pv, which no longer gets security fixes";; "") ;; *) ok "default PHP is $pv";; esac
    [ "$(php -r 'echo ini_get("display_errors");' 2>/dev/null)" = 1 ] && warn "PHP display_errors is on (CLI config; check MultiPHP INI Editor for the web setting)"
  fi

  if [ "${SKIP_UPDATES:-0}" != 1 ]; then
    if have dnf; then n=$(timeout 90 dnf -q updateinfo list --security 2>/dev/null | grep -c . || true)
    elif have yum; then n=$(timeout 90 yum -q updateinfo list security 2>/dev/null | grep -c . || true)
    else n=""; fi
    if [ -n "$n" ]; then [ "$n" -gt 0 ] && warn "$n security update(s) pending for the operating system" || ok "no pending OS security updates"; fi
  fi

  # WHM backups: .env and uploaded files (storage/app) exist only on this server, git and the database snapshots do not cover them
  if [ "${DISK_SNAPSHOTS:-0}" = 1 ]; then
    ok "whole-disk snapshots are taken by the cloud provider (DISK_SNAPSHOTS=1) - WHM backup check skipped"
  elif have whmapi1; then
    whmapi1 backup_config_get 2>/dev/null | tr -d "'\"" > "$TMP/bk"
    if grep -qE '^[[:space:]]*backupenable:[[:space:]]*1' "$TMP/bk"; then
      ok "WHM backups are enabled"
      bdir=$(awk '$1=="backupdir:" {print $2; exit}' "$TMP/bk")
      # ponytail: newest entry up to 3 levels deep stands in for "last backup run"; incremental backups that only rewrite deeper files may look older
      last=$(find "${bdir:-/backup}" -mindepth 1 -maxdepth 3 -printf '%T@\n' 2>/dev/null | sort -n | tail -n1)
      if [ -z "$last" ]; then bad "no backup files found in ${bdir:-/backup}"
      else
        age=$(( ($(date +%s) - ${last%.*}) / 86400 ))
        [ "$age" -le 2 ] && ok "last backup written $age day(s) ago in ${bdir:-/backup}" || bad "last backup is $age days old (${bdir:-/backup}) - the backup job has stopped"
      fi
      n=$(whmapi1 backup_destination_list 2>/dev/null | tr -d "'\"" | grep -cE '^[[:space:]]*disabled:[[:space:]]*0' || true)
      [ "$n" -gt 0 ] && ok "$n off-server backup destination(s) enabled" \
        || bad "backups are kept only on this server - add an off-server copy (WHM > Backup Configuration > Additional Destinations)"
    else bad "WHM backups are disabled - .env files and uploaded files (storage/app) are not backed up anywhere"; fi
    grep -sHE 'storage|\.env' /etc/cpbackup-exclude.conf /home/*/cpbackup-exclude.conf > "$TMP/bkx"
    [ -s "$TMP/bkx" ] && { warn "backup exclude list skips app files (storage or .env):"; indent < "$TMP/bkx"; }
  fi
else
  note "skipped (needs root)"
fi

# functions a webshell needs to run server commands; Laravel needs proc_open, so it is not in the list.
# Websites should run on PHP-FPM, whose pools must disable them. The CLI php.ini (artisan, tinker) keeps them on purpose.
SHELL_FN="exec system shell_exec passthru popen"
ls /opt/cpanel/ea-php*/root/usr/bin/php >/dev/null 2>&1 && sub "PHP settings (each installed cPanel PHP version)"
# how each Apache site really runs PHP: FPM if its block hands PHP to a php-fpm socket, otherwise CGI with php.ini
# (brand names are ServerAlias lines inside a site, so one switch covers them; leftover pool files are ignored)
HTTPD=/etc/apache2/conf/httpd.conf
if [ -r "$HTTPD" ]; then
  # prints: FPM|CGI site socket - the socket names the pool actually used (pool files named after the site can be unused leftovers)
  awk '/<VirtualHost/{n="";k=""} $1=="ServerName"{n=$2} /SetHandler.*proxy:unix:/{k=$0; sub(/.*proxy:unix:/,"",k); sub(/\|.*/,"",k)} /<\/VirtualHost>/{print (k?"FPM":"CGI"), n, k}' "$HTTPD" \
    | sort -u | grep -vE "^[A-Z]+ (proxy-subdomains-vhost\.localhost|$(hostname -f 2>/dev/null || hostname)) " > "$TMP/handlers"
  awk '$1=="FPM"{print $2}' "$TMP/handlers" | sort -u > "$TMP/fpmsites"
  awk '$1=="CGI"{print $2}' "$TMP/handlers" | sort -u | comm -23 - "$TMP/fpmsites" > "$TMP/nofpm"
  : > "$TMP/fpm"; npool=0
  awk '$1=="FPM"{print $2, $3}' "$TMP/handlers" | sort -u | while read -r site sock; do
    for p in $(grep -lF "listen = $sock" /opt/cpanel/ea-php*/root/etc/php-fpm.d/*.conf 2>/dev/null); do
      echo "$site $p"
    done
  done > "$TMP/pools"
  while read -r site p; do
    npool=$((npool+1))
    d=$(grep -h '^php_admin_value\[disable_functions\]' "$p" | cut -d= -f2 | tr -d ' ')
    miss=""; for f in $SHELL_FN; do case ",$d," in *",$f,"*) ;; *) miss="$miss $f";; esac; done
    [ -n "$miss" ] && echo "$(echo "$p" | grep -oE 'ea-php[0-9]+') $site (pool $(basename "$p" .conf)):$miss" >> "$TMP/fpm"
  done < "$TMP/pools"
  if [ -s "$TMP/fpm" ]; then
    warn "website PHP-FPM pools still allow shell functions - add php_admin_value_disable_functions to /var/cpanel/userdata/USER/POOL.php-fpm.yaml, then /scripts/php_fpm_config --rebuild (keep proc_open):"
    indent < "$TMP/fpm"
  elif [ "$npool" -gt 0 ]; then ok "all $npool PHP-FPM pools in use disable $SHELL_FN"; fi
  if [ -s "$TMP/nofpm" ]; then
    warn "site(s) not on PHP-FPM - they run PHP through php.ini, where shell functions are usually enabled. Switch each to PHP-FPM in WHM > MultiPHP Manager (covers all its alias domains):"
    indent < "$TMP/nofpm"
  fi
elif [ $IS_ROOT -eq 0 ] && [ -e "$HTTPD" ]; then
  note "PHP handler and PHP-FPM pool checks need root - skipped"
fi
for phpb in /opt/cpanel/ea-php*/root/usr/bin/php; do
  [ -x "$phpb" ] || continue
  pv=$(echo "$phpb" | grep -oE 'ea-php[0-9]+')
  r=$("$phpb" -r 'echo ini_get("expose_php"), "|", ini_get("allow_url_include");' 2>/dev/null) || continue
  IFS='|' read -r ex au <<< "$r"
  case "${ex,,}" in 1|on) warn "$pv: expose_php is On - set it Off";; esac
  case "${au,,}" in 1|on) bad "$pv: allow_url_include is On - set it Off";; esac
done

if [ "$(date +%u)" = 7 ] || [ "${VERBOSE:-0}" = 1 ]; then   # weekly reminder (Sundays), not every night
sub "Managed database - check these in your cloud console (not visible from this server)"
out "         [ ] Database IP whitelist contains ONLY this server's private IP - never 0.0.0.0/0"
out "         [ ] Public (internet) endpoint is released if the app uses the intranet endpoint"
out "         [ ] SSL encryption enabled on the instance"
out "         [ ] Audit / query log on; review the error log and slow query log"
out "         [ ] Automated backups on, and a restore has been tested"
out "         [ ] Cloud security group: 22, 2083, 2087 limited to your IPs; only 80/443 open to all"
fi

# =============================================================================
# 6. CAPACITY: when does the server run out of CPU, memory or workers?
# =============================================================================
section "6. Capacity and peak periods"

CORES=$(nproc 2>/dev/null || echo 1)
MEM_MB=$(awk '/MemTotal/ {printf "%d", $2/1024}' /proc/meminfo 2>/dev/null)
AVAIL_MB=$(awk '/MemAvailable/ {printf "%d", $2/1024}' /proc/meminfo 2>/dev/null)
SWAP_MB=$(awk '/SwapTotal/ {printf "%d", $2/1024}' /proc/meminfo 2>/dev/null)
note "now: $CORES CPU core(s), ${MEM_MB:-?} MB RAM (${AVAIL_MB:-?} MB available), ${SWAP_MB:-0} MB swap, load $(cut -d' ' -f1-3 /proc/loadavg 2>/dev/null)"
[ "${SWAP_MB:-0}" -eq 0 ] && warn "no swap configured - a memory spike goes straight to the out-of-memory killer"
df -P -x tmpfs -x devtmpfs 2>/dev/null | awk 'NR>1 && $5+0>=85 {print $6, $5}' > "$TMP/df"
if [ -s "$TMP/df" ]; then warn "filesystems at 85%+ full:"; indent < "$TMP/df"; else ok "disk space under 85% on all filesystems"; fi

sub "CPU, memory and load peaks (from sysstat history)"
SADIR=""; for d in /var/log/sa /var/log/sysstat; do ls "$d"/sa[0-9]* >/dev/null 2>&1 && { SADIR="$d"; break; }; done
if have sar && [ -n "$SADIR" ]; then
  sar_peak() {  # file, sar-flag, column-name, max|min  ->  "value time" (worst 1)
    local s='-rn'; [ "$4" = min ] && s='-n'
    sar "$2" -f "$1" 2>/dev/null | awk -v c="$3" '
      { for(i=1;i<=NF;i++) if($i==c){col=i; next} }
      col && $1 ~ /^[0-9][0-9]:[0-9][0-9]/ && $col ~ /^[0-9.]+$/ { print $col, substr($1,1,5) }' | sort -k1,1 $s | head -n 1
  }
  nd=7; [ "$DAYS" != all ] && [ "$DAYS" -lt 7 ] && nd=$DAYS
  out "$(printf '         %-11s %-22s %-22s %-24s %-18s' DAY 'CPU BUSIEST' 'LOAD PEAK (1 min)' 'MEMORY LOWEST AVAILABLE' 'SWAP PEAK')"
  for i in $(seq 0 $((nd-1))); do
    f="$SADIR/sa$(date -d "-$i day" +%d)"; [ -r "$f" ] || continue
    day=$(date -d "-$i day" +%Y-%m-%d)
    read -r idle t_cpu < <(sar_peak "$f" -u %idle min)
    read -r ld t_ld    < <(sar_peak "$f" -q ldavg-1 max)
    read -r av t_av    < <(sar_peak "$f" -r kbavail min)
    read -r sw t_sw    < <(sar_peak "$f" -S %swpused max)
    [ -n "${idle:-}" ] || continue
    busy=$(awk -v i="$idle" 'BEGIN{printf "%.0f", 100-i}')
    avmb=$(awk -v a="${av:-0}" 'BEGIN{printf "%d", a/1024}')
    memtxt="n/a"; [ -n "${av:-}" ] && memtxt="${avmb} MB at ${t_av}"
    out "$(printf '         %-11s %-22s %-22s %-24s %-18s' "$day" "${busy}% at ${t_cpu}" "${ld:-?} at ${t_ld:-?}" "$memtxt" "${sw:-0}% at ${t_sw:-?}")"
    [ "$busy" -ge 90 ] && warn "$day: CPU reached ${busy}% at $t_cpu"
    awk -v l="${ld:-0}" -v c="$CORES" 'BEGIN{exit !(l>c)}' && warn "$day: load ${ld} exceeded the $CORES core(s) at $t_ld - requests were queueing"
    [ -n "${av:-}" ] && [ "${MEM_MB:-0}" -gt 0 ] && [ "$avmb" -lt $((MEM_MB/10)) ] && warn "$day: only ${avmb} MB memory left at $t_av (under 10% of RAM)"
    awk -v s="${sw:-0}" 'BEGIN{exit !(s>=50)}' && warn "$day: swap ${sw}% used at $t_sw - the server was short of RAM"
  done
else
  warn "sysstat history not available, so past CPU/memory peaks cannot be shown. Install once: dnf install -y sysstat && systemctl enable --now sysstat (negligible overhead)"
fi

sub "Out-of-memory kills and exhausted worker pools"
if [ $IS_ROOT -eq 1 ]; then
  : > "$TMP/oom"
  if have journalctl; then
    since="30 days ago"; [ "$DAYS" != all ] && since="$DAYS days ago"
    journalctl -k --since "$since" --no-pager 2>/dev/null | grep -aiE 'out of memory|oom-kill|killed process' > "$TMP/oom"
  fi
  [ -s "$TMP/oom" ] || grep -ahiE 'out of memory|oom-kill|killed process' /var/log/messages 2>/dev/null > "$TMP/oom"
  if [ -s "$TMP/oom" ]; then
    bad "the kernel killed processes for lack of memory $(grep -ci 'killed process' "$TMP/oom") time(s). Most recent:"
    grep -ai 'killed process' "$TMP/oom" | tail -n 5 | cut -c1-160 | indent
    out "         Processes killed most often:"
    grep -aoiE 'killed process [0-9]+ \([^)]+\)' "$TMP/oom" | sed -E 's/.*\(([^)]+)\)/\1/' | top 5 | indent
  else ok "no out-of-memory kills"; fi

  : > "$TMP/fpm"; FL="last $DAYS day(s)"
  for f in /opt/cpanel/ea-php*/root/usr/var/log/php-fpm/error.log; do
    [ -r "$f" ] || continue
    windowed "$f" "$TMP/d_fpm" "$TMP/fpm1" '^\[[0-9]{2}-[A-Z][a-z]{2}-[0-9]{4} '; FL=$WLABEL
    grep -a 'max_children' "$TMP/fpm1" >> "$TMP/fpm" || true
  done
  n=$(wc -l < "$TMP/fpm")
  if [ "$n" -gt 0 ]; then
    warn "PHP-FPM hit pm.max_children $n time(s) ($FL) - visitors waited or got 503. Raise it only if RAM allows (about 40-80 MB per worker)"
    out "         By site (pool) and its current limit:"
    grep -aoE '\[pool [^]]+\].*setting \([0-9]+\)' "$TMP/fpm" | sed -E 's/\] .*setting \(([0-9]+)\)/] limit \1/' | top 8 | indent
    out "         Hours it happened (top 5):"
    cut -c2-15 "$TMP/fpm" | sed 's/$/:00/' | top 5 | indent
  else ok "PHP-FPM never hit max_children ($FL)"; fi
  for f in /usr/local/apache/logs/error_log /etc/apache2/logs/error_log; do
    [ -r "$f" ] || continue
    windowed "$f" "$TMP/d_aperr" "$TMP/ape" '^\[[A-Z][a-z]{2} [A-Z][a-z]{2} [0-9]{2} '
    n=$(grep -acE 'MaxRequestWorkers|MaxClients|scoreboard is full' "$TMP/ape" || true)
    [ "$n" -gt 0 ] && warn "Apache reached its worker limit $n time(s) ($WLABEL) (MaxRequestWorkers)" || ok "Apache never reached its worker limit ($WLABEL)"
    break
  done
else
  note "skipped (needs root)"
fi
n=$(cnt 'Too many connections|SQLSTATE\[HY000\] \[1040\]' "$TMP/lv_all")
[ "$n" -gt 0 ] && warn "The database refused connections $n time(s) (Too many connections) - compare the database max connections with your PHP worker count"
n=$(cnt 'Allowed memory size' "$TMP/lv_all")
[ "$n" -gt 0 ] && warn "PHP memory_limit exhausted $n time(s) in Laravel"

sub "Busiest hours"
if [ "$TOTAL" -gt 0 ]; then
  out "         Requests per hour (top 5):"
  awk '{print substr($5,2,14)":00"}' "$ACC" | top 5 | indent
  awk '$10>=500 {print substr($5,2,14)":00"}' "$ACC" | top 5 > "$TMP/h5"
  [ -s "$TMP/h5" ] && { out "         5xx errors per hour (top 5):"; indent < "$TMP/h5"; }
fi
if [ -s "$TMP/lv_all" ]; then
  grep -aE '\.(ERROR|CRITICAL|ALERT|EMERGENCY):' "$TMP/lv_all" | awk '{print substr($0,2,13)":00"}' | top 5 > "$TMP/hl"
  [ -s "$TMP/hl" ] && { out "         Laravel errors per hour (top 5):"; indent < "$TMP/hl"; }
fi
note "when the same hour tops requests, errors and CPU/memory, that is your capacity limit"

# =============================================================================
section "Summary"
out "  OK: $NPASS    WARN: $NWARN    FAIL: $NFAIL"
todo() { [ -s "$TMP/actions" ] && { grep '^FAIL' "$TMP/actions"; grep '^WARN' "$TMP/actions"; } | cut -c1-200; }
if [ -s "$TMP/actions" ]; then out ""; out "  To do (FAIL first):"; todo | sed 's/^/    /' | tee -a "$REPORT"; fi
out "  Attack attempts in section 2 are normal background noise for any public server;"
out "  act on FAIL items first, then WARN."

if [ -n "${MAILTO:-}" ]; then
  subj="[server-audit] $(hostname): $NFAIL fail, $NWARN warn"
  { [ -s "$TMP/actions" ] && { echo "TO DO (details below):"; todo | sed 's/^/  /'; echo; }
    cat "$REPORT"; } | sed 's/\x1b\[[0-9;]*m//g' > "$TMP/plain"   # to-do list first in the email
  mg_dom=""; mg_key=""; mg_end=""; m_host=""; m_port=""; m_user=""; m_pass=""; m_from="${MAIL_FROM:-}"
  if [ -n "${MAIL_ENV:-}" ] && [ -r "$MAIL_ENV" ]; then
    mg_dom=$(envget "$MAIL_ENV" MAILGUN_DOMAIN); mg_key=$(envget "$MAIL_ENV" MAILGUN_SECRET); mg_end=$(envget "$MAIL_ENV" MAILGUN_ENDPOINT)
    m_host=$(envget "$MAIL_ENV" MAIL_HOST); m_port=$(envget "$MAIL_ENV" MAIL_PORT)
    m_user=$(envget "$MAIL_ENV" MAIL_USERNAME); m_pass=$(envget "$MAIL_ENV" MAIL_PASSWORD)
    [ -n "$m_from" ] || m_from=$(envget "$MAIL_ENV" MAIL_FROM_ADDRESS)
  elif [ -n "${MAIL_ENV:-}" ]; then
    printf '  [WARN] MAIL_ENV file %s is not readable - falling back to the server mailer\n' "$MAIL_ENV"
  fi
  case "$m_from" in *@*.*) ;; *) m_from="server-audit@${mg_dom:-$(hostname)}";; esac
  sent=""
  if [ -n "$mg_dom" ] && [ -n "$mg_key" ] && have curl; then
    # Mail provider HTTP API (port 443). The key is passed on stdin so it never shows in the process list.
    mg_end=${mg_end#http://}; mg_end=${mg_end#https://}; mg_end=${mg_end%/}; mg_end=${mg_end:-api.mailgun.net}
    code=$(printf 'user = "api:%s"\n' "$mg_key" | curl -K - -sS -m 30 -o "$TMP/mailout" -w '%{http_code}' \
        "https://$mg_end/v3/$mg_dom/messages" -F "from=Server Audit <$m_from>" -F "to=$MAILTO" -F "subject=$subj" -F "text=<$TMP/plain" 2>"$TMP/mailerr")
    if [ "$code" = 200 ]; then sent="the mail provider API ($mg_dom)"
    else printf '  [WARN] the mail provider API refused the email (HTTP %s): %s\n' "${code:-none}" "$(head -c 200 "$TMP/mailout" "$TMP/mailerr" 2>/dev/null | tr '\n' ' ')"; fi
  elif [ -n "$m_host" ] && [ -n "$m_user" ] && [ -n "$m_pass" ] && have curl; then
    # SMTP login on 465/587 (works where outgoing port 25 is blocked)
    m_port=${m_port:-587}; scheme=smtp; tls="--ssl-reqd"; [ "$m_port" = 465 ] && { scheme=smtps; tls=""; }
    { echo "From: Server Audit <$m_from>"; echo "To: $MAILTO"; echo "Subject: $subj"; echo "Date: $(date -R)"; echo; cat "$TMP/plain"; } > "$TMP/msg"
    # shellcheck disable=SC2086
    if printf 'user = "%s:%s"\n' "$m_user" "$m_pass" | curl -K - -sS -m 30 $tls --url "$scheme://$m_host:$m_port" \
        --mail-from "$m_from" --mail-rcpt "$MAILTO" -T "$TMP/msg" 2>"$TMP/mailerr"; then sent="SMTP ($m_host:$m_port)"
    else printf '  [WARN] SMTP send failed: %s\n' "$(head -c 200 "$TMP/mailerr" | tr '\n' ' ')"; fi
  fi
  if [ -z "$sent" ]; then
    if have mail; then mail -s "$subj" "$MAILTO" < "$TMP/plain" && sent="the server's own mailer (delivery not confirmed)"
    elif [ -x /usr/sbin/sendmail ]; then { echo "To: $MAILTO"; echo "Subject: $subj"; echo; cat "$TMP/plain"; } | /usr/sbin/sendmail -t && sent="the server's own mailer (delivery not confirmed)"
    fi
  fi
  [ -n "$sent" ] && printf '  [info] report emailed to %s via %s\n' "$MAILTO" "$sent" || printf '  [WARN] report was NOT emailed\n'
fi
[ "$NFAIL" -gt 0 ] && exit 2
[ "$NWARN" -gt 0 ] && exit 1
exit 0
