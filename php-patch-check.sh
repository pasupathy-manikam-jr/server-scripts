#!/usr/bin/env bash
# php-patch-check.sh - is every PHP on this server patched, and is the patched code actually running?
#
# Read-only. Run as root on the server itself:
#   bash php-patch-check.sh
#
# For each PHP binary found (cPanel ea-php*, system php, php-fpm):
#   - version against the first fixed release of its branch (table below)
#   - package changelog mentions the CVE (catches vendor backports that keep an old version number)
# Then:
#   - PHP-FPM masters still running a binary that was replaced on disk (patched but not restarted)
#   - error-log signs of the attack (memory exhausted before any script ran, worker segfaults)
#
# Exit: 0 all patched, 1 warnings (restart needed / log signs), 2 a vulnerable PHP was found.

set -u
export LC_ALL=C

# ---- update this block for the next PHP security release -------------------------------------
CVE="CVE-2026-109618"                                  # one CVE id from the release, for changelog checks
FIXED="8.2.35 8.3.36 8.4.27 8.5.12"                    # first fixed release per supported branch
OLDEST_SUPPORTED="8.2"                                 # branches below this get no upstream fix
# ---------------------------------------------------------------------------------------------

if [ -t 1 ]; then R=$'\e[31m'; Y=$'\e[33m'; G=$'\e[32m'; N=$'\e[0m'; else R=; Y=; G=; N=; fi
RC=0
bad()  { echo "  ${R}[VULNERABLE]${N} $*"; RC=2; }
warn() { echo "  ${Y}[WARN]${N} $*"; [ $RC -lt 1 ] && RC=1; }
ok()   { echo "  ${G}[ OK ]${N} $*"; }
[ "$(id -u)" -eq 0 ] || echo "  [info] not root - FPM process and some log checks will be incomplete"

ver_lt()  { [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)" = "$1" ]; }   # version $1 < $2
# package that owns a file, and whether its changelog lists the CVE
pkg_of()  { if command -v rpm >/dev/null 2>&1; then rpm -qf "$1" 2>/dev/null | head -1
            elif command -v dpkg >/dev/null 2>&1; then dpkg -S "$1" 2>/dev/null | head -1 | cut -d: -f1; fi; }
has_cve() { if command -v rpm >/dev/null 2>&1; then rpm -q --changelog "$1" 2>/dev/null | grep -q "$CVE"
            else zgrep -qs "$CVE" "/usr/share/doc/$1/changelog.Debian.gz"; fi; }

echo "PHP patch check ($CVE)  -  $(hostname)  -  $(date '+%F %H:%M')"
echo
echo "--- Installed PHP versions ---"
mapfile -t BINS < <( { ls /opt/cpanel/ea-php*/root/usr/bin/php /opt/alt/php*/usr/bin/php 2>/dev/null
                       command -v php 2>/dev/null; ls /usr/bin/php[0-9]* 2>/dev/null; } | xargs -r -n1 readlink -f | sort -u )
[ ${#BINS[@]} -eq 0 ] && echo "  [info] no PHP binary found"
for b in "${BINS[@]}"; do
  [ -x "$b" ] || continue
  v=$("$b" -n -r 'echo PHP_VERSION;' 2>/dev/null) || continue
  branch=$(echo "$v" | cut -d. -f1,2)
  fix=$(echo "$FIXED" | tr ' ' '\n' | grep "^$branch\." | head -1)
  pkg=$(pkg_of "$b"); cl=""; [ -n "$pkg" ] && has_cve "$pkg" && cl=" (changelog lists $CVE)"
  label="$b  PHP $v${pkg:+  [$pkg]}"
  if [ -n "$fix" ]; then
    if ! ver_lt "$v" "$fix"; then ok "$label$cl"
    elif [ -n "$cl" ]; then ok "$label - older version number, but patched by the vendor$cl"
    else bad "$label - update to $fix or later"; fi
  elif ver_lt "$branch" "$OLDEST_SUPPORTED"; then
    [ -n "$cl" ] && ok "$label - end-of-life branch, vendor backport installed$cl" \
                 || bad "$label - end-of-life branch with no upstream fix; needs a vendor backport or an upgrade"
  else ok "$label - newer than the fixed releases"; fi
done

echo
echo "--- Running PHP-FPM (patched on disk is not enough until FPM restarts) ---"
n=0
for pid in $(pgrep -f 'php-fpm: master' 2>/dev/null); do
  n=$((n+1)); exe=$(readlink "/proc/$pid/exe" 2>/dev/null); cmd=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)
  case "$exe" in
    *"(deleted)"*) warn "master $pid runs a binary replaced on disk - restart it (${cmd% })";;
    "") echo "  [info] master $pid - cannot read its binary (run as root)";;
    *) ok "master $pid runs the current binary (${cmd% })";;
  esac
done
[ $n -eq 0 ] && echo "  [info] no PHP-FPM master running (with mod_php, restart Apache after a PHP update)"

echo
echo "--- Signs of exploitation in error logs ---"
LOGS=$(ls /opt/cpanel/ea-php*/root/usr/var/log/php-fpm/error.log /var/log/php*-fpm.log /var/log/php-fpm/*.log \
          /etc/apache2/logs/error_log /var/log/apache2/error.log /var/log/httpd/error_log /var/log/nginx/error.log \
          /home/*/logs/*.php.error.log 2>/dev/null)
if [ -z "$LOGS" ]; then echo "  [info] no error logs found"
else
  # memory exhausted "in Unknown on line 0" = failed before any script ran, the trigger described in the advisories
  m=$(grep -hE 'Allowed memory size of [0-9]+ bytes exhausted.*Unknown on line 0' $LOGS 2>/dev/null | wc -l)
  s=$(grep -hE 'Segmentation fault|SIGSEGV' $LOGS 2>/dev/null | wc -l)
  [ "$m" -gt 0 ] && warn "$m 'memory exhausted ... Unknown on line 0' error(s) - review times and source IPs:" \
                 && grep -hE 'Allowed memory size.*Unknown on line 0' $LOGS 2>/dev/null | tail -n 5 | cut -c1-160 | sed 's/^/        /'
  [ "$s" -gt 0 ] && warn "$s segmentation fault(s) in PHP/web server logs - compare with the memory errors above"
  [ "$m" -eq 0 ] && [ "$s" -eq 0 ] && ok "no memory-exhaustion-at-startup errors or segfaults in $(echo "$LOGS" | wc -l) log file(s)"
  echo "  [info] a successful attack can leave no trace here; rotated-away logs are not covered"
fi

echo
case $RC in
  0) echo "Result: all PHP versions patched and running the fixed code.";;
  1) echo "Result: patched, but see the warnings above.";;
  2) echo "Result: VULNERABLE PHP found - update it, then restart PHP-FPM (and Apache if it uses mod_php).";;
esac
exit $RC
