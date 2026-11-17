#!/usr/bin/env bash
# NightWarden agent pro Linux: jednou denně pošle seznam nainstalovaných balíčků do NightWarden.
# Nic neinstaluje ani nemění, jen čte (dpkg-query / rpm / apk, /etc/os-release, uname, /proc, příznak restartu,
# needrestart -b / needs-restarting -r, když jsou nainstalované) a posílá přes HTTPS.
#
#   Instalace (root):   curl -fsSL https://SERVER/agent/nightwarden-agent.sh | sudo bash -s -- install --url https://SERVER
#                       klíč se zeptá na terminálu /dev/tty (bez echa; stdin je při `curl | bash` sám skript), nebo
#                       --key-file /root/nw-key (0600, ne symlink), nebo NW_AGENT_KEY, když už běžíš jako root (sudo
#                       proměnné zahazuje; `sudo NW_AGENT_KEY=… bash` by dal klíč do argumentů sudo);
#                       --key pcve_… dál funguje, ale zůstane v historii a v `ps`
#                       volitelně --ca /cesta/k/ca.pem (vlastní certifikační autorita, např. Caddy v domácí síti)
#   Ruční odeslání:     sudo nightwarden-agent run
#   Aktualizace:        sudo nightwarden-agent update   (stáhne agenta ze serveru z konfigurace, atomicky nahradí)
#                       sudo nightwarden-agent update --sha256 <hash>   (#210: jen se shodným SHA-256, např. z Release)
#   Co by se poslalo:   nightwarden-agent payload       (nic neodešle)
#   Offline (1.2.0):    nightwarden-agent run --output /srv/nw-reports/host-20261115.json[.gz]
#                       stejné hlášení do souboru místo odeslání (bez sítě, bez tajemství klíče: jen jeho prefix);
#                       bez instalace: bash nightwarden-agent.sh run --output FILE --key-prefix a1b2c3d4
#   Offline instalace:  sudo bash nightwarden-agent.sh install --offline --dir /srv/nw-reports --key-file /root/nw-key
#                       denně zapíše <host>-<datum>.json do složky (0600 root); nahrání: Import vulnerabilities
#                       → NightWarden offline report, nebo relay skript nightwarden-relay.sh na stroji s přístupem ven
#   Odinstalace:        sudo nightwarden-agent uninstall
#
# Závislosti: bash, curl, awk (a správce balíčků distribuce). Konfigurace /etc/nightwarden-agent.conf (jen root).
set -euo pipefail
umask 077

AGENT_VERSION="1.2.0"
CONF="${PCVE_CONF:-/etc/nightwarden-agent.conf}"
BIN="${PCVE_BIN:-/usr/local/sbin/nightwarden-agent}"  # PCVE_BIN jen pro testy
UNIT="nightwarden-agent"
ROOT="${PCVE_ROOT:-}"  # jen pro testy: kořen pro /etc/systemd, /etc/cron.d a /run/systemd
LEGACY="project-cve-agent"  # dřívější název (Project CVE): instalace ho nahradí

die() { echo "nightwarden-agent: $*" >&2; exit 1; }

# --------------------------------------------------------------------------- JSON (bez jq)

# Řetězec -> JSON (uvozovky, zpětná lomítka, řídicí znaky)
jstr() {
  printf '%s' "$1" | awk 'BEGIN { ORS = "" } {
    gsub(/\\/, "\\\\"); gsub(/"/, "\\\""); gsub(/\t/, " "); gsub(/[\001-\037\177]/, "")
    if (NR > 1) print " "; print } END { if (NR == 0) print "" }' | { printf '"'; cat; printf '"'; }
}

# TSV "jméno<TAB>zdrojový balíček<TAB>verze" -> JSON pole balíčků; $1 = dpkg / rpm / apk
packages_json() {
  awk -F '\t' -v src_kind="$1" 'BEGIN { ORS = ""; print "["; n = 0 }
    function esc(s) { gsub(/\\/, "\\\\", s); gsub(/"/, "\\\"", s); gsub(/[\001-\037\177]/, "", s); return s }
    $1 != "" && $3 != "" {
      if (n++) print ","
      print "{\"name\":\"" esc($1) "\",\"version\":\"" esc($3) "\",\"source\":\"" src_kind "\""
      if ($2 != "" && $2 != $1) print ",\"src\":\"" esc($2) "\""
      print "}"
    }
    END { print "]" }'
}

# --------------------------------------------------------------------------- sběr dat (jen čtení)

os_release_value() {  # ID / VERSION_ID / PRETTY_NAME z /etc/os-release
  local file="${PCVE_TEST_OS_RELEASE:-/etc/os-release}"
  [ -r "$file" ] || file=/usr/lib/os-release
  [ -r "$file" ] || return 0
  sed -n "s/^$1=//p" "$file" | head -n1 | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//"
}

# Výstup správce balíčků jako TSV jméno<TAB>zdroj<TAB>verze; vypíše na stderr použitý formát
collect_packages() {
  local fmt="${PCVE_TEST_FORMAT:-}"
  if [ -n "${PCVE_TEST_PKGS:-}" ]; then
    raw() { cat "$PCVE_TEST_PKGS"; }  # testy: uložený výstup místo spuštění příkazu
  else
    raw() { :; }
    if command -v dpkg-query >/dev/null 2>&1; then
      fmt=dpkg
      raw() { dpkg-query -W -f='${db:Status-Abbrev}\t${binary:Package}\t${source:Package}\t${Version}\n' 2>/dev/null; }
    elif command -v rpm >/dev/null 2>&1; then
      fmt=rpm
      raw() { rpm -qa --qf '%{NAME}\t\t%{VERSION}-%{RELEASE}\n' 2>/dev/null; }
    elif command -v apk >/dev/null 2>&1; then
      fmt=apk
      raw() { apk list -I 2>/dev/null; }
    fi
  fi
  echo "$fmt" >&2
  case "$fmt" in
    dpkg)  # jen nainstalované (ii), bez architektury v názvu (libc6:amd64)
      raw | awk -F '\t' '$1 ~ /^ii/ { split($2, a, ":"); print a[1] "\t" $3 "\t" $4 }' ;;
    rpm)
      raw | awk -F '\t' '$1 != "" && $1 != "gpg-pubkey" { print $1 "\t\t" $3 }' ;;
    apk)  # busybox-1.36.1-r29 x86_64 {busybox} (GPL-2.0-only) [installed]
      raw | awk '{ n = split($1, p, "-"); if (n < 3) next
                   ver = p[n-1] "-" p[n]; name = p[1]; for (i = 2; i <= n - 2; i++) name = name "-" p[i]
                   origin = $3; gsub(/[{}]/, "", origin); print name "\t" origin "\t" ver }' ;;
  esac
}

# --------------------------------------------------------------------------- kernel, restart, služby (1.1.0)

# Řádky ze stdin -> JSON pole řetězců (nejvýš $1 položek, jen znaky $2; ostatní řádky se vynechají)
json_list() {
  awk -v max="$1" -v ok="$2" 'BEGIN { ORS = ""; print "["; n = 0 }
    $0 ~ ok && n < max { if (n++) print ","; print "\"" $0 "\"" }
    END { print "]" }'
}

# Verze balíčku běžícího kernelu -> "verze<TAB>balíček" (nic, když ji nejde zjistit). $1 = ID a ID_LIKE z os-release
#   Debian: uname -v "#1 SMP PREEMPT_DYNAMIC Debian 6.1.76-1 (2024-02-01)"          -> 6.1.76-1        linux
#   Ubuntu: /proc/version_signature "Ubuntu 5.15.0-91.101-generic 5.15.131"        -> 5.15.0-91.101   linux (aws -> linux-aws)
#   RHEL / Alma / Rocky / Oracle / Fedora: uname -r "5.14.0-362.8.1.el9_3.x86_64"  -> 5.14.0-362.8.1.el9_3 kernel
#   Alpine: uname -r "6.6.14-0-lts"                                                -> 6.6.14-r0       linux-lts
kernel_package() {
  local ids="$1" release="$2" uv="$3" sig="$4"
  case " $ids " in
    *" ubuntu "*)
      # verze až po pomlčku před flavourem (HWE: 6.8.0-45.45~22.04.1-generic); balíček jen jako záloha, server bere
      # variantu ze zdrojového balíčku linux-image-<uname -r>
      printf '%s\n' "$sig" | awk '{ v = $2; if (match(v, /^[0-9][0-9.]*-[0-9][^-]*-/)) {
          ver = substr(v, 1, RLENGTH - 1); fl = substr(v, RLENGTH + 1); split(ver, n, ".")
          base = (fl ~ /^generic/) ? "linux" : (fl ~ /^lowlatency/) ? "linux-lowlatency" : "linux-" fl
          if (ver ~ /~[0-9]+\.[0-9]+/) base = ((base == "linux") ? "linux-hwe" : base "-hwe") "-" n[1] "." n[2]
          print ver "\t" base } }' ;;
    *" debian "*|*" raspbian "*)
      printf '%s\n' "$uv" | sed -n 's/.* Debian \([0-9][^ ]*\) .*/\1\tlinux/p' | head -n1 ;;
    *" alpine "*)
      printf '%s\n' "$release" | sed -n 's/^\([0-9][0-9.]*\)-\([0-9][0-9]*\)-\([a-z0-9]*\)$/\1-r\2\tlinux-\3/p' ;;
    *" rhel "*|*" fedora "*|*" centos "*|*" almalinux "*|*" rocky "*|*" ol "*|*" amzn "*)
      printf '%s\n' "$release" | awk '{ v = $0; sub(/\.(x86_64|aarch64|ppc64le|s390x|i686)(\+[a-z0-9]+)?$/, "", v)
          if (v != $0) print v "\t" (v ~ /uek/ ? "kernel-uek" : "kernel") }' ;;
  esac
}

# Restart: "true<TAB>důvod" / "false<TAB>důvod" / "null<TAB>" (neví: server porovná běžící a nainstalovaný kernel)
reboot_state() {
  local dir="${PCVE_TEST_RUN_DIR:-/var/run}" rc
  if [ -e "$dir/reboot-required" ]; then printf 'true\treboot-required\n'; return; fi
  if [ -n "${PCVE_TEST_NEEDS_RESTARTING:-}" ]; then
    rc="$PCVE_TEST_NEEDS_RESTARTING"
  elif command -v needs-restarting >/dev/null 2>&1; then  # dnf-utils / yum-utils: 1 = restart potřeba
    rc=0; timeout 120 needs-restarting -r >/dev/null 2>&1 || rc=$?
  else
    printf 'null\t\n'; return
  fi
  case "$rc" in
    0) printf 'false\tneeds-restarting\n' ;;
    1) printf 'true\tneeds-restarting\n' ;;
    *) printf 'null\t\n' ;;
  esac
}

# Služby se starými knihovnami po aktualizaci: jen když je needrestart nainstalovaný (nic se neinstaluje)
services_restart() {
  if [ -n "${PCVE_TEST_NEEDRESTART:-}" ]; then cat "$PCVE_TEST_NEEDRESTART"
  elif command -v needrestart >/dev/null 2>&1; then timeout 120 needrestart -b 2>/dev/null || true
  fi | sed -n 's/^NEEDRESTART-SVC: *//p'
}

# Poslední start (UTC, ISO 8601) z /proc/uptime
last_boot() {
  local up now
  up="$(cut -d' ' -f1 "${PCVE_TEST_UPTIME:-/proc/uptime}" 2>/dev/null | cut -d. -f1)" || return 0
  case "$up" in ''|*[!0-9]*) return 0 ;; esac
  now="${PCVE_TEST_NOW:-$(date +%s)}"
  date -u -d "@$((now - up))" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || true
}

host_name() {
  local host
  host="${PCVE_TEST_HOSTNAME:-$(hostname 2>/dev/null || cat /proc/sys/kernel/hostname)}"
  printf '%s' "${host%%.*}"
}

machine_id() {
  printf '%s' "${PCVE_TEST_MACHINE_ID:-$(cat /etc/machine-id 2>/dev/null || cat /var/lib/dbus/machine-id 2>/dev/null || true)}"
}

payload() {
  local host machine_id ip kernel fmt pkgs_file
  host="$(host_name)"
  machine_id="$(machine_id)"
  ip="${PCVE_TEST_IP-$(ip -o route get 1.1.1.1 2>/dev/null | awk '{ for (i = 1; i < NF; i++) if ($i == "src") print $(i+1) }' | head -n1 || true)}"
  kernel="${PCVE_TEST_KERNEL:-$(uname -r)}"
  pkgs_file="$(mktemp)"
  fmt="$(collect_packages 2>&1 >"$pkgs_file" | tail -n1)"
  printf '{"agent":{"version":%s,"platform":"linux"},' "$(jstr "$AGENT_VERSION")"
  printf '"hostname":%s,"machine_id":%s,"ip":%s,' "$(jstr "$host")" "$(jstr "$machine_id")" "$(jstr "$ip")"
  printf '"os":{"family":"linux","id":%s,"version_id":%s,"name":%s,"kernel":%s},' \
    "$(jstr "$(os_release_value ID)")" "$(jstr "$(os_release_value VERSION_ID)")" \
    "$(jstr "$(os_release_value PRETTY_NAME)")" "$(jstr "$kernel")"
  # 1.1.0: běžící kernel, restart, služby k restartu, poslední start
  local ids kpkg reboot rdir="${PCVE_TEST_RUN_DIR:-/var/run}"
  ids="$(os_release_value ID) $(os_release_value ID_LIKE)"
  kpkg="$(kernel_package "$ids" "$kernel" "${PCVE_TEST_UNAME_V:-$(uname -v 2>/dev/null || true)}" \
          "$(cat "${PCVE_TEST_VERSION_SIGNATURE:-/proc/version_signature}" 2>/dev/null || true)")"
  reboot="$(reboot_state)"
  printf '"running_kernel":{"release":%s,"version":%s,"package":%s},' "$(jstr "$kernel")" \
    "$(jstr "$(printf '%s' "$kpkg" | cut -f1)")" "$(jstr "$(printf '%s' "$kpkg" | cut -f2)")"
  printf '"reboot_required":%s,"reboot_reason":%s,' "${reboot%%$'\t'*}" "$(jstr "${reboot#*$'\t'}")"
  printf '"reboot_packages":'
  { cat "$rdir/reboot-required.pkgs" 2>/dev/null || true; } | json_list 50 '^[A-Za-z0-9][A-Za-z0-9+.~:_-]*$'
  printf ',"services_restart":'
  services_restart | json_list 100 '^[A-Za-z0-9][A-Za-z0-9@._:\\-]*$'
  printf ',"last_boot":%s,' "$(jstr "$(last_boot)")"
  printf '"packages":'
  if [ -n "$fmt" ]; then packages_json "$fmt" <"$pkgs_file"; else printf '[]'; fi
  printf '}\n'
  rm -f "$pkgs_file"
}

# --------------------------------------------------------------------------- konfigurace a odeslání

conf() {  # hodnota z konfigurace; soubor se jen čte, nikdy nespouští (source)
  [ -r "$CONF" ] || die "missing $CONF (run: install --url … --key …)"
  sed -n "s/^$1=//p" "$CONF" | head -n1
}

# --------------------------------------------------------------------------- offline (1.2.0)

# Offline hlášení: stejné hlášení jako payload, obalené časem, verzí a prefixem klíče (bez tajemství).
# $1 = cílový soubor (.gz = gzip), $2 = prefix klíče. Zápis atomicky přes dočasný soubor ve stejné složce, 0600.
safe_dir() {  # #129: složka patří tomuto účtu (EUID) a skupina ani ostatní do ní nesmí zapisovat
  local st
  [ -d "$1" ] && [ ! -L "$1" ] || return 1
  st="$(stat -c '%u %a' -- "$1" 2>/dev/null)" || return 1
  # sticky bit (např. /tmp): cizí účet náš dočasný soubor nesmaže ani nepřejmenuje, odkaz místo něj nepodstrčí
  case "${st#* }" in [1357]???) return 0 ;; esac
  [ "${st%% *}" = "$EUID" ] || return 1
  case "${st#* }" in *[2367]?|*[2367]) return 1 ;; esac
  return 0
}

write_offline() {
  local out="$1" prefix="$2" dir tmp now
  case "$prefix" in ????????) ;; *) die "key prefix must be 8 characters (pcve_<prefix>_…)";; esac
  case "$prefix" in *[!0-9a-f]*) die "key prefix must be 8 hexadecimal characters";; esac
  dir="$(dirname -- "$out")"
  [ -d "$dir" ] || die "directory $dir does not exist"
  # #129: do složky smí zapisovat jen tento účet – jinak by kdokoli s právem zápisu podstrčil místo dočasného
  # souboru symbolický odkaz (přepis / chmod cizího souboru jako root)
  safe_dir "$dir" || die "directory $dir is writable by other users or not owned by this account; write reports to a directory only root can write to (others may read it)"
  [ ! -L "$out" ] || die "$out is a symlink"
  tmp="$(mktemp "$dir/.nightwarden-agent.XXXXXX")"
  trap "rm -f '$tmp'" EXIT
  now="${PCVE_TEST_NOW:-$(date +%s)}"
  {
    printf '{"format":"nightwarden-offline-report","format_version":1,"generated_at":"%s",' \
      "$(date -u -d "@$now" +%Y-%m-%dT%H:%M:%SZ)"
    printf '"key_prefix":"%s","agent_version":%s,"hostname":%s,"machine_id":%s,"report":' \
      "$prefix" "$(jstr "$AGENT_VERSION")" "$(jstr "$(host_name)")" "$(jstr "$(machine_id)")"
    payload | tr -d '\n'
    printf '}\n'
  } | case "$out" in *.gz) gzip -9n ;; *) cat ;; esac >"$tmp"
  chmod 0600 "$tmp"
  mv -f "$tmp" "$out"
  trap - EXIT
  echo "nightwarden-agent: offline report written to $out ($(wc -c <"$out") bytes)"
}

key_prefix_of() {  # pcve_<prefix>_<tajemství> -> prefix
  local k="${1#pcve_}"
  printf '%s' "${k%%_*}"
}

run_cmd() {  # run [--output FILE] [--key-prefix P]
  local out="" prefix=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --output|-o) out="${2:-}"; shift 2 ;;
      --key-prefix) prefix="${2:-}"; shift 2 ;;
      *) die "unknown option $1" ;;
    esac
  done
  if [ -z "$out" ] && [ -r "$CONF" ] && [ "$(conf MODE)" = offline ]; then
    out="$(conf DIR)/$(host_name)-$(date -u +%Y%m%d).json"
  fi
  if [ -n "$out" ]; then
    if [ -z "$prefix" ] && [ -r "$CONF" ]; then
      prefix="$(conf KEY_PREFIX)"
      [ -n "$prefix" ] || prefix="$(key_prefix_of "$(conf KEY)")"
    fi
    [ -n "$prefix" ] || die "no key prefix: use --key-prefix (the part after pcve_ in the agent key) or install first"
    write_offline "$out" "$prefix"
  else
    send
  fi
}

send() {
  local url key ca tmp hdr resp code
  url="$(conf URL)"; key="$(conf KEY)"; ca="$(conf CA)"
  case "$url" in https://*) ;; *) die "URL must start with https://";; esac
  [ -n "$key" ] || die "KEY is empty in $CONF"
  tmp="$(mktemp)"; hdr="$(mktemp)"; resp="$(mktemp)"
  # cesty rozbalené hned: trap běží až po návratu z funkce, kdy lokální proměnné už neexistují
  trap "rm -f '$tmp' '$hdr' '$resp'" EXIT
  payload >"$tmp"
  # klíč v souboru, ne na příkazové řádce (byl by vidět v `ps`)
  printf 'Authorization: Bearer %s\nContent-Type: application/json\nUser-Agent: nightwarden-agent/%s\n' \
    "$key" "$AGENT_VERSION" >"$hdr"
  set -- --silent --show-error --proto =https --proto-redir =https --connect-timeout 20 --max-time 120 \
    --header @"$hdr" --data-binary @"$tmp" --output "$resp" --write-out '%{http_code}'
  [ -n "$ca" ] && set -- "$@" --cacert "$ca"
  # znovu jen když se nepodaří spojení; odpověď serveru (i 429 "počkej") se neopakuje, příště to zkusí timer
  local attempt rc
  for attempt in 1 2 3; do
    rc=0
    code="$(curl "$@" "${url%/}/api/v1/agent/report")" || rc=$?
    [ "$rc" = 0 ] && break
    case "$rc" in
      6|7|28|52|55|56) ;;  # DNS, spojení, timeout, přerušené spojení: zkusit znovu
      *) die "cannot send to ${url} (curl error $rc, e.g. 60 = untrusted certificate: use --ca)" ;;
    esac
    [ "$attempt" = 3 ] && die "cannot reach ${url} (curl error $rc)"
    sleep $((attempt * 30))
  done
  case "$code" in
    2??) echo "nightwarden-agent: report sent ($(wc -c <"$tmp") bytes): $(cat "$resp")" ;;
    429) echo "nightwarden-agent: server asks to wait: $(cat "$resp")" >&2 ;;
    *) die "server answered HTTP $code: $(cat "$resp")" ;;
  esac
}

# --------------------------------------------------------------------------- instalace

# Ohlášení instalace (1.1.1): server u klíče ukáže „Installed but never reported“, když pak hlášení nepřijde.
# Klíč jen v souboru s hlavičkou (ne na příkazové řádce). Nepovede se: jen varování, instalace pokračuje.
hello() {  # $1 = URL, $2 = klíč, $3 = CA
  local hdr code
  hdr="$(mktemp)"
  printf 'Authorization: Bearer %s\nUser-Agent: nightwarden-agent/%s\n' "$2" "$AGENT_VERSION" >"$hdr"
  code="$(curl --silent --proto =https --proto-redir =https --connect-timeout 20 --max-time 30 --header @"$hdr" \
          ${3:+--cacert "$3"} --data-binary '{}' --output /dev/null --write-out '%{http_code}' \
          "${1%/}/api/v1/agent/hello" 2>/dev/null)" || code="000"
  rm -f "$hdr"
  case "$code" in
    2??) ;;
    *) echo "nightwarden-agent: warning: install check with ${1%/} failed (HTTP $code); the first report shows why" >&2 ;;
  esac
}

# Klíč agenta: --key (starší příkazy), --key-file, proměnná NW_AGENT_KEY, jinak dotaz na terminálu bez echa.
# Klíč nikdy jako argument jiného procesu, do výstupu ani do logu (jen builtiny bash: read, printf, case).
read_key() {  # $1 = --key, $2 = --key-file; výsledek v proměnné KEY_VALUE
  local k="$1"
  if [ -z "$k" ] && [ -n "$2" ]; then
    # jen obyčejný soubor (ne symlink), který nečte nikdo jiný (0600 / 0400); po instalaci se nemaže
    [ ! -L "$2" ] || die "--key-file $2 is a symlink; use the file itself"
    [ -f "$2" ] && [ -r "$2" ] || die "--key-file $2 not readable"
    local mode
    mode="$(stat -c '%a' "$2" 2>/dev/null)" || die "--key-file $2: cannot read its permissions"
    case "$mode" in
      [0-7]00|[0-7][0-7]00) ;;
      *) die "--key-file $2 is readable by others (mode $mode); run: chmod 600 $2" ;;
    esac
    IFS= read -r k <"$2" || true
  fi
  if [ -z "$k" ] && [ -n "${NW_AGENT_KEY:-}" ]; then k="$NW_AGENT_KEY"; fi
  unset NW_AGENT_KEY  # nedědí ho nic, co se spustí potom
  if [ -z "$k" ] && { : </dev/tty; } 2>/dev/null; then
    printf 'Agent key (pcve_..., input hidden): ' >/dev/tty
    IFS= read -rs k </dev/tty || true
    printf '\n' >/dev/tty
  fi
  k="${k//[[:space:]]/}"
  [ -n "$k" ] || die "no agent key: run on a terminal (it asks), or use --key-file FILE or NW_AGENT_KEY"
  case "$k" in pcve_*_*) ;; *) die "the agent key must look like pcve_…_… (Add machine shows it)";; esac
  case "$k" in *[!A-Za-z0-9_-]*) die "the agent key contains unexpected characters";; esac
  KEY_VALUE="$k"
}

install_agent() {
  local url="" key="" keyfile="" ca="" offline="" dir="" prefix=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --offline) offline=1; shift ;;
      --dir) dir="${2:-}"; shift 2 ;;
      --key-prefix) prefix="${2:-}"; shift 2 ;;
      --url) url="${2:-}"; shift 2 ;;
      --key) key="${2:-}"; shift 2 ;;
      --key-file) keyfile="${2:-}"; shift 2 ;;
      --ca) ca="${2:-}"; shift 2 ;;
      *) die "unknown option $1" ;;
    esac
  done
  [ "$(id -u)" = 0 ] || die "install must run as root (sudo)"
  if [ -n "$offline" ]; then install_offline "$dir" "$key" "$keyfile" "$prefix"; return; fi
  case "$url" in https://*) ;; *) die "--url must start with https://";; esac
  read_key "$key" "$keyfile"
  key="$KEY_VALUE"
  [ -z "$ca" ] || [ -r "$ca" ] || die "--ca file $ca not readable"
  command -v curl >/dev/null || die "curl is required"

  url="${url%/}"
  hello "$url" "$key" "$ca"
  # vždy přes $BIN.new vedle cíle (adresář patří rootovi, žádný soubor v /tmp) a atomické přejmenování:
  # přerušené stažení nikdy nenechá poškozeného agenta
  if [ -f "${BASH_SOURCE[0]:-}" ] && grep -q 'nightwarden-agent' "${BASH_SOURCE[0]}"; then
    install -m 0755 -o root -g root "${BASH_SOURCE[0]}" "$BIN.new"
    mv -f "$BIN.new" "$BIN"
  else  # spuštěno přes rouru (curl … | bash): skript stáhnout znovu, jen stejnou verzi (#125)
    fetch_agent "$url" "$ca" same
  fi
  printf 'URL=%s\nKEY=%s\nCA=%s\n' "$url" "$key" "$ca" >"$CONF"
  chmod 0600 "$CONF"; chown root:root "$CONF"
  if [ -e "$ROOT/etc/$LEGACY.conf" ] || [ -e "$ROOT/usr/local/sbin/$LEGACY" ]; then
    remove_legacy
    echo "nightwarden-agent: replaced the previous project-cve-agent (same machine, same asset)"
  fi

  schedule
}

# Offline instalace (1.2.0): bez sítě a bez curl; v konfiguraci jen složka a prefix klíče (tajemství klíče se na
# izolovaný stroj neukládá). $1 = složka, $2 = --key, $3 = --key-file, $4 = --key-prefix
install_offline() {
  local dir="$1" prefix="$4"
  [ -n "$dir" ] || die "--offline needs --dir /path/to/reports"
  case "$dir" in /*) ;; *) die "--dir must be an absolute path";; esac
  if [ -z "$prefix" ]; then
    read_key "$2" "$3"
    prefix="$(key_prefix_of "$KEY_VALUE")"
    KEY_VALUE=""
  fi
  case "$prefix" in *[!0-9a-f]*|"") die "invalid key prefix";; esac
  [ "${#prefix}" = 8 ] || die "invalid key prefix"
  if [ ! -d "$dir" ]; then
    mkdir -p -m 0700 "$dir"
  fi
  if [ -f "${BASH_SOURCE[0]:-}" ] && grep -q 'nightwarden-agent' "${BASH_SOURCE[0]}"; then
    install -m 0755 -o root -g root "${BASH_SOURCE[0]}" "$BIN.new"
    mv -f "$BIN.new" "$BIN"
  else
    die "offline install needs the script as a file: bash nightwarden-agent.sh install --offline …"
  fi
  printf 'MODE=offline\nDIR=%s\nKEY_PREFIX=%s\n' "$dir" "$prefix" >"$CONF"
  chmod 0600 "$CONF"; chown root:root "$CONF"
  RW_DIR="$dir" schedule  # ProtectSystem=strict: zápis jen do složky s hlášeními
}

# Denní spuštění `run` (systemd timer, jinak cron); první běh hned
schedule() {
  if command -v systemctl >/dev/null 2>&1 && [ -d "$ROOT/run/systemd/system" ]; then
    cat >"$ROOT/etc/systemd/system/$UNIT.service" <<EOF
[Unit]
Description=NightWarden agent (send installed software inventory)
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=$BIN run
Nice=10
IOSchedulingClass=idle
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes${RW_DIR:+
ReadWritePaths=$RW_DIR}
EOF
    cat >"$ROOT/etc/systemd/system/$UNIT.timer" <<EOF
[Unit]
Description=NightWarden agent, once a day

[Timer]
OnCalendar=daily
RandomizedDelaySec=6h
Persistent=true

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable --now $UNIT.timer >/dev/null
    echo "nightwarden-agent: installed (systemd timer, daily with random delay). First report now:"
    systemctl start $UNIT.service && journalctl -u $UNIT.service -n 3 --no-pager -o cat 2>/dev/null || true
  else  # bez systemd: cron s náhodnou minutou a hodinou
    echo "$((RANDOM % 60)) $((RANDOM % 24)) * * * root $BIN run >/dev/null 2>&1" >"$ROOT/etc/cron.d/$UNIT"
    chmod 0644 "$ROOT/etc/cron.d/$UNIT"
    echo "nightwarden-agent: installed (cron, daily). First report now:"
    "$BIN" run
  fi
}

# Stáhne agenta ze serveru do $BIN.new (jen https), ověří a atomicky nahradí $BIN. $1 = URL serveru, $2 = CA
version_lt() {  # $1 < $2 (sort -V)
  [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n 1)" = "$1" ]
}

fetch_agent() {  # $1 URL, $2 CA, $3 same = jen stejná verze jako běžící skript (instalace rourou), jinak ne nižší
                 # $4 očekávaný SHA-256 (#210, update --sha256; prázdné = bez kontroly)
  local new="$BIN.new" got
  rm -f "$new"
  if ! curl -fsS --proto =https --proto-redir =https ${2:+--cacert "$2"} -o "$new" "${1%/}/agent/nightwarden-agent.sh"; then
    rm -f "$new"; die "cannot download the agent from ${1}"
  fi
  if [ -n "${4:-}" ] && [ "$(sha256sum "$new" | cut -d' ' -f1)" != "$4" ]; then
    rm -f "$new"; die "SHA-256 of the downloaded agent does not match $4; nothing installed"
  fi
  if ! grep -q 'nightwarden-agent' "$new" || ! bash -n "$new"; then
    rm -f "$new"; die "downloaded file is not a valid agent script"
  fi
  # #125: server smí dát jen tutéž verzi (instalace rourou: nainstaluje se to, co se spustilo), při update ne nižší
  got="$(sed -n 's/^AGENT_VERSION="\([0-9][0-9.]*\)"$/\1/p' "$new" | head -n 1)"
  [ -n "$got" ] || { rm -f "$new"; die "downloaded file is not a valid agent script (no version)"; }
  if [ "${3:-}" = same ] && [ "$got" != "$AGENT_VERSION" ]; then
    rm -f "$new"; die "the server sent a different agent version ($got) than the one running ($AGENT_VERSION); download the script again and run it"
  fi
  if version_lt "$got" "$AGENT_VERSION"; then
    rm -f "$new"; die "refusing to downgrade the agent from $AGENT_VERSION to $got"
  fi
  chmod 0755 "$new"; chown root:root "$new"
  mv -f "$new" "$BIN"
}

update_agent() {  # 1.1.0: aktualizace jedním příkazem, konfigurace (URL, klíč, CA) zůstává
  local url ca sha=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --sha256) sha="$(printf '%s' "${2:-}" | tr 'A-F' 'a-f')"; shift 2 ;;
      *) die "unknown option $1" ;;
    esac
  done
  case "$sha" in "") ;; *[!0-9a-f]*) die "--sha256 needs 64 hexadecimal characters" ;; *) [ ${#sha} = 64 ] || die "--sha256 needs 64 hexadecimal characters" ;; esac
  [ "$(id -u)" = 0 ] || die "update must run as root (sudo)"
  [ "$(conf MODE)" != offline ] || die "offline install: copy the new script to the machine and run install --offline again"
  url="$(conf URL)"; ca="$(conf CA)"
  case "$url" in https://*) ;; *) die "URL must start with https://";; esac
  fetch_agent "$url" "$ca" "" "$sha"
  echo "nightwarden-agent: updated to $("$BIN" version); sending a report now"
  "$BIN" run
}

remove_legacy() {  # agent nainstalovaný pod starým názvem project-cve-agent
  if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now $LEGACY.timer >/dev/null 2>&1 || true
    rm -f "$ROOT/etc/systemd/system/$LEGACY.service" "$ROOT/etc/systemd/system/$LEGACY.timer"
    systemctl daemon-reload 2>/dev/null || true
  fi
  rm -f "$ROOT/etc/cron.d/$LEGACY" "$ROOT/etc/$LEGACY.conf" "$ROOT/usr/local/sbin/$LEGACY"
}

uninstall_agent() {
  [ "$(id -u)" = 0 ] || die "uninstall must run as root (sudo)"
  if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now $UNIT.timer >/dev/null 2>&1 || true
    rm -f "$ROOT/etc/systemd/system/$UNIT.service" "$ROOT/etc/systemd/system/$UNIT.timer"
    systemctl daemon-reload 2>/dev/null || true
  fi
  rm -f "$ROOT/etc/cron.d/$UNIT" "$CONF" "$BIN"
  remove_legacy
  echo "nightwarden-agent: removed. The asset stays in NightWarden (delete it there if you want)."
}

case "${1:-}" in
  run) shift; run_cmd "$@" ;;
  payload) payload ;;
  install) shift; install_agent "$@" ;;
  update) shift; update_agent "$@" ;;
  uninstall) uninstall_agent ;;
  version) echo "$AGENT_VERSION" ;;
  *) sed -n '2,/^# Závislosti/p' "$0" 2>/dev/null | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
