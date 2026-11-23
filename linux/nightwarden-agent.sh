#!/usr/bin/env bash
# NightWarden agent pro Linux: jednou denně pošle seznam nainstalovaných balíčků do NightWarden.
# Nic neinstaluje ani nemění, jen čte (dpkg-query / rpm / apk, /etc/os-release, uname, /proc, příznak restartu,
# needrestart -b / needs-restarting -r, když jsou nainstalované) a posílá přes HTTPS.
#
#   Instalace (root):   curl -fsSL https://SERVER/agent/nightwarden-agent.sh | sudo bash -s -- install --url https://SERVER
#                       klíč se zeptá na terminálu /dev/tty (bez echa; stdin je při `curl | bash` sám skript), nebo
#                       --key-file /root/nw-key (0600, ne symlink), nebo NW_AGENT_KEY, když už běžíš jako root (sudo
#                       proměnné zahazuje; `sudo NW_AGENT_KEY=… bash` by dal klíč do argumentů sudo);
#                       --key-file - čte klíč / jednorázový token ze stdin (1.5.0, staženým skriptem);
#                       --key pcve_… dál funguje, ale zůstane v historii a v `ps`
#                       volitelně --ca /cesta/k/ca.pem (vlastní certifikační autorita, např. Caddy v domácí síti)
#                       volitelně --interval 4h|12h|1d|7d (#290, jak často se hlásit; výchozí 1d = denně)
#   Četnost (1.3.0):    sudo nightwarden-agent configure --interval 12h   (změní plánování, konfigurace zůstane)
#   Kontejnery (1.7.0): sudo nightwarden-agent configure --containers     (--no-containers vypne; výchozí vypnuto)
#                       Docker / rootový Podman: jen čtení (ps, image inspect, image save), žádné exec / run / pull.
#                       Obsah image přes syft nebo trivy, jsou-li na stroji (agent nic nestahuje), jinak balíčky
#                       dpkg / apk přečtené z vrstev image bez spuštění kontejneru (RPM image jen se syft / trivy).
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

AGENT_VERSION="1.7.0"
CONF="${PCVE_CONF:-/etc/nightwarden-agent.conf}"
INTERVALS="4h 12h 1d 7d"  # #290: povolené četnosti hlášení (server zná stejný seznam, core.agent.INTERVALS)
DEFAULT_INTERVAL="1d"
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
      # #347 (1.6.0): verze s epochou (1:3.0.7-27.el9) jako v opravách OSV; bez epochy jen verze-release
      raw() { rpm -qa --qf '%{NAME}\t\t%|EPOCH?{%{EPOCH}:}:{}|%{VERSION}-%{RELEASE}\n' 2>/dev/null; }
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
  printf '{"agent":{"version":%s,"platform":"linux","interval":%s},' "$(jstr "$AGENT_VERSION")" "$(jstr "$(current_interval)")"
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
    2??) save_machine_key "$resp"
         # klíč stroje (#348) se nikdy nevypíše (výstup jde do logu cronu / journalu)
         echo "nightwarden-agent: report sent ($(wc -c <"$tmp") bytes): $(sed 's/"machine_key": *"[^"]*"/"machine_key": "(saved)"/' "$resp")"
         # v podshellu: vlastní úklid (trap) a chyba kontejnerů nikdy neshodí hlášení balíčků
         [ "$(conf CONTAINERS)" = 1 ] && { ( containers_send ) || echo "nightwarden-agent: containers: failed ($?)" >&2; }
         true ;;
    429) echo "nightwarden-agent: server asks to wait: $(cat "$resp")" >&2 ;;
    *) die "server answered HTTP $code: $(cat "$resp")" ;;
  esac
}

# #348 (1.4.0): server po prvním hlášení klíčem klienta vydá stroji VLASTNÍ klíč (jen jednou, v odpovědi). Uloží se do
# konfigurace místo klíče klienta (atomicky, 0600 root) – klíč klienta na stroji nezůstane. Když se uložení nepovede,
# agent skončí chybou a klíč nikam nevypíše; další hlášení klíčem klienta server odmítne (stroj má vlastní klíč) –
# admin ho pak u stroje zruší a agent se znovu nainstaluje. Žádný návrat na klíč klienta (bez tichého fallbacku).
save_machine_key() {  # $1 = soubor s odpovědí serveru
  local mk tmp
  mk="$(sed -n 's/.*"machine_key": *"\(pcve_[0-9a-f]\{8\}_[A-Za-z0-9_-]\{20,64\}\)".*/\1/p' "$1" | head -n 1)"
  [ -n "$mk" ] || return 0
  [ -r "$CONF" ] && [ ! -L "$CONF" ] || die "cannot save the machine key: $CONF missing or a symlink"
  tmp="$(mktemp "$CONF.XXXXXX")" || die "cannot save the machine key (mktemp)"
  chmod 0600 "$tmp"
  { grep -v '^KEY=' "$CONF"; printf 'KEY=%s\n' "$mk"; } >"$tmp" || { rm -f "$tmp"; die "cannot save the machine key"; }
  chown root:root "$tmp" 2>/dev/null || true
  mv -f "$tmp" "$CONF" || { rm -f "$tmp"; die "cannot save the machine key"; }
  echo "nightwarden-agent: this machine got its own key (saved in $CONF, the client key was removed)"
}

# --------------------------------------------------------------------------- kontejnery (1.7.0, #338)
#
# Bezpečnost (agent běží jako root): do příkazů jde jen ID image ověřené regexem ^sha256:[0-9a-f]{64}$; názvy, tagy
# a labely nikdy do shellu ani do argumentů (jen do JSON přes jstr a do URL přes urlenc). Jen čtecí příkazy runtime
# (ps, image inspect, image save) – žádné exec / run / create / pull. Limity: 50 image na hlášení, 120 s na image,
# image > 4 GB se přeskočí, nice / ionice, dočasné soubory v mktemp -d s úklidem.

CT_MAX_IMAGES=50
CT_TIMEOUT=120
CT_MAX_BYTES=$((2 * 1024 * 1024 * 1024))   # větší image se přeskočí (review #417: dřív 4 GB)
CT_BUDGET="${PCVE_CT_BUDGET:-900}"         # celkový čas na SBOM v jednom běhu (15 min); zbytek příště (server vrátí need)
CT_LOCK="${ROOT}/run/nightwarden-agent-containers.lock"

ct_workdir() {  # pracovní složka mimo /tmp (často tmpfs = RAM): WORKDIR z konfigurace, jinak /var/tmp
  local d
  d="$(conf WORKDIR 2>/dev/null || true)"
  [[ -n "$d" && -d "$d" ]] || d=/var/tmp
  mktemp -d "$d/nightwarden-ct.XXXXXX"
}

ct_free_kb() { df -Pk "$1" 2>/dev/null | awk 'NR == 2 { print $4 + 0 }'; }

ct_lock() {  # jeden běh kontejnerů najednou (timer + ruční run); podshell drží zámek do konce
  if command -v flock >/dev/null 2>&1; then
    exec 8>"$CT_LOCK" 2>/dev/null || return 0  # bez /run (nezvyklý systém) bez zámku
    flock -n 8 || return 1
    return 0
  fi
  if mkdir "$CT_LOCK.d" 2>/dev/null; then
    trap "rm -rf '$CT_LOCK.d'" EXIT
    return 0
  fi
  # zámek starší než 2 h = po pádu, převzít
  if [[ -n "$(find "$CT_LOCK.d" -maxdepth 0 -mmin +120 2>/dev/null)" ]]; then
    rm -rf "$CT_LOCK.d"; mkdir "$CT_LOCK.d" 2>/dev/null && { trap "rm -rf '$CT_LOCK.d'" EXIT; return 0; }
  fi
  return 1
}

ct_runtime() {  # docker, jinak rootový podman (kontejnery jiných uživatelů ne)
  if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then echo docker; return; fi
  if command -v podman >/dev/null 2>&1; then echo podman; return; fi
  return 1
}

ct_id_ok() { [[ "$1" =~ ^sha256:[0-9a-f]{64}$ ]]; }

ct_slow() {  # spustí příkaz s nižší prioritou a časovým limitem (bez shellu: argumenty se předávají beze změny)
  local pre=()
  command -v timeout >/dev/null 2>&1 && pre+=(timeout "$CT_TIMEOUT")
  command -v nice >/dev/null 2>&1 && pre+=(nice -n 19)
  command -v ionice >/dev/null 2>&1 && pre+=(ionice -c 3)
  "${pre[@]}" "$@"
}

urlenc() {  # bajt po bajtu, jen nerezervované znaky beze změny
  local LC_ALL=C s="$1" out="" c i hex
  for ((i = 0; i < ${#s}; i++)); do
    c="${s:i:1}"
    case "$c" in
      [A-Za-z0-9._~-]) out+="$c" ;;
      *) printf -v hex '%%%02X' "'$c"; out+="$hex" ;;
    esac
  done
  printf '%s' "$out"
}

# Běžící kontejnery -> "<počet> <sha256:id>" na řádek (jen ověřená ID, nejvýš CT_MAX_IMAGES)
ct_images() {  # $1 = runtime
  "$1" ps --no-trunc --format '{{.ImageID}}' 2>/dev/null | awk '
    { id = $0; if (id ~ /^[0-9a-f]{64}$/) id = "sha256:" id; if (id ~ /^sha256:[0-9a-f]{64}$/) n[id]++ }
    END { for (i in n) print n[i], i }' | sort -k2 | head -n "$CT_MAX_IMAGES"
}

ct_tags() {  # $1 = runtime, $2 = ověřené ID -> tagy po řádcích (data, ne příkazy)
  "$1" image inspect --format '{{range .RepoTags}}{{println .}}{{end}}' "$2" 2>/dev/null | awk 'NF && NR <= 10'
}

ct_size() {  # $1 = runtime, $2 = ověřené ID -> velikost v bajtech (neznámá = 0)
  local n
  n="$("$1" image inspect --format '{{.Size}}' "$2" 2>/dev/null | head -n 1)"
  [[ "$n" =~ ^[0-9]{1,15}$ ]] && echo "$n" || echo 0
}

# OS balíčky z vrstev image bez spuštění kontejneru: `image save` -> manifest.json -> vrstvy v pořadí; z každé jen
# os-release a databáze dpkg / apk (nejvyšší vrstva vyhrává, whiteout .wh. maže). Výstup = CycloneDX JSON.
ct_layers_sbom() {  # $1 = runtime, $2 = ověřené ID, $3 = pracovní složka
  local rt="$1" id="$2" w="$3" layer f members list osid osver
  local files="etc/os-release usr/lib/os-release var/lib/dpkg/status lib/apk/db/installed"
  # jen GNU tar: busybox tar (Alpine hostitel) neumí spolehlivě --no-same-owner / --no-same-permissions ani vybírat
  # jednotlivé soubory ze vrstvy – raději žádná data než chybná (review #417)
  tar --version 2>/dev/null | head -n 1 | grep -q 'GNU tar' || return 6
  mkdir -p "$w/fs" "$w/x"
  ct_slow "$rt" image save "$id" >"$w/img.tar" 2>/dev/null || return 3
  tar -xf "$w/img.tar" -C "$w/x" manifest.json 2>/dev/null || return 3
  list="$(tr -d '\n' <"$w/x/manifest.json" | grep -o '"Layers"[[:space:]]*:[[:space:]]*\[[^]]*\]' | head -n 1 |
          sed 's/^"Layers"[^[]*//' | grep -o '"[^"]*"' | tr -d '"')" || return 3
  for layer in $list; do
    # cesta vrstvy z manifestu jen jako bezpečný relativní název uvnitř archivu
    [[ "$layer" =~ ^[A-Za-z0-9._/-]+$ ]] && [[ "$layer" != *..* ]] && [[ "$layer" != /* ]] || return 3
    tar -xf "$w/img.tar" -C "$w/x" -- "$layer" 2>/dev/null || return 3
    members="$(tar -tf "$w/x/$layer" 2>/dev/null | sed 's#^\./##')" || { rm -f "$w/x/$layer"; return 3; }
    for f in $files; do
      local d="${f%/*}" b="${f##*/}"
      if grep -qxF -e "$d/.wh.$b" -e "$d/.wh..wh..opq" <<<"$members"; then rm -f "$w/fs/$f"; fi
      if grep -qxF -e "$f" -e "./$f" <<<"$members"; then
        rm -f "$w/fs/$f"
        tar -xf "$w/x/$layer" -C "$w/fs" --no-same-owner --no-same-permissions -- "$f" 2>/dev/null ||
          tar -xf "$w/x/$layer" -C "$w/fs" --no-same-owner --no-same-permissions -- "./$f" 2>/dev/null || true
      fi
    done
    rm -f "$w/x/$layer"
  done
  rm -f "$w/img.tar"
  for f in $files; do  # jen obyčejné soubory uvnitř pracovní složky (symlink z image by vedl na soubor hostitele)
    if [ -L "$w/fs/$f" ] || { [ -e "$w/fs/$f" ] && [ ! -f "$w/fs/$f" ]; }; then rm -f "$w/fs/$f"; fi
  done
  f="$w/fs/etc/os-release"; [ -f "$f" ] || f="$w/fs/usr/lib/os-release"
  osid="$( [ -f "$f" ] && sed -n 's/^ID="\{0,1\}\([a-z0-9._-]*\)"\{0,1\}$/\1/p' "$f" | head -n 1)"
  osver="$( [ -f "$f" ] && sed -n 's/^VERSION_ID="\{0,1\}\([A-Za-z0-9._-]*\)"\{0,1\}$/\1/p' "$f" | head -n 1)"
  if [ -f "$w/fs/var/lib/dpkg/status" ]; then
    awk -v RS= -F '\n' '{ name = ver = src = ""; ok = 0
        for (i = 1; i <= NF; i++) {
          if ($i ~ /^Package: /) name = substr($i, 10)
          else if ($i ~ /^Version: /) ver = substr($i, 10)
          else if ($i ~ /^Source: /) { src = substr($i, 9); sub(/ .*/, "", src) }
          else if ($i ~ /^Status: .* installed$/) ok = 1 }
        if (ok && name != "" && ver != "") print name "\t" src "\t" ver }' "$w/fs/var/lib/dpkg/status" |
      ct_cyclonedx deb "${osid:-debian}" "$osver"
  elif [ -f "$w/fs/lib/apk/db/installed" ]; then
    awk -v RS= -F '\n' '{ name = ver = src = ""
        for (i = 1; i <= NF; i++) {
          if ($i ~ /^P:/) name = substr($i, 3); else if ($i ~ /^V:/) ver = substr($i, 3)
          else if ($i ~ /^o:/) src = substr($i, 3) }
        if (name != "" && ver != "") print name "\t" src "\t" ver }' "$w/fs/lib/apk/db/installed" |
      ct_cyclonedx apk "${osid:-alpine}" "$osver"
  else
    return 4  # RPM nebo bez správce balíčků: jen se syft / trivy
  fi
}

# TSV "jméno<TAB>zdroj<TAB>verze" -> CycloneDX 1.5 s purl pkg:<typ>/<distro>/<jméno>@<verze>?distro=<id>-<verze>
ct_cyclonedx() {  # $1 = deb / apk, $2 = ID distribuce, $3 = VERSION_ID
  awk -F '\t' -v t="$1" -v os="$2" -v ver="$3" -v agent="$AGENT_VERSION" '
    function esc(s) { gsub(/\\/, "\\\\", s); gsub(/"/, "\\\"", s); gsub(/[\001-\037\177]/, "", s); return s }
    function pe(s,   out, i, c) { out = ""; for (i = 1; i <= length(s); i++) { c = substr(s, i, 1)
        out = out (c ~ /[A-Za-z0-9._~+:-]/ ? c : sprintf("%%%02X", ord[c])) } return out }
    BEGIN { ORS = ""; for (i = 0; i < 256; i++) ord[sprintf("%c", i)] = i
      print "{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.5\",\"metadata\":{\"tools\":[{\"name\":\"nightwarden-agent\",\"version\":\"" agent "\"}]},\"components\":["; n = 0 }
    $1 != "" && $3 != "" { if (n++) print ","
      q = (ver != "" ? "?distro=" pe(os "-" ver) : "")
      if ($2 != "" && $2 != $1) q = q (q == "" ? "?" : "&") "upstream=" pe($2)
      print "{\"type\":\"library\",\"name\":\"" esc($1) "\",\"version\":\"" esc($3) "\",\"purl\":\"pkg:" t "/" pe(os) "/" pe($1) "@" pe($3) q "\"}" }
    END { print "]}\n" }'
}

ct_sbom() {  # $1 = runtime, $2 = ověřené ID, $3 = výstupní soubor; 0 = SBOM hotový
  local rt="$1" id="$2" out="$3" w rc=0
  w="$(mktemp -d "${out%/*}/sbom.XXXXXX")"  # v pracovní složce běhu (ne /tmp); syft / trivy tam mají i TMPDIR
  if command -v syft >/dev/null 2>&1 &&
     TMPDIR="$w" ct_slow syft -q "$rt:$id" -o cyclonedx-json >"$out" 2>/dev/null && [ -s "$out" ]; then
    rm -rf "$w"; return 0; fi
  if command -v trivy >/dev/null 2>&1 &&
     TMPDIR="$w" ct_slow trivy image --quiet --format cyclonedx --skip-db-update --offline-scan --image-src "$rt" "$id" \
       >"$out" 2>/dev/null && [ -s "$out" ]; then rm -rf "$w"; return 0; fi
  ct_layers_sbom "$rt" "$id" "$w" >"$out" || rc=$?
  rm -rf "$w"
  [ "$rc" = 0 ] && [ -s "$out" ] || return "${rc/#0/5}"
}

ct_post() {  # $1 = cesta API (+ query), $2 = soubor s tělem, $3 = soubor pro odpověď -> HTTP kód na stdout
  local url key ca hdr code
  url="$(conf URL)"; key="$(conf KEY)"; ca="$(conf CA)"
  hdr="$(mktemp)"
  printf 'Authorization: Bearer %s\nContent-Type: application/json\nUser-Agent: nightwarden-agent/%s\n' \
    "$key" "$AGENT_VERSION" >"$hdr"
  code="$(curl --silent --show-error --proto =https --proto-redir =https --connect-timeout 20 --max-time 300 \
          --header @"$hdr" ${ca:+--cacert "$ca"} --data-binary @"$2" --output "$3" --write-out '%{http_code}' \
          "${url%/}$1")" || code="000"
  rm -f "$hdr"
  echo "$code"
}

containers_send() {
  local rt w n id first q code sent=0 skipped=0 size need_kb deadline rc
  rt="$(ct_runtime)" || { echo "nightwarden-agent: containers: no docker / podman found"; return 0; }
  ct_lock || { echo "nightwarden-agent: containers: another run is in progress, skipped"; return 0; }
  deadline=$(( $(date +%s) + CT_BUDGET ))
  w="$(ct_workdir)" || { echo "nightwarden-agent: containers: cannot create a work directory" >&2; return 0; }
  trap "rm -rf '$w'" EXIT  # běží v podshellu (viz send): trap rodiče se nemění
  ct_images "$rt" >"$w/list"
  { printf '{"images":['
    first=1
    while read -r n id; do
      ct_id_ok "$id" || continue
      [ -n "$first" ] || printf ','
      first=""
      printf '{"digest":"%s","containers":%d,"tags":[' "$id" "$n"
      ct_tags "$rt" "$id" | { t1=1; while IFS= read -r tag; do [ -n "$t1" ] || printf ','; t1=""; jstr "$tag"; done; }
      printf ']}'
    done <"$w/list"
    printf ']}'; } >"$w/images.json"
  code="$(ct_post /api/v1/agent/containers "$w/images.json" "$w/resp")"
  case "$code" in 2??) ;; *) echo "nightwarden-agent: containers: server answered HTTP $code: $(cat "$w/resp")" >&2; return 0 ;; esac
  for id in $(grep -o 'sha256:[0-9a-f]\{64\}' "$w/resp" | sort -u | head -n "$CT_MAX_IMAGES"); do
    ct_id_ok "$id" || continue
    n="$(awk -v id="$id" '$2 == id { print $1 }' "$w/list")"
    [ -n "$n" ] || continue  # server smí žádat jen o image z našeho seznamu
    if [ "$(date +%s)" -ge "$deadline" ]; then  # zbytek v příštím běhu (server ho vrátí v need znovu)
      echo "nightwarden-agent: containers: time budget ($CT_BUDGET s) used, the rest next run"; break
    fi
    size="$(ct_size "$rt" "$id")"
    if [ "$size" -gt "$CT_MAX_BYTES" ]; then
      echo "nightwarden-agent: containers: ${id:7:12} larger than 2 GB, skipped"; skipped=$((skipped + 1)); continue
    fi
    need_kb=$(( (size > 0 ? size : 256 * 1024 * 1024) * 2 / 1024 ))  # 2× velikost image (neznámá = 512 MB)
    if [ "$(ct_free_kb "$w")" -lt "$need_kb" ]; then
      echo "nightwarden-agent: containers: ${id:7:12}: not enough free space in ${w%/*} (need $((need_kb / 1024)) MB), skipped"
      skipped=$((skipped + 1)); continue
    fi
    rc=0
    ct_sbom "$rt" "$id" "$w/sbom.json" || rc=$?
    if [ "$rc" != 0 ]; then
      case "$rc" in
        6) echo "nightwarden-agent: containers: ${id:7:12}: reading layers needs GNU tar (install tar, syft or trivy)" ;;
        *) echo "nightwarden-agent: containers: ${id:7:12}: no package data (RPM image: install syft or trivy)" ;;
      esac
      skipped=$((skipped + 1)); continue
    fi
    q="?digest=$id&containers=$n"
    while IFS= read -r tag; do q="$q&tag=$(urlenc "$tag")"; done < <(ct_tags "$rt" "$id")
    code="$(ct_post "/api/v1/agent/containers/sbom$q" "$w/sbom.json" "$w/resp")"
    case "$code" in
      2??) sent=$((sent + 1)) ;;
      *) echo "nightwarden-agent: containers: ${id:7:12}: server answered HTTP $code: $(cat "$w/resp")" >&2 ;;
    esac
  done
  echo "nightwarden-agent: containers: $(wc -l <"$w/list") images running, $sent SBOM sent, $skipped skipped"
  rm -rf "$w"
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
  if [ -z "$k" ] && [ "$2" = "-" ]; then
    # #348 (1.5.0): klíč / jednorázový token ze stdin (`printf '%s\n' TOKEN | sudo bash nightwarden-agent.sh install
    # … --key-file -`) – ne jako argument procesu; jen se staženým skriptem (při `curl | bash` je stdin skript)
    [ ! -t 0 ] || die "--key-file -: pipe the key to stdin (or run without --key-file to be asked)"
    IFS= read -r k || true
  elif [ -z "$k" ] && [ -n "$2" ]; then
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
  local url="" key="" keyfile="" ca="" offline="" dir="" prefix="" interval="$DEFAULT_INTERVAL" containers=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --offline) offline=1; shift ;;
      --containers) containers=1; shift ;;
      --interval) interval="${2:-}"; shift 2 ;;
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
  valid_interval "$interval" || die "--interval must be one of: $INTERVALS"
  if [ -n "$offline" ]; then install_offline "$dir" "$key" "$keyfile" "$prefix" "$interval"; return; fi
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
  printf 'URL=%s\nKEY=%s\nCA=%s\nINTERVAL=%s\nCONTAINERS=%s\n' "$url" "$key" "$ca" "$interval" "$containers" >"$CONF"
  chmod 0600 "$CONF"; chown root:root "$CONF"
  if [ -e "$ROOT/etc/$LEGACY.conf" ] || [ -e "$ROOT/usr/local/sbin/$LEGACY" ]; then
    remove_legacy
    echo "nightwarden-agent: replaced the previous project-cve-agent (same machine, same asset)"
  fi

  schedule "$interval"
}

# Offline instalace (1.2.0): bez sítě a bez curl; v konfiguraci jen složka a prefix klíče (tajemství klíče se na
# izolovaný stroj neukládá). $1 = složka, $2 = --key, $3 = --key-file, $4 = --key-prefix, $5 = --interval
install_offline() {
  local dir="$1" prefix="$4" interval="${5:-$DEFAULT_INTERVAL}"
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
  printf 'MODE=offline\nDIR=%s\nKEY_PREFIX=%s\nINTERVAL=%s\n' "$dir" "$prefix" "$interval" >"$CONF"
  chmod 0600 "$CONF"; chown root:root "$CONF"
  RW_DIR="$dir" schedule "$interval"  # ProtectSystem=strict: zápis jen do složky s hlášeními
}

valid_interval() {  # #290: jen hodnota z INTERVALS
  case " $INTERVALS " in *" ${1:-} "*) return 0 ;; *) return 1 ;; esac
}

current_interval() {  # INTERVAL z konfigurace (starší instalace bez něj = denně)
  local v=""
  [ -r "$CONF" ] && v="$(conf INTERVAL 2>/dev/null || true)"
  valid_interval "$v" && echo "$v" || echo "$DEFAULT_INTERVAL"
}

# Pravidelné spuštění `run` podle intervalu (systemd timer, jinak cron); první běh hned, když $2 != norun.
# Náhodné zpoždění úměrné intervalu, ať se stroje nehlásí všechny naráz.
schedule() {
  local interval="${1:-$DEFAULT_INTERVAL}" first="${2:-run}" cal delay label m h
  case "$interval" in
    4h)  cal="*-*-* 00/4:00:00"; delay="1h"; label="every 4 hours" ;;
    12h) cal="*-*-* 00/12:00:00"; delay="3h"; label="every 12 hours" ;;
    7d)  cal="weekly"; delay="1d"; label="weekly" ;;
    *)   cal="daily"; delay="6h"; label="daily" ;;
  esac
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
Description=NightWarden agent, $label

[Timer]
OnCalendar=$cal
RandomizedDelaySec=$delay
Persistent=true

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable --now $UNIT.timer >/dev/null
    [ "$first" = run ] || { systemctl restart $UNIT.timer >/dev/null; echo "nightwarden-agent: reports $label (systemd timer)"; return; }
    echo "nightwarden-agent: installed (systemd timer, $label with random delay). First report now:"
    systemctl start $UNIT.service && journalctl -u $UNIT.service -n 3 --no-pager -o cat 2>/dev/null || true
  else  # bez systemd: cron s náhodnou minutou (a hodinou v rámci intervalu)
    m=$((RANDOM % 60))
    case "$interval" in
      4h)  h="$((RANDOM % 4))-23/4"; echo "$m $h * * * root $BIN run >/dev/null 2>&1" ;;
      12h) h="$((RANDOM % 12))-23/12"; echo "$m $h * * * root $BIN run >/dev/null 2>&1" ;;
      7d)  echo "$m $((RANDOM % 24)) * * $((RANDOM % 7)) root $BIN run >/dev/null 2>&1" ;;
      *)   echo "$m $((RANDOM % 24)) * * * root $BIN run >/dev/null 2>&1" ;;
    esac >"$ROOT/etc/cron.d/$UNIT"
    chmod 0644 "$ROOT/etc/cron.d/$UNIT"
    [ "$first" = run ] || { echo "nightwarden-agent: reports $label (cron)"; return; }
    echo "nightwarden-agent: installed (cron, $label). First report now:"
    "$BIN" run
  fi
}

# configure --interval X (#290): změní četnost u nainstalovaného agenta; ostatní konfigurace zůstane
set_conf() {  # $1 = klíč, $2 = hodnota: atomicky, 0600 root (ostatní řádky zůstávají)
  local tmp
  tmp="$(mktemp "$CONF.XXXXXX")"
  grep -v "^$1=" "$CONF" >"$tmp" || true
  printf '%s=%s\n' "$1" "$2" >>"$tmp"
  chmod 0600 "$tmp"; chown root:root "$tmp" 2>/dev/null || true
  mv -f "$tmp" "$CONF"
}

configure_agent() {
  local interval="" containers=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --interval) interval="${2:-}"; shift 2 ;;
      --containers) containers=1; shift ;;
      --no-containers) containers=0; shift ;;
      *) die "unknown option $1" ;;
    esac
  done
  [ "$(id -u)" = 0 ] || die "configure must run as root (sudo)"
  [ -r "$CONF" ] || die "missing $CONF (run: install first)"
  [ -n "$interval" ] || [ -n "$containers" ] || die "nothing to change: use --interval or --containers / --no-containers"
  if [ -n "$containers" ]; then
    set_conf CONTAINERS "$containers"
    if [ "$containers" = 1 ]; then echo "nightwarden-agent: containers on (Docker / Podman images in the next report)"
    else echo "nightwarden-agent: containers off"; fi
    [ -n "$interval" ] || return 0
  fi
  valid_interval "$interval" || die "--interval must be one of: $INTERVALS"
  set_conf INTERVAL "$interval"
  if [ "$(conf MODE 2>/dev/null || true)" = offline ]; then
    RW_DIR="$(conf DIR)" schedule "$interval" norun
  else
    schedule "$interval" norun
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
      # review #212: bez hodnoty / s prázdnou hodnotou chyba (dřív tiše „bez kontroly“, chybějící argument = shift 2)
      --sha256) [ $# -ge 2 ] && [ -n "$2" ] || die "--sha256 needs 64 hexadecimal characters"
                sha="$(printf '%s' "$2" | tr 'A-F' 'a-f')"; shift 2 ;;
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
  configure) shift; configure_agent "$@" ;;
  update) shift; update_agent "$@" ;;
  uninstall) uninstall_agent ;;
  version) echo "$AGENT_VERSION" ;;
  *) sed -n '2,/^# Závislosti/p' "$0" 2>/dev/null | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
