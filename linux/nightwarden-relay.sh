#!/usr/bin/env bash
# NightWarden relay pro offline agenty: na stroji s přístupem ven projde sdílenou složku s hlášeními
# (nightwarden-agent run --output / install --offline), nahraje nové soubory přes POST /api/v1/agent/offline
# a úspěšně nahrané (i ty, které server vyhodnotil jako starší než poslední hlášení) přesune do <složka>/done/.
# Soubory, které server odmítl, zůstanou na místě a relay to vypíše (příště to zkusí znovu).
#
#   Použití:   nightwarden-relay.sh --url https://SERVER --dir /srv/nw-reports --key-file /root/nw-api-key
#              klíč API se scope "write" (Settings → API keys, ne agentní klíč): --key-file (0600, ne symlink)
#              nebo proměnná NW_API_KEY; volitelně --ca /cesta/k/ca.pem
#   Plánování: cron, např. /etc/cron.d/nightwarden-relay:
#              15 * * * * root /usr/local/sbin/nightwarden-relay.sh --url https://SERVER --dir /srv/nw-reports --key-file /root/nw-api-key
#
# Závislosti: bash, curl. Klíč jen v souboru s hlavičkou (ne na příkazové řádce: byl by vidět v `ps`).
set -euo pipefail
umask 077

die() { echo "nightwarden-relay: $*" >&2; exit 1; }

url="" dir="" keyfile="" ca=""
while [ $# -gt 0 ]; do
  case "$1" in
    --url) url="${2:-}"; shift 2 ;;
    --dir) dir="${2:-}"; shift 2 ;;
    --key-file) keyfile="${2:-}"; shift 2 ;;
    --ca) ca="${2:-}"; shift 2 ;;
    -h|--help) sed -n '2,/^# Závislosti/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown option $1" ;;
  esac
done
case "$url" in https://*) ;; *) die "--url must start with https://";; esac
[ -d "$dir" ] || die "--dir $dir is not a directory"
[ -z "$ca" ] || [ -r "$ca" ] || die "--ca file $ca not readable"
command -v curl >/dev/null || die "curl is required"

key=""
if [ -n "$keyfile" ]; then
  [ ! -L "$keyfile" ] || die "--key-file $keyfile is a symlink; use the file itself"
  [ -f "$keyfile" ] && [ -r "$keyfile" ] || die "--key-file $keyfile not readable"
  mode="$(stat -c '%a' "$keyfile" 2>/dev/null)" || die "--key-file $keyfile: cannot read its permissions"
  case "$mode" in [0-7]00|[0-7][0-7]00) ;; *) die "--key-file $keyfile is readable by others (mode $mode)";; esac
  IFS= read -r key <"$keyfile" || true
elif [ -n "${NW_API_KEY:-}" ]; then
  key="$NW_API_KEY"
fi
unset NW_API_KEY
key="${key//[[:space:]]/}"
[ -n "$key" ] || die "no API key: use --key-file FILE or NW_API_KEY"
case "$key" in pcve_*_*) ;; *) die "the API key must look like pcve_…_…";; esac
case "$key" in *[!A-Za-z0-9_-]*) die "the API key contains unexpected characters";; esac

hdr="$(mktemp)"; resp="$(mktemp)"
trap 'rm -f "$hdr" "$resp"' EXIT
printf 'Authorization: Bearer %s\nUser-Agent: nightwarden-relay/1.0\n' "$key" >"$hdr"
key=""
# #129: done/ – existující odkaz nebo cizí / zapisovatelná složka by přesunula soubory přijaté serverem jinam
if [ -e "$dir/done" ] || [ -L "$dir/done" ]; then
  [ -d "$dir/done" ] && [ ! -L "$dir/done" ] || die "$dir/done is not a directory (or is a symlink)"
  st="$(stat -c '%u %a' -- "$dir/done")" || die "$dir/done: cannot read its owner"
  [ "${st%% *}" = "$EUID" ] || die "$dir/done is owned by another account"
  case "${st#* }" in *[2367]?|*[2367]) die "$dir/done is writable by other users";; esac
else
  mkdir -m 0700 -- "$dir/done"
fi
realdir="$(cd -- "$dir" && pwd -P)"

sent=0 kept=0
shopt -s nullglob
for f in "$dir"/*.json "$dir"/*.json.gz "$dir"/*.zip; do
  [ -f "$f" ] && [ ! -L "$f" ] || continue
  name="$(basename -- "$f")"
  case "$name" in .*) continue ;; *[!A-Za-z0-9._-]*) echo "nightwarden-relay: skipping $name (unexpected characters in the name)" >&2; kept=$((kept + 1)); continue ;; esac
  # #129: soubor se otevře jednou a ověří, že deskriptor je opravdu tento soubor (ne odkaz podstrčený po kontrole);
  # curl čte z deskriptoru, ne znovu podle cesty
  exec 4<"$f" || { kept=$((kept + 1)); continue; }
  if [ "$(readlink "/proc/$$/fd/4" 2>/dev/null)" != "$realdir/$name" ]; then
    exec 4<&-
    echo "nightwarden-relay: skipping $name (replaced while reading)" >&2; kept=$((kept + 1)); continue
  fi
  rc=0
  code="$(curl --silent --show-error --proto =https --proto-redir =https --connect-timeout 20 --max-time 300 \
          --header @"$hdr" ${ca:+--cacert "$ca"} --form "file=@/dev/fd/4;filename=$name" --output "$resp" \
          --write-out '%{http_code}' "${url%/}/api/v1/agent/offline")" || rc=$?
  exec 4<&-
  [ "$rc" = 0 ] || die "cannot reach ${url} (curl error $rc); nothing moved"
  case "$code" in
    200)
      if grep -Eq '"error": *0[,}]' "$resp"; then
        mv -f -- "$f" "$dir/done/$name"
        sent=$((sent + 1))
        echo "nightwarden-relay: $name uploaded"
      else
        kept=$((kept + 1))
        echo "nightwarden-relay: $name rejected by the server: $(head -c 600 "$resp")" >&2
      fi ;;
    401|402|403) die "server answered HTTP $code: $(head -c 300 "$resp")" ;;
    429) echo "nightwarden-relay: server asks to wait; the rest next time" >&2; break ;;
    *) kept=$((kept + 1)); echo "nightwarden-relay: $name: server answered HTTP $code: $(head -c 300 "$resp")" >&2 ;;
  esac
done
echo "nightwarden-relay: $sent uploaded, $kept left in $dir"
[ "$kept" = 0 ]
