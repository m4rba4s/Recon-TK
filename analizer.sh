#!/usr/bin/env bash
#   _____ _           _ ____                  _
#  / ____| |         | |  _ \                | |
# | |  __| | ___  ___| | |_) | ___  ___ _   _| |_
# | | |_ | |/ _ \/ __| |  _ < / _ \/ __| | | | __|
# | |__| | |  __/ (__| | |_) |  __/ (__| |_| | |_
#  \_____|_|\___|\___|_|____/ \___|\___|\__,_|\__|
#
#  GL⚡B-RECON  •  multi-tool CTF / red-team spider
#  Author: 0xSilver
#
set -euo pipefail
IFS=$'\n\t'
VERSION="1.0"

##### ---- cli / globals --------------------------------------------------
usage() { echo "Usage: $0 <target-ip/domain> [mode]"; exit 1; }
[[ $# -lt 1 ]] && usage

TARGET="$1"; MODE="${2:-full}"
RUNDIR="${HOME}/globruns/${TARGET}-$(date +%s)"
mkdir -p "$RUNDIR"
LOG="$RUNDIR/job.log"

color() { echo -e "\e[1;32m[+]\e[0m $*"; }
err()   { echo -e "\e[1;31m[-]\e[0m $*" >&2; }
log()   { color "$*"; echo "[*] $*" >>"$LOG"; }

##### ---- pkg-manager auto-discover -------------------------------------
if command -v apt-get &>/dev/null;     then PKG=apt
elif command -v dnf &>/dev/null;       then PKG=dnf
elif command -v pacman &>/dev/null;    then PKG=pacman
else err "No supported package manager found."; exit 1; fi
log "Package manager: $PKG"

install_pkgs() {
  local list=("$@")
  case $PKG in
    apt)    sudo apt-get -qq update && sudo apt-get -y install "${list[@]}" ;;
    dnf)    sudo dnf -y install "${list[@]}" ;;
    pacman) sudo pacman -Sy --noconfirm "${list[@]}" ;;
  esac
}

##### ---- dependency installer ------------------------------------------
BASE_PKGS=(nmap masscan rustscan gobuster ffuf feroxbuster nikto sqlmap \
           git make gcc wget curl unzip jq whois smbclient nbtscan hydra)
GO_PKGS=(github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
         github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
         github.com/projectdiscovery/httpx/cmd/httpx@latest \
         github.com/OJ/gobuster/v3@latest)

need_install=()
for bin in "${BASE_PKGS[@]}"; do
  [[ "$bin" == "sqlmap" ]] && { command -v sqlmap >/dev/null || need_install+=(sqlmap); continue; }
  command -v "$bin" >/dev/null || need_install+=("$bin")
done
[[ ${#need_install[@]} -gt 0 ]] && install_pkgs "${need_install[@]}"

if ! command -v go &>/dev/null; then
  log "Installing Go (tool-chains)…"
  install_pkgs golang
fi

for tool in "${GO_PKGS[@]}"; do
  name=$(basename "${tool%%@*}")
  command -v "$name" >/dev/null || { log "go-install $name"; go install "$tool"; }
done
export PATH="$PATH:$(go env GOPATH)/bin"

##### ---- modules --------------------------------------------------------
MODULES=()

mass_portscan() {           # ultra-fast 0-65535 → open-ports.txt
  log "▶ masscan full-port sweep"
  sudo masscan -p0-65535 --rate 10000 "$TARGET" -oL "$RUNDIR/masscan.lst" 2>>"$LOG"
  awk '/open/{print $4}' "$RUNDIR/masscan.lst" | sort -n > "$RUNDIR/open-ports.txt"
}; MODULES+=(mass_portscan)

nmap_deep() {               # version-detect + NSE
  log "▶ nmap service-enum"
  nmap -sV -sC -p"$(paste -sd, "$RUNDIR/open-ports.txt")" -oA "$RUNDIR/nmap" "$TARGET" >>"$LOG" 2>&1
}; MODULES+=(nmap_deep)

web_enum() {                # gobuster + ferox + nuclei
  log "▶ web enum (dir brute + nuclei)"
  for p in 80 8080 8000 443; do
    grep -qx "$p" "$RUNDIR/open-ports.txt" || continue
    (
      PROT="http"; [[ $p == 443 ]] && PROT="https"
      URL="$PROT://$TARGET:$p"
      gobuster dir -u "$URL" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
        -t 50 -o "$RUNDIR/gobuster_$p.txt" >>"$LOG" 2>&1
      feroxbuster -u "$URL" -x php,txt,bak,zip -t 200 -q -o "$RUNDIR/ferox_$p.txt" >>"$LOG" 2>&1
      nuclei -u "$URL" -o "$RUNDIR/nuclei_$p.txt" >>"$LOG" 2>&1
    ) &
  done
  wait
}; MODULES+=(web_enum)

smb_enum() {                # enum4linux-ng + smbmap
  grep -qx "445" "$RUNDIR/open-ports.txt" || return
  log "▶ SMB enum"
  enum4linux-ng -A "$TARGET" | tee "$RUNDIR/enum4linux.txt" >>"$LOG" 2>&1
  smbmap -H "$TARGET" -P 445 -u guest | tee "$RUNDIR/smbmap.txt" >>"$LOG" 2>&1
}; MODULES+=(smb_enum)

db_checks() {               # MySQL / Redis quick info
  grep -qx "3306" "$RUNDIR/open-ports.txt" && {
    log "▶ MySQL enum (banner)"
    timeout 5 mysql -h "$TARGET" -e 'status;' 2>&1 | tee "$RUNDIR/mysql_banner.txt" >>"$LOG"
  }
  grep -qx "6379" "$RUNDIR/open-ports.txt" && {
    log "▶ Redis enum (INFO)"
    (echo INFO; sleep 1) | nc "$TARGET" 6379 | tee "$RUNDIR/redis_info.txt" >>"$LOG"
  }
}; MODULES+=(db_checks)

quick_web_fuzz() {          # httpx status survey
  log "▶ httpx quick survey"
  httpx -silent -status-code -web-server -title -no-color -ports "$(paste -sd, "$RUNDIR/open-ports.txt")" \
    -o "$RUNDIR/httpx.txt" -host "$TARGET"
}; MODULES+=(quick_web_fuzz)

##### ---- runner ---------------------------------------------------------
run_all() {
  log "### RECON START @ $(date)  ###"
  for mod in "${MODULES[@]}"; do
    time "$mod"
  done
  log "### DONE @ $(date)  ###"
}

case "$MODE" in
  full) run_all ;;
  install) log "Only deps installed." ;;
  *) err "Unknown mode $MODE" ;;
esac

log "Artifacts saved in $RUNDIR"
