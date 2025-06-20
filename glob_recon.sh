#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
VERSION="1.3"

# ────────────────────────  CLI  ────────────────────────
[[ $# -lt 1 ]] && { echo "Usage: $0 <target-ip/domain> [mode]"; exit 1; }
TARGET="$1"; MODE="${2:-full}"
RUNDIR="${HOME}/globruns/${TARGET}-$(date +%s)"
mkdir -p "$RUNDIR"; LOG="$RUNDIR/job.log"
say(){ echo -e "\e[1;32m[+]\e[0m $*"; echo "[*] $*" >>"$LOG"; }
die(){ echo -e "\e[1;31m[-]\e[0m $*"; exit 1; }

# ───────────────────  PKG manager detect  ──────────────
if   command -v apt-get &>/dev/null;  then PKG=apt
elif command -v dnf &>/dev/null;      then PKG=dnf
elif command -v pacman &>/dev/null;   then PKG=pacman
else die "No supported package manager"; fi
say "Package manager: $PKG"

safe_install(){ for p in "$@"; do
  case $PKG in
    apt)    sudo apt-get -y install "$p"   >/dev/null 2>&1 || say "skip $p" ;;
    dnf)    sudo dnf -y install "$p"       >/dev/null 2>&1 || say "skip $p" ;;
    pacman) sudo pacman -Sy --noconfirm "$p" >/dev/null 2>&1 || say "skip $p";;
  esac; done; }

# ────────────────  базовые тулзы + dev-deps  ───────────
BASE_PKGS=(nmap masscan gobuster ffuf git make gcc wget curl unzip jq whois \
           smbclient nbtscan hydra python3-pip go perl-core openssl-devel \
           pkgconf-pkg-config)
safe_install "${BASE_PKGS[@]}"

export PATH="$PATH:$(go env GOPATH)/bin"

# ────────────────  util: link_tool <name> ──────────────
link_tool(){ command -v "$1" &>/dev/null && sudo ln -sf "$(command -v "$1")" /usr/local/bin/"$1"; }

# ──────────────  install RustScan (bin + link) ─────────
install_rustscan(){
  RS_VER="2.4.1"
  URL="https://github.com/bee-san/RustScan/releases/download/v${RS_VER}/rustscan_${RS_VER}_amd64.deb"
  TMP=$(mktemp -d); pushd "$TMP" >/dev/null
  wget -q "$URL" -O rustscan.deb || die "RustScan download failed"
  sudo dnf -y install ./rustscan.deb || sudo apt-get -y install ./rustscan.deb || true
  popd; rm -rf "$TMP"; link_tool rustscan; say "RustScan ${RS_VER} installed (bin)"
}

# ──────────────  install Feroxbuster (bin + link) ──────
install_feroxbuster(){
  FB_VER="2.11.0"
  URL="https://github.com/epi052/feroxbuster/releases/download/v${FB_VER}/x86_64-linux-feroxbuster.tar.gz"
  TMP=$(mktemp -d); pushd "$TMP" >/dev/null
  wget -q "$URL" -O fb.tar.gz || die "Ferox download failed"
  tar xf fb.tar.gz; sudo mv feroxbuster /usr/local/bin/; popd; rm -rf "$TMP"
  sudo chmod +x /usr/local/bin/feroxbuster; say "Feroxbuster ${FB_VER} installed (bin)"
}

command -v rustscan >/dev/null || install_rustscan
command -v feroxbuster >/dev/null || install_feroxbuster

# ───────────────  python-pip sqlmap + nikto  ───────────
command -v sqlmap  >/dev/null || { pip3 install --break-system-packages --upgrade --user sqlmap; link_tool sqlmap; }
command -v nikto   >/dev/null || { sudo git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto; sudo ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto; }

# ──────────────────  Recon MODULES  ────────────────────
MODULES=()

mass_portscan(){ say "▶ masscan"; sudo masscan -p0-65535 --rate 15000 "$TARGET" \
                         -oL "$RUNDIR/masscan.lst" 2>>"$LOG"; awk '/open/{print $4}' \
                         "$RUNDIR/masscan.lst"|sort -n>"$RUNDIR/open-ports.txt"; }
MODULES+=(mass_portscan)

nmap_deep(){ say "▶ nmap"; nmap -sV -sC -p"$(paste -sd, "$RUNDIR/open-ports.txt")" \
                       -oA "$RUNDIR/nmap" "$TARGET" >>"$LOG" 2>&1; }
MODULES+=(nmap_deep)

web_enum(){ say "▶ web-enum"; for p in 80 8080 8000 443; do
  grep -qx "$p" "$RUNDIR/open-ports.txt" || continue
  PROT=http; [[ $p == 443 ]] && PROT=https
  URL="$PROT://$TARGET:$p"
  gobuster dir -u "$URL" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
        -t 40 -o "$RUNDIR/gobuster_$p.txt" >>"$LOG" 2>&1 &
  feroxbuster -u "$URL" -x php,txt,bak,zip -q -o "$RUNDIR/ferox_$p.txt" >>"$LOG" 2>&1 &
  nuclei -u "$URL" -o "$RUNDIR/nuclei_$p.txt" >>"$LOG" 2>&1 &
done; wait; }
MODULES+=(web_enum)

smb_enum(){ grep -qx 445 "$RUNDIR/open-ports.txt" || return
  say "▶ SMB"; enum4linux-ng -A "$TARGET" | tee "$RUNDIR/enum4linux.txt" >>"$LOG" 2>&1
  smbmap -H "$TARGET" -P 445 -u guest | tee "$RUNDIR/smbmap.txt" >>"$LOG" 2>&1; }
MODULES+=(smb_enum)

db_checks(){ grep -qx 3306 "$RUNDIR/open-ports.txt" && {
    say "▶ MySQL banner"; timeout 5 mysql -h "$TARGET" -e 'status;' 2>&1 \
      | tee "$RUNDIR/mysql_banner.txt" >>"$LOG"; }
  grep -qx 6379 "$RUNDIR/open-ports.txt" && {
    say "▶ Redis INFO"; (echo INFO; sleep 1)|nc "$TARGET" 6379 \
      | tee "$RUNDIR/redis_info.txt" >>"$LOG"; }; }
MODULES+=(db_checks)

quick_web_fuzz(){ say "▶ httpx"; httpx -silent -status-code -title \
      -ports "$(paste -sd, "$RUNDIR/open-ports.txt")" -host "$TARGET" \
      -o "$RUNDIR/httpx.txt"; }
MODULES+=(quick_web_fuzz)

# ───────────────────  Runner  ──────────────────────────
run_all(){ say "### RECON START $(date) ###"; for m in "${MODULES[@]}"; do "$m"; done
           say "### DONE $(date) ###"; }

case $MODE in
  full)     run_all ;;
  install)  say "Dependencies installed only." ;;
  *)        die "Unknown mode '$MODE'" ;;
esac

say "Artifacts → $RUNDIR"
