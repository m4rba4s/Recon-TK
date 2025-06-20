#!/usr/bin/env bash
###############################################################################
#  setup_ctf_stack.sh  v2  –  full env + immediate recon
###############################################################################
set -euo pipefail
IFS=$'\n\t'

############################ CLI + cosmetics ##################################
[[ $# -lt 1 ]] && { echo "Usage: $0 <target-ip|domain>"; exit 1; }
TARGET="$1"

ok()   { echo -e "\e[1;32m[+]\e[0m $*"; }
die()  { echo -e "\e[1;31m[-]\e[0m $*"; exit 1; }

####################### package-manager autodetect ############################
if command -v apt-get &>/dev/null; then PM=apt
elif command -v dnf   &>/dev/null; then PM=dnf
elif command -v pacman&>/dev/null; then PM=pacman
else die "No supported package manager found"; fi
ok "Package manager: $PM"

install() {
  case $PM in
    apt)    sudo apt-get -y install "$@"   ;;
    dnf)    sudo dnf     -y install "$@"   ;;
    pacman) sudo pacman  -Sy --noconfirm "$@" ;;
  esac
}

######################## base toolchain #######################################
BASE_PKGS=(nmap masscan gobuster ffuf git make gcc wget curl unzip jq whois \
           smbclient nbtscan hydra python3-pip go perl-core openssl-devel \
           pkgconf-pkg-config)
install "${BASE_PKGS[@]}"
export PATH="$PATH:$(go env GOPATH)/bin"

######################## RustScan via cargo ###################################
if ! command -v rustscan &>/dev/null; then
  ok "Installing RustScan (cargo)…"
  cargo install rustscan --locked
  sudo ln -sf "$HOME/.cargo/bin/rustscan" /usr/local/bin/rustscan
fi
rustscan -V | head -1

######################## Feroxbuster binary ###################################
if ! command -v feroxbuster &>/dev/null; then
  FB_VER="2.11.0"
  TMP=$(mktemp -d)
  ok "Fetching Feroxbuster v$FB_VER…"
  sudo curl -L \
       -o "$TMP/fx.tar.gz" \
       "https://github.com/epi052/feroxbuster/releases/download/v${FB_VER}/x86_64-linux-feroxbuster.tar.gz"
  sudo tar -xzf "$TMP/fx.tar.gz" -C "$TMP" feroxbuster
  sudo mv "$TMP/feroxbuster" /usr/local/bin/
  sudo chmod +x /usr/local/bin/feroxbuster
  rm -rf "$TMP"
fi
feroxbuster --version

######################## nuclei + httpx #######################################
for gocmd in nuclei httpx; do
  command -v "$gocmd" >/dev/null && continue
  ok "Installing $gocmd…"
  go install "github.com/projectdiscovery/${gocmd}/v3/cmd/${gocmd}@latest"
  sudo ln -sf "$(go env GOPATH)/bin/$gocmd" /usr/local/bin/$gocmd
done

######################## wordlists bootstrap ##################################
WL_DIR="/opt/wordlists"
if [[ ! -d $WL_DIR ]]; then
  ok "Cloning SecLists (≈3 GB)…"
  sudo git clone --depth 1 https://github.com/danielmiessler/SecLists.git "$WL_DIR/SecLists"
  sudo tar -xzvf "$WL_DIR/SecLists/Passwords/Leaked-Databases/rockyou.txt.tar.gz" \
       -C "$WL_DIR" rockyou.txt
  sudo ln -sfn "$WL_DIR" /usr/share/wordlists
fi
ok "Wordlists ready in $WL_DIR"

######################## glob_recon.sh (minimal) ##############################
GLOB="$HOME/explo/glob_recon.sh"
mkdir -p "$(dirname "$GLOB")"
cat > "$GLOB" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail; IFS=$'\n\t'
[[ $# -lt 1 ]] && { echo "Usage: $0 <target> [mode]"; exit 1; }
T="$1"; MODE="${2:-full}"
R="$HOME/globruns/${T}-$(date +%s)"; mkdir -p "$R"; L="$R/job.log"
log(){ echo -e "\e[1;36m[→]\e[0m $*"; echo "$*" >>"$L"; }
WL="/usr/share/wordlists"

mass(){ log masscan; sudo masscan -p0-65535 --rate 20000 "$T" -oL "$R/m.lst" 2>>"$L"
         awk '/open/{print $4}' "$R/m.lst"|sort -n>"$R/ports.txt"; }
nmapx(){ log nmap; nmap -sVC -p"$(paste -sd, "$R/ports.txt")" -oA "$R/nmap" "$T" >>"$L" 2>&1; }
web(){ log web_enum; for p in 80 8080 8000 443; do
       grep -qx "$p" "$R/ports.txt"||continue
       P=http; [[ $p==443 ]]&&P=https
       URL="$P://$T:$p"
       gobuster dir -q -u "$URL" -w "$WL/Discovery/Web-Content/big.txt" \
         -o "$R/gob_$p.txt" >>"$L" 2>&1 &
       feroxbuster -q -u "$URL" -o "$R/fx_$p.txt" >>"$L" 2>&1 &
       nuclei -u "$URL" -o "$R/nuc_$p.txt" >>"$L" 2>&1 &
       done; wait; }
[[ $MODE == install ]] && { log "deps only"; exit 0; }
log "START"; mass; nmapx; web; log "END (output → $R)"
EOF
chmod +x "$GLOB"

######################## run recon immediately ################################
ok "Launching recon against $TARGET"
sudo "$GLOB" "$TARGET"
