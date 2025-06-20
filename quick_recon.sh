#!/usr/bin/env bash
set -euo pipefail; IFS=$'\n\t'

[[ $# -lt 1 ]] && { echo "Usage: $0 <target-ip|domain>"; exit 1; }
TGT="$1"
RUN="recon-${TGT}-$(date +%s)"
mkdir -p "$RUN"
LOG="$RUN/job.log"

note(){ echo -e "\e[1;32m[+]\e[0m $*"; echo "[*] $*" >>"$LOG"; }

########## 1. быстрый full-port sweep (root) ############################
note "masscan → $RUN/ports.raw"
sudo masscan -p0-65535 --rate 20000 "$TGT" -oL "$RUN/ports.raw" | tee -a "$LOG"
awk '/open/{print $4}' "$RUN/ports.raw" | sort -n > "$RUN/ports.txt"
PORTS=$(paste -sd, "$RUN/ports.txt")

########## 2. сервисные баннеры #########################################
note "nmap → $RUN/nmap.gnmap"
nmap -sVC -p"$PORTS" -oA "$RUN/nmap" "$TGT" | tee -a "$LOG"

########## 3. web-фаза (если есть http/https) ###########################
for p in 80 443 8080 8000; do
  grep -qx "$p" "$RUN/ports.txt" || continue
  PROT=http; [[ $p == 443 ]] && PROT=https
  URL="$PROT://$TGT:$p"

  note "gobuster @$p"
  gobuster dir -q -u "$URL" -w /opt/wordlists/SecLists/Discovery/Web-Content/big.txt \
    -o "$RUN/gob_$p.txt" >>"$LOG" 2>&1 &

  note "feroxbuster @$p"
  feroxbuster -q -u "$URL" -o "$RUN/fx_$p.txt" >>"$LOG" 2>&1 &

  note "nuclei @$p"
  nuclei -u "$URL" -o "$RUN/nuc_$p.txt" >>"$LOG" 2>&1 &
done
wait
note "DONE!  everything in → $RUN"
