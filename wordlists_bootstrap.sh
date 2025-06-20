#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

TARGET_DIR="/opt/wordlists"
mkdir -p "$TARGET_DIR"

say(){ echo -e "\e[1;32m[wl]\e[0m $*"; }

# ── ищем уже существующие коллекции ────────────────────────────
for d in "$TARGET_DIR" "$HOME/wordlists" /data/wordlists /mnt/*/wordlists; do
  [[ -e "$d/rockyou.txt" ]] && { say "Found wordlists in $d"; ln -sfn "$d" "$TARGET_DIR"; exit 0; }
done

# ── если не нашли – тащим SecLists (≈3 GB) ──────────────────────
say "Cloning SecLists… (first time only, grab a coffee)"
sudo git clone --depth 1 https://github.com/danielmiessler/SecLists.git "$TARGET_DIR/SecLists"

# короткие алиасы для популярных файлов
ln -s "$TARGET_DIR/SecLists/Passwords/Leaked-Databases/rockyou.txt.tar.gz" \
      "$TARGET_DIR/rockyou.txt.tar.gz"
ln -s "$TARGET_DIR/SecLists/Discovery/DNS/namelist.txt" \
      "$TARGET_DIR/big.txt"

# распакуем rockyou (часто нужна незажатая)
if [[ ! -f $TARGET_DIR/rockyou.txt ]]; then
  sudo tar -xzvf "$TARGET_DIR/rockyou.txt.tar.gz" -C "$TARGET_DIR"
fi

# симлинк системный
sudo ln -sfn "$TARGET_DIR" /usr/share/wordlists
say "Wordlists ready in $TARGET_DIR (linked to /usr/share/wordlists)"
