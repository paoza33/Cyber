#!/bin/bash

#verification
if [ -z "$1" ]; then
   echo "Usage: $0 <gif_file>"
   exit 1
fi

GIF="$1"

# creer dossier temp pour les frames du gif
TMP_DIR=$(mktemp -d)
echo "[+] Extraction des frames dans $TMP_DIR"

# Extraction de tout les frames (%03d -> entier decimal sur 3 chiffres)
magick "$GIF" "$TMP_DIR/frame_%03d.png"

# Decode chaque frame et concatene les char
FLAG=$(zbarimg "$TMP_DIR"/frame_*.png | awk -F':' '{printf "%s", $2}')

# print flag
echo "[+] Flag found : $FLAG"

# clean
echo "[+] suppression de $TMP_DIR"
rm -r "$TMP_DIR"
