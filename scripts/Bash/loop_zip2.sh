#!/bin/bash

# https://training.cyberwave.network/challenges : So Many Zips 2

WORDLIST="/usr/share/wordlists/rockyou.txt"
current_zip="$1"


# si aucun argument
if [ -z "$current_zip" ]; then
   echo "Usage: $0 <zipfile>"
   exit 1
fi

while true; do
   echo "[+] Processing $current_zip"

   # extraction hash
   zip2john "$current_zip" > hash.txt 2>/dev/null

   # crack mdp zip
   john hash.txt --wordlist="$WORDLIST" >/dev/null 2>&1

   # recupereation mdp
   password=$(john --show hash.txt | awk -F':' '/:/{print $2}')

   if [ -z "$password" ]; then
      echo "[-] Password not found."
      exit 1
   fi

   echo "[+] Password found: $password"

   # extraction du nom du fichier interne
   inner_file=$(unzip -Z1 "$current_zip")

   # Decompression
   unzip -P "$password" "$current_zip" >/dev/null

   # nettoyage / suppression du zip decompresser
   rm "$current_zip"
   # nettoyage cache de john
   rm john.pot 2>/dev/null
   
   # verifier si le fichier extrait est un zip
   if file "$inner_file" | grep -q "Zip archive data"; then
      current_zip="$inner_file"
   else
      echo "[+] Final file reached: $inner_file"
      break
   fi
done
