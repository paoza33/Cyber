#!/bin/bash

# https://training.cyberwave.network/challenges : So Many Zips

while true
do
   if file next.mzip | grep -q "Zip archive"; then
      unzip -o next.mzip
   else
      break
   fi
done
