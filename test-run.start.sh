#!/bin/bash

#GHIDRA_INSTALL_DIR=/snap/ghidra/current/ghidra_12.0_PUBLIC/ zorya /home/kh3m/Research/PhD/volos-repo/zorya-volos/tests/go-reversing/twothreads --compiler gc --thread-scheduling all-threads --lang go 
GHIDRA_INSTALL_DIR=/snap/ghidra/current/ghidra_12.0_PUBLIC/ zorya $1 --compiler gc --thread-scheduling all-threads --lang go --arg "a b c d e" --no-negate-path-exploration --mode start
