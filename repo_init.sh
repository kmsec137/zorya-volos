#!/bin/bash
git checkout main
git fetch upstream
git merge upstream/main  # Or use 'git pull upstream main'
git submodule update --init --recursive
