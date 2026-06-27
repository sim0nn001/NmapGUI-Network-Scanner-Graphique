#!/bin/bash
# install_and_build.sh — NmapGUI setup script
set -e

echo "┌─────────────────────────────────────┐"
echo "│     NmapGUI — Installation          │"
echo "└─────────────────────────────────────┘"

# Deps
echo "[1/3] Vérification des dépendances..."
PKGS=""
command -v nmap      >/dev/null 2>&1 || PKGS="$PKGS nmap"
pkg-config gtk+-3.0  >/dev/null 2>&1 || PKGS="$PKGS libgtk-3-dev"
command -v g++       >/dev/null 2>&1 || PKGS="$PKGS g++"

if [ -n "$PKGS" ]; then
    echo "    Installation :$PKGS"
    sudo apt-get install -y $PKGS
fi

echo "[2/3] Compilation..."
make -C "$(dirname "$0")" clean all

echo "[3/3] Lancement..."
echo ""
echo "  ⬡  NmapGUI est prêt."
echo "  Pour les scans SYN/OS, lancez avec : sudo ./nmap_gui"
echo ""
"$(dirname "$0")/nmap_gui"
