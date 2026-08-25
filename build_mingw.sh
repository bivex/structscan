#!/usr/bin/env bash
# StructScan MinGW-w64 Cross-Compilation Script for macOS
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

COMPILER="${CXX:-x86_64-w64-mingw32-g++}"

if ! command -v "$COMPILER" >/dev/null 2>&1; then
    echo "[-] Error: $COMPILER not found in PATH."
    echo "    Install with Homebrew: brew install mingw-w64"
    exit 1
fi

mkdir -p bin

echo "[+] Building StructScan (x64) using $COMPILER..."
"$COMPILER" -shared -O2 -std=c++17 \
    -Iinclude \
    src/Main.cpp \
    src/Utils.cpp \
    src/SmartFieldAnalyzer.cpp \
    src/ScanEngine.cpp \
    src/ListCrossRefEngine.cpp \
    src/HeaderSynthesizer.cpp \
    src/EntropyEngine.cpp \
    src/UafEngine.cpp \
    -o bin/structscan_x64.dll \
    -ldbgeng -ldbghelp \
    -static-libgcc -static-libstdc++ \
    -Wl,--enable-auto-image-base

echo "[+] Successfully generated: bin/structscan_x64.dll"
file bin/structscan_x64.dll
