#!/bin/bash
echo "⚡ AutoScript VPN - Quick Start"
echo "==============================="

if [ "$EUID" -ne 0 ]; then
    echo "❌ Please run as root: sudo ./quick-start.sh"
    exit 1
fi

# Download and run installer
if [ ! -f "install.sh" ]; then
    echo "📥 Downloading installer..."
    wget -q https://raw.githubusercontent.com/dhyntoh/autoscript-vpn/main/install.sh
    chmod +x install.sh
fi

# Run installation
./install.sh

echo
echo "🚀 Quick start complete!"
echo "   Open Telegram and start chatting with your bot!"
