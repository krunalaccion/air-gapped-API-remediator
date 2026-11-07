#!/bin/bash
# Double-clickable macOS launcher for AirGap Remediator
cd "$(dirname "$0")"

echo "=========================================================="
echo "          🛡️  AIR-GAP REMEDIATOR CONTROL CENTER           "
echo "=========================================================="
echo ""

# 1. Start Ollama in background if not already running
if ! pgrep -x "ollama" > /dev/null; then
    echo "⚡ Starting local Ollama server..."
    ollama serve &
    sleep 2
else
    echo "✓ Local Ollama server is running"
fi

# 2. Open dashboard in default browser after 1.5 seconds
(sleep 1.5 && open "http://localhost:8080") &

# 3. Start AirGap Remediator Web Server
echo "🚀 Launching AirGap Remediator on http://localhost:8080 ..."
python3 web_server.py 8080

