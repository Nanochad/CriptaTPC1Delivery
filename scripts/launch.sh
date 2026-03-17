#!/bin/bash



# Get the directory of this script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR/.."


# Terminal 1: hjStreamServer
gnome-terminal --title="Stream Server" -- bash -c "
cd \"$PROJECT_ROOT/hjStreamServer\";
java -cp "$PROJECT_ROOT:." hjStreamServer \"$PROJECT_ROOT/hjStreamServer/movies/monsters.dat\" localhost 8090;
exec bash
" &


# Terminal 2: hjUDPproxy  
gnome-terminal --title="UDP Proxy" -- bash -c "
cd \"$PROJECT_ROOT/hjUDPproxy\";
java -cp "$PROJECT_ROOT:." hjUDPproxy;
exec bash
" &


# Terminal 3: VLC receiver
gnome-terminal --title="VLC UDP Receiver" -- bash -c "
vlc udp://@127.0.0.1:8080;
exec bash
" &

wait
