#!/bin/bash


MOVIE=$1
# Get the directory of this script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR/.."




# Terminal 1: hjUDPproxy  
gnome-terminal --title="UDP Proxy" -- bash -c "
cd \"$PROJECT_ROOT/hjUDPproxy\";
java -cp "$PROJECT_ROOT:." hjUDPproxy;
exec bash
" &


# Terminal 2: VLC receiver
gnome-terminal --title="VLC UDP Receiver" -- bash -c "
vlc udp://@127.0.0.1:8080;
exec bash
" &

sleep 3;

# Terminal 3: hjStreamServer
gnome-terminal --title="Stream Server" -- bash -c "
cd \"$PROJECT_ROOT/hjStreamServer\";
java -cp "$PROJECT_ROOT:." hjStreamServer \"$MOVIE\" localhost 8090;
exec bash
" &

wait
