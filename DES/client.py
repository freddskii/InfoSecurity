#!/usr/bin/env python3
import sys
from peer import run_connect, DEFAULT_PORT

if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PORT
    run_connect(host, port)