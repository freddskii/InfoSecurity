#!/usr/bin/env python3
import sys
from peer import run_listen, DEFAULT_PORT

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PORT
    run_listen(port)