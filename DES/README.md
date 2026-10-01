# Two-Way DES Encrypted Transmission (InfoSec Coursework)

A clean, barebones implementation of DES (Data Encryption Standard) and two-way encrypted peer-to-peer communication over TCP sockets built without any third-party cryptography libraries.

## Project Files

- **`des.py`**: Manual implementation of the DES algorithm from scratch:
  - Standard tables: IP, FP, E, P, PC-1, PC-2, and S-Boxes 1–8.
  - 16-round Feistel structure with reversible subkey schedule.
  - PKCS#7 padding and CBC mode with random 8-byte IV (`os.urandom(8)`).
  - Built-in verification with the NIST standard test vector.
- **`peer.py`**: Two-way TCP communication program:
  - Multi-threaded: background thread listens and decrypts; main thread reads stdin, encrypts, and transmits.
  - 4-byte length-prefixed framing to handle TCP streaming boundaries.
  - Logs both plaintext and ciphertext in hexadecimal for live demo.
  - Supports `--plaintext` flag for easy Wireshark contrast demonstration.
- **`server.py` & `client.py`**: Simple convenience entry points for `peer.py`.

---

## 1. Verify DES Implementation (Test Vector)

Run `des.py` directly to verify against the NIST reference test vector:

```bash
python3 des.py
```

Expected output:
```text
Test Vector Key:        133457799BBCDFF1
Test Vector Plaintext:  0123456789ABCDEF
Expected Ciphertext:    85E813540F0AB405
Calculated Ciphertext:  85E813540F0AB405
[+] Test Vector Check: PASSED
[+] Single Block Decrypt Check: PASSED
[+] CBC Mode & PKCS#7 Round-Trip Checks: ALL PASSED
```

---

## 2. Running Two-Way Communication Demo

### A. Encrypted Mode (Default)

**Terminal 1 (Listener / Server):**
```bash
python3 peer.py listen 5000
```

**Terminal 2 (Connector / Client):**
```bash
python3 peer.py connect 127.0.0.1 5000
# (Or use the listener's IP if across VMs/devices)
```

---

### B. Unencrypted Plaintext Mode (For Wireshark Contrast)

To demonstrate the difference in Wireshark:

**Terminal 1:**
```bash
python3 peer.py listen 5000 --plaintext
```

**Terminal 2:**
```bash
python3 peer.py connect 127.0.0.1 5000 --plaintext
```

---

## 3. Pre-Shared Key (PSK)

- The default 8-byte pre-shared key is `INFOS3C!`.
- The key is **never transmitted** over the network.
- To customize the key, set the `DES_KEY` environment variable on both sides:
  ```bash
  export DES_KEY="MySecret"
  python3 peer.py listen 5000
  ```

---

## 4. Wireshark Capture Instructions (Demo / Report)

1. Open Wireshark and listen on the active network interface:
   - For WSL $\leftrightarrow$ Windows: select `vEthernet (WSL (Hyper-V firewall))`.
   - For Windows localhost: select `Adapter for loopback traffic capture`.
   - For VMs or physical machines: select `eth0`, `wlan0`, or the bridged adapter.
2. Apply the display filter:
   ```text
   tcp.port == 5000
   ```
3. Type messages in both terminals.
4. In Wireshark, right-click any captured packet and choose **Follow -> TCP Stream**.
   - In **Encrypted Mode**: Only random IV and ciphertext bytes appear (unreadable hex).
   - In **Plaintext Mode**: The exact readable text you typed appears directly in the ASCII column.