# Implementation Plan: Two-Way DES Ciphertext Transmission (Keamanan Informasi)

**Stack:** Python 3, `socket` + `threading`, DES written by hand (no `Crypto` / `cryptography` / `pyDes`). Using only `socket`, `struct`, and `os` is fine.

## Requirements Recap

1. Two-way communication (sender and receiver both send and receive ciphertext).
2. Key is pre-shared on both sides and is never transmitted.
3. Must be two separate parties exchanging data over a real connection (VMs or physical devices), not a single script that encrypts and decrypts in one place.
4. Any programming language.
5. No ready-made encryption/decryption libraries. DES must be implemented manually.
6. Algorithm must be DES.
7. Optional bonus: show the captured ciphertext in Wireshark.

## 1. Implement DES Manually (`des.py`)

- Tables: IP, FP, E, P, S-boxes 1-8, PC-1, PC-2, and the shift schedule.
- Key schedule: 64-bit key -> PC-1 -> 16 rotated halves -> 16 subkeys of 48 bits.
- Feistel round: expand R with E, XOR with the subkey, run through the S-boxes, then apply P, XOR with L, and swap.
- `encrypt_block` and `decrypt_block` share one function. Decryption just reverses the subkey order.
- **Test first** with the classic vector: key `133457799BBCDFF1`, plaintext `0123456789ABCDEF` should give `85E813540F0AB405`. Do not move on until this passes.

## 2. Block Mode and Padding (`modes.py`)

- Use CBC with PKCS#7 padding. Plain ECB works, but it looks weak in Wireshark because identical blocks repeat.
- Use a random IV per message and prepend it to the ciphertext. An IV is not secret, so this does not break the "key is not sent" rule.
- Get the IV from `os.urandom(8)`. That is random bytes, not a crypto library.

## 3. Protocol (`protocol.py`)

- Framing: a 4-byte length prefix (`struct.pack('!I', n)`), then `IV || ciphertext`. This avoids TCP message-boundary bugs.
- The pre-shared key is a constant or read from an env var or config file on both sides. It is never transmitted.

## 4. Sender / Receiver Programs (`peer.py`)

- One script with a `--mode listen` or `--mode connect` flag, or two separate scripts (`sender.py`, `receiver.py`).
- Each side runs two threads: one reads stdin, encrypts, and sends; the other receives, decrypts, and prints. This gives the two-way communication the task asks for.
- Log both the plaintext and the ciphertext hex on each side so the demo is easy to follow.
- Two processes talking over a real TCP socket satisfies the rule against a single script that encrypts and decrypts in one place with no transmission.

## 5. Deployment for the Demo

- **Best:** two VMs on a bridged or host-only network, or two physical machines. Wireshark captures this cleanly.
- **Fallback:** localhost. On Windows this needs Npcap's loopback adapter. On Linux, capture on `lo`.
- Use a fixed port such as 5000.

## 6. Wireshark (Bonus)

- Capture with the filter `tcp.port == 5000`.
- Right-click a packet -> Follow TCP Stream. This shows the unreadable ciphertext.
- For contrast, briefly show a plaintext send so the difference is obvious.
- Screenshot the capture next to the decrypted output on the receiver.

## 7. Testing Checklist

- [ ] DES test vector passes.
- [ ] Encrypt then decrypt round-trips for messages of various lengths, including empty and exact multiples of 8 bytes.
- [ ] Messages go both ways, and several in a row work.
- [ ] Wireshark shows only ciphertext.

## 8. Suggested Timeline

| Step | Time |
|---|---|
| DES core + test vector | 1 day |
| CBC + padding | 0.5 day |
| Socket layer + threads | 0.5 day |
| VM setup + Wireshark + screenshots | 0.5 day |
| Demo rehearsal | 0.5 day |

## Demo Talking Points

- Why CBC with a random IV instead of ECB.
- How the Feistel structure lets one function handle both encryption and decryption (reversed subkey order).
