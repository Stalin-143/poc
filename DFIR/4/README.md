# JCOE CTF — TCP Sequence Number Steganography Writeup



---

## What is TCP Steganography?

Steganography is hiding secret data inside something that looks normal. In network steganography, attackers embed hidden messages inside **protocol header fields** — fields that exist in every packet but whose exact values aren't usually scrutinized.

The TCP header has a 32-bit **Sequence Number** field. Normally, the OS sets this to track byte positions in a stream. But in a crafted packet, an attacker can set it to **any value** — and hide data in it. That's exactly what this challenge does:

```
Normal TCP seq:   0x4A3F01B2  (random, set by OS)
This challenge:   5004001     (carefully crafted — last digit = 1 = one bit of the flag)
```

---

## Wireshark Analysis — Step by Step

### Step 1 — Open the PCAP & Survey the Traffic

Open [4.pcap](file:///home/w4nn4d13/Downloads/4/4.pcap) in Wireshark. At first glance, you see 293 TCP packets between two hosts:

- **`192.168.1.100`** (attacker/sender)
- **`192.168.1.1`** (receiver)

Go to **Statistics → Conversations → TCP tab** to get a bird's-eye view:

| Conversation | Frames | What it is |
|---|---|---|
| `192.168.1.100:13337 → 192.168.1.1:8080` | **224** | Main data stream — **this is where the flag is** |
| `192.168.1.100:12345–12347 → 192.168.1.1:80` | 6 | Three TCP handshakes (SYN/SYN-ACK/ACK) — setup noise |
| ~45 connections to random ports (1446, 4181, 7478...) | 1 each | Single-packet noise — **decoys to distract you** |
| ~15 connections to random ports (6256, 255, 5936...) | 1 each | End-marker packets — more decoys |

> [!TIP]
> **Why 224?** That's exactly **28 bytes × 8 bits = 224 bits**. The flag `JCOE_CTF{tcp_s3qu3nc3_st3g0}` is 28 characters. Each packet carries one bit → 224 packets.

---

### Step 2 — Inspect the Payloads to Understand the Structure

Apply this Wireshark display filter to see only packets that carry data:

```
data
```
<img width="1778" height="543" alt="image" src="https://github.com/user-attachments/assets/d67bc551-ef81-4340-aeea-79868cf16671" />


Click on any packet and look at the **Packet Bytes** pane at the bottom. You'll see ASCII text in the payload. There are three types:

#### Type 1: "Data" packets (the flag carriers)

```
Filter: tcp.dstport == 8080 && tcp.srcport == 13337
```
<img width="1852" height="480" alt="image" src="https://github.com/user-attachments/assets/e9373db0-72f4-49d5-bd15-1bc62cc30839" />


These 224 packets all go to **port 8080** from source port **13337**. Their payloads read `Data000`, `Data001`, ..., `Data223`. These payloads are just **labels** — the real secret is in the TCP header (sequence number).

#### Type 2: "Noise" packets (decoys)

```
Filter: tcp.payload contains "Noise"
```
<img width="1495" height="485" alt="image" src="https://github.com/user-attachments/assets/b539ee1d-a7a1-40a2-948c-746761b3bd69" />


45 packets sent to **random destination ports** (1446, 4181, 7478...) with payloads like `Noise0`, `Noise5`, `Noise10`. These are deliberately placed between Data packets to make you think the **destination port numbers** encode the flag (they don't — it's a trap).

#### Type 3: "End" packets (terminator decoys)

```
Filter: tcp.payload contains "End"
```
<img width="1699" height="623" alt="image" src="https://github.com/user-attachments/assets/7e992874-351e-4349-af86-59ec26c71952" />

15 packets at the end of the capture with payloads `End0`–`End14`. More red herrings with random port numbers.

> [!WARNING]
> **The trap**: The Noise/End packets have suspicious random destination ports that look like encoded data. You might waste time trying to decode port numbers (mod 256, pairs of digits, etc.) — this is intentional misdirection. The real data is in the **sequence numbers** of the **Data** packets.

---

### Step 3 — Discover the Anomaly in Sequence Numbers

This is the **"aha" moment**. Filter for only the Data packets:

```
tcp.dstport == 8080 && tcp.srcport == 13337
```


Now add a custom column to show raw sequence numbers:
1. Right-click any column header → **Column Preferences**
2. Click **+** to add a new column
3. Set **Title** = `Seq Raw`, **Fields** = `tcp.seq_raw`, **Type** = Custom
4. Click **OK**

Now look at the sequence numbers:

```
Packet   Payload     Seq Number    Last Digit
─────────────────────────────────────────────
  10     Data000     5000000        0
  12     Data001     5001001        1
  13     Data002     5002000        0
  14     Data003     5003000        0
  15     Data004     5004001        1
  16     Data005     5005000        0
  17     Data006     5006001        1
  18     Data007     5007000        0
  ...
```

**The pattern**:
- The base increments by **1000** per packet: `5000xxx`, `5001xxx`, `5002xxx`...
- The last digit is always **`0`** or **`1`**
- Normal TCP sequence numbers would never look this clean — this is **crafted data**

Each packet's last digit is **one binary bit** of the flag.

> [!IMPORTANT]
> **How to spot this in Wireshark**: Sequence numbers that increment by exactly 1000 with only the units digit changing between 0 and 1 is a massive red flag. Real TCP sequence numbers are basically random 32-bit integers that increment by the number of bytes sent — they'd never look this regular.

---

### Step 4 — Extract the Bits

Use `tshark` (Wireshark's command-line version) to extract all sequence numbers:

```bash
tshark -r 4.pcap \
  -Y "tcp.dstport == 8080 && tcp.srcport == 13337" \
  -T fields -e tcp.seq_raw
```

<img width="445" height="939" alt="image" src="https://github.com/user-attachments/assets/c158ce9a-1cbe-40aa-bc0d-dfd3fc7e583e" />


This outputs:

```
5000000
5001001
5002000
5003000
5004001
5005000
...
```

Extract the last digit of each number to get the bitstream:

```
0 1 0 0 1 0 1 0 | 0 1 0 0 0 0 1 1 | 0 1 0 0 1 1 1 1 | 0 1 0 0 0 1 0 1
    'J'                 'C'                 'O'                 'E'

0 1 0 1 1 1 1 1 | 0 1 0 0 0 0 1 1 | 0 1 0 1 0 1 0 0 | 0 1 0 0 0 1 1 0
    '_'                 'C'                 'T'                 'F'

0 1 1 1 1 0 1 1 | 0 1 1 1 0 1 0 0 | 0 1 1 0 0 0 1 1 | 0 1 1 1 0 0 0 0
    '{'                 't'                 'c'                 'p'

0 1 0 1 1 1 1 1 | 0 1 1 1 0 0 1 1 | 0 0 1 1 0 0 1 1 | 0 1 1 1 0 0 0 1
    '_'                 's'                 '3'                 'q'

0 1 1 1 0 1 0 1 | 0 0 1 1 0 0 1 1 | 0 1 1 0 1 1 1 0 | 0 1 1 0 0 0 1 1
    'u'                 '3'                 'n'                 'c'

0 0 1 1 0 0 1 1 | 0 1 0 1 1 1 1 1 | 0 1 1 1 0 0 1 1 | 0 1 1 1 0 1 0 0
    '3'                 '_'                 's'                 't'

0 0 1 1 0 0 1 1 | 0 1 1 0 0 1 1 1 | 0 0 1 1 0 0 0 0 | 0 1 1 1 1 1 0 1
    '3'                 'g'                 '0'                 '}'
```

---

### Step 5 — The Flag

```
JCOE_CTF{tcp_s3qu3nc3_st3g0}
```

The flag name is a leetspeak version of **"tcp sequence stego"** — confirming the technique.

---

## Solve Script

```python
#!/usr/bin/env python3
"""Solve: extract flag from TCP seq number LSBs."""
import subprocess

result = subprocess.run(
    ['tshark', '-r', '4.pcap',
     '-Y', 'tcp.dstport == 8080 && tcp.srcport == 13337',
     '-T', 'fields', '-e', 'tcp.seq_raw'],
    stdout=subprocess.PIPE, text=True, stderr=subprocess.PIPE
)

# Last digit of each seq number = 1 bit
bits = ''.join(str(int(seq) % 10) for seq in result.stdout.strip().split('\n'))

# Group into bytes and convert to ASCII
flag = ''.join(chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8))
print(f"Flag: {flag}")
```

```bash
$ python3 solve.py
Flag: JCOE_CTF{tcp_s3qu3nc3_st3g0}
```

---

## Summary

| Aspect | Detail |
|---|---|
| **Technique** | TCP Sequence Number Steganography |
| **Carrier** | 224 TCP packets (src 13337 → dst 8080) |
| **Encoding** | 1 bit per packet in the last digit of `tcp.seq` (0 or 1) |
| **Misdirection** | Noise/End packets with random destination ports to distract |
| **Key Wireshark skill** | Adding custom columns (`tcp.seq_raw`) to spot header anomalies |
| **Flag** | `JCOE_CTF{tcp_s3qu3nc3_st3g0}` |
