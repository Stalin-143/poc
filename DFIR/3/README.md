# RC4 Covert Channel CTF - Wireshark Forensics Analysis Writeup

## Challenge Overview
Extract the flag from a packet capture containing covert exfiltration channels using DNS queries and ICMP packets encrypted with RC4.

**Flag:** `DCxTCTF{ph4nt0m_dns_3xf1ltr4t10n_d3t3ct3d}`

---

## 1. Opening the PCAP in Wireshark

```bash
wireshark capture.pcap
```

### Initial Observations
- **Total packets:** 443
- **Protocols present:** FTP, HTTP, DNS, ICMP
- **Suspicious patterns:** DNS queries to `evil-c2.net`, ICMP to `10.0.0.53`

---

## 2. DNS Exfiltration Channel Analysis

### Filter in Wireshark:
```
dns.qry.name contains "evil-c2.net"
```

### What to Look For:
Each query follows the pattern: `[HEX_DATA].[INDEX].data.evil-c2.net`

**Captured chunks (7 total):**
```
Frame 9:   5c967e59f7c9.00.data.evil-c2.net
Frame 22:  ae1c30048cac.01.data.evil-c2.net
Frame 43:  2951d884d3d1.02.data.evil-c2.net
Frame 67:  d5a428f4f901.03.data.evil-c2.net
Frame 86:  d6f0edbdfaa1.04.data.evil-c2.net
Frame 91:  99ff5b72a40e.05.data.evil-c2.net
Frame 118: 138e0d565641.06.data.evil-c2.net
```
<img width="1682" height="311" alt="image" src="https://github.com/user-attachments/assets/b48ad60f-5139-4141-9535-39f5c7133350" />


### Extraction Steps:
1. Right-click each DNS query → **Copy** → **Printable Text**
2. Extract the hex portion before the `.XX.data.evil-c2.net`
3. Concatenate in numerical order (00→06)

**Result:** 
```
5c967e59f7c9ae1c30048cac2951d884d3d1d5a428f4f901d6f0edbdfaa199ff5b72a40e138e0d565641
```

---

## 3. ICMP Honeypot Channel Analysis

### Filter in Wireshark:
```
icmp.type == 8 && ip.dst == 10.0.0.53
```

### What to Look For:
- **Destination IP:** `10.0.0.53` (honeypot)
- **Source IP:** `192.168.1.105`
- **Protocol:** ICMP Echo Request (type 8)
- **Sequences:** 4 packets (seq 1, 2, 3, 4)

**Captured frames:**
```
Frame 272: Seq 1 - 48 bytes payload
Frame 346: Seq 2 - 48 bytes payload (with HiPerConTracer header: 091072b8...)
Frame 361: Seq 3 - 48 bytes payload
Frame 414: Seq 4 - 48 bytes payload
```
<img width="1788" height="600" alt="image" src="https://github.com/user-attachments/assets/f51ddfcc-eba0-47e0-b959-81fa2a99e710" />


### Key Discovery in ICMP:
The ICMP packet payloads contain patterns that reveal:
- **Key:** `S3cr3t_ICMP_K3y!` (16 bytes)
- **Cipher:** RC4
- **Purpose:** Encryption key for DNS blob

---

## 4. Red Herring Detection

### Filter in Wireshark:
```
ftp
```

**What you find:**
```
FTP Stream 2: Files transferred
Filename: confidential.txt
Content: "TOP SECRET - Project PHANTOM"
         "==========================="
         "The flag is NOT here. Keep looking."
         "Key: REDHERRING{th1s_1s_n0t_th3_fl4g}"
         "This file is a decoy planted by the attacker."
```

**Action:** Ignore this. It's intentional misdirection.

---

## 5. Decryption Process

### Tools Needed:
- Python 3
- RC4 cipher implementation

### RC4 Decryption Algorithm:

```python
def rc4(key, ciphertext):
    # Key Scheduling Algorithm (KSA)
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) % 256
        s[i], s[j] = s[j], s[i]
    
    # Pseudo-Random Generation Algorithm (PRGA)
    i = j = 0
    plaintext = bytearray()
    for byte in ciphertext:
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        K = s[(s[i] + s[j]) % 256]
        plaintext.append(byte ^ K)
    
    return bytes(plaintext)

# Apply decryption
ciphertext_hex = "5c967e59f7c9ae1c30048cac2951d884d3d1d5a428f4f901d6f0edbdfaa199ff5b72a40e138e0d565641"
key = b'S3cr3t_ICMP_K3y!'
ciphertext = bytes.fromhex(ciphertext_hex)
plaintext = rc4(key, ciphertext)
print(plaintext.decode())  # OUTPUT: DCxTCTF{ph4nt0m_dns_3xf1ltr4t10n_d3t3ct3d}
```
<img width="1183" height="837" alt="image" src="https://github.com/user-attachments/assets/1431cb71-cd2f-41f2-8245-44f0769dd0fb" />

---

## 6. Forensic Indicators Summary

| Indicator | Evidence | Type |
|-----------|----------|------|
| **DNS Exfiltration** | Indexed queries to `evil-c2.net` | Covert Channel |
| **ICMP Honeypot** | Echo requests to internal honeypot IP `10.0.0.53` | Covert Channel |
| **Encryption** | RC4 cipher detected via payload entropy | Defense Evasion |
| **Red Herring** | FTP plaintext labeled "REDHERRING{...}" | Anti-Forensics |
| **Operational Failure** | Key stored in plaintext ICMP data | OPSEC Breach |

---

## 7. Attack Flow Diagram

```
Attacker Machine
       |
       ├─→ Exfil Flag via DNS (encrypted with RC4)
       │   └─ Chunks 00-06 to evil-c2.net
       │
       ├─→ Send Key via ICMP (to honeypot 10.0.0.53)
       │   └─ Embedded in echo request packets
       │
       └─→ Decoy FTP Transfer (plaintext marker)
           └─ REDHERRING{...} to distract

Network (IDS/Monitoring)
       |
       ├─ Captures DNS queries ✓
       ├─ Captures ICMP packets ✓
       ├─ Logs FTP transfer ✓
       └─ Alert: Suspicious C2 patterns detected

Analyst
       |
       ├─ Use Wireshark to visualize traffic
       ├─ Extract ciphertext from DNS
       ├─ Discover key in ICMP
       ├─ Implement RC4 decryption
       └─ Recover flag: DCxTCTF{...}
```

---

## 8. Key Takeaways

✅ **Multi-protocol covert channels** are harder to detect than single-protocol exfil  
✅ **DNS subdomain encoding** bypasses simple string-based IDS rules  
✅ **ICMP to internal IPs** can indicate honeypot/beaconing activity  
✅ **Symmetric encryption keys embedded in secondary channels** suggest coordinated attack  
✅ **Explicit decoys** (like FTP red herring) indicate sophisticated threat actor  

---

## 9. Detection/Prevention

### Network Defense:
- Flag DNS queries with hex-like subdomains
- Alert on ICMP to non-routable/honeypot IPs
- Monitor for protocol nesting anomalies
- Inspect packet payloads for encryption signatures

### Wireshark Filtering Tips:
```
# Hunt for abnormal DNS
dns.qry.name matches "[0-9a-f]{10,}"

# Find ICMP with unusual payloads
icmp && frame.len > 60

# Identify beaconing patterns
ip.dst == 10.0.0.53

# Follow TCP/ICMP streams
Stream → Follow → [TCP/UDP/ICMP]
```

---

**Challenge Solved:** `DCxTCTF{ph4nt0m_dns_3xf1ltr4t10n_d3t3ct3d}`
