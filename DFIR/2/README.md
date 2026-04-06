# CTF Writeup: DNS CNAME Challenge

## Challenge Overview
**Difficulty:** Easy  
**Category:** Network Forensics / DNS  
**Flag:** `ctf7{hidden_cname_masterpiece}`

## Challenge Description
A PCAP (packet capture) file contains network traffic with DNS queries. The challenge requires finding a hidden flag encoded within the DNS responses.

## Solution

### Step 1: Analyze the PCAP File
```bash
tshark -r 2.pcap -Y "dns.qry.name" -T fields -e dns.qry.name
```

The file contains hundreds of DNS queries to domains like `www748.example.com`, `www568.example.com`, etc., along with a special query: `target-challenge.example`.

### Step 2: Find the Special DNS Response
The key is querying for the "target-challenge.example" record:

```bash
tshark -r 2.pcap -Y "dns.qry.name == \"target-challenge.example\"" -T text
```

This reveals a **CNAME response** containing hex-encoded data in the subdomain structure:
```
637466377b68696464656e5f636e616d655f6d617374657270.696563657d.challenge.hidden
```
<img width="1677" height="76" alt="image" src="https://github.com/user-attachments/assets/b0e60771-a632-469e-9bac-1b6a55eed99b" />


### Step 3: Decode the Hex Data
The subdomain contains two hex strings:
- `637466377b68696464656e5f636e616d655f6d617374657270`
- `696563657d`

Decoding these:
```bash
echo "637466377b68696464656e5f636e616d655f6d617374657270" | xxd -r -p
# Output: ctf7{hidden_cname_masterp

echo "696563657d" | xxd -r -p
# Output: iece}
```

<img width="693" height="99" alt="image" src="https://github.com/user-attachments/assets/8f3e2b26-ceba-48c6-9acb-7095bf8723c7" />


### Step 4: Combine and Get the Flag
```
ctf7{hidden_cname_masterpiece}
```

## Key Insights
1. **DNS records can be abused for data exfiltration** - The challenge demonstrates how data can be hidden in DNS CNAME records
2. **Hex encoding** - The flag itself was encoded in hexadecimal within the DNS response
3. **Pattern recognition** - Among many decoy queries, the special "target-challenge.example" query stood out
4. **Network forensics importance** - Analyzing network traffic is crucial for security

## Tools Used
- **tshark** - Efficient command-line packet analyzer
- **xxd** - Hex/binary converter
- **Wireshark** - GUI packet analyzer (alternative to tshark)

## Defense Tips
- Monitor unusual DNS queries (especially with hex in subdomains)
- Look for CNAME records pointing to suspicious domains
- Implement DNS monitoring and filtering
- Restrict DNS query patterns in your network
