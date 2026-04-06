
This guide details a step-by-step approach to manually solving the PCAP challenge using the Wireshark GUI and standard decoder tools like CyberChef.

## 1. Initial Reconnaissance & Finding the Keys
When you first open `5.pcap` in Wireshark, it's good practice to get an overview of the traffic using **Statistics -> Protocol Hierarchy**. 
- You'll notice a lot of ICMP traffic, some UDP traffic, and some TCP segments.

Let's look at the UDP traffic first, as it often contains simpler text-based communications or setup data:
1. Apply the display filter `udp`.
2. Right-click on the first UDP packet and select **Follow -> UDP Stream**.
3. In the pop-up window, you will see a conversation between two parties mentioning a "transfer" and "high-stakes".
4. Two encoded strings stand out:
   - `Ujl0IUptNExhQEJxWGUyUG8jV2MlVXlOczdEa0h2WmY=`
   - `TGtKaEdmRHNBelhjVmJObQ==`
  
<img width="1910" height="733" alt="image" src="https://github.com/user-attachments/assets/02887739-f033-45f7-9831-38b602a056d8" />

5. Copy these strings and paste them into CyberChef to decode them from Base64:
   - The first decodes to: `R9t!Jm4La@BqXe2Po#Wc%UyNs7DkHvZf` (Exactly 32 characters -> 256 bits, perfect for an AES-256 Key).
  
   <img width="1223" height="640" alt="image" src="https://github.com/user-attachments/assets/8fb9c35d-2654-4d59-a11c-87dac7ccb838" />

   - The second decodes to: `LkJhGfDsAzXcVbNm` (Exactly 16 characters -> 128 bits, perfect for an AES IV).
   <img width="1076" height="645" alt="image" src="https://github.com/user-attachments/assets/a975312d-1820-43e6-a535-1a3504db464d" />

## 2. Analyzing the File Transfer (ICMP Covert Channel)
Now look at the vast amount of ICMP ping requests in the PCAP.
1. Apply the display filter `icmp`.
2. You'll notice thousands of packets pointing to `192.168.1.200`. Select one of the "Echo (ping) request" packets and inspect it in the Packet Details pane.
3. Expand expanding the **Data** section. You'll see arbitrary hex data filling the payload—this is likely our encrypted file!


<img width="1918" height="924" alt="image" src="https://github.com/user-attachments/assets/d1f1561a-5199-44b6-9269-8e55a22979e8" />

### The Wireshark Dissector Trap!
If you scroll closely through the ICMP packets (or rely entirely on the `data` display filter), you might notice something bizarre: randomly, some packets are identified as `HiPerConTracer` rather than standard ICMP Echo Requests!
- **Why does this happen?** The ciphertext sent over ICMP is essentially random data. By sheer coincidence, the bytes in a few of the ciphertext chunks happened to perfectly match the magic signatures that Wireshark looks for when identifying the `HiPerConTracer` protocol. 
- **The consequence:** When Wireshark dissects a packet as `HiPerConTracer`, it parses the `data` out into specific fields (like `Round` and `SendTTL`) meaning the raw `data` field no longer exists for that packet in Wireshark. Any standard extraction of the `data` field will literally **skip or corrupt** these 250 missing packets, failing your AES decryption.

To fix this trap:
1. Go to **Analyze -> Enabled Protocols...**
<img width="562" height="448" alt="image" src="https://github.com/user-attachments/assets/f4457d6c-2af4-45e1-a528-e2af6d0fda8e" />

3. Search for `hipercontracer`.
4. Uncheck the box to disable this protocol entirely.
<img width="1240" height="664" alt="image" src="https://github.com/user-attachments/assets/1fea2b4c-8bf8-44e4-b00a-cb07f0134327" />

5. Click OK. Now, all 1691 ping requests gracefully appear as standard ICMP Echo Requests with uninterrupted `Data` payloads.

## 3. Extracting the Data
While exporting a single packet's bytes is easy in the Wireshark GUI (File -> Export Packet Bytes), doing so for 1691 packets is tedious. The optimal "manual" pivot is to quickly drop the payloads using a one-liner standard terminal `tshark` command, keeping the disabled protocol:

```bash
tshark -r 5.pcap --disable-protocol hipercontracer -Y "ip.dst==192.168.1.200 and icmp.type==8" -T fields -e data | tr -d '\n' > extracted_hex.txt
```

<img width="1438" height="161" alt="image" src="https://github.com/user-attachments/assets/a3173385-37fc-4d12-acd9-5f3dd5e37f1f" />

*(Alternatively, you can write a tiny Python script to extract and concatenate the `Raw` layers using `scapy`.)*

## 4. Decrypting the File 
Now that you have the clean, uninterrupted hex data, you can decrypt it.

**Using OpenSSL (Terminal):**
1. Convert the extracted hex back to raw binary:
   ```bash
   xxd -r -p extracted_hex.txt > encrypted.bin
   ```
2. Decrypt with the Key and IV we found earlier:
   ```bash
   openssl enc -d -aes-256-cbc -in encrypted.bin -out decrypted.png -K $(echo -n 'R9t!Jm4La@BqXe2Po#Wc%UyNs7DkHvZf' | xxd -p | tr -d '\n') -iv $(echo -n 'LkJhGfDsAzXcVbNm' | xxd -p | tr -d '\n')
   ```
<img width="1640" height="280" alt="image" src="https://github.com/user-attachments/assets/283ae32a-3de3-4f29-b268-a8ebb250b1c3" />


<img width="539" height="543" alt="image" src="https://github.com/user-attachments/assets/8bd5fbff-8834-4dcd-af3f-f75b5b6e4f3b" />

**Using CyberChef (GUI):**
1. Paste the entire content of `extracted_hex.txt` into the Input pane of CyberChef.
2. Build the following recipe:
   - **From Hex**
   - **AES Decrypt**
     - Key: `R9t!Jm4La@BqXe2Po#Wc%UyNs7DkHvZf` (Mode: UTF8)
     - IV: `LkJhGfDsAzXcVbNm` (Mode: UTF8)
     - Mode: `CBC`
     - Input/Output: `Raw`
   - **Render Image** (If you suspect it's an image!)
3. The output window will instantly render the decrypted picture—a drifting car meme with the flag embedded right in the image text!

## 5. The Flag
**`flag{d34d_p4ck3ts_t3ll_n0_t4l3s_0x28934}`**
