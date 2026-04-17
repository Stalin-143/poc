# Memory Analysis Writeup

## Challenge
- Hint says Notepad is the key artifact.
- Required flag format: PEPxCyber{...}

## Method
1. Start from the memory image and scan file objects with Volatility.
2. Filter results for Notepad package paths and TabState artifacts.
3. Dump the Notepad TabState file objects from memory.
4. Inspect dumped binary blobs as UTF-16/hex.
5. Recover encoded token and decode it.
6. Wrap decoded text in the required flag format.

## Commands Used
Run from volatility3 folder:

source venv/bin/activate
python3 vol.py -f ../WINDOWS11-20251103-181217.raw -q -r csv windows.filescan > /tmp/filescan.csv

<img width="1513" height="928" alt="image" src="https://github.com/user-attachments/assets/fc48be59-39b0-43dd-bb15-9b293116ce5e" />

grep -Ei "WindowsNotepad|TabState|settings.dat" /tmp/filescan.csv
<img width="1721" height="850" alt="image" src="https://github.com/user-attachments/assets/a263f21c-1a3d-4ccd-909f-4444b6c015e7" />


Key FileObject virtual addresses found for TabState:
- 0xd20fdf5ba460
- 0xd20fdf5bd340
- 0xd20fe058ebf0

Dump those objects:

python3 vol.py -f ../WINDOWS11-20251103-181217.raw -q -o ../dumped_files2 windows.dumpfiles --virtaddr 0xd20fdf5ba460 0xd20fdf5bd340 0xd20fe058ebf0

<img width="1589" height="205" alt="image" src="https://github.com/user-attachments/assets/b12051ec-e3c5-4801-b1d1-58d52b65a86c" />


Inspect dumped content:

xxd -g 1 ../dumped_files2/file.0xd20fe058ebf0.0xd20fe0489b40.DataSectionObject.703f5836-f2e4-43c0-8522-59e788aa06de.bin.tmp.dat | head
<img width="1179" height="252" alt="image" src="https://github.com/user-attachments/assets/144b7fda-90b4-4d3f-bfcb-e9b0195e0cdf" />

strings -el ../dumped_files2/file.0xd20fe058ebf0.0xd20fe0489b40.DataSectionObject.703f5836-f2e4-43c0-8522-59e788aa06de.bin.tmp.dat

<img width="1124" height="95" alt="image" src="https://github.com/user-attachments/assets/969f2a79-c1db-4577-a476-a2394f6841f6" />


Recovered encoded token:
- AcDDH_C507_F?5

Decode step:
- ROT47(AcDDH_C507_F?5) = p4ssw0rd_f0und

<img width="1539" height="907" alt="image" src="https://github.com/user-attachments/assets/5fe9590e-7b39-4804-b9f3-11036c3184fe" />


## Final Flag
PEPxCyber{p4ssw0rd_f0und}

## Notes
- Full direct flag string was not plainly present in memory string scans.
- The decisive evidence came from Notepad TabState temporary binary content.
