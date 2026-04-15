from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64

# Base64 encrypted data
ciphertext_b64 = "Nzd42HZGgUIUlpILZRv0jeIXp1WtCErwR+j/w/lnKbmug31opX0BWy+pwK92rkhjwdf94mgHfLtF26X6B3pe2fhHXzIGnnvVruH7683KwvzZ6+QKybFWaedAEtknYkhe"

# Secret key (16 bytes for AES-128)
key = b"my-secret-key-16"

# Decode Base64
ciphertext = base64.b64decode(ciphertext_b64)

# Decrypt using AES-128-ECB
cipher = AES.new(key, AES.MODE_ECB)
plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

print("Decrypted text:", plaintext.decode())
