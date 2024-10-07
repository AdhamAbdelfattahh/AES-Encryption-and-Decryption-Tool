from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

def generate_key():
    """Generate a random 16-byte key for AES encryption."""
    return os.urandom(16)

def encrypt(message, key):
    """Encrypt a message using AES encryption."""
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
    return cipher.iv, ct_bytes

def decrypt(iv, ciphertext, key):
    """Decrypt a ciphertext using AES decryption."""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return pt.decode()

if __name__ == "__main__":
    key = generate_key()
    message = "This is a secret message."
    
    # Encrypt the message
    iv, ciphertext = encrypt(message, key)
    print(f"IV: {iv.hex()}")
    print(f"Ciphertext: {ciphertext.hex()}")

    # Decrypt the message
    decrypted_message = decrypt(iv, ciphertext, key)
    print(f"Decrypted: {decrypted_message}")
