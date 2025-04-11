from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
from Crypto.Util.number import bytes_to_long
from Crypto.Cipher import ARC4

# aes_key is 128 1 bits = 16 bytes
# RC4_key is 40 1 bits = 5 bytes
# Using AES and RC4, encrypt the following plaintext, “this is the wireless security 
# lab”. For AES, the key is 128-bit 1s; for RC4, the key is 40-bit 1s.

plaintext = bytearray("this is the wireless security lab", "utf-8")
print(plaintext.decode("utf-8"))

# AES encryption
aes_key = bytearray([0xFF]) * 16 # FF = 1111_1111
def aes_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(plaintext, AES.block_size))
  
print("AES Key:", aes_key.hex())
print("AES Plaintext:", plaintext.decode("utf-8"))
aes_Ciphertext = aes_encrypt(plaintext, aes_key)
print("AES Ciphertext:", " ".join(format(x, '02x') for x in aes_Ciphertext))

# RC4 encryption
RC4_key = bytearray([0xFF]) * 5
def rc4_encrypt(plaintext, key):
    cipher = ARC4.new(key)
    return cipher.encrypt(plaintext)

print("RC4 Key:", RC4_key.hex())
print("RC4 Plaintext:", plaintext.decode("utf-8"))
rc4_Ciphertext = rc4_encrypt(plaintext, aes_key)
print("RC4 Ciphertext", " ".join(format(x, '02x') for x in rc4_Ciphertext))


# Utilizing the resulting ciphertext (encrypted plaintext), try to crack them without 
# knowing the key information except the key size and encryption algorithm.
import time
import sys

def brute_force_aes(ciphertext, expected, start, end):
    start_time = time.time()
    for key in range(start, end): # try every combination of keys until a match is found
      try:
        key_bytes = key.to_bytes(16, byteorder='big')
      except OverflowError:
          continue
      cipher = AES.new(key_bytes, AES.MODE_ECB)
      decrypted_text = cipher.decrypt(ciphertext)

      try:
        plaintext = unpad(decrypted_text, AES.block_size)
      except ValueError:
        continue
      
      if expected in plaintext:
        elapsed = time.time() - start_time
        print(f"\nFound key: {key_bytes.hex()} (int: {key}) in {elapsed:.2f} seconds")
        print("Decrypted plaintext:", plaintext)
        return key_bytes, plaintext

      if(key - start) % 10000 == 0 and key > start:
        elapsed = time.time() - start_time
        print(f"Tested {key - start} keys in {elapsed:.2f} seconds", file=sys.stderr)

    print("No key found in the given range")
    return None, None


def brute_force_rc4(ciphertext, expected, start, end):
    start_time = time.time()
    for key in range(start, end):
      key_bytes = key.to_bytes(5, byteorder='big')
      cipher = ARC4.new(key_bytes)
      decrypted_text = cipher.decrypt(ciphertext)

      if expected in decrypted_text:
        elapsed = time.time() - start_time
        print(f"\nFound key: {key_bytes.hex()} (int: {key}) in {elapsed:.2f} seconds")
        print("Decrypted plaintext:", decrypted_text)
        return key_bytes, decrypted_text

      if(key - start) % 10000 == 0 and key > start:
        elapsed = time.time() - start_time
        print(f"Tested {key - start} keys in {elapsed:.2f} seconds", file=sys.stderr)

    print("No key found in the given range")
    return None, None

start_aes = (2**128) - 10000000 # limit key space
end_aes = 2**128

start_rc4 = (2**40) - 10000000
end_rc4 = 2**40

found_key_ECB, found_plaintext_ECB = brute_force_aes(aes_Ciphertext, plaintext, start_aes, end_aes)
found_key_RC4, found_plaintext_RC4 = brute_force_rc4(rc4_Ciphertext, plaintext, start_rc4, end_rc4)
