import copy
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Util import Counter

# encode with ECB CBC CFB OPB CTR
key = b'1' * 16 # 128 bit key

def encrypt_selection(mode, plaintext):
  if mode == 'ECB':
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    
    decipher = AES.new(key, AES.MODE_ECB)
    decrypted = unpad(decipher.decrypt(ciphertext), AES.block_size)
    return ciphertext, decrypted


  elif mode == 'CBC':
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    full_ciphertext = iv + ciphertext

    decipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(decipher.decrypt(ciphertext), AES.block_size)
    return full_ciphertext, decrypted


  elif mode == 'CFB':
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    ciphertext = cipher.encrypt(plaintext)
    full_ciphertext = iv + ciphertext

    decipher = AES.new(key, AES.MODE_CFB, iv)
    decrypted = decipher.decrypt(ciphertext)
    return full_ciphertext, decrypted


  elif mode == 'OPB':
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_OFB, iv)
    ciphertext = cipher.encrypt(plaintext)
    full_ciphertext = iv + ciphertext
    
    decipher = AES.new(key, AES.MODE_OFB, iv)
    decrypted = decipher.decrypt(ciphertext)
    return full_ciphertext, decrypted


  elif mode == 'CTR':
    nonce = get_random_bytes(8)
    counter_encrypt = Counter.new(64, prefix=nonce, initial_value=0)
    cipher = AES.new(key, AES.MODE_CTR, counter=counter_encrypt)
    ciphertext = cipher.encrypt(plaintext)
    full_ciphertext = nonce + ciphertext

    decrypt_counter = Counter.new(64, prefix=nonce, initial_value=0)
    decipher = AES.new(key, AES.MODE_CTR, counter=decrypt_counter)
    decrypted = decipher.decrypt(ciphertext)
    return full_ciphertext, decrypted


  else:
    raise ValueError("Invalid mode")

def flip_cipher_bit(ciphertext, index, bit_position=0):
  modified = bytearray(ciphertext)
  modified[index] ^= (1 << bit_position)
  return bytes(modified)

def test(mode, plaintext):

  print(f"Testing {mode}")

  header_len = 0 # set header for each of the nodes, ECB has no header
  if mode in ['CBC', 'CFB', 'OPB']: # these modes use 16 byte header
    header_len = 16
  elif mode == 'CTR': # CTR uses 8 byte header
    header_len = 8

  ciphertext, decrypted = encrypt_selection(mode, plaintext) # encrypt with current mode

  actual_ciphertext = ciphertext[header_len:]
  blocks = [actual_ciphertext[i:i+16] for i in range(0, len(actual_ciphertext), 16)]
  for i, block in enumerate(blocks):
      print(f"Block {i}: {block.hex()}")

  print("Decrypted text before bit-flip:", decrypted)

  flip_index = header_len # move index beyond the header
  flipped_cipher = flip_cipher_bit(ciphertext, flip_index, bit_position=0) # flip the first bit of the ciphertext

  # decrypt flipped ciphertext
  if mode == 'ECB':
    decipher = AES.new(key, AES.MODE_ECB)
    decrypted = unpad(decipher.decrypt(flipped_cipher), AES.block_size)

  elif mode == 'CBC':
    decipher = AES.new(key, AES.MODE_CBC, flipped_cipher[:header_len])
    decrypted = unpad(decipher.decrypt(flipped_cipher[header_len:]), AES.block_size)

  elif mode == 'CFB':
    decipher = AES.new(key, AES.MODE_CFB, flipped_cipher[:header_len])
    decrypted = decipher.decrypt(flipped_cipher[header_len:])

  elif mode == 'OPB':
    decipher = AES.new(key, AES.MODE_OFB, flipped_cipher[:header_len])
    decrypted = decipher.decrypt(flipped_cipher[header_len:])

  elif mode == 'CTR':
    decrypt_counter = Counter.new(64, prefix=flipped_cipher[:header_len], initial_value=0)
    decipher = AES.new(key, AES.MODE_CTR, counter=decrypt_counter)
    decrypted = decipher.decrypt(flipped_cipher[header_len:])
      
  print("Decrypted text after bit-flip:", decrypted)
  blocks = [decrypted[i:i+16] for i in range(0, len(decrypted), 16)]
  for i, block in enumerate(blocks):
      print(f"Block {i}: {block.hex()}")


if __name__ == '__main__':
  plaintext = b'0123456789ABCDEF' * 4 # 4 blocks of 16 bytes
  modes = ['ECB', 'CBC', 'CFB', 'OPB', 'CTR']
  for mode in modes:
    test(mode, plaintext)
