def xor_encrypt(decrypted_shellcode, key):
  encrypted_shellcode = bytearray()
  for byte in decrypted_shellcode:
      encrypted_shellcode.append(byte ^ key)
  return encrypted_shellcode

def shellcode_to_bytearray(shellcode_str):
  shellcode = bytearray.fromhex(shellcode_str)
  return shellcode

def format_encrypted_shellcode(shellcode):
  formatted_shellcode = ''.join(f'{byte:02x}' for byte in shellcode)
  return formatted_shellcode

# Decrypted shellcode input
decrypted_shellcode_str = ""

# Convert decrypted shellcode string to bytearray for processing
decrypted_shellcode = shellcode_to_bytearray(decrypted_shellcode_str)

# The key used for XOR encryption/decryption (must be the same key used for decryption)
key = 0xAA

# Encrypt the shellcode
encrypted_shellcode = xor_encrypt(decrypted_shellcode, key)

# Format the encrypted shellcode
formatted_encrypted_shellcode = format_encrypted_shellcode(encrypted_shellcode)

# Output the formatted encrypted shellcode
print("Formatted Encrypted Shellcode:", formatted_encrypted_shellcode)
