"""
Shellcode should look like the following:
\x33\xc9\x64\x8b\x49\x30\x8b\x49\...

"""

def prepare_shellcode_for_encryption(shellcode_str):
  # Remove all whitespaces, line breaks, and double quotes, and keep "\x" for hexadecimal notation
  formatted_shellcode = ''.join(shellcode_str.split())
  formatted_shellcode = formatted_shellcode.replace('"', '').replace("\\x", "")
  return formatted_shellcode

# Example usage with a complete shellcode string
shellcode_str = r"""
                    
"""

# this function call will prepare it correctly for encryption:
formatted_shellcode = prepare_shellcode_for_encryption(shellcode_str)

# This will output the formatted shellcode without spaces, new lines, double quotes, or "\x" prefixes.
print(formatted_shellcode)
