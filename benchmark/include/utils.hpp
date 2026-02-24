#ifndef UTILS_HPP
#define UTILS_HPP

#include <vector>
#include <cstdint>
#include <string>

namespace Utils {
    //Adds PKCS7 padding to the plaintext.
    void addPKCS7Padding(std::vector<uint8_t>& data, size_t blockSize);

    //Removes PKCS7 padding after decryption.
    void removePKCS7Padding(std::vector<uint8_t>& data);

    //Converts byte arrays to readable Hex strings for the benchmark logs.
    std::string toHexString(const std::vector<uint8_t>& data);

    //Converts Hex strings back to byte arrays.
    std::vector<uint8_t> fromHexString(const std::string& hex);
}

#endif // UTILS_HPP