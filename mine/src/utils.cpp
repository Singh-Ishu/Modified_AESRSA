#include "utils.hpp"
#include <stdexcept>
#include <iomanip>
#include <sstream>

namespace Utils {

void addPKCS7Padding(std::vector<uint8_t>& data, size_t blockSize) {
    uint8_t paddingLen = blockSize - (data.size() % blockSize);
    data.insert(data.end(), paddingLen, paddingLen);
}

void removePKCS7Padding(std::vector<uint8_t>& data) {
    if (data.empty()) return;
    
    uint8_t paddingLen = data.back();
    
    // Validate padding length
    if (paddingLen == 0 || paddingLen > 16 || paddingLen > data.size()) {
        throw std::invalid_argument("Invalid PKCS7 padding length.");
    }
    
    // Verify all padding bytes match
    for (size_t i = data.size() - paddingLen; i < data.size(); ++i) {
        if (data[i] != paddingLen) {
            throw std::invalid_argument("Corrupted PKCS7 padding.");
        }
    }
    
    data.resize(data.size() - paddingLen);
}

std::string toHexString(const std::vector<uint8_t>& data) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (uint8_t b : data) {
        oss << std::setw(2) << static_cast<int>(b);
    }
    return oss.str();
}

std::vector<uint8_t> fromHexString(const std::string& hex) {
    if (hex.length() % 2 != 0) {
        throw std::invalid_argument("Hex string must have an even length.");
    }
    
    std::vector<uint8_t> bytes;
    bytes.reserve(hex.length() / 2);
    
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::strtol(byteString.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

} // namespace Utils