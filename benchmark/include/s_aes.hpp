#ifndef S_AES_HPP
#define S_AES_HPP

#include <vector>
#include <cstdint>
#include <future>

class SAES {
public:
    // Initialize with a 256-bit key
    explicit SAES(const std::vector<uint8_t>& key);

    // Encrypts using CBC mode, PKCS7 padding, 7 rounds, and 3-thread pool
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& iv);

    // Decrypts using CBC mode, PKCS7 padding, 7 rounds, and 3-thread pool
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& iv);

private:
    static constexpr int ROUNDS = 7; 
    std::vector<uint8_t> expandedKey;

    // Single block transformations mapped to Algorithm 1 and 2
    void encryptBlock(const uint8_t* input, uint8_t* output) const;
    void decryptBlock(const uint8_t* input, uint8_t* output) const;

    // Thread pool orchestration for CBC processing
    void processBlocksParallel(const std::vector<uint8_t>& input, std::vector<uint8_t>& output, const std::vector<uint8_t>& iv, bool isEncrypting);
};

#endif