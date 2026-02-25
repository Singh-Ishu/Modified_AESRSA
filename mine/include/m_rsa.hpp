#ifndef M_RSA_HPP
#define M_RSA_HPP

#include <vector>
#include <cstdint>
#include <string>

// Forward declarations for OpenSSL types if we don't want to include full bn.h
typedef struct bignum_st BIGNUM;
typedef struct bignum_ctx BN_CTX;

// The paper specifies using 3 primes for the RSA modulus
struct TriplePrimeKey {
    std::vector<uint8_t> n; // Modulus (a * b * c) 
    std::vector<uint8_t> e; // Public exponent 
    std::vector<uint8_t> d; // Private exponent 
    std::vector<uint8_t> p; // Prime 1
    std::vector<uint8_t> q; // Prime 2
    std::vector<uint8_t> r; // Prime 3
};

class MRSA {
public:
    // Generate keys using the 3-prime method
    static TriplePrimeKey generateKey(int keyLength);

    // Encrypt the S-AES key using the M-RSA public key
    // Uses OAEP padding with Hash 256 as per experimental settings
    static std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext, 
                                        const std::vector<uint8_t>& n, 
                                        const std::vector<uint8_t>& e);

    // Decrypt the S-AES key using the M-RSA private key[cite: 425].
    // Uses the full TriplePrimeKey for CRT optimization
    static std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext, 
                                        const TriplePrimeKey& privateKey);

private:
    // Internal math for the Euler function: φ(n) = (a-1)(b-1)(c-1).
    static std::vector<uint8_t> calculateEuler(BIGNUM* a, BIGNUM* b, BIGNUM* c, BN_CTX* ctx);
};

#endif