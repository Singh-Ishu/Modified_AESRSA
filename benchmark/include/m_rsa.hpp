#ifndef M_RSA_HPP
#define M_RSA_HPP

#include <vector>
#include <cstdint>
#include <string>

// The paper specifies using 3 primes for the RSA modulus
struct TriplePrimeKey {
    std::vector<uint8_t> n; // Modulus (a * b * c) 
    std::vector<uint8_t> e; // Public exponent 
    std::vector<uint8_t> d; // Private exponent 
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
    static std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext, 
                                        const std::vector<uint8_t>& n, 
                                        const std::vector<uint8_t>& d);

private:
    // Internal math for the Euler function: φ(n) = (a-1)(b-1)(c-1).
    static std::vector<uint8_t> calculateEuler(const std::vector<uint8_t>& a, 
                                               const std::vector<uint8_t>& b, 
                                               const std::vector<uint8_t>& c);
};

#endif