#ifndef AES_CORE_HPP
#define AES_CORE_HPP

#include <cstdint>
#include <array>
#include <vector>

namespace AESCore {
    // Standard AES State: 4x4 matrix of bytes in column-major order
    using State = std::array<uint8_t, 16>;

    // Core forward transformations
    void SubBytes(State& state);
    void ShiftRows(State& state);
    void MixColumns(State& state);
    void AddRoundKey(State& state, const uint8_t* roundKey);

    // Core inverse transformations (for decryption)
    void InvSubBytes(State& state);
    void InvShiftRows(State& state);
    void InvMixColumns(State& state);

    // Key Expansion
    // For S-AES 256-bit key and 7 rounds, we need 8 round keys (1 initial + 7 rounds).
    // Total expansion size: 8 * 16 bytes = 128 bytes.
    std::vector<uint8_t> ExpandKey(const std::vector<uint8_t>& key, int rounds);
}

#endif