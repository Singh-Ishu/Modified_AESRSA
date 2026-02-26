#include "s_aes.hpp"
#include "aes_core.hpp"
#include <thread>
#include <cmath>
#include <cstring>

SAES::SAES(const std::vector<uint8_t>& key) {
    expandedKey = AESCore::ExpandKey(key, ROUNDS);
}

void SAES::encryptBlock(const uint8_t* input, uint8_t* output) const {
    AESCore::State state;
    std::memcpy(state.data(), input, 16);
    
    AESCore::AddRoundKey(state, expandedKey.data());

    for (int round = 1; round < ROUNDS; ++round) {
        AESCore::SubBytes(state);
        AESCore::ShiftRows(state);
        AESCore::MixColumns(state);
        AESCore::AddRoundKey(state, expandedKey.data() + (round * 16));
    }

    AESCore::SubBytes(state);
    AESCore::ShiftRows(state);
    AESCore::AddRoundKey(state, expandedKey.data() + (ROUNDS * 16));
    
    std::memcpy(output, state.data(), 16);
}

void SAES::decryptBlock(const uint8_t* input, uint8_t* output) const {
    AESCore::State state;
    std::memcpy(state.data(), input, 16);

    AESCore::AddRoundKey(state, expandedKey.data() + (ROUNDS * 16));

    for (int round = ROUNDS - 1; round > 0; --round) {
        AESCore::InvShiftRows(state);
        AESCore::InvSubBytes(state);
        AESCore::AddRoundKey(state, expandedKey.data() + (round * 16));
        AESCore::InvMixColumns(state);
    }

    AESCore::InvShiftRows(state);
    AESCore::InvSubBytes(state);
    AESCore::AddRoundKey(state, expandedKey.data());

    std::memcpy(output, state.data(), 16);
}

std::vector<uint8_t> SAES::encrypt(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& iv) {
    std::vector<uint8_t> output(plaintext.size());
    processBlocksParallel(plaintext, output, iv);
    return output;
}

std::vector<uint8_t> SAES::decrypt(const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& iv) {
    std::vector<uint8_t> output(ciphertext.size());
    processBlocksParallel(ciphertext, output, iv);
    return output;
}

void SAES::processBlocksParallel(const std::vector<uint8_t>& input, std::vector<uint8_t>& output, const std::vector<uint8_t>& iv) {
    if (input.empty()) return;

    size_t numBlocks = (input.size() + 15) / 16;
    unsigned int numThreads = std::thread::hardware_concurrency();
    if (numThreads == 0) numThreads = 4;
    if (numThreads > numBlocks) numThreads = numBlocks;

    auto processChunk = [&](size_t startBlock, size_t endBlock) {
        for (size_t i = startBlock; i < endBlock; ++i) {
            uint8_t counter[16];
            std::memcpy(counter, iv.data(), 16);
            
            uint64_t carry = i;
            for (int j = 15; j >= 0 && carry > 0; --j) {
                carry += counter[j];
                counter[j] = carry & 0xFF;
                carry >>= 8;
            }

            uint8_t keystream[16];
            encryptBlock(counter, keystream);

            size_t inOffset = i * 16;
            size_t remaining = input.size() - inOffset;
            size_t bytesToProcess = remaining < 16 ? remaining : 16;

            const uint8_t* inPtr = input.data() + inOffset;
            uint8_t* outPtr = output.data() + inOffset;

            if (bytesToProcess == 16) {
                outPtr[0] = inPtr[0] ^ keystream[0];
                outPtr[1] = inPtr[1] ^ keystream[1];
                outPtr[2] = inPtr[2] ^ keystream[2];
                outPtr[3] = inPtr[3] ^ keystream[3];
                outPtr[4] = inPtr[4] ^ keystream[4];
                outPtr[5] = inPtr[5] ^ keystream[5];
                outPtr[6] = inPtr[6] ^ keystream[6];
                outPtr[7] = inPtr[7] ^ keystream[7];
                outPtr[8] = inPtr[8] ^ keystream[8];
                outPtr[9] = inPtr[9] ^ keystream[9];
                outPtr[10] = inPtr[10] ^ keystream[10];
                outPtr[11] = inPtr[11] ^ keystream[11];
                outPtr[12] = inPtr[12] ^ keystream[12];
                outPtr[13] = inPtr[13] ^ keystream[13];
                outPtr[14] = inPtr[14] ^ keystream[14];
                outPtr[15] = inPtr[15] ^ keystream[15];
            } else {
                for (size_t k = 0; k < bytesToProcess; ++k) {
                    outPtr[k] = inPtr[k] ^ keystream[k];
                }
            }
        }
    };

    std::vector<std::thread> threads;
    size_t blocksPerThread = numBlocks / numThreads;
    size_t remainder = numBlocks % numThreads;

    size_t currentStart = 0;
    for (unsigned int i = 0; i < numThreads; ++i) {
        size_t currentEnd = currentStart + blocksPerThread + (i < remainder ? 1 : 0);
        if (currentEnd > currentStart) {
            threads.emplace_back(processChunk, currentStart, currentEnd);
        }
        currentStart = currentEnd;
    }

    for (auto& t : threads) {
        t.join();
    }
}