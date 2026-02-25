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
    processBlocksParallel(plaintext, output, iv, true);
    return output;
}

std::vector<uint8_t> SAES::decrypt(const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& iv) {
    std::vector<uint8_t> output(ciphertext.size());
    processBlocksParallel(ciphertext, output, iv, false);
    return output;
}

void SAES::processBlocksParallel(const std::vector<uint8_t>& input, std::vector<uint8_t>& output, const std::vector<uint8_t>& iv, bool isEncrypting) {
    size_t numBlocks = input.size() / 16;

    auto processChunk = [&](size_t startBlock, size_t endBlock, std::vector<uint8_t> currentIv) {
        for (size_t i = startBlock; i < endBlock; ++i) {
            const uint8_t* inPtr = input.data() + (i * 16);
            uint8_t* outPtr = output.data() + (i * 16);
            
            if (isEncrypting) {
                uint8_t block[16];
                block[0] = inPtr[0] ^ currentIv[0];
                block[1] = inPtr[1] ^ currentIv[1];
                block[2] = inPtr[2] ^ currentIv[2];
                block[3] = inPtr[3] ^ currentIv[3];
                block[4] = inPtr[4] ^ currentIv[4];
                block[5] = inPtr[5] ^ currentIv[5];
                block[6] = inPtr[6] ^ currentIv[6];
                block[7] = inPtr[7] ^ currentIv[7];
                block[8] = inPtr[8] ^ currentIv[8];
                block[9] = inPtr[9] ^ currentIv[9];
                block[10] = inPtr[10] ^ currentIv[10];
                block[11] = inPtr[11] ^ currentIv[11];
                block[12] = inPtr[12] ^ currentIv[12];
                block[13] = inPtr[13] ^ currentIv[13];
                block[14] = inPtr[14] ^ currentIv[14];
                block[15] = inPtr[15] ^ currentIv[15];
                encryptBlock(block, outPtr);
                std::memcpy(currentIv.data(), outPtr, 16);
            } else {
                decryptBlock(inPtr, outPtr);
                outPtr[0] ^= currentIv[0];
                outPtr[1] ^= currentIv[1];
                outPtr[2] ^= currentIv[2];
                outPtr[3] ^= currentIv[3];
                outPtr[4] ^= currentIv[4];
                outPtr[5] ^= currentIv[5];
                outPtr[6] ^= currentIv[6];
                outPtr[7] ^= currentIv[7];
                outPtr[8] ^= currentIv[8];
                outPtr[9] ^= currentIv[9];
                outPtr[10] ^= currentIv[10];
                outPtr[11] ^= currentIv[11];
                outPtr[12] ^= currentIv[12];
                outPtr[13] ^= currentIv[13];
                outPtr[14] ^= currentIv[14];
                outPtr[15] ^= currentIv[15];
                std::memcpy(currentIv.data(), inPtr, 16);
            }
        }
    };

    if (numBlocks < 3) {
        processChunk(0, numBlocks, iv);
    } else {
        size_t blocksPerThread = numBlocks / 3;
        size_t remainder = numBlocks % 3;

        size_t end1 = blocksPerThread + (remainder > 0 ? 1 : 0);
        size_t end2 = end1 + blocksPerThread + (remainder > 1 ? 1 : 0);

        std::vector<uint8_t> iv1 = iv;
        std::vector<uint8_t> iv2 = iv; 
        std::vector<uint8_t> iv3 = iv; 

        std::thread t1(processChunk, 0, end1, iv1);
        std::thread t2(processChunk, end1, end2, iv2);
        std::thread t3(processChunk, end2, numBlocks, iv3);

        t1.join();
        t2.join();
        t3.join();
    }
}