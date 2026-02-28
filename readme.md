
# MRA Hybrid Encryption: Technical Implementation Overview

This repository contains two C++ implementations of the MRA (Modified RSA-AES) Hybrid Encryption protocol, designed for secure and efficient operation on resource-constrained IoT devices. The `benchmark` and `mine` folders provide distinct approaches to cryptographic operations and parallelization, as detailed below.

## Repository Structure

- `benchmark/`: Reference implementation, closely following the original paper's specification.
- `mine/`: Enhanced implementation with advanced performance optimizations and dynamic parallelization.

## Cryptographic Algorithms

### 1. S-AES (Streamlined AES, 7 Rounds)

- **Rounds:** Both implementations use 7 rounds (see `ROUNDS = 7`). Each round includes SubBytes, ShiftRows, MixColumns (except final round), and AddRoundKey.
- **Block Size:** 128 bits (16 bytes).
- **Key Expansion:** 8 round keys (128 bytes total) are generated for all rounds.
- **AddRoundKey:**
  - `mine`: Manually unrolled XOR for each byte (explicit 16 operations per block).
  - `benchmark`: Uses a for-loop to XOR each byte.
- **Block Mode:**
  - `mine`: CTR (Counter) mode. No padding required. Fully parallelizable.
  - `benchmark`: CBC (Cipher Block Chaining) mode with PKCS7 padding. Sequential dependency within thread chunk.
- **Parallelization:**
  - `mine`: Dynamic thread allocation based on hardware concurrency (uses up to all available CPU cores, or 4 if undetectable). Each thread processes a chunk of blocks independently in CTR mode.
  - `benchmark`: Fixed 3-thread pool. Each thread processes a contiguous chunk of blocks in CBC mode, maintaining its own IV chain.
- **Optimizations:**
  - Both use lambda functions for per-thread block processing and memcpy for fast state/block copying.
  - `mine` leverages manual loop unrolling for AddRoundKey, which can improve performance on some CPUs.

#### S-AES Encryption Algorithm (7 Rounds)

    State ← Plaintext
    AddRoundKey(State, K₀)
    for round = 1 to 6:
        SubBytes(State)
        ShiftRows(State)
        MixColumns(State)
        AddRoundKey(State, K_round)
    SubBytes(State)
    ShiftRows(State)
    AddRoundKey(State, K₇)
    Ciphertext ← State

### 2. M-RSA (Triple-Prime RSA)

- **Key Generation:**
  - Modulus: n = p × q × r, where p, q, r are distinct primes (each ≈ keyLength/3 bits).
  - Euler's totient: φ(n) = (p-1)(q-1)(r-1).
  - Public exponent: e = 65537.
  - Private exponent: d ≡ e⁻¹ mod φ(n).
- **Encryption:** C ≡ M^e mod n.
- **Decryption:**
  - Uses Chinese Remainder Theorem (CRT) for efficiency:
    - Compute dp = d mod (p-1), dq = d mod (q-1), dr = d mod (r-1).
    - m₁ = C^dp mod p, m₂ = C^dq mod q, m₃ = C^dr mod r.
    - Combine results using modular inverses and recombination to recover M.
- **Implementation:** All big integer operations use OpenSSL BIGNUM. CRT decryption provides significant speedup by working with smaller moduli.

## Implementation Comparison

| Feature                | mine                        | benchmark                   |
|------------------------|-----------------------------|-----------------------------|
| AES Rounds             | 7                           | 7                           |
| Block Mode             | CTR                         | CBC + PKCS7                 |
| Threading              | Dynamic (CPU-based)         | Fixed (3 threads)           |
| AddRoundKey            | Manual unroll (XOR each)    | For-loop (XOR)              |
| Padding                | None                        | PKCS7                       |
| Key Expansion          | 7+1 rounds                  | 7+1 rounds                  |
| RSA Variant            | Triple-prime                | Triple-prime                |
| CRT Decryption         | Yes                         | Yes                         |

### Threading and Parallelization

- `mine`: Uses dynamic thread count (up to hardware concurrency), CTR mode (no chaining dependency), and manual unrolling for AddRoundKey. Each thread processes a chunk of blocks independently, maximizing parallelism and throughput.
- `benchmark`: Uses a fixed 3-thread pool, CBC mode (chaining dependency within thread chunk), and a for-loop for AddRoundKey. Each thread processes a contiguous range of blocks, but parallelism is limited by CBC dependencies.

### Block Processing

- Both implementations process blocks in parallel, but `mine` can scale to more threads and is fully parallelizable due to CTR mode. `benchmark` is limited to 3 threads and has partial parallelism due to CBC chaining.

### Padding

- `mine`: No padding required (CTR mode).
- `benchmark`: PKCS7 padding is added/removed for CBC mode.

## Cryptographic Workflow

1. **Key Exchange (M-RSA):**
   - Receiver generates triple-prime keypair.
   - Sender encrypts S-AES session key with receiver's public key.
   - Receiver decrypts using CRT-optimized private key operation.
2. **Data Transmission (S-AES):**
   - Sender encrypts payload with session key using 7-round AES.
   - Block mode and threading as described above.
3. **Decryption:**
   - Receiver applies inverse transformations.
   - Session key ensures confidentiality.
   - Asymmetric overhead is amortized across the session.

## Technical Dependencies

- OpenSSL (libcrypto): BIGNUM arithmetic for M-RSA operations.
- C++11 or later: Threading primitives, smart pointers, lambda functions.
- Standard library: Vector containers, memory management.

## Security and Performance Considerations

- Triple-prime RSA provides security equivalent to dual-prime for the same modulus size, with improved decryption speed via CRT.
- 7-round AES provides a balance between security and computational efficiency for IoT applications.
- CTR mode (mine) is fully parallelizable and requires unique IV per message (nonce reuse is catastrophic).
- CBC mode (benchmark) is less parallelizable and requires PKCS7 padding.
- Manual loop unrolling (mine) can improve performance on some CPUs.

## Summary

This repository demonstrates two approaches to hybrid cryptography for IoT, highlighting the impact of block mode, threading strategy, and code-level optimizations on performance and security. The `mine` implementation is optimized for modern multi-core CPUs and high-throughput scenarios, while `benchmark` provides a reference for the original protocol specification.