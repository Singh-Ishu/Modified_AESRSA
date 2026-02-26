# MRA Hybrid Encryption: Enhanced AES-RSA for IoT

This repository implements the MRA (Modified RSA-AES) Hybrid Encryption protocol, specifically optimized for low-power IoT devices in edge environments. It builds upon the research presented in Scientific Reports (2025).

## Overview

Standard IoT encryption often struggles with the trade-off between security and power consumption. The MRA protocol solves this by combining an optimized asymmetric algorithm for key exchange and a high-speed symmetric algorithm for data transmission.

## Repository Structure

- `benchmark/`: Reference implementation following the original paper's specifications
- `mine/`: Enhanced implementation with performance optimizations

## Core Cryptographic Architecture

### M-RSA (Modified RSA) - Triple-Prime Asymmetric Encryption

The M-RSA implementation replaces traditional dual-prime RSA with a triple-prime modulus system:

**Key Generation Algorithm:**
- Modulus: `n = p × q × r` where p, q, r are distinct primes
- For 1024-bit keys: each prime ≈ 341 bits (keyLength/3)
- Euler's totient: `φ(n) = (p-1)(q-1)(r-1)`
- Public exponent: `e = 65537` (RSA_F4)
- Private exponent: `d ≡ e⁻¹ (mod φ(n))`

**Encryption:** `C ≡ M^e (mod n)`

**Decryption with Chinese Remainder Theorem (CRT):**
- Compute: `dp = d mod (p-1)`, `dq = d mod (q-1)`, `dr = d mod (r-1)`
- Calculate: `m₁ = C^dp mod p`, `m₂ = C^dq mod q`, `m₃ = C^dr mod r`
- Reconstruct: `M = (m₁·qr·(qr)⁻¹ₚ + m₂·pr·(pr)⁻¹_q + m₃·pq·(pq)⁻¹ᵣ) mod n`

**Advantages:**
- Reduced prime bit-length decreases factorization complexity
- CRT optimization provides ~3x speedup for decryption operations
- Lower computational overhead for resource-constrained devices

### S-AES (Streamlined AES) - 7-Round Symmetric Encryption

Both implementations use a reduced-round AES variant with 128-bit keys:

**Core Transformations (per round):**
- `SubBytes`: Non-linear byte substitution using S-box
- `ShiftRows`: Cyclic row shifts in state matrix
- `MixColumns`: Column-wise mixing in GF(2⁸) (rounds 1-6 only)
- `AddRoundKey`: XOR with expanded round key

**Key Schedule:**
- Input: 128-bit key
- Output: 8 round keys (128 bytes total)
- Expansion: Standard AES key expansion for 7 rounds

**Encryption Algorithm:**
```
State ← Plaintext
AddRoundKey(State, K₀)
for round = 1 to 6:
    SubBytes(State)
    ShiftRows(State)
    MixColumns(State)
    AddRoundKey(State, Kᵣₒᵤₙ𝒹)
SubBytes(State)
ShiftRows(State)
AddRoundKey(State, K₇)
Ciphertext ← State
```

**Security Rationale:**
- 7 rounds provide sufficient diffusion and confusion
- No known practical attacks against 7-round AES-128
- Reduces computational cost by 30% vs standard 10-round AES

## Implementation Variants

### Benchmark Implementation (Original Paper Specification)

**S-AES Configuration:**
- Mode: CBC (Cipher Block Chaining)
- Padding: PKCS7
- Threading: Fixed 3-thread pool
- Block processing: Sequential within threads

**CBC Mode Operation:**
- Encryption: `Cᵢ = Eₖ(Pᵢ ⊕ Cᵢ₋₁)`, where `C₀ = IV`
- Decryption: `Pᵢ = Dₖ(Cᵢ) ⊕ Cᵢ₋₁`
- Dependency: Each block depends on previous ciphertext

**Threading Strategy:**
- Workload divided equally among 3 threads
- Each thread processes consecutive blocks with independent IV
- Limited parallelization due to CBC chaining dependencies

### Enhanced Implementation (Optimized)

**S-AES Configuration:**
- Mode: CTR (Counter Mode)
- Threading: Dynamic thread pool (scales to hardware_concurrency)
- Block processing: Fully parallelized with manual loop unrolling

**CTR Mode Operation:**
- Keystream generation: `Kᵢ = Eₖ(IV + i)`
- Encryption/Decryption: `Cᵢ = Pᵢ ⊕ Kᵢ` (symmetric operation)
- No chaining dependencies - fully parallelizable

**Performance Optimizations:**

1. **Dynamic Multithreading:**
   - Detects available CPU cores via `std::thread::hardware_concurrency()`
   - Distributes blocks evenly across all cores
   - Eliminates fixed thread bottleneck from benchmark

2. **Manual Loop Unrolling:**
   - XOR operations unrolled for full 16-byte blocks
   - Eliminates loop overhead and branch prediction penalties
   - Compiler can optimize to SIMD instructions

3. **Counter Mode Benefits:**
   - Parallel block processing (no sequential dependencies)
   - Identical encrypt/decrypt operations
   - No padding required for arbitrary-length messages
   - Random access to any block without processing predecessors

**Code Example (Unrolled XOR):**
```cpp
outPtr[0] = inPtr[0] ^ keystream[0];
outPtr[1] = inPtr[1] ^ keystream[1];
// ... (16 operations total)
outPtr[15] = inPtr[15] ^ keystream[15];
```

## Cryptographic Workflow

1. **Key Exchange Phase (M-RSA):**
   - Receiver generates triple-prime keypair
   - Sender encrypts S-AES session key with receiver's public key
   - Receiver decrypts using CRT-optimized private key operation

2. **Data Transmission Phase (S-AES):**
   - Sender encrypts payload with session key
   - 7-round AES transformation applied to each 16-byte block
   - Mode-specific chaining (CBC in benchmark, CTR in enhanced)

3. **Decryption Phase:**
   - Receiver applies inverse transformations
   - Session key ensures confidentiality
   - Asymmetric overhead amortized across entire session

## Technical Dependencies

- OpenSSL (libcrypto): BIGNUM arithmetic for M-RSA operations
- C++11 or later: Threading primitives, smart pointers, lambda functions
- Standard library: Vector containers, memory management

## Performance Characteristics

The enhanced implementation targets:
- Reduced latency through parallel processing
- Better CPU utilization via dynamic thread scaling
- Lower overhead from unrolled operations
- Improved throughput for bulk data encryption

## Security Considerations

- Triple-prime RSA maintains equivalent security to dual-prime with same modulus size
- 7-round AES provides adequate security margin for IoT applications
- CTR mode requires unique IV per message (nonce reuse catastrophic)
- CRT implementation must use constant-time operations to prevent timing attacks