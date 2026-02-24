# MRA Hybrid Encryption: Enhanced AES-RSA for IoT
This repository implements the MRA (Modified RSA-AES) Hybrid Encryption protocol, specifically optimized for low-power IoT devices in edge environments. It builds upon the research presented in Scientific Reports (2025).


## Overview:
Standard IoT encryption often struggles with the trade-off between security and power consumption. The MRA protocol solves this by combining an optimized asymmetric algorithm for key exchange and a high-speed symmetric algorithm for data transmission.


## Core Architecture per initial paper:

* M-RSA (Modified RSA): Replaces the traditional dual-prime system with a triple-prime system. This reduces the bit length of each prime, decreasing factorization time and optimizing key generation for constrained hardware.
* S-AES (Simplified/Streamlined AES): Optimized from the standard 10-round operation down to 7 rounds. Research indicates that no effective attacks currently exist against the 7-round version, making it a safe choice for efficiency gains.

## Proposed Enhancements:
This version extends the base research with three critical efficiency improvements:
* Manual Loop Unrolling: Applied to the 7-round AES operation to eliminate loop overhead and branching latency.
* Dynamic Multithreading: Upgrading the paper's fixed 3-threaded design  to a dynamic pool that scales to use all available CPU cores.
* Bit Slicing: Transitioning from state-matrix processing to bit-level parallelism, enabling the simultaneous encryption of multiple data blocks via bitwise logical operations.

## Performance (as compared to the base paper)