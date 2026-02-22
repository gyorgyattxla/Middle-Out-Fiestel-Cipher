# Middle-Out Feistel Cipher: CLI Password Vault

## Overview
This project implements a custom 64-bit symmetric block cipher structured on a 16-round Feistel Network, accompanied by a stateful Command Line Interface (CLI) password manager written in Java. 

The cipher departs from traditional sequential block splitting (Left/Right) by introducing a **"Middle-Out" permutation strategy**. Data blocks are divided into "Inner" and "Outer" halves based on their proximity to the center of the block, introducing spatial diffusion prior to the mathematical confusion layer.

## Cryptographic Architecture

### 1. Block and Key Parameters
* **Block Size:** 64 bits (8 bytes).
* **Padding:** Strict PKCS#7 standard applied universally, ensuring deterministic unpadding.
* **Key Derivation Function (KDF):** Unique keys are generated per entry. The user's in-memory Master Key is concatenated with the plaintext entry identifier (the "initializer"). This combined string is hashed via SHA-512.
* **Key Schedule:** The 512-bit SHA-512 hash is sliced into 16 distinct 32-bit (4-byte) round keys, ensuring high entropy and preventing key-reuse vulnerabilities across different stored passwords.

### 2. The Middle-Out Permutation
Before entering the Feistel rounds, the 8-byte block is split using dual-pointer logic starting from indices 3 and 4, moving outward:
* **Inner Half ($Inner_0$):** Indices 3, 4, 2, 5.
* **Outer Half ($Outer_0$):** Indices 1, 6, 0, 7.

This identical spatial mapping is reversed during the final ciphertext reassembly block.

### 3. The 16-Round Engine
For rounds $i = 0$ to $15$, the algorithm applies standard Feistel XOR merging:
$$newInner = Outer_{i-1} \oplus F(Inner_{i-1}, K_i)$$

Following the golden rule of Feistel networks, the data halves are swapped at the end of every round *except* the final round ($i = 15$), ensuring the encryption and decryption processes utilize the exact same structural code by simply reversing the Key Schedule sequence.

### 4. The F-Function ($F$)
The internal F-Function handles bit-level scrambling to achieve both confusion and diffusion within the 32-bit half-block, strictly utilizing bitwise masking to counteract Java's signed-byte promotion constraints. 

For each byte index $j$:
1. **Modular Addition:** $$Sum = (Data_j + Key_j) \pmod{256}$$
2. **Circular Bit Rotation:** Simulates an 8-bit unsigned circular left shift by 3 bits.
   $$Scrambled_j = (Sum \ll 3) \lor (Sum \gg 5)$$
3. **Avalanche Diffusion Cascade:** A sequential XOR cascade is applied post-rotation so modifying $Data_0$ aggressively alters $Data_3$.

### 5. Padding Validation (Tamper Detection)
During decryption, the engine reads the final byte to determine the PKCS#7 pad length. A custom `InvalidKeyException` is thrown if the extracted integer falls outside the valid bounds ($1 \le x \le 8$). This acts as a localized padding oracle, allowing the application to gracefully reject incorrect Master Keys or corrupted ciphertext without throwing native array-bounds exceptions.

## Storage and Application Flow
* **Data Serialization:** Ciphertext `byte[]` arrays are converted to Base64 strings to ensure safe text-encoding.
* **Vault Storage:** Data is persisted in a local `vault.txt` file format using an `Identifier:Base64Ciphertext` schema.
* **Memory Safety:** The Master Key is held in volatile memory (RAM) during the CLI session and is never written to disk. 

## Command Line Interface (CLI) Usage
Upon execution, the user provides the Master Key to unlock the session. The interactive shell supports the following commands:
* `enc.{PASSWORD}.{INITIALIZER}`: Encrypts the password, binds it to the initializer, and appends it to the vault.
* `dec.{INITIALIZER}`: Decrypts the target using the Master Key and outputs the plaintext.
* `shw`: Returns a list of all saved initializers.
* `del.{INITIALIZER}`: Safely purges the selected initializer and ciphertext from the storage file.
* `hlp`: Prints command usage documentation.
* `ext`: Safely closes the stream and terminates the application.

## Academic Limitations & Security Considerations
As a custom cryptographic implementation, this cipher is designed for educational exploration rather than production deployment. Acknowledged limitations include:
1. **Timing Attacks:** The implementation utilizes standard Java array and mathematical operators that do not execute in strictly constant time.
2. **No Message Authentication Code (MAC):** While the PKCS#7 validator acts as a basic integrity check, the cipher lacks a dedicated HMAC-SHA256 signature to mathematically guarantee the ciphertext has not been maliciously altered in transit.
