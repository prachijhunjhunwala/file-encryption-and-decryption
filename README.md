# ASCON Lightweight Cryptographic File Security and Performance Analysis System

[![Python 3.12](https://img.shields.io/badge/Python-3.12-blue.svg)](https://www.python.org/)
[![NIST LWC Standard](https://img.shields.io/badge/NIST-Lightweight_Cryptography_Standard-green.svg)](https://csrc.nist.gov/projects/lightweight-cryptography)
[![Department](https://img.shields.io/badge/Department-AIML-orange.svg)](#)
[![Academic Year](https://img.shields.io/badge/Year-2026-purple.svg)](#)

An integrated, high-performance, secure file preservation system developed as a 

This system implements **ASCON-128**, the modern **NIST Lightweight Cryptography (LWC) Standard** (ratified in 2023 for resource-constrained environments), establishing a highly secure, authenticated alternative to legacy and deprecated ciphers like RC4. It delivers single-pass confidentiality, integrity, and authenticity (AEAD) for local file storage, combined with a secondary, memory-safe, stream-based **SHA-256** directory integrity auditing pipeline.

---

## 📖 Table of Contents
1. [Key Features](#-key-features)
2. [Symmetric Encryption Architecture & File Packaging](#-symmetric-encryption-architecture--file-packaging)
3. [Integrity Auditing & Side-Channel Defense](#-integrity-auditing--side-channel-defense)
4. [Asynchronous GUI Layer](#-asynchronous-gui-layer)
5. [Directory & Repository Layout](#-directory--repository-layout)
6. [Empirical Results & Statistical Performance Analysis](#-empirical-results--statistical-performance-analysis)
7. [Cryptographic Matrix: ASCON-128 vs. Legacy RC4](#-cryptographic-matrix-ascon-128-vs-legacy-rc4)
8. [Installation & Setup](#-installation--setup)
9. [Step-by-Step Execution Manual](#-step-by-step-execution-manual)
10. [Academic Metadata & Attributions](#-academic-metadata--attributions)

---

## 🌟 Key Features

*   **Symmetric Key Generation:** Utilizes the host operating system's cryptographically secure hardware entropy pool (`secrets.token_bytes()`) to generate high-entropy, 128-bit symmetric keys.
*   **ASCON-128 AEAD Encryption/Decryption:** Offers single-pass Authenticated Encryption with Associated Data (AEAD) to encrypt local files (saving as `.ascon`), guaranteeing that any bitwise tampering halts decryption immediately.
*   **Memory-Safe SHA-256 Hashing:** Stream-based digest generator that processes files in static **64 KB chunks**, maintaining a constant memory footprint (< 23 MB RAM) to prevent Out-Of-Memory (OOM) faults on large files.
*   **Constant-Time Integrity Verification:** Implements constant-time byte string matching using Python's `secrets.compare_digest()` to completely neutralize side-channel timing attack vectors.
*   **Dynamic Performance Metrics Engine:** An integrated `CryptographicMetricsAnalyzer` that logs execution times (in milliseconds) and file sizes for all operations, with on-screen performance reports and JSON data exports (`metrics_report.json`).
*   **Professional Cybersecurity Aesthetic:** Built with a multi-threaded Tkinter interface featuring a high-contrast "cybersecurity control room" dark theme and a real-time terminal-style Activity Log.

---

## 🔐 Symmetric Encryption Architecture & File Packaging

The encryption core operates on **ASCON-128**, a lightweight sponge-construction symmetric cipher. To protect file confidentiality and authenticity, the system generates a unique, cryptographically secure 128-bit initialization vector (nonce) for each operation and processes the file with a fixed, system-level Associated Data (AD) tag: `b"ASCON-SECURE-FILE-ENCRYPTION-SYSTEM-v1.0"`.

### Binary Packaging Format (`.ascon`)
When a file is encrypted, it is structured into a proprietary, flat binary stream layout to ensure seamless transport and exact parsing during decryption:

```text
+------------------------------------+-----------------------+---------------------------------------+
|  Nonce Length Header (4 Bytes)     |   Nonce (16 Bytes)    |  Ciphertext + AEAD Tag (Variable)     |
|  (Raw Big-Endian UInt32)           |  (128-bit unique IV)  |  (Plaintext + 16-Byte Auth Tag)       |
+------------------------------------+-----------------------+---------------------------------------+
```

*   **Fixed Packet Overhead:** This structural design incurs a flat **36-byte overhead** (4 bytes for nonce length + 16 bytes for nonce + 16 bytes for the authentication tag) regardless of the original file size or type.

---

## 🛡️ Integrity Auditing & Side-Channel Defense

The system utilizes a dual-layer security approach:
1.  **ASCON AEAD Tag (On-Access Validation):** On decryption, the 128-bit signature is validated. If even a single bit of the encrypted `.ascon` file is tampered with, the ASCON permutation core aborts execution and throws an `Authentication Failure` error, protecting the target system from malicious payload execution.
2.  **SHA-256 Directory Fingerprinting (Cold-Storage Audit):** To permit fast, directory-level audits without executing resource-heavy decryption, the system hashes files and saves their 256-bit fingerprints as `.hash` files. 

### Side-Channel Timing Attack Prevention
Standard string matching functions (`==`) exit immediately on the first non-matching byte, creating tiny timing discrepancies. Over thousands of automated requests, an attacker can analyze these timing differences to reconstruct a valid cryptographic hash byte-by-byte. 

To eliminate this timing leak, the system's verification engine uses a constant-time bitwise XOR comparison:

$$\text{Result} = \bigwedge_{i=0}^{n-1} (A_i \oplus B_i == 0)$$

By implementing `secrets.compare_digest()`, the verification routine evaluates the entire length of the hash digests regardless of where a mismatch occurs, maintaining an absolute constant-time execution profile.

---

## 🖥️ Asynchronous GUI Layer

To prevent the User Interface (UI) from freezing during heavy operations (such as processing large multi-megabyte video files), the system separates the frontend from the backend using an **Asynchronous Multi-threaded Worker Model**:

```text
                      [ Main Tkinter GUI Thread ]
                         /                 \
        (Triggers Browse/UI updates)     (Spawns Async Worker Task)
                       /                     \
                      v                       v
            [ User Interaction ]     [ Background Worker Thread ]
            * Fluid buttons            * Cryptographic processing
            * Activity Log scrolls     * Dynamic metrics collection
            * Folder shortcuts active  * File system read/write
                      \                       /
                       \                     /
                    [ Synchronized Main Thread UI Update ]
```

Cryptographic tasks are executed off-thread, and the results are safely pushed back to the Tkinter main loop to update the central terminal activity log, ensuring fluid usability.

---

## 📂 Directory & Repository Layout

The system utilizes a cleanly separated, directory-based folder hierarchy to manage keys, hashes, output targets, and metadata:

```text
├── main.py                 # Application Entry Point (initializes GUI and launches loop)
├── gui.py                  # Graphical User Interface (Tkinter dark-theme layouts & async threads)
├── crypto_backend.py       # Cryptographic Engine (Key management, ASCON AEAD, SHA-256 stream)
├── requirements.txt        # Third-party dependency definitions (such as 'ascon')
├── Ascon/                  # Native python ASCON permutation core library
├── keys/                   # Secure storage for generated 128-bit key files (.key)
├── encrypted/              # Output folder for encrypted file payloads (.ascon)
├── decrypted/              # Output folder for successfully recovered files
├── hashes/                 # Storage for generated SHA-256 deterministic fingerprints (.hash)
└── metrics/                # Storage for local performance database (metrics_report.json)
```

---

## 📊 Empirical Results & Statistical Performance Analysis

To evaluate efficiency, the system was benchmarked using two sample payloads representing distinct storage classes: a document file (`test.pdf`, size: 388,588 bytes / ~379 KB) and a media file (`test.mp4`, size: 2,699,077 bytes / ~2.57 MB).

### 1. Empirical Latency Measurements

| Cryptographic Operation | Document Payload: `test.pdf` <br> (388,588 Bytes) | Media Payload: `test.mp4` <br> (2,699,077 Bytes) | Computational Behavior |
| :--- | :---: | :---: | :--- |
| **Symmetric Key Generation** | 0.5352 ms | N/A *(Key is Reusable)* | Hardware-entropy based, constant-time |
| **ASCON-128 Encryption** | 1,008.1036 ms | 16,339.9647 ms | Single-pass authenticated AEAD |
| **ASCON-128 Decryption** | 996.8815 ms | 16,594.5181 ms | Signature validation + decryption |
| **SHA-256 Hash Generation** | 2.4340 ms | 6.5541 ms | Streamed chunk hashing (64 KB blocks) |
| **SHA-256 Hash Verification**| 0.7821 ms | 6.8500 ms | Stored vs. computed comparison |
| **Integrity Check Pipeline** | 0.7851 ms | 6.9010 ms *(Est.)* | Constant-time side-channel proof check |

### 2. Throughput & Bottleneck Analysis
*   **ASCON-128 (Symmetric Cipher):** Achieved an encryption throughput of **~0.38 MB/s** on `test.pdf` and **~0.16 MB/s** on `test.mp4`. This latency curve scales linearly due to the **pure software implementation** of the ASCON permutation core within Python. Because Python is an interpreted language, executing the thousands of bitwise substitutions and linear diffusions required by ASCON's 320-bit sponge state on large byte arrays introduces noticeable CPU instruction overhead.
*   **SHA-256 (Hashing Core):** Achieved a processing speed of **~155.87 MB/s** on `test.pdf` and **~392.97 MB/s** on `test.mp4`. This high performance is due to the `Hasher` module tapping directly into Python’s native, pre-compiled C-library bindings (`hashlib`). 

---

## ⚔️ Cryptographic Matrix: ASCON-128 vs. Legacy RC4

This system represents a major security upgrade over previous iterations that relied on stream ciphers like RC4:


| **Cryptographic Primitive** | Legacy RC4 Stream Cipher | ASCON-128 AEAD & SHA-256 | Complies with the **NIST Lightweight Cryptography Standard** for modern IoT/edge networks. |
| **Security Threshold** | Broken / Deprecated (FMS key recovery attacks) | 128-bit cryptographic strength | Highly resilient against linear, differential, and passive cryptanalysis. |
| **Authenticity Verification**| None (Confidentiality only) | Single-pass automatic 128-bit Tag validation | Prevents file tampering by immediately rejecting altered ciphertexts. |
| **Integrity Architecture** | Multi-pass external hashing | Integrated dual-layer (AEAD + Stream SHA-256) | Enables rapid directory auditing on cold-storage without expensive decryption. |
| **Side-Channel Resilience** | Highly vulnerable to timing analysis | Constant-time digest comparison | Uses `secrets.compare_digest()` to eliminate timing leaks entirely. |
| **Memory Management** | Dynamic allocations (O(N) memory risk) | Streamed 64 KB block chunking (O(1) memory) | Retains a flat memory profile under **23 MB**, ensuring stability on edge systems. |

---

## 🛠️ Installation & Setup

### Prerequisites
*   **Python:** Version 3.12 or higher.
*   **Operating System:** Windows, macOS, or Linux.
*   **GUI Libraries:** Tkinter (pre-installed on Windows and macOS. For Linux, install using `sudo apt-get install python3-tk`).

### Setup Steps
1. Clone the repository to your local system:
   ```bash
   git clone https://github.com/yourusername/ascon-file-security-system.git
   cd ascon-file-security-system
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
   *(Note: The `requirements.txt` includes the required lightweight `ascon` Python package).*

3. Run the application:
   ```bash
   python main.py
   ```

---

## 📖 Step-by-Step Execution Manual

1.  **Launch the App:** Run `python main.py` to open the high-contrast dark-themed control dashboard.
2.  **Select a File:** Click the **Browse File** button on the left panel. Choose any target file (e.g., a PDF, image, or video). The system will print the file name, absolute path, and file size in the **Activity Log**.
3.  **Generate a Symmetric Key:** Click **Generate Secret Key**. This creates a secure 128-bit key using hardware entropy and saves it to `keys/ascon.key`.
4.  **Encrypt the File:** Click **Encrypt File**. The system processes the selected file, generates a fresh 128-bit nonce, encrypts the file using ASCON-128 AEAD, and saves it to the `encrypted/` folder as `[filename].ascon`.
5.  **Decrypt the File:** To verify decryption, click **Decrypt File**. The system loads the encrypted `.ascon` payload, reads the key, verifies the tag, and recovers the original file inside the `decrypted/` folder.
6.  **Create an Integrity Fingerprint:** Click **Generate SHA-256 Hash**. The system stream-hashes the plaintext file in 64 KB chunks and saves the digest to `hashes/[filename].hash`.
7.  **Run an Integrity Audit:** Click **Verify Hash** or **Verify File Integrity** to execute constant-time comparisons of the stored vs. current hashes, confirming if any unauthorized tampering occurred.
8.  **Analyze Metrics:** Click **View Metrics** to see the structured on-screen latency report. Click **Export Metrics** to output the performance history as a JSON database in `metrics/metrics_report.json`.
9.  **Quick Folder Access:** Use the shortcut utility buttons (*Open Encrypted Folder*, *Open Decrypted Folder*, *Open Metrics Folder*) to open the output directories directly in your system's file explorer.
## 🎓 Academic Metadata & Attributions

*   **Institution:** Techno International New Town (Formerly Techno India College of Technology)
*   **Affiliation:** Maulana Abul Kalam Azad University of Technology, West Bengal (MAKAUT)
*   **Department:** Department of Artificial Intelligence & Machine Learning
*   **Academic Course:** Project II Report (PROJAIML881)
*   **Academic Batch:** 2022-2026 (Semester 8 - EVEN)
*   **Project Mentor:** Prof. Soumen Bajpayee

### Project Team Members:
*   **Student 1:** Vishal Kumar (Roll No: 18730623070)
*   **Student 2:** Prachi Jhunjhunwala (Roll No: 18730623067)
*   **Student 3:** Tuhin koley (Roll No: 18730623063)
*   **Student 4:** Shanidho nagak (Roll No: [Roll No])


