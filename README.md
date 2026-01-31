# Serpent (FAST) File Encryptor

A Python-based file encryption tool using the Serpent block cipher with parallel processing support for improved performance on multi-core systems.

This is an improvement of the serpent-crypt repo (https://github.com/freqnik/serpent-crypt)

## Overview

Serpent is a symmetric key block cipher that was a finalist in the Advanced Encryption Standard (AES) competition. While Rijndael was ultimately selected as AES, Serpent is considered to have a more conservative security margin and remains a highly secure encryption algorithm.

This tool provides a command-line interface for encrypting and decrypting files using the Serpent cipher, with support for both CBC (Cipher Block Chaining) and CTR (Counter) modes of operation.

## Features

- **Serpent 256-bit encryption** - Uses a 256-bit key for strong security
- **Multiple cipher modes** - Supports both CBC and CTR modes
- **Parallel processing** - Utilizes all CPU cores for faster encryption/decryption
- **Automatic key management** - Generates and saves encryption keys automatically
- **Backward compatible** - Can decrypt files created with older versions

## Installation

### Prerequisites

- Python 3.7 or higher
- pip package manager

### Dependencies

Install the required packages:

```
pip install pyserpent pycryptodome
```

### Download

Clone the repository or download the script directly:

```
git clone https://github.com/yourusername/serpent-encryptor.git
cd serpent-encryptor
```



## Usage

### Basic Syntax

```shell
python serpent_encryptor.py [-e | -d] [-k KEYFILE] [-m MODE] input_file output_file
```



### Arguments

```
|.  Argument.      | Description                                    |
|------------------|------------------------------------------------|
|   -e, --encrypt  | Encrypt the input file                         |
|   -d, --decrypt  | Decrypt the input file                         |
|   -k, --key-file | Path to the key file (for saving or reading)   |
|   -m, --mode     | Encryption mode: ctr (default) or cbc          |
|   input_file     | Path to the input file                         |
|   output_file.   | Path to the output file                        |
```



### Examples

#### Encrypt a file using CTR mode (recommended)

```shell
python serpent_encryptor.py -e -k secret.key -m ctr document.pdf document.pdf.enc
```



#### Encrypt a file using CBC mode

```shell
python serpent_encryptor.py -e -k secret.key -m cbc document.pdf document.pdf.enc
```

#### Decrypt a file

```shell
python serpent_encryptor.py -d -k secret.key document.pdf.enc document_decrypted.pdf
```

The decryption process automatically detects which mode was used during encryption.

#### Interactive key file prompt

If you omit the -k flag, the program will prompt you for a key file name:

```shell
python serpent_encryptor.py -e document.pdf document.pdf.enc
Enter the key file name (for saving or reading): my_secret.key
```




##### Note it is strongly recommended you encrypt your key file with PGP. AND DON'T LOSE IT.

## Encryption Modes

### CTR Mode (Counter Mode) - Recommended

CTR mode transforms the block cipher into a stream cipher by encrypting successive values of a counter and XORing the result with the plaintext.

**Advantages:**

- Fully parallelizable for both encryption and decryption
- Best performance on multi-core systems
- No padding required (though this implementation uses padding for consistency)
- Random access to encrypted data is possible

**How it works:**

Each block can be encrypted/decrypted independently, allowing parallel processing. A nonce combined with a counter value is encrypted, then XORed with the plaintext to produce ciphertext.

### CBC Mode (Cipher Block Chaining)

CBC mode chains each plaintext block with the previous ciphertext block before encryption, providing better diffusion.

**Advantages:**

- Well-established and widely analyzed
- Errors in one ciphertext block only affect two plaintext blocks
- Decryption can be parallelized

**Limitations:**

- Encryption must be performed sequentially
- Requires an initialization vector (IV)

## Performance

The parallel implementation distributes work across all available CPU cores. Performance gains depend on your system's core count and the file size.

### ### Minimum File Size for Parallelization

For files smaller than approximately 1.6KB (100 blocks), the tool automatically falls back to sequential processing to avoid the overhead of process creation.

## File Format

Encrypted files are stored in the following format:

### CTR Mode

| | Offset | Size | Description | |
|--------|------|-------------|
| | 0 | 3 bytes | Mode marker (CTR) | |
| | 3 | 8 bytes | Nonce | |
| | 11 | Variable | Encrypted data | |

### CBC Mode

| | Offset | Size | Description | |
|--------|------|-------------|
| | 0 | 3 bytes | Mode marker (CBC) | |
| | 3 | 16 bytes | Initialization Vector (IV) | |
| | 19 | Variable | Encrypted data | |

### Legacy Format (Backward Compatibility)

Files without a mode marker are assumed to be CBC-encrypted with the IV stored in the first 16 bytes.

## Security Considerations

### Key Management

- Keys are automatically generated using cryptographically secure random bytes
- Keys are stored in a separate file - protect this file carefully
- Without the key file, encrypted data cannot be recovered
- Consider using appropriate file permissions on the key file:

```shell
chmod 600 secret.key
```

### Initialization Vector / Nonce

- A unique random IV (CBC) or nonce (CTR) is generated for each encryption
- The IV/nonce is stored with the encrypted file (this is standard practice and does not weaken security)
- Never reuse a key+nonce combination in CTR mode

### Recommendations

1. Use CTR mode for best performance while maintaining security
2. Back up your key files in a secure location
3. Use strong file permissions to protect key files
4. Generate a new key for different security contexts
5. Verify decryption by comparing file hashes before and after

## API Usage

You can also import and use the encryption functions in your own Python code:

```python
from serpent_encryptor import encrypt_file, decrypt_file

encrypt_file(
 input_file='document.pdf',
 output_file='document.pdf.enc',
 key_file='secret.key',
 mode='ctr'
)

decrypt_file(
 input_file='document.pdf.enc',
 output_file='document_decrypted.pdf',
 key_file='secret.key'
)
```

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Acknowledgments

- The Serpent cipher was designed by Ross Anderson, Eli Biham, and Lars Knudsen
- This implementation uses the pyserpent library
- Padding and random number generation provided by PyCryptodome

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (git checkout -b feature/amazing-feature)
3. Commit your changes (git commit -m 'Add some amazing feature')
4. Push to the branch (git push origin feature/amazing-feature)
5. Open a Pull Request
