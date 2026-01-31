import argparse
from pyserpent.serpent import Serpent
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import os
import multiprocessing
from concurrent.futures import ProcessPoolExecutor

BLOCK_SIZE = 16  # Serpent block size is 128 bits (16 bytes)

# ============== WORKER FUNCTIONS (must be at module level for multiprocessing) ==============

def decrypt_blocks_worker(args):
    """Worker function to decrypt a batch of blocks."""
    key, blocks_data, previous_blocks_data = args
    cipher = Serpent(key)

    results = []
    for i in range(0, len(blocks_data), BLOCK_SIZE):
        block = blocks_data[i:i + BLOCK_SIZE]
        prev_block = previous_blocks_data[i:i + BLOCK_SIZE]
        decrypted = cipher.decrypt(block)
        xored = bytes(a ^ b for a, b in zip(decrypted, prev_block))
        results.append(xored)

    return b''.join(results)

def ctr_worker(args):
    """Worker function for CTR mode encryption/decryption."""
    key, data_chunk, nonce, start_counter = args
    cipher = Serpent(key)

    results = []
    counter = start_counter

    for i in range(0, len(data_chunk), BLOCK_SIZE):
        block = data_chunk[i:i + BLOCK_SIZE]
        counter_block = nonce + counter.to_bytes(8, 'big')
        keystream = cipher.encrypt(counter_block)
        result = bytes(a ^ b for a, b in zip(block, keystream[:len(block)]))
        results.append(result)
        counter += 1

    return b''.join(results)

# ============== ENCRYPTION/DECRYPTION FUNCTIONS ==============

def encrypt_cbc(serpent_cipher, data, iv):
    """Standard CBC encryption - must be sequential."""
    encrypted = []
    previous_block = iv

    for i in range(0, len(data), BLOCK_SIZE):
        block = data[i:i + BLOCK_SIZE]
        block_xored = bytes(a ^ b for a, b in zip(block, previous_block))
        encrypted_block = serpent_cipher.encrypt(block_xored)
        encrypted.append(encrypted_block)
        previous_block = encrypted_block

    return b''.join(encrypted)

def decrypt_cbc_parallel(key, data, iv, num_workers=None):
    """
    Parallel CBC decryption.

    CBC decryption CAN be parallelized because each block only needs
    the previous CIPHERTEXT block (which we already have).
    """
    if num_workers is None:
        num_workers = multiprocessing.cpu_count()

    num_blocks = len(data) // BLOCK_SIZE

    # Don't bother with parallelism for small data
    if num_blocks < 100:
        cipher = Serpent(key)
        decrypted = []
        previous_block = iv
        for i in range(0, len(data), BLOCK_SIZE):
            block = data[i:i + BLOCK_SIZE]
            decrypted_block = cipher.decrypt(block)
            xored = bytes(a ^ b for a, b in zip(decrypted_block, previous_block))
            decrypted.append(xored)
            previous_block = block
        return b''.join(decrypted)

    # Split into chunks for each worker
    blocks_per_worker = num_blocks // num_workers

    work_items = []
    for w in range(num_workers):
        start_block = w * blocks_per_worker
        if w == num_workers - 1:
            end_block = num_blocks  # Last worker takes remaining
        else:
            end_block = (w + 1) * blocks_per_worker

        start_byte = start_block * BLOCK_SIZE
        end_byte = end_block * BLOCK_SIZE

        blocks_data = data[start_byte:end_byte]

        # Previous blocks for XOR (iv for first, then ciphertext blocks)
        if start_block == 0:
            prev_start = iv + data[0:(end_block - 1) * BLOCK_SIZE]
        else:
            prev_start = data[(start_block - 1) * BLOCK_SIZE:start_byte]
            prev_rest = data[start_byte:(end_block - 1) * BLOCK_SIZE]
            prev_start = prev_start + prev_rest

        work_items.append((key, blocks_data, prev_start))

    with ProcessPoolExecutor(max_workers=num_workers) as executor:
        results = list(executor.map(decrypt_blocks_worker, work_items))

    return b''.join(results)

def ctr_parallel(key, data, nonce, num_workers=None):
    """
    Parallel CTR mode - works for both encryption and decryption.
    This is fully parallelizable.
    """
    if num_workers is None:
        num_workers = multiprocessing.cpu_count()

    num_blocks = (len(data) + BLOCK_SIZE - 1) // BLOCK_SIZE

    # Don't bother with parallelism for small data
    if num_blocks < 100:
        return ctr_worker((key, data, nonce, 0))

    # Split data into chunks
    blocks_per_worker = num_blocks // num_workers
    bytes_per_worker = blocks_per_worker * BLOCK_SIZE

    work_items = []
    for w in range(num_workers):
        start_byte = w * bytes_per_worker
        if w == num_workers - 1:
            chunk = data[start_byte:]
        else:
            chunk = data[start_byte:start_byte + bytes_per_worker]

        start_counter = w * blocks_per_worker
        work_items.append((key, chunk, nonce, start_counter))

    with ProcessPoolExecutor(max_workers=num_workers) as executor:
        results = list(executor.map(ctr_worker, work_items))

    return b''.join(results)

# ============== FILE OPERATIONS ==============

def encrypt_file(input_file, output_file, key_file, mode='ctr'):
    if os.path.exists(key_file):
        print(f"Key file {key_file} exists. Using the existing key.")
        with open(key_file, 'rb') as f:
            key = f.read()
    else:
        key = get_random_bytes(32)
        with open(key_file, 'wb') as f:
            f.write(key)
        print(f"Generated new key and saved to {key_file}")

    with open(input_file, 'rb') as f:
        plaintext = f.read()

    padded = pad(plaintext, BLOCK_SIZE)
    num_workers = multiprocessing.cpu_count()

    print(f"Encrypting {len(plaintext):,} bytes using {mode.upper()} mode "
          f"with {num_workers} CPU cores...")

    if mode == 'ctr':
        nonce = get_random_bytes(8)
        ciphertext = ctr_parallel(key, padded, nonce)

        with open(output_file, 'wb') as f:
            f.write(b'CTR')
            f.write(nonce)
            f.write(ciphertext)
    else:
        # CBC mode - encryption is sequential
        iv = get_random_bytes(BLOCK_SIZE)
        cipher = Serpent(key)
        ciphertext = encrypt_cbc(cipher, padded, iv)

        with open(output_file, 'wb') as f:
            f.write(b'CBC')
            f.write(iv)
            f.write(ciphertext)

    print(f"Encryption successful. Output saved to {output_file}")

def decrypt_file(input_file, output_file, key_file):
    if not os.path.exists(key_file):
        print(f"Error: Key file {key_file} does not exist.")
        return

    with open(key_file, 'rb') as f:
        key = f.read()

    with open(input_file, 'rb') as f:
        mode_marker = f.read(3)

        if mode_marker == b'CTR':
            nonce = f.read(8)
            ciphertext = f.read()
            mode = 'CTR'
        elif mode_marker == b'CBC':
            iv = f.read(BLOCK_SIZE)
            ciphertext = f.read()
            mode = 'CBC'
        else:
            # Legacy format - no marker, assume CBC
            f.seek(0)
            iv = f.read(BLOCK_SIZE)
            ciphertext = f.read()
            mode = 'CBC (legacy)'

    num_workers = multiprocessing.cpu_count()
    print(f"Decrypting {len(ciphertext):,} bytes using {mode} mode "
          f"with {num_workers} CPU cores...")

    if mode == 'CTR':
        decrypted = ctr_parallel(key, ciphertext, nonce)
    else:
        decrypted = decrypt_cbc_parallel(key, ciphertext, iv)

    plaintext = unpad(decrypted, BLOCK_SIZE)

    with open(output_file, 'wb') as f:
        f.write(plaintext)

    print(f"Decryption successful. Output saved to: {output_file}")

def main():
    parser = argparse.ArgumentParser(
        description="Encrypt or decrypt files using Serpent with parallel processing."
    )
    parser.add_argument('-e', '--encrypt', action='store_true', help="Encrypt a file")
    parser.add_argument('-d', '--decrypt', action='store_true', help="Decrypt a file")
    parser.add_argument('-k', '--key-file', metavar='FILENAME', required=False,
                        type=str, help="Key file to read/write")
    parser.add_argument('-m', '--mode', choices=['cbc', 'ctr'], default='ctr',
                        help="Encryption mode (default: ctr, faster)")
    parser.add_argument('input_file', type=str, help="Input file")
    parser.add_argument('output_file', type=str, help="Output file")
    args = parser.parse_args()

    if args.encrypt and args.decrypt:
        print("Error: Cannot use both -e and -d at the same time.")
        return
    if not args.encrypt and not args.decrypt:
        print("Error: Must specify either -e or -d.")
        return

    if not args.key_file:
        key_filename = input("Enter the key file name (for saving or reading): ")
    else:
        key_filename = args.key_file

    if args.encrypt:
        encrypt_file(args.input_file, args.output_file, key_filename, args.mode)
    elif args.decrypt:
        decrypt_file(args.input_file, args.output_file, key_filename)

if __name__ == "__main__":
    main()