import hashlib
import binascii

def generate_private_key(index):
    return f'{index:064x}'  # 64 hex chars for a 256-bit key

def generate_public_key(private_key):
    priv_key_bytes = binascii.unhexlify(private_key)
    sha256_hash = hashlib.sha256(priv_key_bytes).digest()
    ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
    versioned_hash = b'\x00' + ripemd160_hash
    checksum = hashlib.sha256(hashlib.sha256(versioned_hash).digest()).digest()[:4]
    address_bytes = versioned_hash + checksum
    return base58_encode(address_bytes)

def base58_encode(byte_string):
    num = int.from_bytes(byte_string, byteorder='big')
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    result = []

    while num > 0:
        num, remainder = divmod(num, 58)
        result.append(alphabet[remainder])

    # Adaugă caractere pentru fiecare 0 inițial din byte_string
    for byte in byte_string:
        if byte == 0:
            result.insert(0, '1')
        else:
            break

    return ''.join(result)

def save_addresses_to_file(start_hex, end_hex, file_counter):
    file_size_limit = 20 * (1024 ** 3)  # 20 GB
    current_file_size = 0
    file_path = f'Prada_{file_counter}.txt'
    results = []  # Stochează rezultatele într-o listă

    start_index = int(start_hex, 16)
    end_index = int(end_hex, 16)
    total_iterations = end_index - start_index + 1

    for index in range(start_index, end_index + 1):
        private_key = generate_private_key(index)
        public_address = generate_public_key(private_key)
        # Extrage primele 4 caractere din fiecare adresă
        extracted_chars = public_address[:4]
        results.append(extracted_chars)

        # Verifică dimensiunea fișierului
        current_file_size += len(extracted_chars) + 1  # +1 pentru newline

        if current_file_size >= file_size_limit:
            print(f'File {file_path} reached size limit. Last private key index: {private_key}')
            break

        # Afișează cheia privată curentă și procentul completării
        completion_percentage = ((index - start_index + 1) / total_iterations) * 100
        print(f'Private Key: {private_key} | Completion: {completion_percentage:.2f}%')

    # Scrie toate rezultatele într-o singură operațiune
    with open(file_path, 'a') as file:
        file.write('\n'.join(results) + '\n')

    return index  # Returnează indexul unde s-a oprit

# Rularea programului
start_hex = '40000000000000000'
end_hex = '7ffffffffffffffff'  # Limita superioară
file_counter = 0

while int(start_hex, 16) <= int(end_hex, 16):
    start_hex = save_addresses_to_file(start_hex, end_hex, file_counter)
    file_counter += 1
