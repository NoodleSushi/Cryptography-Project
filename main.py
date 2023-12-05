import math
import random
import base64
from dataclasses import dataclass

BITS = 8
BITS_SIZE = 2 ** BITS
BITS_MASK = BITS_SIZE - 1
MAX_PERMS = math.factorial(BITS)

RSA_PQ_BITS = 16

RSA_N_BITS = RSA_PQ_BITS * 2
RSA_N_SIZE = 2 ** RSA_N_BITS
RSA_N_BYTES = RSA_N_BITS // 8

def bit_sub_encrypt(input: int, key: int) -> int:
    key %= MAX_PERMS
    output = 0
    used_bits = 0
    for old_bit_pos in range(BITS):
        choice_count = BITS - old_bit_pos
        zeroes_to_bit_pos = key // math.factorial(choice_count - 1) % choice_count
        cursor = 0
        while (bit_value := used_bits >> cursor & 1) == 1 or zeroes_to_bit_pos > 0:
            cursor += 1
            zeroes_to_bit_pos -= ~bit_value & 1
        output |= (input >> old_bit_pos & 1) << cursor
        used_bits |= 1 << cursor
    return output

def bit_sub_decrypt(input: int, key: int) -> int:
    key %= MAX_PERMS
    output = 0
    used_bits = 0
    for old_bit_pos in range(BITS):
        choice_count = BITS - old_bit_pos
        zeroes_to_bit_pos = key // math.factorial(choice_count - 1) % choice_count
        cursor = 0
        while (bit_value := used_bits >> cursor & 1) == 1 or zeroes_to_bit_pos > 0:
            cursor += 1
            zeroes_to_bit_pos -= ~bit_value & 1
        output |= (input >> cursor & 1) << old_bit_pos
        used_bits |= 1 << cursor
    return output

def bit_shift(input: int, sh: int) -> int:
    return (input >> sh % BITS | input << BITS - sh % BITS) & (2 ** BITS - 1)

def vigenere_encrypt(input: int, key: bytes, i: int) -> int:
    if len(key) == 0:
        return input
    return (input + key[i % len(key)]) % BITS_SIZE

def vigenere_decrypt(input: int, key: bytes, i: int) -> int:
    if len(key) == 0:
        return input
    return (input - key[i % len(key)]) % BITS_SIZE

def vernam_cipher(input: int, key: bytes, i: int) -> int:
    if len(key) == 0:
        return input
    return input ^ key[i % len(key)]

def rsa_encrypt(input: int, n: int, e: int) -> int:
    return pow(input, e, n)

def rsa_decrypt(input: int, n: int, d: int) -> int:
    return pow(input, d, n)

# RSA ALGORITHM
def rsa_key_generator() -> (int, int, int):
    # Fermat primality test
    def is_prime(n):
        if n == 2 or n == 3:
            return True
        if n % 2 == 0:
            return False
        for _ in range(100):
            a = random.randint(2, n - 2)
            if pow(a, n - 1, n) != 1:
                return False
        return True

    # Generate a prime number for RSA
    def generate_prime(n):
        while True:
            p = random.randint(2**(n-1), 2**n)
            if is_prime(p):
                return p

    def generate_e(phi_n):
        while True:
            e = random.randint(2, phi_n - 1)
            if math.gcd(e, phi_n) == 1:
                return e

    def generate_d(e, phi_n):
        def extended_gcd(a, b):
            if b == 0:
                return a, 1, 0
            gcd, x, y = extended_gcd(b, a % b)
            return gcd, y, x - (a // b) * y

        _, d, _ = extended_gcd(e, phi_n)
        d %= phi_n
        return d
    
    # Generate p and q
    p = generate_prime(RSA_PQ_BITS)
    q = None
    while True:
        q = generate_prime(RSA_PQ_BITS)
        if q != p:
            break
    # Calculate n
    n = p * q
    # Calculate phi(n)
    phi_n = (p - 1) * (q - 1)
    e = generate_e(phi_n)
    d = generate_d(e, phi_n)
    return (n, e, d)

@dataclass
class CipherKey:
    bit_cipher_key: int # 0 - 8!-1
    shift_init: int # 0-7
    shift_rate: int # 0-7
    vigenere_key: bytes # 0-255[<255]
    vernam_key: bytes # 0-255[<255]
    rsa_n: int # 16 bits
    rsa_key: int # 8 bits

    def __post_init__(self):
        if not (0 <= self.bit_cipher_key < MAX_PERMS):
            raise ValueError("bit_cipher_key is out of range")
        if not (0 <= self.shift_init < BITS):
            raise ValueError("shift_init is out of range")
        if not (0 <= self.shift_rate < BITS):
            raise ValueError("shift_rate is out of range")
        if len(self.vigenere_key) >= BITS_SIZE:
            raise ValueError("vigenere_key is out of range")
        if len(self.vernam_key) >= BITS_SIZE:
            raise ValueError("vernam_key is out of range")
        if not (0 <= self.rsa_n < RSA_N_SIZE):
            raise ValueError("rsa n is out of range")
        if not (0 <= self.rsa_key < RSA_N_SIZE):
            raise ValueError("rsa key is out of range")
    
    def to_bytes(self) -> bytes:
        return self.bit_cipher_key.to_bytes(2, byteorder='big') \
            + bytes([self.shift_init, self.shift_rate, len(self.vigenere_key)]) \
            + self.vigenere_key \
            + bytes([len(self.vernam_key)]) \
            + self.vernam_key \
            + self.rsa_n.to_bytes(RSA_N_BYTES, byteorder='big') \
            + self.rsa_key.to_bytes(RSA_N_BYTES, byteorder='big')

    def to_base64(self) -> str:
        return base64.b64encode(self.to_bytes()).decode('utf-8')

    @classmethod
    def from_random(cls):
        bit_cipher_key = random.randint(0, MAX_PERMS - 1)
        shift_init = random.randint(0, BITS - 1)
        shift_rate = random.randint(0, BITS - 1)
        vigenere_key = bytes([random.randint(0, 255) for _ in range(random.randint(0, 255))])
        vernam_key = bytes([random.randint(0, 255) for _ in range(random.randint(0, 255))])
        n, e, d = rsa_key_generator()
        return (
            cls(bit_cipher_key, shift_init, shift_rate, vigenere_key, vernam_key, n, e),
            cls(bit_cipher_key, shift_init, shift_rate, vigenere_key, vernam_key, n, d),
        )

    @classmethod
    def from_bytes(cls, b: bytes):
        def get_bytes(b_iter, size):
            return bytes([next(b_iter) for _ in range(size)])
        
        b_iter = iter(b)        

        return cls(
            bit_cipher_key = int.from_bytes(get_bytes(b_iter, 2), byteorder='big'),
            shift_init = next(b_iter) % BITS,
            shift_rate = next(b_iter) % BITS,
            vigenere_key = get_bytes(b_iter, next(b_iter)),
            vernam_key = get_bytes(b_iter, next(b_iter)),
            rsa_n = int.from_bytes(get_bytes(b_iter, RSA_N_BYTES), byteorder='big'),
            rsa_key = int.from_bytes(get_bytes(b_iter, RSA_N_BYTES), byteorder='big'),
        )

    @classmethod
    def from_base64(cls, b64: str):
        return cls.from_bytes(base64.b64decode(b64))


class Cipher:
    def __init__(self, key: CipherKey = None) -> None:
        self.i = 0
        self.key = key
    
    def set_key(self, key: CipherKey) -> None:
        self.key = key
    
    def reset(self) -> None:
        self.i = 0
    
    def encrypt(self, x: int) -> bytes:
        if self.key is None:
            raise Exception('Key is Omitted')
        x = bit_shift(x, self.key.shift_init + self.i * self.key.shift_rate)
        x = bit_sub_encrypt(x, self.key.bit_cipher_key)
        x = vigenere_encrypt(x, self.key.vigenere_key, self.i)
        x = vernam_cipher(x, self.key.vernam_key, self.i)
        y = rsa_encrypt(x, self.key.rsa_n, self.key.rsa_key).to_bytes(RSA_N_BYTES, byteorder='big')
        self.i += 1
        return y

    def decrypt(self, y: bytes) -> int:
        if self.key is None:
            raise Exception('Key is Omitted')
        x = rsa_decrypt(int.from_bytes(y, byteorder='big'), self.key.rsa_n, self.key.rsa_key)
        x = vernam_cipher(x, self.key.vernam_key, self.i)
        x = vigenere_decrypt(x, self.key.vigenere_key, self.i)
        x = bit_sub_decrypt(x, self.key.bit_cipher_key)
        x = bit_shift(x, -self.key.shift_init - self.i * self.key.shift_rate)
        self.i += 1
        return x

def encrypt_file(input_path: str, output_path: str, key: CipherKey) -> None:
    with open(input_path, 'rb') as input_file:
        with open(output_path, 'wb') as output_file:
            cipher = Cipher(key)
            # copy by byte to encrypted_filename
            while (byte := input_file.read(1)):
                output_file.write(cipher.encrypt(int.from_bytes(byte, byteorder='big')))

def decrypt_file(input_path: str, output_path: str, key: CipherKey) -> None:
    with open(input_path, 'rb') as input_file:
        with open(output_path, 'wb') as output_file:
            cipher = Cipher(key)
            # copy by byte to decrypted_filename
            while (ecrypted_bytes := input_file.read(RSA_N_BYTES)):
                output_file.write(cipher.decrypt(ecrypted_bytes).to_bytes(1, byteorder='big'))
