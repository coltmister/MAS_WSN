from random import randrange, getrandbits

KEY_SIZE = 1024


def generate_prime_number(length=512):
    def generate_prime_candidate(length):
        p = getrandbits(length)
        p |= (1 << length - 1) | 1
        return p
    
    def is_prime(n, k=128):
        if n == 2 or n == 3:
            return True
        if n <= 1 or n % 2 == 0:
            return False
        s = 0
        r = n - 1
        while r & 1 == 0:
            s += 1
            r //= 2
        for _ in range(k):
            a = randrange(2, n - 1)
            x = pow_mod(a, r, n)
            if x != 1 and x != n - 1:
                j = 1
                while j < s and x != n - 1:
                    x = pow_mod(x, 2, n)
                    if x == 1:
                        return False
                    j += 1
                if x != n - 1:
                    return False
        return True
    
    p = 4
    while not is_prime(p, 128):
        p = generate_prime_candidate(length)
    return p


def extended_gcd(a, b):
    lastremainder, remainder = a, b
    x, lastx, y, lasty = 0, 1, 1, 0
    while remainder:
        lastremainder, (quotient, remainder) = remainder, divmod(lastremainder, remainder)
        x, lastx = lastx - quotient * x, x
        y, lasty = lasty - quotient * y, y
    return lastremainder, lastx * (-1 if a < 0 else 1), lasty * (-1 if b < 0 else 1)


def inverse(a, m):
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise ValueError
    return x % m


def generateKeys(key_size=KEY_SIZE):
    e = 65537
    p = generate_prime_number(key_size // 2)
    q = generate_prime_number(key_size // 2)
    n = p * q
    fi = (p - 1) * (q - 1)
    d = inverse(e, fi)
    return e, d, n, p, q


def pow_mod(base, power, module):  # Быстрое возведение в степень
    result = 1
    while power > 0:
        if power % 2 == 1:
            result = (result * base) % module
        power = power // 2
        base = (base * base) % module
    return result


def encrypt(message, e, n):
    return " ".join([str(pow_mod(i, e, n)) for i in message])


def decrypt(cipher_text, e, p, q):
    result = []
    cipher_text = cipher_text.split(" ")
    for i in cipher_text:  # Китайская теорема об остатках
        m1 = pow_mod(int(i) % p, inverse(e, p - 1), p)
        m2 = pow_mod(int(i) % q, inverse(e, q - 1), q)
        qInv = inverse(q, p)
        h = ((m1 - m2) * qInv)  # Формула Гарнера
        r = m2 + h * q
        result.append(bytes([r]))
    result = b"".join(result).decode('utf-8')
    return result
