from hashlib import sha256
from random import randrange, randint
from gmpy2 import xmpz, to_binary, invert, powmod, is_prime

def generate_p_q(L, N):
    g = N  # g >= 160
    n = (L - 1) // g
    b = (L - 1) % g
    while True:
        # generate q
        while True:
            s = xmpz(randrange(1, 2 ** (g)))
            a = sha256(to_binary(s)).hexdigest()
            zz = xmpz((s + 1) % (2 ** g))
            z = sha256(to_binary(zz)).hexdigest()
            U = int(a, 16) ^ int(z, 16)
            mask = 2 ** (N - 1) + 1
            q = U | mask
            if is_prime(q, 20):
                break
        # generate p
        i = 0  # counter
        j = 2  # offset
        while i < 4096:
            V = []
            for k in range(n + 1):
                arg = xmpz((s + j + k) % (2 ** g))
                zzv = sha256(to_binary(arg)).hexdigest()
                V.append(int(zzv, 16))
            W = 0
            for qq in range(0, n):
                W += V[qq] * 2 ** (160 * qq)
            W += (V[n] % 2 ** b) * 2 ** (160 * n)
            X = W + 2 ** (L - 1)
            c = X % (2 * q)
            p = X - c + 1  # p = X - (c - 1)
            if p >= 2 ** (L - 1):
                if is_prime(p, 10):
                    return p, q
            i += 1
            j += n + 1


def generate_g(p, q):
    while True:
        h = randrange(2, p - 1)
        exp = xmpz((p - 1) // q)
        g = powmod(h, exp, p)
        if g > 1:
            break
    return g


def generate_keys(p, q, g):
    x = randint(1, q-1)
    y = pow(g, x, p)
    return (y, x)

def sign_message(message, p, q, g, x):
    h = sha256(message.encode()).digest()
    h = int.from_bytes(h, 'big')
    while True:
        k = randint(1, q-1)
        r = pow(g, k, p) % q
        s = (invert(k, q) * (h + x*r)) % q
        if r != 0 and s != 0:
            return (r, s)

def verify_signature(message, signature, p, q, g, y):
    h = sha256(message.encode()).digest()
    h = int.from_bytes(h, 'big')
    r, s = signature
    if not (0 < r < q and 0 < s < q):
        return False
    w = invert(s, q)
    u1 = (h * w) % q
    u2 = (r * w) % q
    v = (pow(g, u1, p) * pow(y, u2, p)) % p % q
    return v == r

# Example usage
(p, q) = generate_p_q(1024, 60)
g = generate_g(p, q)

y, x = generate_keys(p, q, g)
message = "Hello, world!"
signature = sign_message(message, p, q, g, x)
print("Signature:", signature)
valid = verify_signature(message, signature, p, q, g, y)
print("Valid signature:", valid)