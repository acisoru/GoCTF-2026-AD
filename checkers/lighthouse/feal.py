def g(a, b, carry):
    value = (a + b + carry) & 255
    return ((value << 2) | (value >> 6)) & 255


def f(value):
    a, b, c, d = value.to_bytes(4, 'big')
    y1 = g(a ^ b, c ^ d, 1)
    y2 = g(c ^ d, y1, 0)
    return int.from_bytes(bytes((g(a, y1, 0), y1, y2, g(d, y2, 1))), 'big')


def fk(x, y):
    a, b, c, d = x.to_bytes(4, 'big')
    u, v, w, z = y.to_bytes(4, 'big')
    middle1 = g(a ^ b, (c ^ d) ^ u, 1)
    middle2 = g(c ^ d, middle1 ^ v, 0)
    return int.from_bytes(bytes((g(a, middle1 ^ w, 0), middle1,
                                 middle2, g(d, middle2 ^ z, 1))), 'big')


def schedule(secret):
    raw = bytes.fromhex(secret)
    if len(raw) != 24:
        raise ValueError('bad read secret')
    material = [int.from_bytes(raw[i:i + 4], 'big') for i in range(0, 24, 4)]
    left, right, previous = material[0], material[1], material[5]
    words = []
    for word in material:
        next_value = fk(left, right ^ previous ^ word)
        previous, left, right = left, right, next_value
        words.extend((next_value >> 16, next_value & 0xffff))
    output_left = (words[8] << 16 | words[9]) ^ material[2]
    output_right = (words[10] << 16 | words[11]) ^ material[3]
    keys = [((words[i] >> 8) << 16 | (words[i] & 255) << 8) ^ output_left ^
            (output_right if i % 2 else 0) ^ material[i] for i in range(4)]
    keys.extend(((words[4] << 16 | words[5]) ^ output_left ^ output_right ^ material[4],
                 (words[6] << 16 | words[7]) ^ output_right ^ material[5]))
    return keys


def block(value, keys, decrypt=False):
    left, right = value >> 32, value & 0xffffffff
    if decrypt:
        x, y = left, right ^ left
        for round_no in range(3, 0, -1):
            x, y = y, x ^ f(y ^ keys[round_no])
        initial = x ^ f(y ^ keys[0])
        return ((initial ^ keys[4]) << 32) | (initial ^ y ^ keys[5])
    left ^= keys[4]
    right ^= keys[5]
    x, y = left ^ right, left ^ f(left ^ right ^ keys[0])
    for round_no in range(1, 3):
        x, y = y, x ^ f(y ^ keys[round_no])
    last = x ^ f(y ^ keys[3])
    return (last << 32) | (last ^ y)


def uncrypt(secret, cipher):
    keys = schedule(secret)
    raw = bytes.fromhex(cipher)
    if not raw or len(raw) % 8:
        raise ValueError('invalid ciphertext length')
    plain = b''.join(block(int.from_bytes(raw[i:i+8], 'big'), keys, True).to_bytes(8, 'big')
                     for i in range(0, len(raw), 8))
    pad = plain[-1]
    if not 1 <= pad <= 8 or plain[-pad:] != bytes([pad]) * pad:
        raise ValueError('invalid message padding')
    return plain[:-pad]
