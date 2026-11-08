# SPDX-License-Identifier: MIT
"""Ed25519 signing, after the reference code of RFC 8032 section 6 (slow,
not constant time: test use only). Lets the itest forge and sign ARCP
frames with the standard library alone."""
import hashlib

P = 2 ** 255 - 19
Q = 2 ** 252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)


def _add(a, b):
    ea = (a[1] - a[0]) * (b[1] - b[0]) % P
    eb = (a[1] + a[0]) * (b[1] + b[0]) % P
    ec = 2 * a[3] * b[3] * D % P
    ed = 2 * a[2] * b[2] % P
    e, f, g, h = eb - ea, ed - ec, ed + ec, eb + ea
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _mul(s, pt):
    acc = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            acc = _add(acc, pt)
        pt = _add(pt, pt)
        s >>= 1
    return acc


def _recover_x(y, sign):
    x2 = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * SQRT_M1 % P
    if (x & 1) != sign:
        x = P - x
    return x


_GY = 4 * pow(5, P - 2, P) % P
_GX = _recover_x(_GY, 0)
G = (_GX, _GY, 1, _GX * _GY % P)


def _compress(pt):
    zinv = pow(pt[2], P - 2, P)
    x, y = pt[0] * zinv % P, pt[1] * zinv % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _expand(seed):
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def public_key(seed):
    return _compress(_mul(_expand(seed)[0], G))


def sign(seed, msg):
    a, prefix = _expand(seed)
    pub = _compress(_mul(a, G))
    r = int.from_bytes(hashlib.sha512(prefix + msg).digest(), "little") % Q
    big_r = _compress(_mul(r, G))
    k = int.from_bytes(hashlib.sha512(big_r + pub + msg).digest(), "little") % Q
    return big_r + ((r + k * a) % Q).to_bytes(32, "little")
