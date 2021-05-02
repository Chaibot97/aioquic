import numpy as np

class Tinymt32:
    # define constant variables
    MIN_LOOP = 8
    PRE_LOOP = 8
    SH0 = np.uint32(1)
    SH1 = np.uint32(10)
    SH8 = np.uint32(8)
    MASK = np.uint32(0x7fffffff)

    # constructor
    def __init__(self, seed):
        # the tinyMT32 PRNG must be initialized with a parameter set that needs to be well chosen
        self.mat1 = np.uint32(0x8f7011ee)
        self.mat2 = np.uint32(0xfc78ff1f)
        self.tmat = np.uint32(0x3793fdff)

        # initialize internal status
        self.status = [seed, self.mat1, self.mat2, self.tmat]

        for i in range(1, Tinymt32.MIN_LOOP):
            self.status[i & 3] ^= i + np.uint32(1812433253) \
                                  * (self.status[(i - 1) & 3] ^ (self.status[(i - 1) & 3] >> 30))

        for i in range(Tinymt32.PRE_LOOP):
            self.next_state()

    def rand16(self):
        return self.generate_uint32() & 0xF

    # this function outputs a pseudorandom integer in [0...255] range
    def rand256(self):
        return self.generate_uint32() & 0xFF

    # this function outputs a 32-bit unsigned integer from the internal state after moving to the next state
    def generate_uint32(self):
        self.next_state()
        return self.temper()

    # helper function to move the internal structure to the next state
    def next_state(self):
        y = self.status[3]
        x = (self.status[0] & Tinymt32.MASK) \
            ^ self.status[1] ^ self.status[2]
        x ^= (x << Tinymt32.SH0)
        y ^= (y >> Tinymt32.SH0) ^ x
        self.status[0] = self.status[1]
        self.status[1] = self.status[2]
        self.status[2] = x ^ (y << Tinymt32.SH1)
        self.status[3] = y

        if y & 1:
            self.status[1] ^= self.mat1
            self.status[2] ^= self.mat2

    # helper function to output a 32-bit unsigned integer from the internal state
    def temper(self):
        t0 = self.status[3]
        t1 = self.status[0] + (self.status[2] >> Tinymt32.SH8)
        t0 ^= t1

        if t1 & 1:
            t0 ^= self.tmat

        return t0


def generate_coding_coefficients(repair_key, window_size, dt):
    prng = Tinymt32(repair_key)
    res = []
    if dt >= 15:
        for i in range(window_size):
            num = prng.rand256()
            while num == 0:
                num = prng.rand256()
            res.append(num)
    else:
        for i in range(window_size):
            if prng.rand16() <= dt:
                num = prng.rand256()
                while num == 0:
                    num = prng.rand256()
                res.append(num)
            else:
                res.append(0)
    return res
