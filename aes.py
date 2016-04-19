import binascii
import numpy as np

SBOX = np.array((
0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
), dtype=np.uint8)

INV_SBOX = np.array((
0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
), dtype=np.uint8)

RCON = np.array((
0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 
0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 
0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 
0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 
0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 
0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 
0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 
0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 
0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 
0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 
0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 
0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 
0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 
0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 
0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 
0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d,
), dtype=np.uint8)

GMUL = np.array((
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255),
    (0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30, 32, 34, 36, 38, 40, 42, 44, 46, 48, 50, 52, 54, 56, 58, 60, 62, 64, 66, 68, 70, 72, 74, 76, 78, 80, 82, 84, 86, 88, 90, 92, 94, 96, 98, 100, 102, 104, 106, 108, 110, 112, 114, 116, 118, 120, 122, 124, 126, 128, 130, 132, 134, 136, 138, 140, 142, 144, 146, 148, 150, 152, 154, 156, 158, 160, 162, 164, 166, 168, 170, 172, 174, 176, 178, 180, 182, 184, 186, 188, 190, 192, 194, 196, 198, 200, 202, 204, 206, 208, 210, 212, 214, 216, 218, 220, 222, 224, 226, 228, 230, 232, 234, 236, 238, 240, 242, 244, 246, 248, 250, 252, 254, 27, 25, 31, 29, 19, 17, 23, 21, 11, 9, 15, 13, 3, 1, 7, 5, 59, 57, 63, 61, 51, 49, 55, 53, 43, 41, 47, 45, 35, 33, 39, 37, 91, 89, 95, 93, 83, 81, 87, 85, 75, 73, 79, 77, 67, 65, 71, 69, 123, 121, 127, 125, 115, 113, 119, 117, 107, 105, 111, 109, 99, 97, 103, 101, 155, 153, 159, 157, 147, 145, 151, 149, 139, 137, 143, 141, 131, 129, 135, 133, 187, 185, 191, 189, 179, 177, 183, 181, 171, 169, 175, 173, 163, 161, 167, 165, 219, 217, 223, 221, 211, 209, 215, 213, 203, 201, 207, 205, 195, 193, 199, 197, 251, 249, 255, 253, 243, 241, 247, 245, 235, 233, 239, 237, 227, 225, 231, 229),
    (0, 3, 6, 5, 12, 15, 10, 9, 24, 27, 30, 29, 20, 23, 18, 17, 48, 51, 54, 53, 60, 63, 58, 57, 40, 43, 46, 45, 36, 39, 34, 33, 96, 99, 102, 101, 108, 111, 106, 105, 120, 123, 126, 125, 116, 119, 114, 113, 80, 83, 86, 85, 92, 95, 90, 89, 72, 75, 78, 77, 68, 71, 66, 65, 192, 195, 198, 197, 204, 207, 202, 201, 216, 219, 222, 221, 212, 215, 210, 209, 240, 243, 246, 245, 252, 255, 250, 249, 232, 235, 238, 237, 228, 231, 226, 225, 160, 163, 166, 165, 172, 175, 170, 169, 184, 187, 190, 189, 180, 183, 178, 177, 144, 147, 150, 149, 156, 159, 154, 153, 136, 139, 142, 141, 132, 135, 130, 129, 155, 152, 157, 158, 151, 148, 145, 146, 131, 128, 133, 134, 143, 140, 137, 138, 171, 168, 173, 174, 167, 164, 161, 162, 179, 176, 181, 182, 191, 188, 185, 186, 251, 248, 253, 254, 247, 244, 241, 242, 227, 224, 229, 230, 239, 236, 233, 234, 203, 200, 205, 206, 199, 196, 193, 194, 211, 208, 213, 214, 223, 220, 217, 218, 91, 88, 93, 94, 87, 84, 81, 82, 67, 64, 69, 70, 79, 76, 73, 74, 107, 104, 109, 110, 103, 100, 97, 98, 115, 112, 117, 118, 127, 124, 121, 122, 59, 56, 61, 62, 55, 52, 49, 50, 35, 32, 37, 38, 47, 44, 41, 42, 11, 8, 13, 14, 7, 4, 1, 2, 19, 16, 21, 22, 31, 28, 25, 26),
), dtype=np.uint8)


class Object(object):
    """
    Dummy object to quickly hold and build up AES intermediate state
    """
    pass


def rot_word(word, by=1):
    return np.append(word[by:], word[:by])

def sub_word(word):
    temp = np.array(word)
    for i in xrange(len(word)):
        temp[i] = SBOX[word[i]]
        pass
    return temp

def sub_word_inv(word):
    temp = np.array(word)
    for i in xrange(len(word)):
        temp[i] = INV_SBOX[word[i]]
        pass
    return temp

def rcon(i):
    return np.array((RCON[i],0,0,0))


def key_expansion(key, Nr, Nb=4):
    """
    key : Input key as a numpy array
    Nr  : Number of rounds
    """
    Nk = key.size/4 # Number of 32-bit words in key
    if Nk not in (4, 6, 8):
        raise ValueError("Invalid key length")

    # Allocate
    w = np.zeros((Nb*(Nr+1),4), dtype=np.uint8)

    # Initialize
    w[:Nk] = key.reshape(Nk,4)

    # Create
    for i in xrange(Nk, w.shape[0]):
        temp = w[i-1]

        if (i % Nk) == 0:
            temp = sub_word(rot_word(temp)) ^ rcon(i/Nk)
        elif Nk > 6 and (i % Nk) == 4:
            temp = sub_word(temp)
            pass

        w[i] = w[i-Nk] ^ temp
        pass

    return w

def derive_key(round_key, Nr, Nb=4):
    """Derive the original key given a round key

    Args:
        round_key: Input key as a numpy array, or string (treated as binary), or bytearray
        Nr: The round that the key comes from (0-based)
    """
    Nk = round_key.size/4 # Number of 32-bit words in key
    if Nk not in (4, 6, 8):
        raise ValueError("Invalid key length")

    # Allocate
    w = np.zeros((Nk*(Nr+1),4), dtype=np.uint8)

    # Initialize
    w[-Nk:] = round_key.reshape((Nk,4))

    # Create
    for i in reversed(xrange(Nk, w.shape[0])):
        temp = w[i-1]
        
        if (i % Nk) == 0:
            temp = sub_word(rot_word(temp)) ^ rcon(i/Nk)
        elif Nk > 6 and (i % Nk) == 4:
            temp = sub_word(temp)
            pass

        w[i-Nk] = w[i] ^ temp 
        pass

    return w[:Nk].reshape(Nk*4)


def add_round_key(state, key):
    """
    """
    return state ^ key

def sub_bytes(state):
    """
    """
    return np.array(map(lambda x: map(lambda y: SBOX[y], x), state), dtype=np.uint8)

def shift_rows(state):
    """
    """
    result = np.array(state)
    for i in xrange(1,4):
        result[i] = rot_word(state[i], i)
        pass
    return result

def shift_rows_inv(state):
    """
    """
    result = np.array(state)
    for i in xrange(1,4):
        result[i] = rot_word(state[i], -i)
        pass
    return result

def gmul(a, b):
    """
    Use for values of 'a' outside (1,2,3)
    """
    p = 0
    for counter in range(8):
        if (b & 1) == 1: p ^= a
        hi_bit_set = (a & 0x80)
        a <<= 1; a &= 0xFF
        if hi_bit_set: a ^= 0x1b
        b >>= 1
        pass
    return p


MIX_COLS = np.array((
        (2, 3, 1, 1),
        (1, 2, 3, 1),
        (1, 1, 2, 3),
        (3, 1, 1, 2),
        ), dtype=np.uint8)

def mix_column(col):
    """
    """
    result = np.array(col)
    for i in range(len(col)):
        # Factor of ~10 speedup if we lookup instead of calculate
        result[i] = GMUL[MIX_COLS[i,0]-1][col[0]] ^ GMUL[MIX_COLS[i,1]-1][col[1]] ^ \
                    GMUL[MIX_COLS[i,2]-1][col[2]] ^ GMUL[MIX_COLS[i,3]-1][col[3]]
        #result[i] = gmul(coefs[i,0], col[0]) ^ gmul(coefs[i,1], col[1]) ^ \
        #            gmul(coefs[i,2], col[2]) ^ gmul(coefs[i,3], col[3])
        pass
    return result

def mix_columns(state):
    """
    """
    result = np.array(state.T)
    for col in range(result.shape[0]):
        result[col] = mix_column(result[col])
        pass
    return result.T

def cipher(inb, key, Nr=10, Nb=4):
    """
    Return a tracker object that allows inspection of intermediate state
    of the AES encryption operation.

    To get the output, use res[-1].fout
    """
    if len(inb) != 4*Nb:
        raise ValueError("Invalid block length: %d" % (len(inb),))

    w = key_expansion(key, Nr, Nb)

    tracker = []
    tracker.append(Object())
    tracker[0].start = state = inb.reshape(4,Nb).T
    tracker[0].k_sch = w[:Nb].T
    tracker[0].out   = state = add_round_key(state, w[:Nb].T)

    for r in xrange(1, Nr):
        tracker.append(Object())
        tracker[r].start = state
        tracker[r].s_box = state = sub_bytes(state)
        tracker[r].s_row = state = shift_rows(state)
        tracker[r].m_col = state = mix_columns(state)
        tracker[r].k_sch = w[r*Nb:(r+1)*Nb].T
        tracker[r].out   = state = add_round_key(state, w[r*Nb:(r+1)*Nb].T)
        tracker[r].fout  = state.T.reshape(16,)
        pass

    tracker.append(Object())
    tracker[Nr].start = state
    tracker[Nr].s_box = state = sub_bytes(state)
    tracker[Nr].s_row = state = shift_rows(state)
    tracker[Nr].k_sch = w[Nr*Nb:(Nr+1)*Nb].T
    tracker[Nr].out   = state = add_round_key(state, w[Nr*Nb:(Nr+1)*Nb].T)
    tracker[Nr].fout  = state.T.reshape(16,)

    return tracker


def cipher_128(inb, key):
    if len(key) != 16:
        raise ValueError("Invalid key length for AES-128: %d" % (len(key),))
    return cipher(inb, key, 10)

def cipher_192(inb, key):
    if len(key) != 24:
        raise ValueError("Invalid key length for AES-192: %d" % (len(key),))
    return cipher(inb, key, 12)

def cipher_256(inb, key):
    if len(key) != 32:
        raise ValueError("Invalid key length for AES-256: %d" % (len(key),))
    return cipher(inb, key, 14)

def cipher_auto(inb, key):
    if len(key) == 16:
        return cipher_128(inb, key)
    elif len(key) == 24:
        return cipher_192(inb, key)
    elif len(key) == 32:
        return cipher_256(inb, key)
    raise ValueError("Invalid key length: %d" % (len(key),))


# Test vectors from FIPS-197
AES_VECTORS = (
    ("00112233445566778899aabbccddeeff",
        "000102030405060708090a0b0c0d0e0f",
        "69c4e0d86a7b0430d8cdb78070b4c55a"),
    ("00112233445566778899aabbccddeeff",
        "000102030405060708090a0b0c0d0e0f1011121314151617",
        "dda97ca4864cdfe06eaf70a0ec0d7191"),
    ("00112233445566778899aabbccddeeff",
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "8ea2b7ca516745bfeafc49904b496089",),
)

KEY_DERIVATION_VECTORS = (
)

def test():
    Nb = 4
    for (p, k, c) in VECTORS:
        pb = np.array(bytearray.fromhex(p))
        kb = np.array(bytearray.fromhex(k))
        cb = np.array(bytearray.fromhex(c))

        full_result = cipher_auto(pb, kb)
        result = full_result[-1].fout
        if cb.data != result.data:
            print "Failed with %s with %s" % (p, k)
            raise ValueError("%s != %s" % (c, binascii.hexlify(result.data)))

        # Ensure the key derivation works
        if len(kb) == 16:
            Nr = 10
            Nk = 4
        if len(kb) == 24:
            Nr = 12
            Nk = 6
        if len(kb) == 32:
            Nr = 14
            Nk = 8

        key_sched = key_expansion(kb, Nr)

        # Slice into contiguous "round keys" to pass into derive_key()
        for i in xrange(0, Nk):
            round_key = key_sched[i*Nk:(i+1)*Nk]
            k = derive_key(round_key, i)

            if k.data != kb.data:
                print "Key derivation failed on round %d with %s" % (i+1, round_key)
                raise ValueError("%s != %s" % (k, kb))

    print "All tests pass."


def main():
    import argparse
    parser = argparse.ArgumentParser(description='AES operations')
    parser.add_argument('--round_key', type=str, required=True,
            help='Round key (ASCII hex)')
    parser.add_argument('--round_num', type=int, required=True,
            help='Key derivation round number (0 based)')

    args = parser.parse_args()

    round_key = np.array(bytearray.fromhex(args.round_key.replace(' ', '')))

    key = derive_key(round_key, args.round_num)

    print "Derived key: '{key}'".format(key=binascii.hexlify(key.data))



if __name__ == "__main__":
    main()

