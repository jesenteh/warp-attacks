#Constants, S-box, Permutation
rc0 = [0, 0, 1, 3, 7, 0xf, 0xf, 0xf, 0xe, 0xd, 0xa, 5, 0xa, 5, 0xb, 6, 0xc, 9, 3, 6, 0xd, 0xb, 7, 0xe, 0xd, 0xb, 6, 0xd, 0xa, 4, 9, 2, 4, 9, 3, 7, 0xe, 0xc, 8, 1, 2]
rc1 = [4, 0xc, 0xc, 0xc, 0xc, 0xc, 8, 4, 8, 4, 8, 4, 0xc, 8, 0, 4, 0xc, 8, 4, 0xc, 0xc, 8, 4, 0xc, 8, 4, 8, 0, 4, 8, 0, 4, 0xc, 0xc, 8, 0, 0, 4, 8, 4, 0xc]
s = [0xc, 0xa, 0xd, 3, 0xe, 0xb, 0xf, 7, 8, 9, 1, 5, 0, 2, 4, 6]
perm = [31, 6, 29, 14, 1, 12, 21, 8, 27, 2, 3, 0, 25, 4, 23, 10, 15, 22, 13, 30, 17, 28, 5, 24, 11, 18, 19, 16, 9, 20, 7, 26]
inv_perm = [11, 4, 9, 10, 13, 22, 1, 30, 7, 28, 15, 24, 5, 18, 3, 16, 27, 20, 25, 26, 29, 6, 17, 14, 23, 12, 31, 8, 21, 2, 19, 0]

def printHex(x):
    print("0x",end="")
    for i in x:
        print("{:x}".format(i), end="")
    print("")

def roundFunc(p, k, r, rounds):
    #Feistel
    temp = []

    #Nibbles 0 and 1
    temp.append(p[0])
    val = s[p[0]] ^ p[1] ^ k[0] ^ rc0[r]
    temp.append(val)

    #Nibbles 2 and 3
    temp.append(p[2])
    val = s[p[2]] ^ p[3] ^ k[1] ^ rc1[r]
    temp.append(val)

    #The rest of the nibbles
    for i in range (4, 32, 2):
        temp.append(p[i])
        val = s[p[i]] ^ p[i+1] ^ k[int(i/2)]
        temp.append(val)

    #Permutation
    #Do not permute if final round
    if r != (rounds-1):
        for i in range (0, 32):
            p[perm[i]] = temp[i]
    else:
        p = temp

    return p

#Perform encryption of plaintext pair
def enc(p1, p0, k1, k0, rounds):
    
    mask = 0xF

    p = []
    for i in range (0, 16):
        p.append(p0 & mask)
        p0=p0>>4

    for i in range (0, 16):
        p.append(p1 & mask)
        p1=p1>>4

    K0 = []
    for i in range (0, 16):
        K0.append(k0 & mask)
        k0=k0>>4

    K1 = []
    for i in range (0, 16):
        K1.append(k1 & mask)
        k1=k1>>4

    for r in range (0, rounds):
        if r % 2 == 0:
            p = roundFunc(p, K0, r, rounds)
        else:
            p = roundFunc(p, K1, r, rounds)
    return p

#Decrypt a pair of nibbles at a particular index for a specific round
def decryptNibble(x0, x1, key, round, index):
    #RC0
    if index == 0:
        val = x1 ^ s[x0] ^ key ^ rc0[round-1]
    #RC1
    elif index == 2:
        val = x1 ^ s[x0] ^ key ^ rc1[round-1]
    else:
        val = x1 ^ s[x0] ^ key

    return val

    
def concat(a, b, c, d):
    return ("{:x}{:x}{:x}{:x}".format(a,b,c,d))