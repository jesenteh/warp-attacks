import math, random, argparse, time
import utils

#Key difference
RK1 = 0x0000000010000010
RK2 = 0x0000000000200000

#Plaintext difference
DP1 = 0x0000000000001000
DP2 = 0x0000000000000000

parser = argparse.ArgumentParser(
    description="""
Sample cmd:
$ time python3 attack.py -r 15 -p 9 > log.out
""".strip()
)
parser.add_argument('-r', "--rounds", type=int, default=15,
                    help='Number of rounds to attack')
parser.add_argument('-p', "--pairs", type=int, default=9,
                    help='Number of plaintext pairs')
parser.add_argument('-s', "--speed", type=int, default=0,
                    help='Check WARP encryption speed')
args = parser.parse_args()

#Parameters for the attack
rounds = args.rounds
pairs = args.pairs
checkComp = args.speed
def main():
    """
    Note:
    The way the original represents the data is the inverse of what is done in cryptanalysis paper.
    Original WARP paper 0 to 31 from left to right.
    Cryptanalysis paper 31 to 0 from left to right. 
    The printHex function will iterate and print each element in the list from 0 to 31 (following the original WARP paper).
    """

    #Key
    K0_1 = random.getrandbits(64)
    K1_1 = random.getrandbits(64)

    #Target keys
    #k0_4
    t4 = K0_1 & 0x00000000000F0000
    t4 = t4>>16
    #k0_7
    t7 = K0_1 & 0x00000000F0000000
    t7 = t7>>28
    #k0_10
    t10 = K0_1 & 0x00000F0000000000
    t10 = t10>>40
    #k0_14
    t14 = K0_1 & 0x0F00000000000000
    t14 = t14>>56

    #Related key
    K0_2 = K0_1 ^ RK1
    K1_2 = K1_1 ^ RK2

    numpairs = int(math.pow(2,pairs))

    """
    In the following, we encrypt each pair and perform the guess-and-determine procedure.
    We will not store the plaintext-ciphertext pairs.
    """
    p0_1 = 0
    p1_1 = 0
    
    #Variables to store plaintexts after encryption
    m1 = []
    m2 = []

    k0_4 = []
    k0_7 = []
    k0_10 = []
    k0_14 = []

    start = time.time()
    for i in range (0, numpairs):
        #Permute plaintext space to make it random-like
        p0_1 += 0xe014a5131e135888
        p1_1 += 0x711df0d1b6ec7110

        #Generate the second plaintext with the required difference
        p0_2 = p0_1 ^ DP1
        p1_2 = p1_1 ^ DP2

        m1 = utils.enc(p1_1, p0_1, K1_1, K0_1, rounds)
        m2 = utils.enc(p1_2, p0_2, K1_2, K0_2, rounds)

        #Check for surviving pairs (Step 1 Key Recovery)
        filter = [2,3,4,5,6,7,10,11,12,13,18,19,24,25,28]
        invalid = 0
        for i in filter:
            if (m1[i] ^ m2[i]) != 0:
                #If pair is invalid, discard
                invalid = 1
                break
        if invalid == 1:
            continue

        """
        Guess and determine procedure begins here, which will be performed for the subround filters 
        of the penultimate round.
        Guess keys from the final round to calculate the nibble that goes through the S-box in the 
        subround filter.
        Calculate the other nibble involved in the subround filter directly from the ciphertext pair
        Check the filter to see if the key/pair is valid, discard if not.
        """

        check = 0
        for k in range (0, 16):
            #Decrypt m1
            x0_1 = utils.decryptNibble(m1[8], m1[9], k, rounds, 8)
            #Decrypt m2
            x0_2 = utils.decryptNibble(m2[8], m2[9], k, rounds, 8)

            x1_1 = m1[20]
            x1_2 = m2[20]

            #Check for surviving pairs
            if ( (utils.s[x0_1] ^ utils.s[x0_2]) ^ (x1_1 ^ x1_2) == 0):
                #If pair is valid, store key
                k0_4.append(k)
                check += 1
        if check == 0: 
            #If no key+pair fulfils difference, discard
            continue

        check = 0
        for k in range (0, 16):
            #Decrypt m1
            x0_1 = utils.decryptNibble(m1[14], m1[15], k, rounds, 14)
            #Decrypt m2
            x0_2 = utils.decryptNibble(m2[14], m2[15], k^1, rounds, 14)

            x1_1 = m1[22]
            x1_2 = m2[22]

            #Check for surviving pairs
            if ( (utils.s[x0_1] ^ utils.s[x0_2]) ^ (x1_1 ^ x1_2) == 0):
                #If pair is valid, store key
                k0_7.append(k)
                check += 1 
        if check == 0:
            #If no key+pair fulfils difference, discard
            continue

        check = 0
        for k in range (0, 16):
            #Decrypt m1
            x0_1 = utils.decryptNibble(m1[20], m1[21], k, rounds, 20)
            #Decrypt m2
            x0_2 = utils.decryptNibble(m2[20], m2[21], k, rounds, 20)

            x1_1 = m1[8]
            x1_2 = m2[8]

            #Check for surviving pairs
            if ( (utils.s[x0_1] ^ utils.s[x0_2]) ^ (x1_1 ^ x1_2) == 0):
                #If pair is valid, store key
                k0_10.append(k)
                check = check + 1 
        if check == 0:
            #If no key+pair fulfils difference, discard
            continue

        check = 0
        for k in range (0, int(math.pow(2,4))):
            #Decrypt m1
            x0_1 = utils.decryptNibble(m1[28], m1[29], k, rounds, 28)
            #Decrypt m2
            x0_2 = utils.decryptNibble(m2[28], m2[29], k, rounds, 28)

            x1_1 = m1[14]
            x1_2 = m2[14]

            #Check for surviving pairs
            if ( (utils.s[x0_1] ^ utils.s[x0_2]) ^ (x1_1 ^ x1_2) == 0):
                #If pair is valid, store key
                k0_14.append(k)
                check = check + 1 
        if check == 0:
            #If no key+pair fulfils difference, discard
            continue

        # Count the keys for each pair
        # Create index
        key_index = [4,7,10,14]

    #Print keys and their corresponding counters
    counter = {}

    if len(k0_4)==0 or len(k0_7)==0 or len(k0_10)==0 or len(k0_14)==0:
        print("No right pair found.")
        exit(-1)

    for k0 in k0_4:  
        for k1 in k0_7:   
            for k2 in k0_10:
                for k3 in k0_14:
                    tmp = utils.concat(k0,k1,k2,k3)
                    if tmp not in counter.keys():
                        counter[tmp] = 1
                    else:
                        counter[tmp] += 1
        
    end = time.time()
    target = utils.concat(t4,t7,t10,t14)
    ctr = 0
    for w in sorted(counter, key=counter.get, reverse=True):
        if ctr > 32:
            break
        if w == target:
            print("\033[92m", w, counter[w],"\033[0m")
        else:
            print(w, counter[w])
        ctr += 1
    
    print("Target key =",target,"Count =", counter[target])
    attackTime = end-start
    print("Attack time = {:.2f} seconds".format(attackTime))
        
    #Check implementation WARP encryption speed and attack complexity
    if checkComp == 1:
        start = time.time()
        for i in range (0, 2**20):
            #Permute plaintext space to make it random-like
            p0_1 += 0xe014a5131e135888
            p1_1 += 0x711df0d1b6ec7110
            m1 = utils.enc(p1_1, p0_1, K1_1, K0_1, rounds)
        end = time.time()
        speed = 2**20 / (end-start)
        print("Encryption speed = 2**{:.2f}".format(math.log2(speed)), "Warp Encryptions/s")
        print("Attack complexity = 2**{:.2f} Warp Encryptions".format(math.log2(attackTime*speed)))

if __name__ == '__main__':
    main()