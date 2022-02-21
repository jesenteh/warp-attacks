#Differential Cryptanalysis of WARP

Verification for the related-key attack on WARP (https://eprint.iacr.org/2021/1641)

For the CryptoSMT boomerang tool, please visit: https://github.com/jesenteh/cryptosmt-boomerang

Instructions:
1. Run ```python3 attack.py``` to perform a 15-round related-key attack using 2^9 chosen plaintext pairs for fast verification.
2. Run ```python3 attack.py -r 25 -r 19``` to verify the 25-round related key attack from the paper.
3. Run ```python3 attack.py -r 25 -r 19 -s 1``` to verify the 25-round related key attack along with its attack complexity. This command will perform additional 2^20 WARP encryptions to estimate the encryption speed of our WARP implementation.

