import os
import subprocess
import hashlib
import sys
from elgamal.elgamal import ElGamal

def PKE_Encaps(M, pk, r):
    """
    takes a plaintext M, a public key PK, and randomness r
    returns a ciphertext C.
    """
    c = ElGamal(pk).encrypt(M, r)
    return c
    


def KME_Encaps(pk, path):
    """
    FO transform applied to PKE.Encaps()
    """
    # M is random
    M = os.urandom(32)
    # (r ∥ k) ← G2(G1(PK) ∥ M)  where G1 and G2 are shake128
    hash = hashlib.shake_128()
    pkh = hash.update(pk)
    # hash pkh || M
    hash.update(M)
    # get r and k
    r = hash.digest(32)
    k = hash.digest(32)
    print("r: ", r)
    print("k: ", k)
    


    
    








def main():
    if len(sys.argv) != 2:
        print("Usage: python3 encaps.py <pk>")
        return
    pk = sys.argv[1]
    KME_Encaps(pk, "test")