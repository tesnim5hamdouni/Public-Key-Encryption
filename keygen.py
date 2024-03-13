# KEM.KeyGen() generates a public key and a secret key for the KEM

import os
import subprocess
import hashlib
import sys


def PKE_KeyGen(path):
    """ 
    useCurve25519 from lab4 to generate a public key and a secret key
    """
    sk = os.urandom(32).hex()
    cmd = path + " " + sk
    result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE)
    pk = result.stdout.decode('utf-8').strip()
    return pk, sk


def KEM_KeyGen(filename, path):
    """
    FO transform applied to PKE.KeyGen()
    """
    #get public key and secret key from PKE.KeyGen()
    pk, sk = PKE_KeyGen(path)
    sk_file = open(filename, "w")
    sk_file.write(sk)
    sk_file.close()
    
    # public key hash using SHAKE-128    
    shake128 = hashlib.shake_128()
    shake128.update(pk.encode('utf-8'))
    pkh = shake128.hexdigest(32)
    
    #sk_prime = KDF(sk, s, pk ,pkh) with s random
    s = os.urandom(32).hex()
    sk_prime = hashlib.shake_128()
    sk_prime.update(s.encode('utf-8'))
    sk_prime.update(pk.encode('utf-8'))
    sk_prime.update(pkh.encode('utf-8'))
    sk_prime = sk_prime.hexdigest(32)
    return pk, sk_prime


#read filename as first argument
def main():
    if len(sys.argv) != 2:
        print("Usage: python3 keygen.py <filename>")
        return
    filename = sys.argv[1]
    path = "./x25519"
    pk, sk_prime = KEM_KeyGen(filename, path)
    print("PK: ", pk)
    print("SK': ", sk_prime)



if __name__ == "__main__":
    main()
    
    
    
    
    