#RSA暗号
import math

class rsaClass:
    
    #generate public key, private key and module
    def generate_keys(p, q):
        N = p*q
        L = math.lcm(p-1, q-1) #least common multiple between p-1 and q-1
        for i in range(2, L):
            if math.gcd(i, L) == 1: #greatest common divisor
                E = i
                break
        for i in range(2, L):
            if(E*i) % L == 1:
                D = i
                break
        #E:public key, D:private key, N:module
        return E,D,N
    
    #encription by public key
    def encrypt(plain_text, E, N):
        plain_integers = [ord(char) for char in plain_text]
        encrypted_integers = [pow(i, E, N) for i in plain_integers]
        encrypted_text = ''.join(chr(i) for i in encrypted_integers)

        return encrypted_text

    #decryption by private key
    def decrypt(encrypted_text, D, N):
        encrypted_integers = [ord(char) for char in encrypted_text]
        decrypted_intergers = [pow(i, D, N) for i in encrypted_integers]
        decrypted_text = ''.join(chr(i) for i in decrypted_intergers)

        return decrypted_text
