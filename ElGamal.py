##!/usr/bin/env python3
##Реализация процедур, составляющих протокол подписи Эль-Гамаля с сокращённой длинной параметров.
import Crypto.Util.number as num
from Crypto import Random
from Crypto.Util import number
from sympy.ntheory import factorint
import random 
import sympy
import math
import hashlib
import sys
from hashlib import sha256

def MillerRabin(n):
        if n!=int(n):
            return False
        n=int(n)
        #Miller-Rabin test for prime
        if n==0 or n==1 or n==4 or n==6 or n==8 or n==9:
            return False 
        if n==2 or n==3 or n==5 or n==7:
            return True
        s = 0
        d = n-1
        while d%2==0:
            d>>=1
            s+=1
        assert(2**s * d == n-1)
 
        def trial_composite(a):
            if pow(a, d, n) == 1:
                return False
            for i in range(s):
                if pow(a, 2**i * d, n) == n-1:
                    return False
            return True   
        for i in range(8):#number of trials 
            a = random.randrange(2, n)
            if trial_composite(a):
                return False 
        return True 
def mod(a,p):                 #приведение по модулю
    mod = (a % p + p) % p
    return mod

def fast_pow(a, w, n):
    s = 1
    v = w
    c = a
    while not v == 0:
        if mod(v,2) == 1:
            s = mod(s*c,n)
            v = (v-1)//2
            c = mod(c**2,n)
        else:
            v = v//2
            c = mod(c*c,n)
    return s
def getPrimeFactors(n):
    prime_factor=[]
    while n%2==0:
        prime_factor.append(2)
        n=n/2
    for i in range(3, int(math.sqrt(n))+1,2):
        while n%i==0:
            prime_factor.append(int(i))
            n=n/i
    if n>2:
        prime_factor.append(int(n))
    return prime_factor

def main_menu():
    while True:
        print("\nLab 2:ELGAMAL DIGITAL SIGNATURE (SIMPLE IMPLEMENTATION)")
        print("1 - Keys generation")
        print("2 - Signing")
        print("3 - Verifying signature")
        print("4 - Test case invalid signature")
        s = int(input('> Enter your choice: '))
        if (s==1):
            print("\nKEYS GENERATION:")
            l_p = int(input("Enter length bits of prime p -> "))
            l_q=int(l_p/12.8)
            q=random.randint((2**l_q)/2,(2**l_q)-1)
            while not MillerRabin(q):
                q=random.randint((2**l_q)/2,(2**l_q)-1)
            i=1
            p=4
            dif =int(l_p-l_q)
            while not MillerRabin(p): #p=2*r*q+1
                p=q*2
                r=random.randint((2**dif)//2,(2**dif)-1) #r- нечетное число 
                p=int(p*r)+1
                i+=1
            g=1 #g- число относящееся к q как к показателю
            while g==1:
                aa=random.randint(2,p-1)
                qq=(p-1)//q
                g=fast_pow(aa,qq,p)

            #while 1: 
            #    #q= genprimeBits(l)
            #    p=2*q+1 #выбор показатель q, q|p-1
            #    if num.isPrime(p):
            #        break                         
            #r=getPrimeFactors(q)
            #print(r)
            #while 1:
            #    g=num.getRandomRange(3,p)
            #    safe=1
            #    if pow(g,2,p)==1:
            #        safe==0
            #    if safe and pow(g,q,p)==1:
            #        safe=0
            #    if safe and divmod(p-1,g)[1]==0:
            #        safe=0
            #        # g^(-1) must not divide p-1 because of Khadir's attack 
            #    ginv=num.inverse(g,p)
            #    if safe and divmod(p-1,ginv)[1]==0:
            #        safe=0
            #    if safe:
            #        break
            #while(num.GCD(g,p-1)!=1):
            #    g=num.getRandomRange(3,p)

            print("Prime number p ->", p,"\nBinary p ->","(",bin(p),")")
            print("\nGenerator g ->",g)
            
            x=num.getRandomRange(1,p-1)   
            while (num.GCD(x,p-1)!=1):
                x=num.getRandomRange(1,p-1) 
            print("\nPrivate key x ->",x)

            y=pow(g,x,p)
            print("\nCalculating y=g^x mod p -> y=",y)
            print("\nCombo public key (p,g,y)->",p,g,y)

        elif (s==2):
            print("\nSIGNING:")
            input_message = input("Message: ")
            inputbytes = str.encode(input_message)
            while 1:
                k=num.getRandomRange(1,p-2)#k-random number in range(1,p-2), HOD(k,p-1)=1
                if (num.GCD(k,p-1)==1):
                    break
            #length of hash=256 bits
            h = hashlib.sha256(input_message.encode('utf-8')).hexdigest()
            mes = int(h,16)
            print("\nHashed message  -> (",mes.bit_length(),"bits)",mes) #(length bits M must < length bits p)
            R=pow(g,k,p)
            print("\nParameter signature R=g^k mod p (",R.bit_length(),"bits) -> ",R)
            t=num.inverse(k,q)
            S=t*(mes-R*x)%(q)
            print("\nParameter signature S=(M-Rx)k^(-1) mod p (",S.bit_length(),"bits)-> ",S)
            print("\nSinging signature (R,S).... -> (",R, S,")")
            print("\nMessage is signed! [M,R,S] -> [",input_message,"(",R,S,")]")
            print("\nSecret parameter k ->",k)

        elif (s==3):
            print("\nVERIFYING A SIGNATURE:")
            if (R>p) or (S>(p-1)) or (num.GCD(g,(p-1))!=1) :
                print ("\nWrong Signature! Invalid parameters R or S")                
            D1=pow(g,mes,p) #D1=g^m mod p
            D2=(pow(y,R,p)*pow(R,S,p))%p #D2=y^R*R^S(mod p)
            print ("\nD1=g^m mod p->",D1)
            print("\nD2=y^R*R^Smod p->",D2)
            if (D1==D2):
                print("\nCorrect Signature!")
            else:
                print("\nWrong signature! Invalid parameters R or S")

            
        elif (s==4):
            print("\n4.TEST CASE INVALID SIGNATURE")
            k1=num.getRandomRange(1,p-1) #k random but is not checked
            print("\nNew k' ->",k1)
            R1=pow(g,k1,p) #R changed because of k changed
            print("\nParameter signature (changed) R'=g^k' mod p (",R1.bit_length(),"bits) -> ",R1)
            #t1=num.inverse(k1,q)
            #S1=t1*(mes-R1*x)%(q)
            #print("\nParameter signature S (changed) S'=(M-R'x)k'^(-1) mod p (",S1.bit_length(),"bits)-> ",S1)
            print("\nSinging signature (R',S).... -> (",R1, S,")")
            print("\nMessage is signed! [M,R',S] -> [",input_message,"(",R1,S,")]")
            D1_d=pow(g,mes,p) #D1=g^m mod p
            D2_d=(pow(y,R1,p)*pow(R1,S,p))%p #D2=y^R*R^S(mod p)
            print ("\nD1'=g^m mod p->",D1_d)
            print("\nD2'=y^R'*R'^S'mod p->",D2_d)
            if (D1_d==D2_d):
                print("\nCorrect Signature!")
            else:
                print("\nWrong signature! Invalid parameters R or S")
           
main_menu()








