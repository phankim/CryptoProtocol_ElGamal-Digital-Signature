##!/usr/bin/env python3
##Реализация процедур, составляющих протокол подписи Эль-Гамаля с сокращённой длинной параметров.
import Crypto.Util.number as num
from Crypto import Random
from Crypto.Util import number
import random 
import sympy
import hashlib
import sys
from hashlib import sha256
from binascii import hexlify, unhexlify


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

def genprimeBits(k):
    x = ""
    k = int(k)
    for y in range(k):
        x = x + "1"
    y = "1"
    for z in range(k-1):
        y = y + "0"
    x = int(x,2)
    y = int(y,2)
    p = 0
    while True:
        p = random.randint(y,x)
        if MillerRabin(p):
            break
    return p


def main_menu():
    while True:
        print("\nLab 2:ELGAMAL DIGITAL SIGNATURE (SIMPLE IMPLEMENTATION)")
        print("1 - Keys generation")
        print("2 - Signing")
        print("3 - Verifying signature")
        print("4 - Exit")
        s = int(input('> Enter your choice: '))
        if (s==1):
            print("\nKEYS GENERATION:")
            l = int(input("Enter length bits of prime p -> "))
            
            while 1: 
                q= genprimeBits(l)
                p=2*q+1 #выбор показатель q, q|p-1
                if num.isPrime(p):
                    break                         
            
            while 1:
                g=num.getRandomRange(3,p)
                safe=1
                if pow(g,2,p)==1:
                    safe==0
                if safe and pow(g,q,p)==1:
                    safe=0
                if safe and divmod(p-1,g)[1]==0:
                    safe=0
                    # g^(-1) must not divide p-1 because of Khadir's attack 
                ginv=num.inverse(g,p)
                if safe and divmod(p-1,ginv)[1]==0:
                    safe=0
                if safe:
                    break
            while(num.GCD(g,p-1)!=1):
                g=num.getRandomRange(3,p)

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
            print("\nHashed message (length bits M must < length bits p) -> (",mes.bit_length(),"bits)",mes)
            R=pow(g,k,p)
            print("\nParameter signature R (",R.bit_length(),"bits) -> ",R)
            t=num.inverse(k,q)
            S=t*(mes-R*x)%(q)
            print("\nParameter signature S (",S.bit_length(),"bits)-> ",S)
            print("\nSinging signature (R,S).... -> (",R, S,")")
            print("\nMessage is signed! [M,R,S] -> [",input_message,"(",R,S,")]")
            print("\nSecret parameter k ->",k)
        elif (s==3):
            print("\nVERIFYING A SIGNATURE:")
            if (R>p) or (S>(p-1)) or (num.GCD(g,(p-1))!=1) :
                print ("\nWrong Signature! Invalid parameters R or S")                
            D1=pow(g,mes,p)
            D2=(pow(y,R,p)*pow(R,S,p))%p
            print ("\nD1=g^m mod p->",D1)
            print("\nD2=y^R*R^Smod p->",D2)
            if (D1==D2):
                print("\nCorrect Signature!")
            else:
                print("\nWrong signature! Invalid parameters R or S")
            
        elif (s==4):
            exit()
       
           
main_menu()








