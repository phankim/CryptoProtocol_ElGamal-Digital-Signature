# CryptoProtocol_ElGamal-Digital-Signature
Simple implementation El-Gamal signature protocol with shortened parameter lengths using the Python 

## Requirements  
Implementation of the procedures that make up the ElGamal signature protocol with shortened parameter lengths using Python 3.7.
## Basic theoretical provisions  
ElGamal's cryptosystem is asymmetric with a public key, based on the difficulty of computing discrete logarithms in a finite field. The cryptosystem includes an encryption algorithm and a digital signature algorithm. The El Gamal open encryption method includes an integral part of the Diffie-Hellman public key distribution system.  
Algorithm:  
### 1. Generating keys  
-A random prime number p is generated;  
-An integer g is chosen - the antiderivative root g modulo p (g <p). The numbers p and g are domain parameters (i.e., public system parameters used by many users simultaneously);  -A random integer is chosen, coprime to (p - 1), x, such that 1 <x <p-1;  
y=g^xmod p is calculated;  

The public key is a triple of numbers (p, g, y), the private (secret) key - the number x is kept secret:   
     Number y is the public key used to verify the sender's signature. The number y is openly transmitted to all potential recipients of documents.  
     Number x is the sender's secret key for signing documents and must be kept secret.   
The hash function can be chosen as a one-way function. A hash function is a function that converts an array of input data of arbitrary length into a (output) bit string of a specified length, performed by a certain algorithm.  
### 2. Signing  
The hash of the message is calculated m = H (M), where M is the message. In this case, the condition 1 <m <(p-1) must be fulfilled;  
A random number k is chosen (this is a randomizer, kept secret) from the interval (1; p-1), coprime with p - 1, and calculated:   R≡g ^ k mod p.   
Find the number S from the equation m≡Rx + kS mod (p-1) i.e. S≡ (m-Rx) k ^ (- 1) mod (p-1).   
The signature of message M is the pair (R, S). A triplet (M, R, S) is sent to the recipient, while the pair of numbers (x, k) is kept secret. The peculiarity of this electronic digital signature is that it is not allowed to use the same value of k to generate a signature for two different messages, since this makes it possible to calculate the secret key. The used k values must be kept secret, usually after the signature is generated, they are destroyed.     
### 3.Verifying signature  
Knowing the public key (p, g, y), the signature (R, S) of message M is verified as follows:    
The fulfillment of the conditions is checked: 0 <R <p and 0 <S <p-1. If at least one of them is not fulfilled, then the signature has not been verified;   
The hash of the message is calculated m = H (M);   
Calculate D1≡g^m(mod p) and D2≡y^R* R^S (mod p);  
The signature is only accepted if: D1 = D2 the signature is correct, the message has not been tampered with. This equation is obtained by setting the value R = g ^ m mod p into the signature verification equation:    g^m≡y^R* R^S mod p.    
## ElGamal scheme with reduced length of parameters R and S (book: 2.	Молдовян Н.А. Практикум по криптосистемам с открытым ключом, БХВ-Петербург, 2007-304с)   
-The signature verification equation g^m≡y^R* R^S (mod p) can also be fulfilled in the case when g is taken to be a number related to a prime exponent q, where q | p-1. For this, S must be calculated from the following ratio:   m≡Rx + kS mod q.
-The signature verification relation g^m≡y^R* R^S (mod p) in a scheme with a reduced parameter S (S <q) can be transformed into an equation of the following form:
R≡g^(m/S)* y^(-R/S)mod⁡p.
-In this case, instead of R to the power of y, you can use the value of some hash function of the value of R, i.e. H (R). In this case, the signature verification equation is R = g^(m/S)* y^(-H(R)/S)mod⁡p. For the verification to be correct, the owner of the private key must compute the S parameter from the following comparison:
m≡xH (R) + kS mod q.   
-Since the signature verification does not require any calculations using the R parameter, the signature verification can be performed according to the equation:
H(R)=H(g^(m∕S)* y^(-H(R)/S)mod⁡p).  
-In this case, it is not necessary to present to the verifier the value of R having a comparatively long length. It is enough for verification to represent the value H(R), where the size of the hash function value is, for example, 160 bits. This achieves a significant reduction in the length of the signature.   

-Reducing the length of the signature does not reduce the security of the EDS system, since the complexity of the discrete logarithm problem does not change, i.e. calculations are performed modulo the original size.    
-The hash function H (R) can be taken as follows H(R)=R mod q, where q is the exponent used to reduce the parameter S. Then we arrive at the following signature verification equation:    
R'= (g^(m/S)* y^(-R'/S)mod p) mod q, where (R', S') are signatures to the message M, and the parameter R 'is calculated after choosing a random number k in accordance with the formula R'=(g^kmod p) mod q.   
-The comparison used to calculate the parameter S is: M = R'x+ kS mod q.    

