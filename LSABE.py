
import os
# https://jhuisi.github.io/charm/cryptographers.html
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair

class LSABE():
    def __init__(self):
# ....
# [charm crypto] For symmetric pairing G1 == G2  
        self.group = PairingGroup('SS512')    

    def SystemInit(self):
# ....
# Still some mistery here. 
# g has to be "generator", but f just "belongs" to G
        f, self.g = self.group.random(G1), self.group.random(G1)
        self.alpha, self.beta, self.lmbda = self.group.random(ZR), self.group.random(ZR), self.group.random(ZR)        
        e_gg_alpha = pair(self.g, self.g) ** self.alpha
        MSK = { 'alpha':self.alpha, 'beta':self.beta, 'lambda':self.lmbda }        
        PP =  { 'f':f, 'g':self.g, 'g^beta':self.g ** self.beta, 'g^lambda':self.g ** self.lmbda, 'e(gg)^alpha':e_gg_alpha}
        return (MSK, PP)

    def SecretKeyGen(self):
        self.tau, delta = self.group.random(ZR), self.group.random(ZR)
        K1 = self.g ** (self.alpha/(self.lmbda + self.tau))
        K2 = delta
        K3 = self.g ** self.tau
        K5 = (self.g ** self.alpha) * (self.g ** (self.beta * self.tau))
        SK = (K1, K2, K3, K5)
        return SK

    def TransKeyGen(self):
        zetta = self.group.random(ZR)
        K_3 = self.g ** (zetta * self.tau)    
        K_5 = ( self.g ** (zetta * self.alpha) ) * (self.g ** (zetta * self.beta * self.tau))   
        TK = (K_3, K_5)
        return TK

#
def main():
    print('Hello, World!')
    lsabe = LSABE()
    (MSK, PP) = lsabe.SystemInit()
    SK = lsabe.SecretKeyGen()
    TK = lsabe.TransKeyGen()
    
    print(TK)


if __name__ == '__main__':
    main()