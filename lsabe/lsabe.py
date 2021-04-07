
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
        f, g = self.group.random(G1), self.group.random(G1)
        alfa, beta, lmbda = self.group.random(ZR), self.group.random(ZR), self.group.random(ZR)        
        e_gg_alfa = pair(g, g) ** alfa
        self.MSK = { 'alfa':alfa, 'beta':beta, 'lambda':lmbda }        
        self.PP =  { 'f':f, 'g':g, 'g^beta':g ** beta, 'g^lambda':g ** lmbda, 'e(gg)^alfa':e_gg_alfa}
        return (self.MSK, self.PP)

    def KeyGen(self):
        t, delta = self.group.random(ZR), self.group.random(ZR)
        SK1 = self.PP['g'] ** (self.MSK['alfa']/(self.MSK['lambda'] + t))
        SK2 = delta
        SK3 = self.PP['g'] ** t
        SK5 = (self.PP['g'] ** self.MSK['alfa']) * (self.PP['g'] ** (self.MSK['beta'] * t))
        SK = (SK1, SK2, SK3, SK5)
 
        z = self.group.random(ZR)
        TK3 = self.PP['g'] ** (z * t)    
        TK5 = (self.PP['g'] ** (z * self.MSK['alfa']) ) * (self.PP['g'] ** (z * self.MSK['beta'] * t))   
        TK = (TK3, TK5)
        return (SK,TK)

#
def main():
    print('Hello, World!')
    lsabe = LSABE()
    (MSK, PP) = lsabe.SystemInit()

    (SK, TK) = lsabe.KeyGen()
    
    print(TK)


