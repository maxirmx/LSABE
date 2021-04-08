
import os
import re
# https://jhuisi.github.io/charm/cryptographers.html
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair

class LSABE():
    def __init__(self):
# ....
# [charm crypto] For symmetric pairing G1 == G2  
        self.group = PairingGroup('SS512')    

    def SystemInit(self):
# ....
        f = self.group.random(G1) 
        g = self.group.random(G1)
        alfa, beta, lmbda = self.group.random(ZR), self.group.random(ZR), self.group.random(ZR)        
        e_gg_alfa = pair(g, g) ** alfa
        self.MSK = { 'alfa':alfa, 'beta':beta, 'lambda':lmbda }        
        self.PP =  { 'f':f, 'g':g, 'g^beta':g ** beta, 'g^lambda':g ** lmbda, 'e(gg)^alfa':e_gg_alfa}

        self.__serialize__(self.MSK, "/home/maxirmx/key.lsabe")
        self.__serialize__(self.PP,  "/home/maxirmx/key.lsabe.pub")

        self.__deserialize__MSK("/home/maxirmx/key.lsabe")
        self.__deserialize__PP("/home/maxirmx/key.lsabe.pub")

    def __serialize__(self, dict, filename):
        file = open(filename, 'wb')
        for v in dict.values():
            file.write(self.group.serialize(v))
        file.close

    def __deserialize__MSK(self, filename):
        file = open(filename, 'r')
        data = file.read()
        file.close
        d = re.split('=', data)

        self.MSK = {}
        self.MSK['alfa']    = self.group.deserialize(d[0].encode())
        self.MSK['beta']    = self.group.deserialize(d[1].encode())
        self.MSK['lambda']  = self.group.deserialize(d[2].encode())

    def __deserialize__PP(self, filename):
        file = open(filename, 'r')
        data = file.read()
        file.close
        d = re.split('=', data)

        print (self.PP)
        self.PP = {}
        self.PP['f']            = self.group.deserialize(d[0].encode())
        self.PP['g']            = self.group.deserialize(d[1].encode())
        self.PP['g^beta']       = self.group.deserialize(d[2].encode())
        self.PP['g^lambda']     = self.group.deserialize(d[3].encode())
        self.PP['e(gg)^alfa']   = self.group.deserialize(d[4].encode())
        print (self.PP)

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
    lsabe.SystemInit()
    (SK, TK) = lsabe.KeyGen()
    
 