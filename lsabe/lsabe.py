
import os
import re
# https://jhuisi.github.io/charm/cryptographers.html
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from pathlib import Path

class LSABE():
    def __init__(self, msk_path):

# These are file names to load\store MSK and PP
        self.msk_fname = msk_path.joinpath('lsabe.msk')   
        self.pp_fname  = msk_path.joinpath('lsabe.pp')   
# ....
# [charm crypto] For symmetric pairing G1 == G2  
        self.group = PairingGroup('SS512')

# ....
# System Initialization (MSK and PP)
# Serialized to lsabe.msk and lsabe.pp
    def SystemInit(self):
        f = self.group.random(G1) 
        g = self.group.random(G1)
        alfa, beta, lmbda = self.group.random(ZR), self.group.random(ZR), self.group.random(ZR)        
        e_gg_alfa = pair(g, g) ** alfa
        self.MSK = { 'alfa':alfa, 'beta':beta, 'lambda':lmbda }        
        self.PP =  { 'f':f, 'g':g, 'g^beta':g ** beta, 'g^lambda':g ** lmbda, 'e(gg)^alfa':e_gg_alfa}

        try:
            self.__serialize__MSK()
            self.__serialize__PP()
        except:
            return False
        return True

    def SystemLoad(self):
        try:
            self.__deserialize__MSK()
            self.__deserialize__PP()
        except: 
            return False
        return True

    def __serialize__MSK(self):
        file = self.msk_fname.open(mode='wb')
        for v in self.MSK.values():
            file.write(self.group.serialize(v))
        file.close

    def __serialize__PP(self):
        file = self.pp_fname.open(mode='wb')
        for v in self.PP.values():
            file.write(self.group.serialize(v))
        file.close

    def __deserialize__MSK(self):
        file = self.msk_fname.open(mode = 'r')
        data = file.read()
        file.close
        d = re.split('=', data)

        self.MSK = {}
        self.MSK['alfa']    = self.group.deserialize(d[0].encode())
        self.MSK['beta']    = self.group.deserialize(d[1].encode())
        self.MSK['lambda']  = self.group.deserialize(d[2].encode())

    def __deserialize__PP(self):
        file = self.pp_fname.open(mode = 'r')
        data = file.read()
        file.close
        d = re.split('=', data)

        self.PP = {}
        self.PP['f']            = self.group.deserialize(d[0].encode())
        self.PP['g']            = self.group.deserialize(d[1].encode())
        self.PP['g^beta']       = self.group.deserialize(d[2].encode())
        self.PP['g^lambda']     = self.group.deserialize(d[3].encode())
        self.PP['e(gg)^alfa']   = self.group.deserialize(d[4].encode())

# ....
#
    def KeyGen(self, S):
        t, delta = self.group.random(ZR), self.group.random(ZR)
        SK1 = self.PP['g'] ** (self.MSK['alfa']/(self.MSK['lambda'] + t))
        SK2 = delta
        SK3 = self.PP['g'] ** t
        SK4 = []
        for s in S:
            SK4.append(self.group.hash(s, ZR))
        SK5 = (self.PP['g'] ** self.MSK['alfa']) * (self.PP['g'] ** (self.MSK['beta'] * t))
 
        return (SK1, SK2, SK3, SK4, SK5) 

    def serialize__SK(self, SK, sk_fname):
        (SK1, SK2, SK3, SK4, SK5) = SK
        file = open(sk_fname, mode='wb')
        file.write(self.group.serialize(SK1))
        file.write(self.group.serialize(SK2))
        file.write(self.group.serialize(SK3))
        file.write(b'%(len)04d=' %{b"len":  len(SK4)} )
        for s in SK4:
            file.write(self.group.serialize(s))
        file.write(self.group.serialize(SK5))

    def deserialize__SK(self, sk_fname):
        file = open(sk_fname, 'r')
        data = file.read()
        file.close
        d = re.split('=', data)
        SK1  = self.group.deserialize(d[0].encode())
        SK2  = self.group.deserialize(d[1].encode())
        SK3  = self.group.deserialize(d[2].encode())
        sz = d[3]
        SK4 = []
        for i in range(0, int(sz)):
            SK4.append(self.group.deserialize(d[4+i].encode()))
        SK5 = self.group.deserialize(d[4+int(sz)].encode())

        SK = (SK1, SK2, SK3, SK4, SK5)
        return SK 