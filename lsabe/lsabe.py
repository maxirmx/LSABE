
import os
import re
# https://jhuisi.github.io/charm/cryptographers.html
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from pathlib import Path

class LSABE():
    def __init__(self, msk_path):

# These are file names to load\store MSK and PP
        self._msk_fname = msk_path.joinpath('lsabe.msk')   
        self._pp_fname  = msk_path.joinpath('lsabe.pp')   
# ....
# [charm crypto] For symmetric pairing G1 == G2  
        self.group = PairingGroup('SS512')

    @property
    def msk_fname(self):
        return str(self._msk_fname)

    @property
    def pp_fname(self):
        return str(self._pp_fname)

 # Setup  (κ)→(MSK,PP).  Given  the  security  parameter κ, 
 # setup algorithm outputs the master secret key denoted by MSK and public parameters denoted byPP.
    def SystemInit(self):
        f = self.group.random(G1) 
        g = self.group.random(G1)
        alfa, beta, lmbda = self.group.random(ZR), self.group.random(ZR), self.group.random(ZR)        
        e_gg_alfa = pair(g, g) ** alfa
        self.MSK = { 'alfa':alfa, 'beta':beta, 'lambda':lmbda }        
        self.PP =  { 'f':f, 'g':g, 'g^beta':g ** beta, 'g^lambda':g ** lmbda, 'e(gg)^alfa':e_gg_alfa}

        self.__serialize__MSK()
        self.__serialize__PP()

    def SystemLoad(self):
        self.__deserialize__MSK()
        self.__deserialize__PP()

    def __serialize__MSK(self):
        file = self._msk_fname.open(mode='wb')
        for v in self.MSK.values():
            file.write(self.group.serialize(v))
        file.close


    def __serialize__PP(self):
        file = self._pp_fname.open(mode='wb')
        for v in self.PP.values():
            file.write(self.group.serialize(v))
        file.close

    def __deserialize__MSK(self):
        file =self._msk_fname.open(mode='r')
        data = file.read()
        file.close
        d = re.split('=', data)

        self.MSK = {}
        self.MSK['alfa']    = self.group.deserialize(d[0].encode())
        self.MSK['beta']    = self.group.deserialize(d[1].encode())
        self.MSK['lambda']  = self.group.deserialize(d[2].encode())

    def __deserialize__PP(self):
        file = self._pp_fname.open(mode='r')
        data = file.read()
        file.close
        d = re.split('=', data)

        self.PP = {}
        self.PP['f']            = self.group.deserialize(d[0].encode())
        self.PP['g']            = self.group.deserialize(d[1].encode())
        self.PP['g^beta']       = self.group.deserialize(d[2].encode())
        self.PP['g^lambda']     = self.group.deserialize(d[3].encode())
        self.PP['e(gg)^alfa']   = self.group.deserialize(d[4].encode())

    def KeyGen(self, S):
        t, delta = self.group.random(ZR), self.group.random(ZR)
        SK1 = self.PP['g'] ** (self.MSK['alfa']/(self.MSK['lambda'] + t))
        SK2 = delta
        SK3 = self.PP['g'] ** t
        SKX = []
        for s in S:
            SKX.append(self.group.hash(s, G1) ** t)
        SK5 = (self.PP['g'] ** self.MSK['alfa']) * (self.PP['g'] ** (self.MSK['beta'] * t))
        SK = (SK1, SK2, SK3, SKX, SK5)
 
        return SK

    def IndexGen(self, KW, A, rho):
        s, b = self.group.random(ZR), self.group.random(ZR)

        I = hren * (pair(self.PP['g'], self.PP['g']) ** (self.MSK['alfa'] * s))
        I1 = self.PP['g^beta']
        I2 = self.PP['g'] ** (self.MSK['lambda'] * self.MSK['beta'])
        I3 = self.PP['g'] ** s
        I4 = self.PP['g'] ** hhhhren
        Ii = []
        for r in rho:
            Ii.append()


