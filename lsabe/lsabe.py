
import os
import re
# https://jhuisi.github.io/charm/cryptographers.html
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,GT,pair,extract_key
from pathlib import Path
from .formuleDeViete import formuleDeViete
from .symcrypto import SymmetricCryptoAbstraction

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

# ................................................................................
# Setup  (κ)→(MSK,PP). Given  the  security  parameter к, Setup algorithm  outputs  
# the  master  secret  key  denoted  by MSK and public parameters denoted by PP.    
# ................................................................................
    def SystemInit(self):
        f = self.group.random(G1) 
        g = self.group.random(G1)
        alfa, beta, lmbda = self.group.random(ZR), self.group.random(ZR), self.group.random(ZR)        
        e_gg_alfa = pair(g, g) ** alfa
        self.MSK = { 'alfa':alfa, 'beta':beta, 'lambda':lmbda }        
        self.PP =  { 'f':f, 'g':g, 'g^beta':g ** beta, 'g^lambda':g ** lmbda, 'e(gg)^alfa':e_gg_alfa}

        try:
            self.__serialize__MSK()
            print (self.MSK)
            self.__deserialize__MSK()
            print(self.MSK)
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
        file = self._msk_fname.open(mode='wb')
        map(trace(lambda self, file, v: file.write(self.group.serialize(v))), self.MSK )
        file.close
#        for v in self.MSK.values():
#            file.write(self.group.serialize(v))

    def __serialize__PP(self):
        file = self._pp_fname.open(mode='wb')
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

# .... Secret Key
#
    def SecrekeyGen(self, S):
        t, delta = self.group.random(ZR), self.group.random(ZR)
        K1 = self.PP['g'] ** (self.MSK['alfa']/(self.MSK['lambda'] + t))
        K2 = delta
        K3 = self.PP['g'] ** t
        K4 = []
        for s in S:
            K4.append(self.group.hash(s, G1))
        K5 = (self.PP['g'] ** self.MSK['alfa']) * (self.PP['g'] ** (self.MSK['beta'] * t))
 
        return (K1, K2, K3, K4, K5) 

    def serialize__SK(self, SK, sk_fname):
        (K1, K2, K3, K4, K5) = SK
        file = open(sk_fname, mode='wb')
        file.write(self.group.serialize(K1))
        file.write(self.group.serialize(K2))
        file.write(self.group.serialize(K3))
        file.write(b'%(len)04d=' %{b"len":  len(K4)} )
        for s in K4:
            file.write(self.group.serialize(s))
        file.write(self.group.serialize(K5))

    def deserialize__SK(self, sk_fname):
        file = open(sk_fname, 'r')
        data = file.read()
        file.close
        d = re.split('=', data)
        K1  = self.group.deserialize(d[0].encode())
        K2  = self.group.deserialize(d[1].encode())
        K3  = self.group.deserialize(d[2].encode())
        sz = d[3]
        K4 = []
        for i in range(0, int(sz)):
            K4.append(self.group.deserialize(d[4+i].encode()))
        K5 = self.group.deserialize(d[4+int(sz)].encode())

        return (K1, K2, K3, K4, K5) 

# .... Keyword index
    def EncryptAndIndexGen(self, M, KW, rho):

        UpsilonWithHook = self.group.random(GT)
        kse = extract_key(UpsilonWithHook)
        a   = SymmetricCryptoAbstraction(kse)
        CM = a.lsabe_encrypt(bytes(M, "utf-8"))

        hkw = []
        for kw in KW:
            hkw.append(self.group.hash(kw, ZR))
        
        eta = formuleDeViete(hkw)
# Formule de Viete assumes P(x)=0
# We have P(x)=1, so eta[0] is adjusted
        eta[0] = eta[0] - 1

        s, rho1, b = self.group.random(ZR), self.group.random(ZR), self.group.random(ZR)

        I = UpsilonWithHook * pair(self.PP['g'], self.PP['g']) ** (self.MSK['alfa']*s)
        I1 = self.PP['g'] ** b
        I2 = self.PP['g'] ** (self.MSK['lambda']*b)
        I3 = self.PP['g'] ** s
        I4 = self.PP['g'] ** rho1

        I5 = []
        for i in range(0, len(rho)):
            I5.append((self.PP['g'] ** (self.MSK['beta']*self.MSK['lambda'])*(i+1)) * self.group.hash(rho[i], G1) ** (-rho1))

        I6 = []
        for eta_j in eta:
            I6.append(rho1 * (eta_j ** (-1)))

        E = (pair(self.PP['g'], self.PP['f']) ** rho1) * (pair(self.PP['g'],self.PP['g']) ** (self.MSK['alfa'] * b * rho1))

        return (I, I1, I2, I3, I4, I5, I6, E, CM)

    def serialize__I(self, I, i_fname):
        (I, I1, I2, I3, I4, I5, I6, E, CM) = I
        file = open(i_fname, mode='wb')
        file.write(self.group.serialize(I))
        file.write(self.group.serialize(I1))
        file.write(self.group.serialize(I2))
        file.write(self.group.serialize(I3))
        file.write(self.group.serialize(I4))

        file.write(b'%(len)04d=' %{b"len":  len(I5)} )
        for t in I5:
            file.write(self.group.serialize(t))

        file.write(b'%(len)04d=' %{b"len":  len(I6)} )
        for t in I6:
            file.write(self.group.serialize(t))

        file.write(self.group.serialize(E))
        file.write(bytes(CM, "utf-8"))

    def deserialize__I(self, i_fname):
        file = open(i_fname, 'r')
        data = file.read()
        file.close
        d = re.split('=', data)
        I  = self.group.deserialize(d[0].encode())
        I1  = self.group.deserialize(d[1].encode())
        I2  = self.group.deserialize(d[2].encode())
        I3  = self.group.deserialize(d[3].encode())
        I4  = self.group.deserialize(d[4].encode())
        sz5 = d[5]
        I5 = []
        for i in range(0, int(sz5)):
            I5.append(self.group.deserialize(d[6+i].encode()))

        sz6 = d[6+int(sz5)]
        I6 = []
        for i in range(0, int(sz6)):
            I6.append(self.group.deserialize(d[7+int(sz5)+i].encode()))

        E  = self.group.deserialize(d[7+int(sz5)+int(sz6)].encode())
        CM = d[8+int(sz5)+int(sz6)]

        return (I, I1, I2, I3, I4, I5, I6, E, CM)

# .... Trapdoor

    def TrapdoorGen(self, SK, KW):
        (K1, K2, K3, K4, K5) = SK
        u, rho2 = self.group.random(ZR), self.group.random(ZR)
        T1 = K1 ** u
        T2 = K2
        T3 = u * rho2 * (len(KW) ** (-1))
        T4 = pair(self.PP['f'], self.PP['g']) ** u
        T5 = []

        for j in range(0, len(K4) + 1):
            T5j = 0
            for kw in KW:
                T5j = T5j + self.group.hash(kw, ZR) ** j
            T5j = (rho2 ** (-1)) * T5j 
            T5.append(T5j)

        return (T1, T2, T3, T4, T5)
            
    def serialize__TD(self, TKW, td_fname):
        (T1, T2, T3, T4, T5) = TKW
        file = open(td_fname, mode='wb')
        file.write(self.group.serialize(T1))
        file.write(self.group.serialize(T2))
        file.write(self.group.serialize(T3))
        file.write(self.group.serialize(T4))
        file.write(b'%(len)04d=' %{b"len":  len(T5)} )
        for t in T5:
            file.write(self.group.serialize(t))


    def deserialize__TD(self, td_fname):
        file = open(td_fname, 'r')
        data = file.read()
        file.close
        d = re.split('=', data)
        T1  = self.group.deserialize(d[0].encode())
        T2  = self.group.deserialize(d[1].encode())
        T3  = self.group.deserialize(d[2].encode())
        T4  = self.group.deserialize(d[3].encode())
        sz = d[4]
        T5 = []
        for i in range(0, int(sz)):
            T5.append(self.group.deserialize(d[5+i].encode()))

        return (T1, T2, T3, T4, T5)
