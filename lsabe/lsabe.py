import os
# https://jhuisi.github.io/charm/cryptographers.html
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair,extract_key
from pathlib import Path
from .formuleDeViete import formuleDeViete, polyVal
from .symcrypto import SymmetricCryptoAbstraction
from .serializer import SER, DES

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

    def __load(fname):  
        file =self.fname.open(mode='r')
        data = file.read()
        file.close
        return re.split('=', data)
  

# ................................................................................
# Setup(κ)→(MSK,PP). Given  the  security  parameter к, Setup algorithm  outputs  
# the  master  secret  key  denoted  by MSK and public parameters denoted by PP.    
# ................................................................................
#  SystemInit
#  Generates new MSK and PP and serialize them to files
# ................................................................................
    def SystemInit(self):
        f = self.group.random(G1) 
        g = self.group.random(G1)
        alfa, beta, lmbda = self.group.random(ZR), self.group.random(ZR), self.group.random(ZR)        
        e_gg_alfa = pair(g, g) ** alfa
        self._MSK = { 'alfa':alfa, 'beta':beta, 'lambda':lmbda }        
        self._PP =  { 'f':f, 'g':g, 'g^beta':g ** beta, 'g^lambda':g ** lmbda, 'e(gg)^alfa':e_gg_alfa}

#        print("Master secret key:")
#        print(self._MSK)
#        print("Public properties:")
#        print(self._PP)

        self.__serialize__MSK()
        self.__serialize__PP()


# ................................................................................
#  SystemLoad
#  Deserializes MSK and PP from files
# ................................................................................
    def SystemLoad(self):
        self.__deserialize__MSK()
        self.__deserialize__PP()

#        print("Master secret key:")
#        print(self._MSK)
#        print("Public properties:")
#        print(self._PP)

# ................................................................................
#  MSK and PP serializers and deserializers
# ................................................................................
    def __serialize__MSK(self):
        l = SER(self._msk_fname, self.group)
        l.p_val(self._MSK.values())

    def __serialize__PP(self):
        l = SER(self._pp_fname, self.group)
        l.p_val(self._PP.values())

    def __deserialize__MSK(self):
        l = DES(self._msk_fname, self.group)
        self._MSK = {}
        (self._MSK['alfa'], self._MSK['beta'], self._MSK['lambda']) = l.g_val(3)

    def __deserialize__PP(self):
        l = DES(self._pp_fname, self.group)
        self._PP = {}
        (self._PP['f'], self._PP['g'], self._PP['g^beta'], self._PP['g^lambda'], self._PP['e(gg)^alfa']) = l.g_val(5)

# ................................................................................
# SecretKeyGen(MSK,S,PP)→SK.   
# Given the dataowner’s attribute sets, key generation center (KGC) conducts
# the SecrekeyGen algorithm and outputs the secret key SK.    
# ................................................................................
    def SecretKeyGen(self, S):
        t, delta = self.group.random(ZR), self.group.random(ZR)

        K1 = self._PP['g'] ** (self._MSK['alfa']/(self._MSK['lambda'] + delta))
        K2 = delta
        K3 = self._PP['g'] ** t
        K4 = ()
        for s in S:
            K4 = K4 +(self.group.hash(s, G1) ** t,)
        K5 = (self._PP['g'] ** self._MSK['alfa']) * (self._PP['g'] ** (self._MSK['beta'] * t))

#        print ("Secret key:")
#        print ((K1, K2, K3, K4, K5))


        self.t = t
        return (K1, K2, K3, K4, K5) 

# ................................................................................
#  SK serializer and deserializer
# ................................................................................
    def serialize__SK(self, SK, sk_fname):
        (K1, K2, K3, K4, K5) = SK
        l = SER(sk_fname, self.group)
        l.p_val((K1,K2,K3)).p_tup(K4).p_val((K5,))

    def deserialize__SK(self, sk_fname):
        l = DES(sk_fname, self.group)
        return l.g_val(3) + (l.g_tup(), ) + l.g_val(1) 

# ................................................................................
# TransKeyGen(SK, z) → TK.   
# Given the dataowner’s attribute sets, key generation center (KGC) conducts
# the SecrekeyGen algorithm and outputs the secret key SK.    
# ................................................................................
    
    def TransKeyGen(self, SK):
        (K1, K2, K3, K4, K5) = SK
        z = self.group.random(ZR)
        K3T = K3**z   
        K4T = ()
        for s in K4:
            K4T = K4T +(s**z,)
        K5T = K5**z

#        print ("Transformation key:")
#        print ((K3T, K4T, K5T))

        return (K3T, K4T, K5T)

# ................................................................................
#  SK serializer and deserializer
# ................................................................................
    def serialize__TK(self, TK, tk_fname):
        (K3T, K4T, K5T) = TK
        l = SER(tk_fname, self.group)
        l.p_val((K3T,)).p_tup(K4T).p_val((K5T,))

    def deserialize__TK(self, tk_fname):
        l = DES(tk_fname, self.group)
        return l.g_val(1) + (l.g_tup(), ) + l.g_val(1) 


# ................................................................................
# Encrypt (M,KW,(A,ρ),PP)→CT.  
# Given keyword set KW extracted from file M and the access policy(A,ρ), data owner 
# outputs ciphertext CT, which contains the secure index I and the encrypted file CM
# ................................................................................
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
        eta[0] = eta[0] + 1

# .....
# Check that polynomial coefficients are correct
#        for hkwi in hkw:
#            print ('P(' + str(hkwi) + ') = ' + str(polyVal(eta, hkwi)) + ' ~~~~ expected 1')

        s, rho1, b = self.group.random(ZR), self.group.random(ZR), self.group.random(ZR)

# !!!!!!!!!!!!
        #rho1 = rho1/rho1        

        I = UpsilonWithHook * (pair(self._PP['g'], self._PP['g']) ** (self._MSK['alfa']*s))
        I1 = self._PP['g'] ** b
        I2 = self._PP['g'] ** (self._MSK['lambda']*b)
        I3 = self._PP['g'] ** s
        I4 = self._PP['g'] ** rho1

        I5 = []
        for i in range(0, len(rho)):
            I5.append( (self._PP['g'] ** (self._MSK['beta']*self._MSK['lambda'])*(i+1)) * (self.group.hash(rho[i], G1) ** (-rho1)))

        I6 = []
        for eta_j in eta:
            x = eta_j/rho1
            I6.append( x )

        E = (pair(self._PP['g'], self._PP['f']) ** rho1) * (pair(self._PP['g'],self._PP['g']) ** (self._MSK['alfa'] * b * rho1))

#       print("Ciphertext: ")
#       print((I, I1, I2, I3, I4, I5, I6, E, CM))

        return (I, I1, I2, I3, I4, I5, I6, E, CM)

# ................................................................................
#  Ciphertext serializer and deserializer
# ................................................................................
    def serialize__CT(self, CT, ct_fname):
        (I, I1, I2, I3, I4, I5, I6, E, CM) = CT

        l = SER(ct_fname, self.group)
        l.p_val((I, I1, I2, I3, I4)).p_tup(I5).p_tup(I6).p_val((E,)).p_bytes(CM)

    def deserialize__CT(self, ct_fname):
        l = DES(ct_fname, self.group)
        return (l.g_val(5) + (l.g_tup(), ) + (l.g_tup(), ) + l.g_val(1) + (l.g_bytes(),))

# .... Trapdoor

    def TrapdoorGen(self, SK, KW, nKW):
        (K1, K2, K3, K4, K5) = SK
        u, rho2 = self.group.random(ZR), self.group.random(ZR)

# !!!!!!!!!!!!
        #u = u/u
        #rho2 = rho2/rho2


        T1 = K1 ** u
        T2 = K2
        T3 = u * rho2  / len(KW)                                            #   * (len(KW)**(-1))
        T4 = pair(self._PP['g'], self._PP['f']) ** u
        T5 = []

        for j in range(0, nKW+1):
            T5j = 0
            for kw in KW:
                T5j = T5j + self.group.hash(kw, ZR) ** j
                print (str(j) + ' ... ' + str(kw) + ' ... ' + str(T5j))
            T5j = (rho2 ** (-1)) * T5j 
            #T5j = T5j /rho2
            T5.append(T5j)

        print ("Trapdoor:")
        print ((T1, T2, T3, T4, T5))

        return (T1, T2, T3, T4, T5)
            
# ................................................................................
#  Trapdoor serializer and deserializer
# ................................................................................
    def serialize__TD(self, TKW, td_fname):
        (T1, T2, T3, T4, T5) = TKW
        l = SER(td_fname, self.group)
        l.p_val((T1, T2, T3, T4)).p_tup(T5)

    def deserialize__TD(self, td_fname):
        l = DES(td_fname, self.group)
        return (l.g_val(4) + (l.g_tup(),) )

# ................................................................................
# Search(CT,TKW′) → 0/1.  
# The cloud server takes the trap-door TKW′ and the ciphertext CT as input, 
# and executes the search algorithm. If the output is “0”, the  query  fails.  
# If theoutput is “1”, the query is successful and the cloud serverscontinue 
# to run the transform algorithm.
# ................................................................................
    def Search(self, CT, TKW):
        (I, I1, I2, I3, I4, I5, I6, E, CM) = CT
        (T1, T2, T3, T4, T5) = TKW

        t = T4 * pair(T1, (I1**T2) * I2)
        print (t)

        tj = I6[0]*T5[0]
        for j in range(1, len(T5)):
            tj = tj + I6[j]*T5[j]
            print(str(j) + ' ... ' + str(tj) )


        tj = E ** (T3 * tj) 
        print (tj)

        if t == tj:
            print('OK')
        else:
            print('Nay')
