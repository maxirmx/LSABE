import os
# https://jhuisi.github.io/charm/cryptographers.html
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair,extract_key
from pathlib import Path
from .formuleDeViete import formuleDeViete, polyVal
from .symcrypto import SymmetricCryptoAbstraction
from .serializer import SER, DES
from .accessPolicy import accessPolicy

class LSABE():
    def __init__(self, msk_path, max_kw):

# These are file names to load\store MSK and PP
        self._msk_fname = msk_path.joinpath('lsabe.msk')   
        self._pp_fname  = msk_path.joinpath('lsabe.pp')
# The maximum number of keywords
        self._max_kw = max_kw   
# ....
# [charm crypto] For symmetric pairing G1 == G2  
        self.group = PairingGroup('SS512')

# 1 in ZR (a kind of ugly but I cannot think of better method)
        x = self.group.random(ZR) 
        self._1 = x/x          

# Access policy
        self._ap = accessPolicy()       

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
# For simplicity security attributes are implemented within python class accessPolicy 
# and not passed as a parameter
# ................................................................................
    def SecretKeyGen(self):
        t, delta = self.group.random(ZR), self.group.random(ZR)

        K1 = self._PP['g'] ** (self._MSK['alfa']/(self._MSK['lambda'] + delta))
        K2 = delta
        K3 = self._PP['g'] ** t
        K4 = ()
        for s in self._ap.S:
            K4 = K4 +(self.group.hash(s, G1) ** t,)

        K5 = (self._PP['g'] ** self._MSK['alfa']) * (self._PP['g'] ** (self._MSK['beta'] * t))

#        print ("Secret key:")
#        print ((K1, K2, K3, K4, K5))

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
# z
# The data user chooses a random value z ∈ Zp
# ................................................................................
    def z(self):
        z = self.group.random(ZR)
        return z

# ................................................................................
# TransKeyGen(SK, z) → TK.   
# Transformation key generation(TransKeyGen):
# # ................................................................................
    
    def TransKeyGen(self, SK, z):
        (K1, K2, K3, K4, K5) = SK
        TK3 = K3**z   
        TK4 = ()
        for s in K4:
            TK4 = TK4 +(s**z,)
        TK5 = K5**z

#        print ("Transformation key:")
#        print ((TK3, TK4, TK5))

        return (TK3, TK4, TK5)

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
    def EncryptAndIndexGen(self, M, KW):

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

        rho1, b = self.group.random(ZR), self.group.random(ZR)
        
        v = self._ap.randVector()
        s = v[0]

        I = UpsilonWithHook * (pair(self._PP['g'], self._PP['g']) ** (self._MSK['alfa']*s))
        I1 = self._PP['g'] ** b
        I2 = self._PP['g'] ** (self._MSK['lambda']*b)
        I3 = self._PP['g'] ** s
        I4 = self._PP['g'] ** rho1

        I5 = ( )
        for i in range(0, self._ap.l):  
            I5 = I5 + ( (self._PP['g^beta'] ** self._ap.lmbda(i,v)) * (self.group.hash(self._ap.p(i), G1) ** rho1), )
# ........................................................................ The article says:  ** -rho1          
# ........................................................................ but it is definetely a mistake 

        I6 = ( )
        for eta_j in eta:
            I6 = I6 + ((rho1 ** (-1)) * eta_j,  )

        E = (pair(self._PP['g'], self._PP['f']) ** rho1) * (pair(self._PP['g'],self._PP['g']) ** (self._MSK['alfa'] * b * rho1))

#       print("Ciphertext: ")
#       print((I, I1, I2, I3, I4, I5, I6, E, CM))

        return (I, I1, I2, I3, I4, I5, I6, E, CM)

# ................................................................................
#  Ciphertext serializer and deserializer
# ................................................................................
    def serialize__CT(self, CT, ct_fname):
        (I, I1, I2, I3, I4, I5, I6, E, CM) = CT
        (ctCT, ctIV) = CM

        l = SER(ct_fname, self.group)
        l.p_val((I, I1, I2, I3, I4)).p_tup(I5).p_tup(I6).p_val((E,)).p_bytes(ctCT).p_bytes(ctIV)

    def deserialize__CT(self, ct_fname):
        l = DES(ct_fname, self.group)
        return (l.g_val(5) + (l.g_tup(), ) + (l.g_tup(), ) + l.g_val(1) + ((l.g_bytes(), ) + (l.g_bytes(), ) ,) )

# ................................................................................
# Trapdoor  (SK,KW′,PP) → TKW′.  
# Given  the  secret  key SK, a query keyword set KW′,
#  data user runs the Trapdoor algorithm and outputs the trapdoor TKW′.
# ................................................................................

    def TrapdoorGen(self, SK, KW):
        (K1, K2, K3, K4, K5) = SK
        u, rho2 = self.group.random(ZR), self.group.random(ZR)

        T1 = K1 ** u
        T2 = K2
        lKW = self._1 * len(KW)                     # Make it ZR* value otherwise lkW**(-1) makes little sense 
        T3 = (u * rho2) * (lKW**(-1))
        T4 = pair(self._PP['g'], self._PP['f']) ** u
        T5 = ( )

        for j in range(0, self._max_kw):
            T5j = 0
            for kw in KW:
                T5j = T5j + self.group.hash(kw, ZR) ** j
            T5 = T5 + ((rho2 ** (-1)) * T5j ,)

#        print ("Trapdoor:")
#        print ((T1, T2, T3, T4, T5))

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

        T5j = I6[0]*T5[0]
        for j in range(1, len(I6)):
            T5j = T5j + I6[j]*T5[j]

        return (T4 * pair(T1, (I1**T2) * I2) == E ** (T3 * T5j))

# ................................................................................
# Transform (CT,TK) → CTout/⊥
# Given the transformationkeyTK, the cloud server can transform the ciphertext  
# into a partially decrypted ciphertext. This Transform algorithm is executed if 
# and only if the search algorithm outputs “1" and the attributes embedded in 
# the transformation key satisfy the access structure of the ciphertext CT.
# ................................................................................
    def Transform(self, CT, TK):
        (I, I1, I2, I3, I4, I5, I6, E, CM) = CT
        (TK3, TK4, TK5) = TK

        N = len(TK4)

        Iw  = self._1
        TKw = self._1

        for i in range (N):
            Iw  = Iw * (I5[i] ** self._ap.w(i))
            TKw = TKw * (TK4[i] ** self._ap.w(i))

        TI = pair(TK5,I3)/pair(Iw, TK3)*pair(TKw, I4)

        return (I,CM,TI)    

# ................................................................................
#  Decrypt(z,CTout) → M.  
#  The data user runs theDecryptalgorithm with its blind valuezand the partially 
#  decrypted ciphertext CT out as input, and then the user can recover the message 
#  M with lightweight decryption
# ................................................................................

    def Decrypt(self, z, CTout):

        (I,CM,TI) = CTout

        UpsilonWithHook = I/(TI**(self._1/z))
        kse = extract_key(UpsilonWithHook)
        a   = SymmetricCryptoAbstraction(kse)
        M   = a.lsabe_decrypt(CM)

        return M


