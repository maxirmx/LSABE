
import os
# https://jhuisi.github.io/charm/cryptographers.html
from charm.toolbox.pairinggroup import ZR,G1,G2,GT,pair


# Support for computations on groups supporting bilinear pairings
# https://pypi.org/project/bplib/
import bplib


G = bplib.bp.BpGroup()

alfa = int.from_bytes(os.urandom(2), byteorder="big")
beta = int.from_bytes(os.urandom(2), byteorder="big")
lmbda = int.from_bytes(os.urandom(2), byteorder="big")
print ('alfa   : ', alfa)
print ('beta   : ', beta)
print ('lambda : ', lmbda)

g1,g2 = G.gen1(), G.gen2()
gt = G.pair(g1,g2)
gx = gt**alfa
print(gx)
