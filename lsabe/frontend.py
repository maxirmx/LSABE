import argparse
import pathlib
import functools
from .arguments import arguments_setup, dir_create
from .lsabe import LSABE

def farewell():
        print('Exiting ... To get help please run python -m lsabe --help.')
        exit(-1)


def startup():

    parser = arguments_setup()
    args = parser.parse_args()

    if (not args.init_flag and not args.keygen_flag and not args.encrypt_flag and not args.trapgen_flag):
        print('Nothing to do. Specify either --init or --keygen or --encrypt or --trapgen.')
        farewell()

    msk_path = args.msk_path
    dir_create(msk_path)

    lsabe = LSABE(msk_path, 10)

# MSK and PP are requied always
# So we either generate them (SystemInit) or load from files (SystemLoad)
    if args.init_flag:
        print('Executing "Setup(κ) → (MSK,PP)" ...')
        try:
            lsabe.SystemInit()
        except:
            print('Failed to store MSK and PP to ' + lsabe.msk_fname +' and ' + lsabe.pp_fname)
            farewell()
        print('MSK and PP saved to ' + lsabe.msk_fname +' and ' + lsabe.pp_fname)
    else:
        print('Loading master security key (MSK) and public properies (PP) from ' + lsabe.msk_fname +' and ' + lsabe.pp_fname)
        try:
            lsabe.SystemLoad()
        except:
            print('Failed to load MSK and PP')
            farewell()
        print('MSK and PP loaded succesfully')

    out_path = args.out_path
    dir_create(out_path)

# SK and TK generation
    if (args.keygen_flag):
        print('Executing "SecretKeyGen(MSK,S,PP) → SK" ...')
        if len(args.sec_attr) == 0:
            print(  '--keygen flag is set but no security attributes are supplied.\n'
                    'Secret key generation algorithm is defined as SecretKeyGen(MSK,S,PP) → SK, where S is a set of security attributes.\n'
                    'Please provide at least one attribute. --sec-attr attr will be good enouph')
            farewell()
        sk_fname = out_path.joinpath('lsabe.sk')   
        SK = lsabe.SecretKeyGen(args.sec_attr)
        try:
            lsabe.serialize__SK(SK, sk_fname)
        except:
            print('Failed to store SK to ' + str(sk_fname))
            farewell()
        print('SK saved to ' + str(sk_fname))

        print('Executing "TransKeyGen(SK,z) → TK" ...')
        TK = lsabe.TransKeyGen(SK)
        tk_fname = out_path.joinpath('lsabe.tk')   
        try:
            lsabe.serialize__TK(TK, tk_fname)
        except:
            print('Failed to store TK to ' + str(tk_fname))
            farewell()
        print('TK saved to ' + str(tk_fname))

# Encrypt (file encryption and index generation)
    if (args.encrypt_flag):
        print('Executing Encrypt(M,KW,(A,ρ),PP) → CT ...')
        l1 = len(args.keywords)
        if l1 == 0:
            print('--encrypt flag is set but no keywords are supplied.\n'
                    'Encryption algorithm is defined as Encrypt(M,KW,(A,ρ),PP) → CT, where KW is a set of keywords.\n'
                    'Please provide at least one keyword. --kwd keyword will be good enouph')
            farewell()
        if args.message is None or not args.message:
            print('--encrypt flag is set but no message to encrypt is supplied.\n'
                    'Encryption algorithm is defined as Encrypt(M,KW,(A,ρ),PP) → CT, where M is a message to encrypt.\n'
                    'Please provide it, using quotes if there is more then one word. --msg "A message" will be good enouph')
            farewell()
        try:
            sk_fname = out_path.joinpath('lsabe.sk')   
#            SK = lsabe.deserialize__SK(sk_fname)
        except:
            print('Failed to load SK from ' + str(sk_fname))
            farewell()
        print('SK loaded from ' + str(sk_fname))

        (K1, K2, K3, K4, K5) = SK
        n = len(K4)

        np = len(args.policy)

        if np != l1*n:
            print('Wrong number of access policy entries.\n'
                  'Encryption algorithm is defined as Encrypt(M,KW,(A,ρ),PP) → CT, where (A,ρ) an access policy mapping security attributes to keywords.\n'
                  'Input was ' + str(l1) + ' keywords, ' + str(n) +' attributes at SK(' + str(sk_fname) +'), but ' + str(np) + ' policy entries.\n'
                  'Please provide policy as a list of integers in the amount of <number of attributes> * <number of keywords> = ' + str(l1*n) +'.')
            
            helper = functools.reduce(lambda h, x: h + str(x+1) + ' ', range(l1*n), '')      
            print('--policy ' + helper + 'will be good enouph')
            farewell()

        p = []
        for i in range(0, l1):
            r = []
            for j in range(0, n):
                v = args.policy[i*n+j]
                r.append(v)
            p.append(r)

        c_fname = out_path.joinpath('lsabe.ciphertext')   
        CT = lsabe.EncryptAndIndexGen( args.message, args.keywords, p )
        try:
           lsabe.serialize__CT(CT, c_fname)
        except:
           print('Failed to store ciphertext to ' + str(c_fname))
           farewell()

    if (args.trapgen_flag):
        print('Executing Trapdoor(SK,KW′,PP) → TKW′ ...')
        if len(args.keywords) == 0:
            print('--trapgen flag is set but no keywords are supplied.\n'
                    'Trapdoorgeneration algorithm is defined as Trapdoor(SK,KW′,PP) → TKW′, where KW′ is a set of keywords.\n'
                    'Please provide at least one keyword. --kwd keyword will be good enouph')
            farewell()
        try:
           sk_fname = out_path.joinpath('lsabe.sk')   
#           SK = lsabe.deserialize__SK(sk_fname)
        except:
           print('Failed to load SK from ' + str(sk_fname))
           farewell()
        print('SK loaded from ' + str(sk_fname))

        td_fname = out_path.joinpath('lsabe.trapdoor')   
        TD = lsabe.TrapdoorGen(SK, args.keywords) 
        try:
            lsabe.serialize__TD(TD, td_fname)
        except:
            print('Failed to store trapdoor to ' + str(td_fname))
            farewell()

#        CT=lsabe.deserialize__CT(out_path.joinpath('lsabe.ciphertext'))
        lsabe.Search(CT, TD)

