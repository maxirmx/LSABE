import argparse
import pathlib
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

    lsabe = LSABE(msk_path)

    if args.init_flag:
        print('Creating master security key (MSK) and public properies (PP) ...')
        try:
            lsabe.SystemInit()
        except:
            print('Failed to store MSK and PP to ' + lsabe.msk_fname +' and ' + lsabe.pp_fname)
            farewell()
        print('MSK and PP saved to ' + lsabe.msk_fname +' and ' + lsabe.pp_fname)
    else:
        print('Loading Creating master security key (MSK) and public properies (PP) from ' + lsabe.msk_fname +' and ' + lsabe.pp_fname)
        try:
            lsabe.SystemLoad()
        except:
            print('Failed to load MSK and PP')
            farewell()
        print('MSK and PP loaded succesfully')

    out_path = args.out_path
    dir_create(out_path)
    if (args.keygen_flag):
        sk_fname = out_path.joinpath('lsabe.sk')   
        SK = lsabe.SecrekeyGen(args.sec_attr)
        try:
            lsabe.serialize__SK(SK, sk_fname)
        except:
            print('Failed to store SK to ' + str(sk_fname))
            farewell()

    if (args.encrypt_flag):
        if len(args.keywords) == 0:
            print('--encrypt flag is set but no keywords are supplied. Index generation without keywords won\'t make enough sense')
            farewell()
        if args.message is None or not args.message:
            print('--encrypt flag is set but no message to encrypt is supplied')
            farewell()
        try:
            sk_fname = out_path.joinpath('lsabe.sk')   
            SK = lsabe.deserialize__SK(sk_fname)
        except:
            print('Failed to load SK from ' + str(sk_fname))
            farewell()

        l1 = len(args.keywords)
        (K1, K2, K3, K4, K5) = SK
        n = len(K4)

        if args.policy is None:
            np = 0
        else:
            np = len(args.policy)

        if np != l1*n:
            print('Kindly provide policy as integers in the amount of <number of attributes> * <number of keywords>')
            print('This time I got ' + str(l1) + ' keywords, ' + str(n) +' attributes, but ' + str(np) + ' policy entries')
            print('--policy 1,2,3,4,5 ... will be good enouph at this stage')
            farewell()

        p = []
        for i in range(0, l1):
            r = []
            for j in range(0, n):
                v = args.policy[i*n+j]
                r.append(v)
            p.append(r)

        c_fname = out_path.joinpath('lsabe.ciphertext')   
        I = lsabe.EncryptAndIndexGen( args.message, args.keywords, p )
        print(I)
        try:
           lsabe.serialize__I(I, c_fname)
        except:
           print('Failed to store ciphertext to ' + str(c_fname))
           farewell()

    if (args.trapgen_flag):
        if len(args.keywords) == 0:
           print('Trapdoor generation without keywords does not make enough sense')
           farewell()
        try:
           sk_fname = out_path.joinpath('lsabe.sk')   
           SK = lsabe.deserialize__SK(sk_fname)
        except:
           print('Failed to load SK from ' + str(sk_fname))
           farewell()

        td_fname = out_path.joinpath('lsabe.trapdoor')   
        TD = lsabe.TrapdoorGen(SK, args.keywords)
        try:
            lsabe.serialize__TD(TD, td_fname)
        except:
            print('Failed to store trapdoor to ' + str(td_fname))
            farewell()

