import argparse
import pathlib
from .arguments import arguments_setup, dir_create
from .lsabe import LSABE


def startup():

    parser = arguments_setup()
    args = parser.parse_args()

    if (not args.init_flag and not args.keygen_flag and not args.encrypt_flag and not args.trapgen_flag):
        print('Nothing to do. Specify either --init or --keygen or --encrypt or --trapgen. To get help please run lsabe --help.')
        print('Exiting ...')
        exit(-1)

    msk_path = args.msk_path
    dir_create(msk_path)

    lsabe = LSABE(msk_path)

    if args.init_flag:
        if not lsabe.SystemInit():
            print('Failed to store MSK and PP to ' + str(msk_path))
            print('Exiting ...')
            exit(-1)
    else:
        if not lsabe.SystemLoad():
            print('Failed to load MSK and PP from ' + str(msk_path))
            print('Exiting ...')
            exit(-1)

    out_path = args.out_path
    dir_create(out_path)
    if (args.keygen_flag):
        sk_fname = out_path.joinpath('lsabe.sk')   
        SK = lsabe.SecrekeyGen(args.sec_attr)
        try:
            lsabe.serialize__SK(SK, sk_fname)
        except:
            print('Failed to store SK to ' + str(sk_fname))
            print('Exiting ...')
            exit(-1)

    if (args.encrypt_flag):
        if len(args.keywords) == 0:
            print('--encrypt flag is set but no keywords are supplied. Index generation without keywords won\'t make enough sense')
            print('Exiting ...')
            exit(-1)
        if args.message is None or not args.message:
            print('--encrypt flag is set but no message to encrypt is supplied')
            print('Exiting ...')
            exit(-1)
        try:
            sk_fname = out_path.joinpath('lsabe.sk')   
            SK = lsabe.deserialize__SK(sk_fname)
        except:
            print('Failed to load SK from ' + str(sk_fname))
            print('Exiting ...')
            exit(-1)

        c_fname = out_path.joinpath('lsabe.ciphertext')   
        I = lsabe.EncryptAndIndexGen( args.message, args.keywords, [[1],[2],[3]] )
        print (I)
        try:
           lsabe.serialize__I(I, c_fname)
        except:
           print('Failed to store ciphertext to ' + str(c_fname))
           print('Exiting ...')
           exit(-1)
        I = lsabe.deserialize__I(c_fname)
        print (I)

    if (args.trapgen_flag):
        if len(args.keywords) == 0:
            print('Trapdoor generation without keywords does not make enough sense')
            print('Exiting ...')
            exit(-1)
        try:
            sk_fname = out_path.joinpath('lsabe.sk')   
            SK = lsabe.deserialize__SK(sk_fname)
        except:
            print('Failed to load SK from ' + str(sk_fname))
            print('Exiting ...')
            exit(-1)

        td_fname = out_path.joinpath('lsabe.trapdoor')   
        TD = lsabe.TrapdoorGen(SK, args.keywords)
        try:
            lsabe.serialize__TD(TD, td_fname)
        except:
            print('Failed to store trapdoor to ' + str(td_fname))
            print('Exiting ...')
            exit(-1)

