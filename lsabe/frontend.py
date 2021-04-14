import argparse
import pathlib
from .arguments import arguments_setup, dir_create
from .lsabe import LSABE


def startup():

    parser = arguments_setup()
    args = parser.parse_args()

    if (not args.init_flag and not args.encrypt_flag):
        print('Nothing to do. Specify either --init or --encrypt. To get help please run lsabe --help.')
        print('Exiting ...')
        exit(-1)

    msk_path = args.msk_path
    dir_create(msk_path);

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

    if (args.encrypt_flag):
        out_path = args.out_path
        dir_create(out_path)
        sk_fname = out_path.joinpath('lsabe.sk')   

        SK = lsabe.KeyGen(args.sec_attr)
#  (to remove)   print (SK)
        try:
            lsabe.serialize__SK(SK, sk_fname)
        except:
            print('Failed to store SK to ' + str(sk_fname))
            print('Exiting ...')
            exit(-1)
#  (to remove)  SK = lsabe.deserialize__SK(sk_fname)
#  (to remove)   print (SK)
