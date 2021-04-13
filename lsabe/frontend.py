from .lsabe import LSABE
import argparse
import pathlib


def startup():

    default_msk_path = pathlib.Path(__file__).parent.parent.joinpath('MSK')

    parser = argparse.ArgumentParser(
        description             =   'LSABE algorithm', 
        prog                    =   'lsabe',
        fromfile_prefix_chars   =   '@'
    )

    parser.add_argument('--init', 
                        dest        =   'init-flag', 
                        action      =   'store_true',
                        help        =   'Generate MSK and PP files. >>> CAUTION! NO CHECKS BEFORE OVERWRIGHT! <<<')

    parser.add_argument('--encrypt-in', 
                        type        =   pathlib.Path, 
                        dest        =   'file-name', 
                        metavar     =   '<file>',
                        help        =   'File to encrypt')

    parser.add_argument('--encrypt-out', 
                        type        =   pathlib.Path, 
                        dest        =   'output-name', 
                        metavar     =   '<folder>',
                        help        =   'Directory to store encrypted file and keys')
                    

    parser.add_argument('--msk-path',  
                        type        =   pathlib.Path, 
                        dest        =   'msk_path',
                        metavar     =   '<path>',
                        default     =   default_msk_path,
                        help        =   'Directory to load or store MSK (lsabe.msk) and PP (lsabe.pp). ' + 
                                        'At this sytem it will default to ' + str(default_msk_path)
    )

    args = parser.parse_args()

   # ...
   # Now we will check consistency of the arguments
   # Path for master key store:
    msk_path = args.msk_path
    try:
        msk_path.mkdir(mode=0o777, parents=True, exist_ok=True)
    except:
        if msk_path.Exists() and not msk_path.is_dir():
            print(str(msk_path) + ' exists and is not a directory')
        else:
            print('Could not create ' + str(msk_path))
        print('Exiting ...')
        exit(-1)

    lsabe = LSABE(msk_path)
    lsabe.SystemInit()
    (SK, TK) = lsabe.KeyGen()
    
