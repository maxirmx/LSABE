# ..... LSABE module arguments definition ......

import argparse
import pathlib


def arguments_setup(max_kwd):
    default_key_path = pathlib.Path(__file__).parent.parent.joinpath('keys')
    default_data_path = pathlib.Path(__file__).parent.parent.joinpath('data')

    parser = argparse.ArgumentParser(
        description             =   'LSABE algorithm', 
        prog                    =   'lsabe',
        fromfile_prefix_chars   =   '@',
        epilog                  =   
        '''Suggested initial test call sequence:
           python -m lsabe --init 
           python -m lsabe --keygen
           python -m lsabe --encrypt --msg "Searchable encryption is good" --kwd Searchable encryption 
           python -m lsabe --encrypt --msg "This is unrelated message" --kwd unrelated message
           python -m lsabe --search --kwd Searchable
           python -m lsabe --search --kwd ENCRYPTION''',
        formatter_class=argparse.RawDescriptionHelpFormatter   
    )

    parser.add_argument('--init', 
                        dest        =   'init_flag', 
                        action      =   'store_true',
                        help        =   'Generate MSK and PP files (CAUTION! NO CHECKS BEFORE OVERWRITE!) ' + 
                                        'If this flag is not set, MSK and PP are loaded from the files.'
    )

    parser.add_argument('--key-path',  
                        type        =   pathlib.Path, 
                        dest        =   'key_path',
                        metavar     =   '<path>',
                        default     =   default_key_path,
                        help        =   'Directory to load or store MSK (lsabe.msk), PP (lsabe.pp) and SK (lsabe.sk). ' + 
                                        'At this sytem it will default to ' + str(default_key_path)
    )

    parser.add_argument('--keygen', 
                        dest        =   'keygen_flag', 
                        action      =   'store_true',
                        help        =   'Generate secret key (CAUTION! NO CHECKS BEFORE OVERWRITE!)'
    )

    parser.add_argument('--encrypt', 
                        dest        =   'encrypt_flag', 
                        action      =   'store_true',
                        help        =   'Encrypt message and generate keyword index'
    )

    parser.add_argument('--search', 
                        dest        =   'search_flag', 
                        action      =   'store_true',
                        help        =   'Generate  trapdoor, search matching messages, generate transformation key, tranform and decrypt'
    )

    parser.add_argument('--data-path',  
                        type        =   pathlib.Path, 
                        dest        =   'data_path',
                        metavar     =   '<path>',
                        default     =   default_data_path,
                        help        =   'Directory to store encrypted messages (*.ciphertext). ' + 
                                        'At this sytem it will default to ' + str(default_data_path)
    )

    parser.add_argument('--kwd',  
                        nargs       =   '+',     
                        dest        =   'keywords',
                        metavar     =   '<keywords>',
                        default     =   [],
                        help        =   'Keyword. Multiply keywords are supported, e.g.: --kwd searchable encryption algorithm. Maximun number of keywords is statically set to ' + str(max_kwd) +
                                        ' If you want to change it, please modify MAX_KEYWORDS value in the source code.'
    )

    parser.add_argument('--msg',  
                        dest        =   'message',
                        metavar     =   '<message>',
                        help        =   'A message to encrypt. Quotes are welcome, e.g.: --msg "Searchable encryption is good."' 
    )

    return parser

def dir_create(pth):
    try:
        pth.mkdir(mode=0o777, parents=True, exist_ok=True)
    except:
        if pth.Exists() and not pth.is_dir():
            print(str(pth) + ' exists and is not a directory')
        else:
            print('Could not create ' + str(pth))
        print('Exiting ...')
        exit(-1)
