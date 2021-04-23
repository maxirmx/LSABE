# ..... LSABE module frontend (aka command line and arguments processing) ......

import os
import argparse
import pathlib
import functools
import random
import string
from .arguments import arguments_setup, dir_create
from .lsabe import LSABE

def farewell():
        print('Exiting ... To get help please run python -m lsabe --help.')
        exit(-1)

def startup():

    parser = arguments_setup()
    args = parser.parse_args()

    if (not args.init_flag and not args.keygen_flag and not args.encrypt_flag and not args.search_flag):
        print('Nothing to do. Specify either --init or --keygen or --encrypt or --search.')
        farewell()

    key_path = args.key_path
    dir_create(key_path)

    lsabe = LSABE(key_path, 10)

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

# SK and TK generation
    if (args.keygen_flag):
        print('Executing "SecretKeyGen(MSK,S,PP) → SK" ...')
        if len(args.sec_attr) == 0:
            print(  '''--keygen flag is set but no security attributes are supplied.
                    Secret key generation algorithm is defined as SecretKeyGen(MSK,S,PP) → SK, where S is a set of security attributes.
                    
                    Security attribute is an abstraction representing the basic properties or characteristics of an entity with respect 
                    to safeguarding information; typically associated with internal data structures (e.g., records, buffers, files) within 
                    the information system which are used to enable the implementation of access control and flow control policies; 
                    reflect special dissemination, handling, or distribution instructions; or support other aspects of the information 
                    security policy. [NIST SP 800-53 Rev. 4]
                    
                    Please provide at least one attribute. --sec-attr "full access" will be good enouph'''
                )
            farewell()
        print('Security attributes: ' + str(args.sec_attr))    
        sk_fname = key_path.joinpath('lsabe.sk')   
        SK = lsabe.SecretKeyGen(args.sec_attr)
        try:
            lsabe.serialize__SK(SK, sk_fname)
        except:
            print('Failed to store SK to ' + str(sk_fname))
            farewell()
        print('SK saved to ' + str(sk_fname))

# Encrypt (file encryption and index generation)
    if (args.encrypt_flag):
        data_path = args.data_path
        dir_create(data_path)

        print('Executing "Encrypt(M,KW,(A,ρ),PP) → CT" ...')
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
            sk_fname = key_path.joinpath('lsabe.sk')   
            SK = lsabe.deserialize__SK(sk_fname)
        except:
            print('Failed to load SK from ' + str(sk_fname))
            farewell()
        print('SK loaded from ' + str(sk_fname))

        (K1, K2, K3, K4, K5) = SK

        ct_name = ''.join(random.choice(string.ascii_letters) for _ in range(8))
        ct_fname = data_path.joinpath(ct_name + '.ciphertext')   

        print('Message: \'' + str(args.message) + '\'' )    
        print('Keywords: ' + str(args.keywords))    
        CT = lsabe.EncryptAndIndexGen( args.message, args.keywords)
        try:
           lsabe.serialize__CT(CT, ct_fname)
        except:
           print('Failed to store ciphertext to ' + str(ct_fname))
           farewell()
        print('Сiphertext stored to ' + str(ct_fname))

# Search (trapdoor generation, search, transformation, decription)
    if (args.search_flag):

        if len(args.keywords) == 0:
            print('--search flag is set but no keywords are supplied.\n'
                    'Please provide at least one keyword. --kwd keyword will be good enouph')
            farewell()

        data_path = args.data_path
        dir_create(data_path)

        print('Executing "Trapdoor(SK,KW′,PP) → TKW′" ...')
        try:
           sk_fname = key_path.joinpath('lsabe.sk')   
           SK = lsabe.deserialize__SK(sk_fname)
        except:
           print('Failed to load SK from ' + str(sk_fname))
           farewell()
        print('SK loaded from ' + str(sk_fname))

        TD = lsabe.TrapdoorGen(SK, args.keywords) 
# The code to serialize trapdoor ... (no need to do it with this frontend)
#        td_fname = out_path.joinpath('lsabe.trapdoor')   
#        try:
#            lsabe.serialize__TD(TD, td_fname)
#        except:
#            print('Failed to store trapdoor to ' + str(td_fname))
#            farewell()


        print('Scanning ' + str(data_path) + ' ...')
        msg_files = [f for f in os.listdir(str(data_path)) if f.endswith('.ciphertext')]
        for msg_file in msg_files:
            ct_fname = data_path.joinpath(msg_file)   
            CT = lsabe.deserialize__CT(ct_fname)
            print('===== ' + msg_file + ' =====')
            print('Executing "Search(CT,TD) → True/False" ...')
    
            res = lsabe.Search(CT, TD)
            print('Search algoritm returned "' + str(res) + '"')

            if res:
                print('Executing "TransKeyGen(SK,z) → TK" ...')
                z =  lsabe.z()
                TK = lsabe.TransKeyGen(SK, z)

# The code to serialize transformation key ... (no need to do it with this frontend)
#        tk_fname = out_path.joinpath('lsabe.tk')   
#        try:
#            lsabe.serialize__TK(TK, tk_fname)
#        except:
#            print('Failed to store TK to ' + str(tk_fname))
#            farewell()
#        print('TK saved to ' + str(tk_fname))


                print('Executing "Transform (CT,TK) → CTout/⊥" ...')
                CTout = lsabe.Transform(CT, TK)

                print('Executing "Decrypt(z,CTout) → M" ...')

                msg = lsabe.Decrypt(z, CTout)
                print('Message: \"' + msg + '\"' )


