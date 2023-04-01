# Lightweight Searchable Encryption Protocol for Industrial Internet of Things

This is an impleentation of LSABE protocol as described in https://ieeexplore.ieee.org/document/9158514.
The article has 2 bugs in formulas and one feature that is principal contradiction with the mainline of the algorithm offered so I had to fix it.

```
usage: lsabe [-h] [--init] [--key-path <path>] [--keygen] [--encrypt]
             [--search] [--data-path <path>]
             [--kwd <keywords> [<keywords> ...]] [--msg <message>]

LSABE algorithm

optional arguments:
  -h, --help            show this help message and exit
  --init                Generate MSK and PP files (CAUTION! NO CHECKS BEFORE OVERWRITE!) 
                        If this flag is not set, MSK and PP are loaded from the files.
  --key-path <path>     Directory to load or store MSK (lsabe.msk), PP (lsabe.pp) and SK (lsabe.sk). 
  --keygen              Generate secret key (CAUTION! NO CHECKS BEFORE OVERWRITE!)
  --encrypt             Encrypt message and generate keyword index
  --search              Generate trapdoor, search matching messages, generate transformation key, transform and decrypt
  --data-path <path>    Directory to store encrypted messages (*.ciphertext).
  --kwd <keywords> [<keywords> ...]  Keyword. Multiply keywords are supported, e.g.: --kwd searchable encryption algorithm. 
                        Maximun number of keywords is statically set to 10. 
                        If you want to change it, please modify MAX_KEYWORDS value in the source code.
  --msg <message>       A message to encrypt. Quotes are welcome, e.g.: --msg "Searchable encryption is good."

Suggested initial test call sequence:
           python -m lsabe --init 
           python -m lsabe --keygen
           python -m lsabe --encrypt --msg "Searchable encryption is good" --kwd Searchable encryption 
           python -m lsabe --encrypt --msg "This is unrelated message" --kwd unrelated message
           python -m lsabe --search --kwd Searchable
           python -m lsabe --search --kwd ENCRYPTION
```
```
maxirmx@MSS-WS-N:~/LSABE$ python -m lsabe --init
  Executing "Setup(κ) → (MSK,PP)" ...
  MSK and PP saved to /home/maxirmx/LSABE/keys/lsabe.msk and /home/maxirmx/LSABE/keys/lsabe.pp

maxirmx@MSS-WS-N:~/LSABE$  python -m lsabe --keygen
  Loading master security key (MSK) and public properies (PP) from /home/maxirmx/LSABE/keys/lsabe.msk and /home/maxirmx/LSABE/keys/lsabe.pp
  MSK and PP loaded succesfully
  Executing "SecretKeyGen(MSK,S,PP) → SK" ...
  SK saved to /home/maxirmx/LSABE/keys/lsabe.sk

maxirmx@MSS-WS-N:~/LSABE$ python -m lsabe --encrypt --msg "Searchable encryption is good" --kwd Searchable encryption 
  Loading master security key (MSK) and public properies (PP) from /home/maxirmx/LSABE/keys/lsabe.msk and /home/maxirmx/LSABE/keys/lsabe.pp
  MSK and PP loaded succesfully
  Executing "Encrypt(M,KW,(A,ρ),PP) → CT" ...
  SK loaded from /home/maxirmx/LSABE/keys/lsabe.sk
  Message: 'Searchable encryption is good'
  Keywords: ['Searchable', 'encryption']
  Сiphertext stored to /home/maxirmx/LSABE/data/bbQldVTH.ciphertext

maxirmx@MSS-WS-N:~/LSABE$ python -m lsabe --search --kwd Searchable
  Loading master security key (MSK) and public properies (PP) from /home/maxirmx/LSABE/keys/lsabe.msk and /home/maxirmx/LSABE/keys/lsabe.pp
  MSK and PP loaded succesfully
  Executing "Trapdoor(SK,KW′,PP) → TKW′" ...
  SK loaded from /home/maxirmx/LSABE/keys/lsabe.sk
  Scanning /home/maxirmx/LSABE/data ...
  ===== bbQldVTH.ciphertext =====
  Executing "Search(CT,TD) → True/False" ...
  Search algoritm returned "True"
  Executing "TransKeyGen(SK,z) → TK" ...
  Executing "Transform (CT,TK) → CTout/⊥" ...
  Executing "Decrypt(z,CTout) → M" ...
  Message: "Searchable encryption is good"

maxirmx@MSS-WS-N:~/LSABE$ python -m lsabe --search --kwd ENCRYPTION
  Loading master security key (MSK) and public properies (PP) from /home/maxirmx/LSABE/keys/lsabe.msk and /home/maxirmx/LSABE/keys/lsabe.pp
  MSK and PP loaded succesfully
  Executing "Trapdoor(SK,KW′,PP) → TKW′" ...
  SK loaded from /home/maxirmx/LSABE/keys/lsabe.sk
  Scanning /home/maxirmx/LSABE/data ...
  ===== bbQldVTH.ciphertext =====
  Executing "Search(CT,TD) → True/False" ...
  Search algoritm returned "False"
```
