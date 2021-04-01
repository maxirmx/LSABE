cd ~
mkdir charm-crypto-bootstrap
cd charm-crypto-bootstrap

sudo apt install libgmp-dev \
                 flex \
                 bison

wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz

tar -xvf pbc-0.5.14.tar.gz
cd pbc-0.5.14
./configure
make
sudo make install 
cd ..

git clone --depth 1 https://github.com/JHUISI/charm.git
cd charm
./configure.sh
make
sudo make install 
cd ..

cd ~
sudo rm -rf charm-crypto-bootstrap