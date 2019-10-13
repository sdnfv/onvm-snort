ls | grep setenv.sh
ANS=`echo $?`
if [ $ANS == 1 ]
then
	echo please run this script in situ
	exit
fi

./setenv.sh

# Base directory
BASE_DIR=$(pwd)

# update
sudo apt-get update

#compile onvm
cd $ONVM_HOME/scripts
./install.sh

cd $ONVM_HOME/onvm && make

# Compile DAQ
sudo apt-get install -y libpcap-dev libpcre3-dev libdumbnet-dev zlib1g-dev liblzma-dev libssl-dev autoconf

cd $BASE_DIR/daq*

aclocal
autoconf
autoheader
automake -a
autoreconf -fvi

./configure --enable-static --disable-shared --with-dpdk-includes=$RTE_SDK/$RTE_TARGET/include --with-dpdk-libraries=$RTE_SDK/$RTE_TARGET/lib --with-netvm-includes=$ONVM_HOME/onvm --with-netvm-libraries=$ONVM_HOME/onvm


make clean
make -j7
sudo make install

# Compile snort
cd $BASE_DIR/snort-2.9*
aclocal
autoconf
autoheader
automake -a
autoreconf -fvi
./configure --enable-static --disable-shared --with-dpdk-includes=$RTE_SDK/$RTE_TARGET/include --with-dpdk-libraries=$RTE_SDK/$RTE_TARGET/lib --with-netvm-includes=$ONVM_HOME/onvm --with-netvm-libraries=$ONVM_HOME/onvm

make clean
make -j7
sudo make install

sudo ldconfig

sudo cp -r snort*/simple-etc /etc/snort
sudo mkdir /usr/local/lib/snort_dynamicrules

cd $BASE_DIR
