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

make -j7 T=$RTE_TARGET O=$RTE_TARGET
sudo make install T=x86_64-native-linuxapp-gcc

cd onvm && make

# Compile DAQ
sudo apt-get install -y libpcap-dev libpcre3-dev libdumbnet-dev zlib1g-dev liblzma-dev libssl-dev autoconf

cd $BASE_DIR/daq*

make clean
aclocal
autoconf
autoheader
automake -a

./configure --with-dpdk-includes=$RTE_SDK/$RTE_TARGET/include --with-dpdk-libraries=$RTE_SDK/$RTE_TARGET/lib --with-netvm-includes=$ONVM_HOME/onvm --with-netvm-libraries=$ONVM_HOME/onvm

make -j7
sudo make install

# Compile snort
cd $BASE_DIR/snort*
./configure --enable-sourcefire

cd snort*/src
make clean
make -j7
sudo make install

sudo ldconfig

sudo cp -r snort*/simple-etc /etc/snort
sudo mkdir /usr/local/lib/snort_dynamicrules

cd $ONVM_HOME
scripts/install.sh

cd $BASE_DIR
