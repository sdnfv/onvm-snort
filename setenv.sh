ls | grep setenv.sh
ANS=`echo $?`
if [ $ANS == 1 ]
then
	echo please run this script in situ
	exit
fi

sudo apt-get install realpath

# Base directory
BASE_DIR=$(pwd)

grep RTE_TARGET ~/.bashrc
ANS=`echo $?`
if [ $ANS == 1 ]
then
	echo export RTE_TARGET=x86_64-native-linuxapp-gcc >> ~/.bashrc
fi

grep DPDK_TARGET ~/.bashrc
ANS=`echo $?`
if [ $ANS == 1 ]
then
	echo export DPDK_TARGET=x86_64-native-linuxapp-gcc >> ~/.bashrc
fi

cd $BASE_DIR/dpdk*
grep RTE_SDK ~/.bashrc
ANS=`echo $?`
if [ $ANS == 1 ]
then
	echo export RTE_SDK=$(pwd) >> ~/.bashrc
fi

cd $BASE_DIR/openNetVM*
grep ONVM_HOME ~/.bashrc
ANS=`echo $?`
if [ $ANS == 1 ]
then
	echo export ONVM_HOME=$(pwd) >> ~/.bashrc
fi

cd $BASE_DIR
ls | grep Makefile.patched
ANS=`echo $?`
if [ $ANS == 0 ]
then
	read -p "Do you want to create the snort Makefile again? (y/N): " ANS
else
	ANS='y'
fi

if [ "$ANS" == "y" ]
then
	./patching-Makefile.sh
	cp ./Makefile.patched $BASE_DIR/snort*/src/
fi

grep "/opt/snort" ~/.bashrc
ANS=`echo $?`
if [ $ANS == 0 ]
then
	echo export PATH=$PATH:/opt/snort/bin >> ~/.bashrc
fi

grep ONVM_NUM_HUGEPAGES ~/.bashrc
ANS=`echo $?`
if [ $ANS == 1 ]
then
	echo export ONVM_NUM_HUGEPAGES=1024 >> ~/.bashrc
fi

echo using nics 06:00.0 and 06:00.1
grep ONVM_NIC_PCI ~/.bashrc
ANS=`echo $?`
if [ $ANS == 1 ]
then
	echo 'export ONVM_NIC_PCI=" 06:00.0 06:00.1 "' >> ~/.bashrc
fi

source ~/.bashrc

sudo sh -c "echo 0 > /proc/sys/kernel/randomize_va_space"

cd $BASE_DIR
