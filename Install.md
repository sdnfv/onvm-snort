# Snort Installation

This guide helps you build and install Snort.

---
1. Compile DPDK
---

1. Export correct target variable for your system as required by DPDK.

    ```sh
    export RTE_TARGET=x86_64-native-linuxapp-gcc
    export DPDK_TARGET=x86_64-native-linuxapp-gcc
    ```

2.  Navigate to your DPDK source repository and set environment variable RTE_SDK to the path of the DPDK library. 
    ```sh
    cd dpdk-stable-16.11.1
    export RTE_SDK=$(pwd)
    ```

3. Build DPDK.
    ```sh
    make config T=x86_64-native-linuxapp-gcc O=x86_64-native-linuxapp-gcc
    make -j7 T=$RTE_TARGET O=$RTE_TARGET
    sudo make install T=x86_64-native-linuxapp-gcc
    ```  
---
2. Compile ONVM
---

1. Navigate to openNetVM source directory.
    ```sh
    cd openNetVM/
    export ONVM_HOME=$(pwd)
    ```
    
2. Compile onvm.
    ```sh
    cd onvm && make
    ```
---
3. Compile DAQ
---

1. Install dependencies.
    ```sh
    sudo apt-get install -y libpcap-dev libpcre3-dev libdumbnet-dev zlib1g-dev liblzma-dev libssl-dev autoconf
    ```

2. Navigate to the DAQ source directory.
    ```sh
    cd daq-2.0.6/
    ```

2. Clean the build. 
    ```sh
    make clean
    ```
    
3. Prepare for automake, then autocreate makefile. 
    ```sh
    aclocal
    autoconf
    autoheader
    automake -a
    ```
  
4. Run the configuration script and include the dpdk and netvm libraries.
    ```sh
    ./configure --with-dpdk-includes=$RTE_SDK/$RTE_TARGET/include --with-dpdk-libraries=$RTE_SDK/$RTE_TARGET/lib --with-netvm-includes=$ONVM_HOME/onvm --with-netvm-libraries=$ONVM_HOME/onvm
    ```
    User should see yes for both DPDK and NetVM DAQs
    ![onvm daq][onvm-daq]
    
    
5. Build the DAQ 
    ```sh
    make -j7
    sudo make install
    ```  
---
4. Compile Snort
---

1. Navigate to the snort source directory.
    ```sh
    cd snort-2.9.8.3/
    ```
    
2. Run the configuration script.
    ```sh
    ./configure --enable-sourcefire
    ```

3. Create Patch of Makefille      
   ```sh
   cd ../
   ./patching-Makefile.sh
   ```

4. Navigate to the src folder of snort and Make snort.
    ```sh
    cd snort-2.9.8.3/src
    make clean
    cp ../../Makefile.patched Makefile
    make -j7
    sudo make install
    ```
    
5. Configure linker. 
    ```sh
    sudo ldconfig
    ```
---
5. Configure and run openNetVM-snort
---

1. Copy snort files into `/etc/snort` and create dynamic rules folder.
    ```sh
    sudo cp -r snort-2.9.8.3/simple-etc /etc/snort
    sudo mkdir /usr/local/lib/snort_dynamicrules
    ```
    
2. Run openNetVM manager. To install openNetVM, refer to this [guide][onvm-install].
    ```sh
    cd openNetVM-dev/onvm
    ./go.sh 0,1,2,3,4 3 -v 0x7f000000000
    ```
3. Run Snort.
    ```sh
    sudo snort -A console -Q -c /etc/snort/snort.conf -i dpdk0:dpdk1 -N --alert-before-pass --daq-var netvm_args="-l 5 -n 3 --proc-type=secondary -- -r 1 -- -d 4"
    ```
    ![snort init][snort-init]
    
3. Run Bridge.
    ```sh
    cd openNetVM-dev/examples/bridge/
    ./go.sh 6 4
    ```

[onvm-install]: https://github.com/sdnfv/openNetVM/blob/master/docs/Install.md
[onvm-daq]: https://github.com/sdnfv/onvm-snort/blob/master/onvm-daq.png "onvm daq"
[snort-init]: https://github.com/sdnfv/onvm-snort/blob/master/snort-initialization.png "snort initialization"
