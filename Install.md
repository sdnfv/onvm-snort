# Snort Installation

This guide helps you build and install Snort.

---
1. Setup Repositories
---

1. Download source code
    ```sh
    git clone https://github.com/sdnfv/onvm-snort
    cd onvm-snort
    ```
2. Initialize openNetVM submodule
    ```sh
    git submodule sync
    git submodule update --init
    ```
---
2. Compile DPDK and openNetVM
---

Please follow [the openNetVM installation guide](https://github.com/sdnfv/openNetVM/blob/master/docs/Install.md).

---
3. Compile DAQ
---

1. Install dependencies.
    ```sh
    sudo apt-get install -y libpcap-dev libpcre3-dev libdumbnet-dev zlib1g-dev liblzma-dev libssl-dev autoconf flex bison luajit libtool libglib2.0-dev pkg-config
    ```
2. Navigate to the DAQ source directory.
    ```sh
    cd daq-2.0.6/
    ```
3. Prepare for automake, then autocreate makefile.
    ```sh
    aclocal
    autoconf
    autoheader
    autoreconf -ivf
    automake -a
    ```
4. Run the configuration script and include the dpdk and netvm libraries.
    ```sh
    ./configure --enable-static --disable-shared --with-dpdk-includes=$RTE_SDK/$RTE_TARGET/include --with-dpdk-libraries=$RTE_SDK/$RTE_TARGET/lib --with-netvm-includes=$ONVM_HOME/onvm --with-netvm-libraries=$ONVM_HOME/onvm
    ```
    User should see yes for both DPDK and NetVM DAQs
    ![onvm daq][onvm-daq]
5. Build the DAQ 
    ```sh
    make clean
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
2. Prepare for automake, then autocreate makefile. 
    ```sh
    aclocal
    autoconf
    autoheader
    autoreconf -ivf
    automake -a
    ```
3. Run the configuration script.
    ```sh
    ./configure --enable-sourcefire --enable-static --disable-shared
    ```
4. Navigate to the src folder of snort and Make snort.
    ```sh
    cd snort-2.9.8.3/src
    make clean
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
2. Add snort to path (change /opt/snort if the install path is different)
    ```
    export PATH=$PATH:/opt/snort/bin
    ```
3. Run openNetVM manager. To install openNetVM, refer to this [guide][onvm-install].
    ```sh
    cd openNetVM/onvm
    ./go.sh 0,1,2,3 3 0xF0 -a 0x7f000000000 -s stdout
    ```
4. Run Snort.
    ```sh
    sudo snort -A console -Q -c /etc/snort/snort.conf -i dpdk0 -N --alert-before-pass --daq-var netvm_args="-l 5 -n 3 --proc-type=secondary -- -r 1 -- -d 4"
    ```
    If the above does not work then try:
    ```
    which snort
    sudo `which snort` -A console -Q -c /etc/snort/snort.conf -i dpdk0:dpdk1 -N --alert-before-pass --daq-var netvm_args="-l 5 -n 3 --proc-type=secondary -- -r 1 -- -d 4"
    ```
    ![snort init][snort-init]
    
6. Run Bridge.
    ```sh
    cd openNetVM-dev/examples/bridge/
    ./go.sh 6 4
    ```

[onvm-install]: https://github.com/sdnfv/openNetVM/blob/master/docs/Install.md
[onvm-daq]: https://github.com/sdnfv/onvm-snort/blob/master/onvm-daq.png "onvm daq"
[snort-init]: https://github.com/sdnfv/onvm-snort/blob/master/snort-initialization.png "snort initialization"

