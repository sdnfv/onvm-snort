# onvm-snort: Snort IDS ported to [openNetVM][onvm]

About
--
Snort is a free and open source network intrusion detection system owned by Cisco. Snort runs in conjuction with the openNetVM platform to provide enhanced security for packet processing.

openNetVM is a high performance NFV platform based on [Intel DPDK][dpdk] and [Docker][docker] containers.  openNetVM is SDN-enabled, allowing the network controller to provide rules that dictate what network functions need to process each packet flow.

openNetVM is an open source version of the NetVM platform described in our [NSDI 2014 paper][nsdi04], released under the [BSD][license] license.

Installing
--
To install Snort and configure it for openNetVM, please see the [snort Installation][install] guide for a thorough walkthrough.


[onvm]: http://sdnfv.github.io/onvm/
[license]: LICENSE
[dpdk]: http://dpdk.org
[docker]: https://www.docker.com/
[nsdi04]: http://faculty.cs.gwu.edu/~timwood/papers/14-NSDI-netvm.pdf
[install]: Install.md
