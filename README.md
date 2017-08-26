# onvm-snort: Snort IDS ported to [openNetVM][onvm]

About
--
[Snort][snort-link] is a free and open source network intrusion detection system owned by Cisco. Snort runs in conjuction with the openNetVM platform to provide enhanced security for packet processing.

openNetVM is a high performance NFV platform based on [Intel DPDK][dpdk] and [Docker][docker] containers.  openNetVM is SDN-enabled, allowing the network controller to provide rules that dictate what network functions need to process each packet flow.

openNetVM is an open source version of the NetVM platform described in our [NSDI 2014 paper][nsdi04], released under the [BSD][license] license.

Publication
--
The design challenges with integrating Snort into openNetVM's high performance NF chains are described in our [KBNets 2017 paper][kbnets17].

Installing
--
To install Snort and configure it for openNetVM, please see the [snort Installation][install] guide for a thorough walkthrough.

Contributors
--
Jean Tourrilhes -- Hewlett Packard Labs
Grace Liu -- GWU (Contact: guyue at gwu.edu)
Riley Kennedy -- GWU

[snort-link]: https://www.snort.org/
[onvm]: http://sdnfv.github.io/onvm/
[license]: LICENSE
[dpdk]: http://dpdk.org
[docker]: https://www.docker.com/
[kbnets17]: http://grace-liu.github.io/static/papers/17-KBNets-onvm.pdf
[nsdi04]: http://faculty.cs.gwu.edu/~timwood/papers/14-NSDI-netvm.pdf
[install]: Install.md
