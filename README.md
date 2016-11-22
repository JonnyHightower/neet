NEET - Network Enumeration and Exploitation Tool

Neet is a flexible, multi-threaded tool for network penetration testing. It runs on Linux and co-ordinates the use of numerous other open-source network tools, with the aim of gathering as much network information as possible in clear, easy-to-use formats. The core scanning engine finds and identifies network services, the modules test or enumerate those services, and the Neet Shell provides an integrated environment for processing the results and exploiting known vulnerabilities. As such, it sits somewhere between manually running your own port scans and subsequent tests, and running a fully automated vulnerability assessment (VA) tool. It has many options which allow the user to tune the test parameters for network scanning in the most efficient and practical way.

Neet is aimed at professional penetration testers, internal IT security teams and network administrators who wish to know more about what's actually on their network infrastructure. You might want to try it out if you fall into one of those categories.

It has been written (and continues to be developed) by a professional penetration tester over years of engagements, and has been designed explicitly to do the leg-work for you and to make it convenient and safe to get your hands on useful network information before the customer brings your first cup of tea of the day.

Neet has a simple and flexible command-line interface, and gathers a lot of data about the networks within its scope. It will give you an up-to-the second view of how many services it's found on the network, what types of services they are, what types of hosts, what their hostnames are, whether they belong to domains, etc. If the modules are enabled (as they are by default) then it will perform tests against certain services - looking for default SNMP community strings and enumerating whatever is possible from SMB services, for example. It will also check for glaring security vulnerabilities and allow you to exploit them if you so choose.

All the information gathered is stored in human-readable text files so they can be grepped and awked as the user sees fit and, as well as storing the raw data, Neet aggregates a lot of it into files of related information for easier processing.

There's also a customised shell which takes a lot of the common tasks you'd normally perform and rolls them into simple commands. For example, the win command lists the Windows hosts on the network, and cross-references them against issues and vulnerabilities found to give you a colour-coded list of live Windows hosts, and the testshares command checks for unauthenticated access to SMB shares.

There is also documentation. Check out the man pages, the help command inside the neet shell, and the HTML documentation in /opt/neet/doc. Also, please check out the project page for the latest news and issue tracking/feature requests.

In summary, Neet is not a point-and-click hacking or vulnerability assessment tool. It is a console-based environment best run under X Windows, designed for the operator to gain insight into the components, relationships and operation of the network under test. It is also designed to help reporting by gathering as much evidence as possible. 

Neet is released under version 3 of the GNU Public License. See the LICENSE file for details.

Copyright 2008-2016 Jonathan Roach
Email: jonnyhightower [at] funkygeek.com

Some of the main features include:

    Single interface to co-ordinate many tools;

    Port scans and service identification are done in batches, so useful results appear early on;

    Easy to specify ranges to include and exclude, both for IP addresses and ports;

    Doesn't create more traffic than is strictly necessary;

    Detailed, timestamped logging;

    All raw tool output available, as well as sensibly-arranged output in text format;

    Customisable speed and intensity;

    Reliable scanning from multiple interfaces and over VPNs;

    Scan control allows you to pause / resume the scan;

    Cancel scans on individual hosts;

    Monitor progress of the scanning;

    Very configurable;

    Neet shell (neetsh) is bash shell with many aliases for getting through results quickly;

    Exploitation for specific exploits included in the Neet shell;

    Dump credentials from remote hosts directly into your Neet results without manually shunting files and commands between machines;

    Online incremental updates without having to do a full reinstall each time;

    Documentation: man pages, HTML help and the help command in the Neet shell;

    Many more.

** INSTALLATION **

Owing to the number of open-source tools orchestrated by Neet, the installation process will check the target system to ensure that it has the tools required. For the Debian, Ubuntu, Kali and Mint Linux distributions, the required prerequisites will be installed using APT prior to the main installation process.

See the INSTALL file for installation instructions.

