NEET - Network Enumeration and Exploitation Tool

Neet is a flexible, multi-threaded network penetration test tool which runs on Linux and is aimed at professional penetration testers or network administrators. It co-ordinates the use of numerous other open-source network tools to gather as much network information as possible in an easily-understood format. The core identifies network services, the modules test or enumerate those services, and the neet shell provides an integrated environment for processing the results and exploiting known vulnerabilities.

As such, Neet sits somewhere between manually running your own port scans and subsequent tests, and running a fully automated VA tool. Neet has many options which allow the user to tune the test parameters for network scanning in the most reliable and practical way.

Neet is not a point-and-click hacking or vulnerability assessment tool. It is a console-based environment best run under X Windows, designed for the operator to gain a great deal of insight into the operation of the network under test. It is also designed to help reporting by gathering as much evidence as possible. 

Owing to the number of open-source tools orchestrated by Neet, the installation process will check the target system to ensure that it has the tools required.

Neet is released under version 3 of the GNU Public License. See the LICENSE file for details.

Copyright 2007-2014 Jonathan Roach
Email: jonnyhightower [at] funkygeek.com

The main features are:
	Single interface to co-ordinate many tools
	Portscans and service identification are done in batches, so useful results appear early on.
	Easy to specify ranges to include and exclude, both for IP addresses and ports.
	Doesn't create more traffic than is strictly necessary.
	Detailed, timestamped logging
	All raw tool output available, as well as sensibly-arranged output in text format.
	Customisable speed and intensity
	Reliable scanning from multiple interfaces and over VPNs
	Scan control allows you to pause / resume the scan
	Cancel scans on individual hosts.
	Monitor progress of the scanning.
	Very configurable.
	Neet shell (neetsh) is bash shell with many aliases for getting through results quickly.
	Exploitation for specific exploits included in the neet shell.
	Documentation! man pages and "help" command in the neet shell.
	Many more.

** INSTALLATION **

See the INSTALL file in this directory for installation instructions.


