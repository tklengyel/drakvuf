DRAKVUF
=======

Introduction
------

DRAKVUF is a virtualization based agentless black-box binary analysis system. DRAKVUF allows for in-depth execution tracing of arbitrary binaries (including operating systems), all without having to install any special software within the virtual machine used for analysis.

Hardware requirements
------

DRAKVUF uses hardware virtualization extensions found in Intel CPUs. You will need an Intel CPU with virtualization support (VT-x) and with Extended Page Tables (EPT). DRAKVUF is not going to work on any other CPUs (such as AMD) or on Intel CPUs without the required virtualization extensions.

Supported guests
------

DRAKVUF currently supports Windows 7, both 32 and 64-bit versions.

Malware analysis
------

DRAKVUF provides a perfect platform for stealthy malware analysis as its footprint is nearly undectebable from the malware's perspective. While DRAKVUF has been mainly developed with malware analysis in mind, it is certainly not limited to that task as it can be used to monitor the execution of arbitrary binaries.

More information @ http://drakvuf.com
