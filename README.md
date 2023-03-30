# DRAKVUF&copy;


[![OpenSSF Best Practices](https://bestpractices.coreinfrastructure.org/projects/6836/badge)](https://bestpractices.coreinfrastructure.org/projects/6836)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/tklengyel/drakvuf/badge)](https://api.securityscorecards.dev/projects/github.com/tklengyel/drakvuf)
[![ci](https://github.com/tklengyel/drakvuf/actions/workflows/ci.yml/badge.svg)](https://github.com/tklengyel/drakvuf/actions/workflows/ci.yml)
[![Coverity](https://scan.coverity.com/projects/3238/badge.svg)](https://scan.coverity.com/projects/tklengyel-drakvuf)

## Introduction

DRAKVUF is a virtualization based agentless black-box binary analysis system. DRAKVUF
allows for in-depth execution tracing of arbitrary binaries (including operating
systems), all without having to install any special software within the virtual machine
used for analysis.

## Hardware requirements

DRAKVUF uses hardware virtualization extensions found in Intel CPUs. You will need an
Intel CPU with virtualization support (VT-x) and with Extended Page Tables (EPT). DRAKVUF
 is not going to work on any other CPUs (such as AMD) or on Intel CPUs without the
required virtualization extensions.

## Supported guests

DRAKVUF currently supports:
 - Windows 7 - 8, both 32 and 64-bit
 - Windows 10 64-bit
 - Linux 2.6.x - 6.x, both 32-bit and 64-bit

## Pre-built Debian packages

You can find pre-built Debian packages of the latest DRAKVUF builds at
https://github.com/tklengyel/drakvuf-builds/releases
 
## Malware analysis

DRAKVUF provides a perfect platform for stealthy malware analysis as its footprint is
nearly undectebable from the malware's perspective. While DRAKVUF has been mainly
developed with malware analysis in mind, it is certainly not limited to that task as it
can be used to monitor the execution of anything that executes within a VM, including
firmware, OS kernels and user-space processes.

## Graphical frontend

If you would like a full-featured DRAKVUF GUI to setup as automated analysis sandbox, check out the
[DRAKVUF Sandbox project](https://github.com/CERT-Polska/drakvuf-sandbox).

## Installation steps

Installation steps can be found on the project website: [https://drakvuf.com](https://drakvuf.com)
