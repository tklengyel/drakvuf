#!/usr/bin/perl
#
#********************IMPORTANT DRAKVUF LICENSE TERMS*********************#
#                                                                        #
# DRAKVUF (C) 2014-2016 Tamas K Lengyel.                                 #
# Tamas K Lengyel is hereinafter referred to as the author.              #
# This program is free software; you may redistribute and/or modify it   #
# under the terms of the GNU General Public License as published by the  #
# Free Software Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE  #
# CLARIFICATIONS AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your  #
# right to use, modify, and redistribute this software under certain     #
# conditions.  If you wish to embed DRAKVUF technology into proprietary  #
# software, alternative licenses can be aquired from the author.         #
#                                                                        #
# Note that the GPL places important restrictions on "derivative works", #
# yet it does not provide a detailed definition of that term.  To avoid  #
# misunderstandings, we interpret that term as broadly as copyright law  #
# allows.  For example, we consider an application to constitute a       #
# derivative work for the purpose of this license if it does any of the  #
# following with any software or content covered by this license         #
# ("Covered Software"):                                                  #
#                                                                        #
# o Integrates source code from Covered Software.                        #
#                                                                        #
# o Reads or includes copyrighted data files.                            #
#                                                                        #
# o Is designed specifically to execute Covered Software and parse the   #
# results (as opposed to typical shell or execution-menu apps, which will#
# execute anything you tell them to).                                    #
#                                                                        #
# o Includes Covered Software in a proprietary executable installer.  The#
# installers produced by InstallShield are an example of this.  Including#
# DRAKVUF with other software in compressed or archival form does not    #
# trigger this provision, provided appropriate open source decompression #
# or de-archiving software is widely available for no charge.  For the   #
# purposes of this license, an installer is considered to include Covered#
# Software even if it actually retrieves a copy of Covered Software from #
# another source during runtime (such as by downloading it from the      #
# Internet).                                                             #
#                                                                        #
# o Links (statically or dynamically) to a library which does any of the #
# above.                                                                 #
#                                                                        #
# o Executes a helper program, module, or script to do any of the above. #
#                                                                        #
# This list is not exclusive, but is meant to clarify our interpretation #
# of derived works with some common examples.  Other people may interpret#
# the plain GPL differently, so we consider this a special exception to  #
# the GPL that we apply to Covered Software.  Works which meet any of    #
# these conditions must conform to all of the terms of this license,     #
# particularly including the GPL Section 3 requirements of providing     #
# source code and allowing free redistribution of the work as a whole.   #
#                                                                        #
# Any redistribution of Covered Software, including any derived works,   #
# must obey and carry forward all of the terms of this license, including#
# obeying all GPL rules and restrictions.  For example, source code of   #
# the whole work must be provided and free redistribution must be        #
# allowed.  All GPL references to "this License", are to be treated as   #
# including the terms and conditions of this license text as well.       #
#                                                                        #
# Because this license imposes special exceptions to the GPL, Covered    #
# Work may not be combined (even as part of a larger work) with plain GPL#
# software.  The terms, conditions, and exceptions of this license must  #
# be included as well.  This license is incompatible with some other open#
# source licenses as well.  In some cases we can relicense portions of   #
# DRAKVUF or grant special permissions to use it in other open source    #
# software.  Please contact tamas.k.lengyel@gmail.com with any such      #
# requests.  Similarly, we don't incorporate incompatible open source    #
# software into Covered Software without special permission from the     #
# copyright holders.                                                     #
#                                                                        #
# If you have any questions about the licensing restrictions on using    #
# DRAKVUF in other works, are happy to help.  As mentioned above,        #
# alternative license can be requested from the author to integrate      #
# DRAKVUF into proprietary applications and appliances.  Please email    #
# tamas.k.lengyel@gmail.com for further information.                     #
#                                                                        #
# If you have received a written license agreement or contract for       #
# Covered Software stating terms other than these, you may choose to use #
# and redistribute Covered Software under those terms instead of these.  #
#                                                                        #
# Source is provided to this software because we believe users have a    #
# right to know exactly what a program is going to do before they run it.#
# This also allows you to audit the software for security holes.         #
#                                                                        #
# Source code also allows you to port DRAKVUF to new platforms, fix bugs,#
# and add new features.  You are highly encouraged to submit your changes#
# on https://github.com/tklengyel/drakvuf, or by other methods.          #
# By sending these changes, it is understood (unless you specify         #
# otherwise) that you are offering unlimited, non-exclusive right to     #
# reuse, modify, and relicense the code.  DRAKVUF will always be         #
# available Open Source, but this is important because the inability to  #
# relicense code has caused devastating problems for other Free Software #
# projects (such as KDE and NASM).                                       #
# To specify special license conditions of your contributions, just say  #
# so when you send them.                                                 #
#                                                                        #
# This program is distributed in the hope that it will be useful, but    #
# WITHOUT ANY WARRANTY; without even the implied warranty of             #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the DRAKVUF  #
# license file for more details (it's in a COPYING file included with    #
# DRAKVUF, and also available from                                       #
# https://github.com/tklengyel/drakvuf/COPYING)                          #
#                                                                        #
#************************************************************************#

######
# This script creates an LVM disk CoW of the specified VM
# then live-snapshots the VM to duplicate its memory
# followed by memsharing to deduplicate memory.
#
# The LVM volume should have the same name as the domain.
#
# NOTICE:
# If an LVM volume exists with the clone's name, it is removed.
#
use strict;
use warnings;

## Settings
#
# The LVM volume group
our $lvm_vg = "t0vg";
# Clone network bridge name
our $clone_bridge = "xenbr1";
# Vif script to pass to clone Xen config.
# The backend specifies the name of the openvswitch domain.
our $vif_script = "script=vif-openvswitch,backend=0";

############################################################

our $lvcreate = `which lvcreate`;
our $lvremove = `which lvremove`;
our $lvdisplay = `which lvdisplay`;
our $xl = `which xl`;
our $mkfifo = `which mkfifo`;

$lvcreate =~ s/\015?\012?$//;;
$lvremove =~ s/\015?\012?$//;;
$lvdisplay =~ s/\015?\012?$//;;
$xl =~ s/\015?\012?$//;;
$mkfifo =~ s/\015?\012?$//;

sub clone {
    if (@ARGV != 3) {
        die "Insufficient number of arguments!\nUsage: ./clone.pl <domain name> <vlan> <path/to/domain.cfg>\n";
    }

    my $origin = $_[0];
    my $vlan = $_[1];
    my $config = $_[2];
    my $clone = "$origin-$vlan-clone";

    my $origin_test = `$xl domid $origin`;
    if(length $origin_test == 0) {
        die "0";
    }

    my $clone_test = `$xl domid $clone 2>/dev/null`;
    if(length $clone_test) {
        `$xl destroy $clone`;
    }

    unless (-e $config) {
        die "0";
    }

    my $domconfig = `cat $config`;

    open(my $fh, '>', "/tmp/$clone.config") or die "Could not open file!";

    while($domconfig =~ /([^\n]+)\n?/g){

        if(index($1, "name") != -1) {
            print $fh "name = \"$clone\"\n";
            next;
        }

        if(index($1, "vif") != -1) {
            my @values = split(',', $1);
            my $value;
            my $count = 0;
            foreach $value (@values) {
                if(index($value, "bridge")!=-1 && index($value, "vif-bridge")==-1) {
                    print $fh "bridge=$clone_bridge.$vlan,$vif_script";
                } else {
                    if(index($value, "script")==-1 && index($value, "backend")==-1) {
                        print $fh "$value";
                    } else {
                        if($count == $#values) {
                            print $fh "']";
                        }
                    }
                }

                if($count < $#values) {
                    print $fh ",";
                }
                $count++;
            }
            print $fh "\n";
            next;
        }

        if(index($1, "disk") != -1) {
            my $disk = $1;
            my $pos = index($disk, $origin);
            while ( $pos > -1 ) {
                substr( $disk, $pos, length( $origin ), $clone );
                $pos = index( $disk, $origin, $pos + length( $clone ));
            }
            print $fh $disk;
            print $fh "\n";
            next;
        }

        print $fh "$1\n";
    }

    # TODO: evaluate qemu stubdomain usability
    #print $fh "device_model_stubdomain_override = 1\n";
    close $fh;

    `$xl pause $origin 2>&1`;

    my $test = `$lvdisplay /dev/$lvm_vg/$clone 2>&1`;
    if(($test =~ tr/\n//) != 1) {
       #print "Removing existing LVM snapshot of $clone\n";
        `$lvremove -f /dev/$lvm_vg/$clone 2>&1`;
    }

    `$lvcreate -s -n $clone -L20G /dev/$lvm_vg/$origin 2>&1`;
    `$mkfifo /tmp/drakvuf_pipe_$clone 2>&1`;
    `$xl save -c $origin /tmp/drakvuf_pipe_$clone 2>&1 | $xl restore -p -e /tmp/$clone.config /tmp/drakvuf_pipe_$clone 2>&1`;
    my $cloneID = `$xl domid $clone`;
    chomp($cloneID);
    print "$cloneID";
}

############################################################

clone($ARGV[0], $ARGV[1], $ARGV[2]);
