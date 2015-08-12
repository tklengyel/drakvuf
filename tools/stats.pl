#!/usr/bin/perl
#********************IMPORTANT DRAKVUF LICENSE TERMS*********************#
#                                                                        #
# DRAKVUF Dynamic Malware Analysis System (C) 2014-2015 Tamas K Lengyel. #
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

use strict;
use warnings;
use Statistics::OnLine;
use IO::Handle;

my %apistats = ();
my %heapstats = ();

my $filestats = Statistics::OnLine->new;
my $deletestats = Statistics::OnLine->new;
my $targetfilestats = Statistics::OnLine->new;
my $memstats = Statistics::OnLine->new;
my $calledapistats = Statistics::OnLine->new;
my $totalcalledapistats = Statistics::OnLine->new;
my $heaptagsstats = Statistics::OnLine->new;
my $totalheaptagsstats = Statistics::OnLine->new;

my $total = 0;
my $success = 0;
my $fail = 0;

sub getcr3 {
    my $cr3 = "0";
    my $file = $_[0];
    my $line = `cat $file | grep "Injected process CR3:"`;
    my @value = split(': ', $line);
    if (defined $value[1]) {
        $cr3 = $value[1];
        chomp($cr3);
    }

    if ($cr3 eq "0x0") {
        my $line2 = `cat $file | grep -B1 "Started vmi clone thread" | head -n1`;
        my @value2 = split(': ', $line2);
        my @value3 = split(']', $value2[3]);
        if (defined $value3[0]) {
            $cr3 = $value3[0];
            chomp($cr3);
        }
    }

    return $cr3;
}

sub get_files_accessed{
    my $file = $_[0];
    my $count = `cat $file | grep "File access" | wc -l`;
    chomp $count;
    return $count;
}

sub get_files_accessed_by_cr3{
    my $file = $_[0];
    my $cr3 = $_[1];
    my $count = `cat $file | grep "File access" | grep $cr3 | wc -l`;
    chomp $count;
    return $count;
}

sub get_extracted_files{
    my $file = $_[0];
    my $count = `cat $file | grep "Extracting file" | wc -l`;
    chomp $count;
    return $count;
}

sub get_mem_shared{
    my $file = $_[0];
    my $line = `tail -n3 $file | grep "Shared memory pages"`;
    chomp($line);
    my @v = split(": ", $line);
    if (defined $v[1]) {
        return $v[1];
    }

    return -1;
}


sub get_api_calls{
    my $file = $_[0];
    my $cr3 = $_[1];
    my $count_api = 0;
    my $count_target_api = 0;
    my %apis = ();
    open(my $fh, $file)
    or die "Could not open file '$file' $!";
 
    while (my $row = <$fh>) {
        chomp $row;
        if (index($row,"ntoskrnl.exe!") != -1 && index($row, "Failed to import") == -1 && index($row, "HarddiskVolume2") == -1) {

            $count_api++;

            if (index($row,$cr3) != -1) {
                my @value = split('!', $row);
                my $api = $value[1];
                $count_target_api++;

                if (defined $api) {
                    if (exists $apis{ $api }) {
                        my $count = $apis{ $api };
                        $apis{ $api } = $count+1;
                    } else {
                        $apis{ $api } = 1;
                    }
                }
            }
        }
    }
    close($fh);
    return ($count_api, $count_target_api, \%apis);
}

sub get_heap_allocations {
    my $file = $_[0];
    my $cr3 = $_[1];
    my %heaps = ();
    my $count_heap = 0;
    my $count_target_heap = 0;
    my $prev_row;
    open(my $fh, $file)
    or die "Could not open file '$file' $!";
 
    while (my $row = <$fh>) {
        chomp $row;

        if (index($row,"pool tag:") != -1) {
            if (index($prev_row,"ntoskrnl.exe!") != -1 && index($prev_row, "Failed to import") == -1 && index($prev_row, "HarddiskVolume2") == -1) {
                $count_heap++;

                if (index($prev_row,$cr3) != -1) {
                    my @value = split(':', $row);
                    my @value2 = split('\'', $value[1]);
                    my $heaptag = $value2[1];
                    $count_target_heap++;

                    if (defined $heaptag && length $heaptag <= 4) {
                        if (exists $heaps{ $heaptag }) {
                            my $count = $heaps{ $heaptag };
                            $heaps{ $heaptag } = $count+1;
                        } else {
                            $heaps{ $heaptag } = 1;
                        }
                    }
                }
            }
        }        

        $prev_row = $row;
    }
    close($fh);
    return ($count_heap, $count_target_heap, \%heaps);

}

sub stats {
    my $file = $_[0];
    print "$file,";
    my $lastline = `tail -n1 $file`;
    if ($lastline eq "Process startup failed\n") {
        print "\n";
        return 0;
    }
    
    my $cr3 = getcr3($file);
    if ($cr3 eq "0" || $cr3 eq "0x0") {
        print "\n";
        return 0;
    }

    my ($count_api, $count_target_api, $apis) = get_api_calls($file, $cr3);
    my ($count_heap, $count_target_heap, $heaps) = get_heap_allocations($file, $cr3);
    my $files_accessed = get_files_accessed($file);
    my $files_accessed_by_cr3 = get_files_accessed_by_cr3($file, $cr3);
    my $extracted_files = get_extracted_files($file);
    my $apis_called_count = keys %$apis;
    my $heaptags_count = keys %$heaps;
    my $total_apis_called_count = 0;
    my $total_heaptags_count = 0;
    my $shared = get_mem_shared($file);

    print "{ ";
    while ( my ($key, $value) = each(%$apis) ) {
        my ($count, $api, $list);
        if (exists $apistats{ $key }) {
            $apistats{ $key }[0] += 1;
            $api = $apistats{ $key }[1];
            $list = $apistats{ $key }[2];
        } else {
            $api = Statistics::OnLine->new;
            my @array = ();
            $list = \@array;
            $apistats{ $key }[0] = 1;
            $apistats{ $key }[1] = $api;
            $apistats{ $key }[2] = $list;
        }

        $total_apis_called_count += $value;

        $api->add_data($value);
        push @{$list}, $value;

        print "$key:$value "
    }
    print "},";

    print "{ ";
    while ( my ($key, $value) = each(%$heaps) ) {
        my ($count, $heap, $list);
        if (exists $heapstats{ $key }) {
            $heapstats{ $key }[0] += 1;
            $heap = $heapstats{ $key }[1];
            $list = $heapstats{ $key }[2];
        } else {
            $heap = Statistics::OnLine->new;
            my @array = ();
            $list = \@array;
            $heapstats{ $key }[0] = 1;
            $heapstats{ $key }[1] = $heap;
            $heapstats{ $key }[2] = $list;
        }

        $total_heaptags_count += $value;

        $heap->add_data($value);
        push @{$list}, $value;
        print "'$key':$value ";
    }
    print "},";

    $filestats->add_data($files_accessed);
    $targetfilestats->add_data($files_accessed_by_cr3);
    $deletestats->add_data($extracted_files);
    $memstats->add_data($shared);
    $calledapistats->add_data($apis_called_count);
    $totalcalledapistats->add_data($total_apis_called_count);
    $heaptagsstats->add_data($heaptags_count);
    $totalheaptagsstats->add_data($total_heaptags_count);

    print "Injected CR3:$cr3,";
    print "Memshare:$shared,";
    print "Files accessed:$files_accessed_by_cr3,";
    print "Total files accessed:$files_accessed,";
    print "Deleted files:$extracted_files,";
    print "Number of APIs hit by target:$apis_called_count,";
    print "Total Number of API calls:$count_api,";
    print "Total Number of API calls by target:$total_apis_called_count,";
    print "Number of heap tags used by target:$heaptags_count,";
    print "Total heap allocations:$count_heap,";
    print "Total heap allocations by target:$total_heaptags_count,";
    print "\n";

    return 1;
}

sub recursedir {
    my $dir = $_[0];

    opendir (my $dirh, $dir) or die $!;
    while (my $file = readdir($dirh)) {
        next if $file =~ /^[.]/;
        if (-d "$dir/$file") {
            recursedir("$dir/$file");
        }
        if (-f "$dir/$file" && index($file, "drakvuf") != -1) {
            $total = $total + 1;
            print "$total,";
            if (stats("$dir/$file") == 1) {
                $success = $success+1;
            } else {
                $fail = $fail + 1;
            }
        }
    }
    closedir($dirh);
}

sub printstat {
    my $header = $_[0];
    my $stats = $_[1];

    print "$header,",$stats->mean;

    if($stats->count >= 2) {
        print ",",$stats->variance,",",sqrt($stats->variance);
    }

    if($stats->count >= 3 && $stats->variance != 0) {
        print ",",$stats->skewness;
    }

    if($stats->count >= 4 && $stats->variance != 0) {
        print ",",$stats->kurtosis;
    }

    print "\n";
}

############################################################

STDOUT->autoflush(1);
if (!@ARGV || $ARGV[0] eq "--help" || $ARGV[0] eq "-h") {
    print "DRAKVUF 0.1 log parser\n";
    print "Usage: perl stats.pl <folder containing drakvuf log(s)>\n";
    exit 1;
}

recursedir($ARGV[0]);

print "--------------------------\n";
print "DRAKVUF startup: $success/$total\n";

printstat("Memory share stats", $memstats);
printstat("File access stats", $filestats);
printstat("Injected process file access stats", $targetfilestats);
printstat("Deleted file stats", $deletestats);
printstat("Number of API calls stats", $calledapistats);
printstat("Total numer of API calls stats", $totalcalledapistats);
printstat("Number of heaptags stats", $heaptagsstats);
printstat("Total numer of heaptags stats", $totalheaptagsstats);
print "--------------------------\n";

while ( my $key = each(%apistats) ) {
    my $count = $apistats{$key}[0];
    print "$key,{ ";
    foreach (@{$apistats{$key}[2]}) { 
        print $_, " ";
    }
    printstat("}, $count", $apistats{$key}[1]);
}

print "--------------------------\n";

while ( my $key = each(%heapstats) ) {
    my $count = $heapstats{$key}[0];
    print "'$key',{ ";
    foreach (@{$heapstats{$key}[2]}) { 
        print $_, " ";
    }
    printstat("}, $count", $heapstats{$key}[1]);
}

exit 0;
