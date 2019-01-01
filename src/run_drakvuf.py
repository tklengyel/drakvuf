#!/usr/bin/env python3

##
## Spawns DRAKVUF and parses its outbound messages via pipe.
##

## @TODO:
## - add async support (poll on outpipe)
## - improve ^C support
## - remote breakpoints, verify correct handling of bad input


import os
import sys
import subprocess
import json
import logging


i = 0

def get_event(outpipe):
    global i

    line = b''
    prevcol = -1 # column of previous error
    while True:
        #import pdb;pdb.set_trace()
        line += outpipe.readline()
        #if not line:
        #    break

        i += 1
        try:
            dline = line.decode("utf-8")
        except UnicodeDecodeError as e:
            logging.warning("Failed to decode message %d [%s...]: %s", i, line[:40], e)
            import pdb;pdb.set_trace()
            break
        try:
            j = json.loads(dline)
            line = b''
            #print(j)
        except json.decoder.JSONDecodeError as e:
            logging.info("Failed to parse JSON from message %d [%s...]: %s", i, dline[:40], e)
            if prevcol == e.colno:
                logging.warning("Giving up an malformed JSON document")
                line = b''
                prevcol = -1
            else:
                prevcol = e.colno
            import pdb;pdb.set_trace()
            continue
            # break
        yield j

    # all done...
    yield None

def parse_event(event):
    global i

    if i % 500 == 0:
        print("Parsed {} events".format(i))
    #print(event)


def spawn_drakvuf(profile, domid):
    fmt = 'json'

    cmd  = ['drakvuf', '-r', profile, '-d', domid, '-o', fmt]
    #cmd.append('-v')

    logging.info("Running %s", ' '.join(cmd))

    p = subprocess.Popen(cmd,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)

    for e in get_event(p.stdout):
        if not e:
            break

        parse_event(e)

    # No more input...
    rc = p.wait()
    if rc:
        logging.warn("Returned %d, stderr: %s", rc, p.stderr.read())
    p.terminate()

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: {} <rekall_profile> <domid>".format(sys.argv[0]))
        print("Run as root (sudo)!")
        sys.exit(1)

    logging.basicConfig(level=logging.INFO)

    (profile, domid) = sys.argv[1:]

    spawn_drakvuf(profile, domid)
