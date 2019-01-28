#!/usr/bin/env python3

##
## Spawns DRAKVUF and parses its outbound messages via async pipe. Requires Python 3.6 or greater.
##

import os
import sys
import signal

import json
import logging

if not (sys.version_info.major >= 3 and sys.version_info.minor >= 6):
    print("This script requires Python 3.6+")
    sys.exit(1)

import curio
import curio.subprocess
import asyncio


deactivated_plugins = ['regmon', ]

proc = None # handle to DRAKVUF process
event_ct = 0

def signal_handler(sig, frame):
    global proc
    logging.info("Handling signal %d: stopping DRAKVUF", sig)
    if proc:
        proc.terminate()
    sys.exit(0)

async def get_event(outpipe):
    global event_ct

    line = b''
    prevcol = -1 # column of previous error
    while True:
        line += await outpipe.readline()
        if not line:
            break

        event_ct += 1
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
            logging.info("Failed to parse JSON from message %d [%s...]: %s", event_ct, dline[:40], e)
            if prevcol == e.colno:
                logging.warning("Giving up an malformed JSON document:\n%s", dline)
                line = b''
                prevcol = -1
            else:
                prevcol = e.colno
            import pdb;pdb.set_trace()
            continue
            # break
        return j

    # all done...
    return None

def parse_event(event):
    global event_ct

    if event_ct % 10000 == 0:
        logging.info("Parsed %d events", event_ct)


async def handle_output(outpipe):
    while True:
        json = await get_event(outpipe)
        if not json:
            break
        print(json)
        parse_event(json)


async def read_nop(outpipe):
    while True:
        line = await outpipe.readline()
        if not line:
            continue

        try:
            dline = line.decode("utf-8").strip()
        except UnicodeDecodeError as e:
            logging.warning("Failed to decode message %d [%s...]: %s", i, line[:40], e)
            continue

        logging.info("Observed on stderr: %s", dline)

    return True


async def spawn_drakvuf(profile, domid):
    global proc

    fmt = 'json'
    #fmt = 'kv'

    deactivated = ' '.join('-x {}'.format(p) for p in deactivated_plugins)

    cmd  = ['drakvuf', '-r', profile, '-d', domid, '-o', fmt, deactivated]
    #cmd.append('-v')

    logging.info("Running %s", ' '.join(cmd))

    proc = curio.subprocess.Popen(cmd,
                                  stdout=curio.subprocess.PIPE,
                                  stderr=curio.subprocess.PIPE)

    # kick off the stdout, stderr handlers and allow them to run forever
    children = list()
    async with curio.TaskGroup() as f:
        children.append( await f.spawn(read_nop, proc.stderr) )
        children.append( await f.spawn(handle_output, proc.stdout) )
        await curio.sleep(100)
        if proc.poll():
            logging.info("Detected that process has terminated")
            [x.cancel() for x in children]

    rc = proc.wait()
    if rc:
        logging.warn("Returned %d, stderr: %s", rc, proc.stderr.read())
    proc.terminate()

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: {} <rekall_profile> <domid>".format(sys.argv[0]))
        print("Run as root (sudo)!")
        sys.exit(1)

    logging.basicConfig(stream=sys.stderr, level=logging.INFO)

    (profile, domid) = sys.argv[1:]

    signal.signal(signal.SIGHUP,  signal_handler)
    signal.signal(signal.SIGINT,  signal_handler)
    signal.signal(signal.SIGQUIT, signal_handler)
    signal.signal(signal.SIGABRT, signal_handler)

    curio.run(spawn_drakvuf, profile, domid)
