#!/usr/bin/python

import sys
import json

# to run: ./rekall_linux_profile_fix.sh 4.13.9-300.fc27.x86_64.json
# will write output to 4.13.9-300.fc27.x86_64.json-2

with open(sys.argv[-1], 'r') as orig_fh, \
    open('%s-2' % sys.argv[-1], 'w') as new_fh:

    # Load json and find anonymous struct
    j = json.loads(orig_fh.read())

    struct_offset = j['$STRUCTS']['task_struct'][1]['u1'][0]
    struct_name = j['$STRUCTS']['task_struct'][1]['u1'][1][0]

    print(struct_offset)
    print(struct_name)

    del j['$STRUCTS']['task_struct'][1]['u1']

    # Move all of anon struct's members into task_struct
    for key, item in j['$STRUCTS'][struct_name][1].items():
        print('%s -> %s' % (key, item))
        item[0] += struct_offset
        print('%s -> %s' % (key, item))
        j['$STRUCTS']['task_struct'][1][key] = item

    print(j['$STRUCTS']['task_struct'][0])
    j['$STRUCTS']['task_struct'][0] += j['$STRUCTS'][struct_name][0]
    print(j['$STRUCTS']['task_struct'][0])

    del j['$STRUCTS'][struct_name]

    # save modified profile
    json.dump(j, new_fh, sort_keys=True, indent=1,)
