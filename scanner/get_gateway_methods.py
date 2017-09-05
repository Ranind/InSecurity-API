#python3

#
#
#       get_gateway Method
#
#

"""
#untested stackoverflow code!
import socket, struct

#Read the default gateway directly from /proc
def get_gateway():
    with open("/proc/net/route") as f:
        for line in f:
            fields = line.strip().split()
            if fields[1] != '00000000' or not int(fields[3], 16) & 2:
                    continue

        return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))
"""