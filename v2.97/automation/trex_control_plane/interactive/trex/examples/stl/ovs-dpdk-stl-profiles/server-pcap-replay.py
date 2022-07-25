import stl_path
from trex.stl.api import *
import argparse
import sys

# import sys
# sys.path.insert(0, '/home/annuszulfiqar/research/trex-traffic-generator/v2.97/automation/trex_control_plane/interactive/') # allow parent modules to be included
# from trex_stl_lib.api import *
# import argparse
import inspect
import os

# CP = os.path.join(os.path.dirname(__file__))
EQ_pcap_path = "/home/annuszulfiqar/research/CAIDA/Equinix-2019/data.caida.org/datasets/passive-2019/equinix-nyc/20190117-130000.UTC/pcap/equinix-nyc.dirA.20190117-130000.UTC.anon.pcap"

c = STLClient(server = "localhost")

try:
    this_port = 0
    c.connect()
    c.reset(ports = [this_port])

    # use an absolute path so the server can reach this
    pcap_file = os.path.abspath(EQ_pcap_path)

    print(inspect.signature(c.push_remote))
    c.push_remote(pcap_filename=pcap_file, speedup=20000, ports=this_port, ipg_usec=100, count=1)

    c.wait_on_traffic()

    stats = c.get_stats()
    opackets = stats[this_port]['opackets']
    print("{0} packets were Tx on port {1}\n".format(opackets, this_port))

except STLError as e:
    print(e)
    sys.exit(1)

finally:
    c.disconnect()