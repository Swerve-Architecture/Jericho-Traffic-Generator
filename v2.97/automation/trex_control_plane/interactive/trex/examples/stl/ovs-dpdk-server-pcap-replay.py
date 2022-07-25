import stl_path
from trex.stl.api import *
import argparse
import sys

import inspect
import os

# EQ_pcap_path = "/home/annuszulfiqar/research/CAIDA/Equinix-2019/data.caida.org/datasets/passive-2019/equinix-nyc/20190117-130000.UTC/pcap/equinix-nyc.dirA.20190117-130000.UTC.anon.pcap"
EQ_pcap_dir_path = "/home/annuszulfiqar/research/CAIDA/Equinix-2019/data.caida.org/datasets/passive-2019/equinix-nyc/20190117-130000.UTC/pcap/"
# EQ_pcap_path = "/home/annuszulfiqar/research/CAIDA/Sripath/CAIDA.pcap"

c = STLClient(server = "localhost")

try:
    this_port = 0
    c.connect()
    c.reset(ports = [this_port])

    pcap_file_list = os.listdir(EQ_pcap_dir_path)
    for this_pcap_name in pcap_file_list:
        this_pcap_path = os.path.join(EQ_pcap_dir_path, this_pcap_name)
        # use an absolute path so the server can reach this
        pcap_file = os.path.abspath(this_pcap_path)

        # print(inspect.signature(c.push_remote))
        c.push_remote(pcap_filename=pcap_file, speedup=2000.0, ports=this_port, count=1)

        c.wait_on_traffic()

        stats = c.get_stats()
        opackets = stats[this_port]['opackets']
        print("{0} packets were Tx on port {1}\n".format(opackets, this_port))

except STLError as e:
    print(e)
    sys.exit(1)

finally:
    c.disconnect()