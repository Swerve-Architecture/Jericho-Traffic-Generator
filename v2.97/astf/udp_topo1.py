# Example of Topology profile

from trex.astf.api import *


def get_topo():
    topo = ASTFTopology()

# VIFs

    topo.add_gw(
        port_id = '0',
        src_start = '16.0.0.1',
        src_end = '16.0.0.2',
        dst = '00:00:00:01:00:02',
    )

    topo.add_gw(
        port_id = '0',
        src_start = '16.0.0.3',
        src_end = '16.0.0.4',
        dst = '00:00:00:01:00:02',
    )

    topo.add_gw(
        port_id = '0',
        src_start = '16.0.0.5',
        src_end = '16.0.0.8',
        dst = '00:00:00:01:00:02',
    )

    return topo

