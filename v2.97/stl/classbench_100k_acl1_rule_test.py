from trex_stl_lib.api import *
import argparse
import os

# stream from pcap file. continues pps 10 in sec 

CP = os.path.join(os.path.dirname(__file__))
ACL1_RULE_SET_PATH = "/home/annuszulfiqar/research/trex-traffic-generator/deps/classbench-mapper/mapped_rules/acl1_100K_mapped_rules.txt"

class STLS1(object):

    def read_rule_set(self):
        self.flows = []
        with open(ACL1_RULE_SET_PATH) as these_flows:
            for idx, flow in enumerate(these_flows, 1):
                dl_type, nw_proto, nw_src, nw_dst, tp_src, tp_dst, priority, actions = flow.split(',')
                # dl_type = dl_type.split('=')[-1]
                try:
                    nw_proto = int(nw_proto.split('=')[-1])
                except:
                    continue
                if nw_proto != 6 and nw_proto != 17:
                    # print("faulty nw_proto = {0}".format(nw_proto))
                    continue
                nw_src = nw_src.split('=')[-1].split('/')[0]
                nw_dst = nw_dst.split('=')[-1].split('/')[0]
                tp_src = int(tp_src.split('=')[-1].split('/')[0], 0)
                tp_dst = int(tp_dst.split('=')[-1].split('/')[0], 0)
                self.flows.append({ 'nw_proto':nw_proto, 'nw_src':nw_src, 'nw_dst':nw_dst, 'tp_src':tp_src, 'tp_dst':tp_dst })
                if idx % 10000 == 0:
                    print(" Reading Flow Rule {0} => {1}".format(idx, self.flows[-1]))

    def create_stream (self):
        self.read_rule_set()
        self.rule_based_streams = []
        for idx, flow in enumerate(self.flows[:2000]):
            if flow['nw_proto'] == 6:
                this_nw_proto = TCP
            elif flow['nw_proto'] == 17:
                this_nw_proto = UDP
            else:
                continue
                # print("problem with protocol = {0}".format(flow['nw_proto']))
            self.rule_based_streams.append(
                STLStream(  name='S{0}'.format(idx),
                            packet=STLPktBuilder(pkt=Ether()/IP(src=flow['nw_src'],dst=flow['nw_dst'])/this_nw_proto(dport=flow['tp_dst'],sport=flow['tp_src'])/(10*'x')), 
                            mode=STLTXCont()
                        ))
        return STLProfile(self.rule_based_streams).get_streams()

    def get_streams (self, tunables, **kwargs):
        parser = argparse.ArgumentParser(description='Argparser for {}'.format(os.path.basename(__file__)), 
                                         formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        args = parser.parse_args(tunables)
        # create multiple streams
        return self.create_stream()


# dynamic load - used for trex console or simulator
def register():
    return STLS1()
