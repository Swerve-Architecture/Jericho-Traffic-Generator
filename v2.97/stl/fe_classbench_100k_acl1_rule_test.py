from socket import TIPC_SRC_DROPPABLE
from sys import flags
from trex_stl_lib.api import *
import argparse
import os

# stream from pcap file. continues pps 10 in sec 

CP = os.path.join(os.path.dirname(__file__))
ACL1_RULE_SET_PATH = "/home/annuszulfiqar/research/trex-traffic-generator/deps/classbench-mapper/mapped_rules/acl1_100K_mapped_rules.txt"

class STLS1(object):

    def read_rule_set(self):
        self.flows = []
        self.nw_proto = []
        self.nw_src = []
        self.nw_dst = []
        self.tp_src = []
        self.tp_dst = []

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
                self.nw_proto.append(nw_proto)
                self.nw_src.append(nw_src)
                self.nw_dst.append(nw_dst)
                self.tp_src.append(tp_src)
                self.tp_dst.append(tp_dst)
                if idx % 10000 == 0:
                    print(" Reading Flow Rule {0} => {1}".format(idx, self.flows[-1]))
        
        self.nw_src = list(set(self.nw_src))
        self.nw_dst = list(set(self.nw_dst))
        self.tp_src = list(set(self.tp_src))
        self.tp_dst = list(set(self.tp_dst))

        print("\nIP.src count = {0}, IP.dst count = {1}, TCP.sport count = {2}, TCP.dst count = {3}".format(len(self.nw_src), len(self.nw_dst), len(self.tp_src), len(tp_dst)))
        print("\nnw_src: ", self.nw_src)
        print("\nnw_dst: ", self.nw_dst)
        print("\ntp_src: ", self.tp_src)
        print("\ntp_dst: ", self.tp_dst)
        print("Common IPs in ip.src and ip.dst = {0}".format(set(self.nw_src).intersection(self.nw_dst)))

    def create_stream (self):
        self.read_rule_set()
        base_pkt = Ether()/IP()/TCP(flags="S")
        
        classbench_vm = STLScVmRaw([

                                    STLVmFlowVar(name="nw_src", value_list=self.nw_src, size=4, op="random"),
                                    STLVmWrFlowVar(fv_name="nw_src", pkt_offset= "IP.src"),

                                    STLVmFlowVar(name="nw_dst", value_list=self.nw_dst, size=4, op="random"),
                                    STLVmWrFlowVar(fv_name="nw_dst", pkt_offset= "IP.dst"),

                                    STLVmFlowVar(name="tp_src", value_list=self.tp_src, size=2, op="random"),
                                    STLVmWrFlowVar(fv_name="tp_src", pkt_offset="TCP.sport"),

                                    STLVmFlowVar(name="tp_dst", value_list=self.tp_dst, size=2, op="random"),
                                    STLVmWrFlowVar(fv_name="tp_dst", pkt_offset= "TCP.dport"),
                                    
                                    ],
                                    )

        pkt_a = STLPktBuilder(pkt=base_pkt/(10*'x'), vm=classbench_vm)

        return STLStream(packet=pkt_a, mode=STLTXCont())

    def get_streams (self, tunables, **kwargs):
        parser = argparse.ArgumentParser(description='Argparser for {}'.format(os.path.basename(__file__)), 
                                         formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        args = parser.parse_args(tunables)
        # create multiple streams
        return self.create_stream()


# dynamic load - used for trex console or simulator
def register():
    return STLS1()
