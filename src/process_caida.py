import scapy.all as scpy
import argparse


def main(args):
    print(args)
    pkts = scpy.PcapReader(args["pcap"])
    count = 0
    for i, pkt in enumerate(pkts, 1):
        if i % 10000 == 0:
            print("On packet {0}".format(i))
    print("Total Packets = {0}".format(i))


if __name__ == "__main__":
    CLI = argparse.ArgumentParser()
    # CLI.add_argument("--list", nargs="*", type=int)
    CLI.add_argument("--pcap", type=str)
    args = vars(CLI.parse_args())
    main(args)