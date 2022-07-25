from trex.astf.api import *
import argparse

my_message='This is a message from Our Company'
message=''
for x in range(1000):
    message=my_message+message


class Prof1():
    def __init__(self):
        pass  # tunables

    def create_profile(self,size,loop,mss):

        # client commands
        prog_c = ASTFProgram()        
        prog_c.connect()


        prog_c.send_chunk(message,205,0)
        prog_c.set_send_blocking(False)
        prog_c.send_chunk(message,205,0)
        prog_c.set_send_blocking(True)



        prog_s = ASTFProgram()
        prog_s.recv(len(my_message)*1000) # I do not need this since our test is a single-interface where TRex connects (prog_c) to another app which is not TRex



        info = ASTFGlobalInfo()

        info.tcp.mss=1400
        info.tcp.initwnd = 20  # start big
        #info.tcp.no_delay = 1   #1i is  to get fast feedback for acks
        #info.tcp.delay_ack_msec = 50
        info.tcp.rxbufsize = 1024*1024  # 1MB window
        info.tcp.txbufsize = 1024*1024
        info.tcp.no_delay_counter=65533  #number of bytes to
        info.tcp.do_rfc1323 =0 # no time-stamps


        # ip generator
        ip_gen_c = ASTFIPGenDist(ip_range=["192.168.37.1", "192.168.37.1"], distribution="seq")
        ip_gen_s = ASTFIPGenDist(ip_range=["192.168.37.132", "192.168.37.132"], distribution="seq")
        ip_gen = ASTFIPGen(glob=ASTFIPGenGlobal(ip_offset="0.0.0.0"),
                           dist_client=ip_gen_c,
                           dist_server=ip_gen_s)


        # template
        temp_c = ASTFTCPClientTemplate(program=prog_c,  ip_gen=ip_gen, cps=60,limit=60, cont=True)
        temp_s = ASTFTCPServerTemplate(program=prog_s)  # using default association
        template = ASTFTemplate(client_template=temp_c, server_template=temp_s)

        # profile
        profile = ASTFProfile(default_ip_gen=ip_gen,
                              templates=template,                              
                              default_c_glob_info=info,
                              default_s_glob_info=info)

        return profile

    def get_profile(self, tunables, **kwargs):
        parser = argparse.ArgumentParser(description='Argparser for {}'.format(os.path.basename(__file__)),
                                         formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        parser.add_argument('--size',
                            type=int,
                            default=100,
                            help='size is in KB for download chuck')
        parser.add_argument('--loop',
                            type=int,
                            default=10,
                            help='how many chunks')
        parser.add_argument('--mss',
                            type=int,
                            default=0,
                            help='the mss of the traffic.')
        args = parser.parse_args(tunables)

        size = args.size
        loop = args.loop
        mss = args.mss
        return self.create_profile(size,loop,mss)


def register():
    return Prof1()
