import socket
from tkinter import *
from threading import Thread, Event
from _thread import *
from threading import *

# classes for different packets
from net_types import *

# global list of packets
packets = []

# global function for returning source & destination 
def get_ipv4_src_dest(packet):
    ipv4 = IPv4(packet.data)
    return ipv4.src, ipv4.target

# returns protocol type
def get_ipv4_protocol(packet):
        ipv4 = IPv4(packet.data)

        if ipv4.proto == 1:
            return 'ICMP'

        elif ipv4.proto == 6:
            tcp = TCP(ipv4.data)

            if len(tcp.data) > 0:
                return 'HTTP'
            return 'TCP'

        elif ipv4.proto == 17:
            return 'UDP'

        else:
            return 'OTHER'

# returns the respective color for the GUI
def get_color_code(protocol):

    if protocol == 'ICMP':
        return '#fbb5df'

    if protocol == 'HTTP':
        return '#80e6ff'

    if protocol == 'TCP':
        return '#29fbc1'
        
    if protocol == 'UDP':
        return '#448888'

    if protocol == 'OTHER':
        return '#fff6a7'

    else:
        return '#fff6a7'


# tkinter GUI for the packet analyzer
class Sniffer_GUI():

    def __init__(self, root):

        self.root = root
        self.filter = StringVar()
        self.root.title('Packet Sniffer')
        self.root.geometry("630x500")
        self.total_packets = 0
        self.packet_button = []
        self.packet_btn_list = []

        self.create_GUI()

    def create_GUI(self):

        self.start_capture_button = Button(self.root, text="START CAPTURE", width=40, height=1, command=self.start_capture, borderwidth=1, relief="solid")
        self.start_capture_button.place(x=15, y=10, height=30)

        self.stop_capture_button = Button(self.root, text="STOP CAPTURE", width=25, height=1, command=self.stop_capture, borderwidth=1, relief="solid")
        self.stop_capture_button.place(x=380, y=10, height=30)

        filter_label = Label(self.root, text="Filter ", font=("Arial", 15))
        filter_label.place(x=15, y=60)

        self.entry_box_filter = Entry(self.root, textvariable=self.filter, width=35, bg="white", borderwidth=2, relief="groove")
        self.entry_box_filter.place(x=75, y=60, height=30)

        self.apply_filter_button = Button(self.root, text="Apply Filter", width=10, height=1, command=self.apply_filter, borderwidth=1, relief="solid")
        self.apply_filter_button.place(x=380, y=60, height=30)

        self.remove_filter_button = Button(self.root, text="Remove Filter", width=10, height=1, command=self.remove_filter, borderwidth=1, relief="solid")
        self.remove_filter_button.place(x=500, y=60, height=30)

        capture_feed_label = Label(self.root, text="Capture Feed", font=("Arial", 13))
        capture_feed_label.place(x=15, y=100)

        self.reply_frame = Frame(self.root, borderwidth=1, relief="solid")
        self.reply_frame.place(x=15, y=130)

        self.reply_canvas = Canvas(self.reply_frame, width=580, height=350)
        self.reply_canvas.pack(side=LEFT, fill=BOTH, expand=YES)

        reply_scrollbar = Scrollbar(self.reply_frame, orient=VERTICAL, command=self.reply_canvas.yview)
        reply_scrollbar.pack(side=RIGHT, fill=Y, pady=10)

        self.sframe = Frame(self.reply_canvas, width=580, height=340)
        self.sframe.pack()
        self.sframe.bind("<Configure>", lambda e: self.reply_canvas.configure(scrollregion=self.reply_canvas.bbox("all")))

        self.reply_canvas.configure(yscrollcommand=reply_scrollbar.set)
        self.reply_canvas.bind('<Configure>', lambda e: self.reply_canvas.configure(scrollregion=self.reply_canvas.bbox("all")))

        self.reply_canvas.create_window((0,0), window=self.sframe, anchor="nw")

    # function to start the sniffer thread
    def start_capture(self):
        print('starting capture')

        self.start_capture_button['state'] = 'disabled'
        self.stop_thread = Event()

        self.sniffer = PacketSniffer(guiobject=self)
        self.sniffer_thread = Thread(target=self.sniffer.sniff)
        self.sniffer_thread.start()


    # function to add the packet to GUI
    def add_packet_button(self, protocol, src, dest, packet):

        global get_color_code

        color = get_color_code(protocol)

        if self.filter.get() == '':
            self.total_packets = len(self.packet_button) + 1
            btn = Button(self.sframe, text=f'{self.total_packets}\t Source:{src}\t Destination: {dest}\t Protocol: {protocol}', width=68, bg=color, command=lambda: self.expand_packet(btn), borderwidth=1, relief="solid", anchor="w")
            btn.pack(padx=0, pady=2)
            self.packet_button.append(btn)
            self.packet_btn_list.append(packet)


        elif self.filter.get().upper() == protocol:
            self.total_packets = len(self.packet_button) + 1
            btn = Button(self.sframe, text=f'{self.total_packets}\t Source:{src}\t Destination: {dest}\t Protocol: {protocol}', width=68, bg=color, command=lambda: self.expand_packet(btn), borderwidth=1, relief="solid", anchor="w")
            btn.pack(padx=0, pady=2)
            self.packet_button.append(btn)
            self.packet_btn_list.append(packet)


    # function to expand the packet for analyzing
    def expand_packet(self, btn):

        global packets
        btn_num = int(str(btn).split('button')[-1] or '1')
        pkt = self.packet_btn_list[btn_num-1]

        newWindow = Toplevel(self.root)
        newWindow.title("IPv4 Packet")
        newWindow.geometry("500x600")

        ipv4 = IPv4(pkt.data)
        Label(newWindow, text ='Version: {}'.format(ipv4.version)).pack(padx=10, anchor="w")
        Label(newWindow, text ='Header Length: {}'.format(ipv4.header_length)).pack(padx=10, anchor="w")
        Label(newWindow, text ='TTL: {}'.format(ipv4.ttl)).pack(padx=10, anchor="w")

        Label(newWindow, text ='Protocol: {}'.format(ipv4.proto)).pack(padx=10, anchor="w")
        Label(newWindow, text ='Source: {}'.format(ipv4.src)).pack(padx=10, anchor="w")
        Label(newWindow, text ='Target: {}'.format(ipv4.target)).pack(padx=10, anchor="w")


        # ICMP
        if ipv4.proto == 1:
            icmp = ICMP(ipv4.data)

            Label(newWindow, text ='ICMP Packet').pack(padx=10, pady=10, anchor="w")
            Label(newWindow, text ='Type: {}'.format(icmp.type)).pack(padx=10, anchor="w")
            Label(newWindow, text ='Code: {}'.format(icmp.code)).pack(padx=10, anchor="w")
            Label(newWindow, text ='Checksum: {},'.format(icmp.checksum)).pack(padx=10, anchor="w")
            Label(newWindow, text ='ICMP Data:').pack(padx=10, pady=10, anchor="w")

            data = format_multi_line(icmp.data)
            Label(newWindow, text =data).pack(padx=10, pady=10, anchor="w")

        # TCP
        elif ipv4.proto == 6:
            tcp = TCP(ipv4.data)


            Label(newWindow, text ='TCP Segment:').pack(padx=10, pady=10, anchor="w")
            Label(newWindow, text ='Source Port: {}'.format(tcp.src_port)).pack(padx=10, anchor="w")
            Label(newWindow, text ='Destination Port: {}'.format(tcp.dest_port)).pack(padx=10, anchor="w")
            Label(newWindow, text ='Sequence: {}'.format(tcp.sequence)).pack(padx=10, anchor="w")
            Label(newWindow, text ='Acknowledgment: {}'.format(tcp.acknowledgment)).pack(padx=10, anchor="w")

            Label(newWindow, text ='Flags:').pack(padx=10, pady=10, anchor="w")
            Label(newWindow, text ='URG: {}, ACK: {}, PSH: {}'.format(tcp.flag_urg, tcp.flag_ack, tcp.flag_psh)).pack(padx=10, anchor="w")
            Label(newWindow, text ='RST: {}, SYN: {}, FIN:{}'.format(tcp.flag_rst, tcp.flag_syn, tcp.flag_fin)).pack(padx=10, anchor="w")

            if len(tcp.data) > 0:

                # HTTP
                if tcp.src_port == 80 or tcp.dest_port == 80:
                    Label(newWindow, text ='HTTP Data:').pack(padx=10,pady=10, anchor="w")
                    try:
                        http = HTTP(tcp.data)
                        http_info = str(http.data).split('\n')
                        for line in http_info:
                            Label(newWindow, text=str(line)).pack(padx=10, anchor="w")
                    except:
                        data = format_multi_line(tcp.data)
                        Label(newWindow, text =data).pack(padx=10, pady=10, anchor="w")
                else:
                    Label(newWindow, text ='TCP Data:').pack(padx=10, pady=10, anchor="w")
                    data = format_multi_line(tcp.data)
                    Label(newWindow, text =data).pack(padx=10, pady=10, anchor="w")


        # UDP
        elif ipv4.proto == 17:
            udp = UDP(ipv4.data)

            Label(newWindow, text='UDP Segment').pack(padx=10,pady=10, anchor="w")
            Label(newWindow, text='Source Port: {}'.format(udp.src_port)).pack(padx=10, anchor="w")
            Label(newWindow, text='Destination Port: {}'.format(udp.dest_port)).pack(padx=10, anchor="w")
            Label(newWindow, text='Length: {}'.format(udp.dest_port)).pack(padx=10, anchor="w")
            Label(newWindow, text='its udp').pack(padx=10, anchor="w")

        # Other IPv4
        else:
            Label(newWindow, text= 'Other IPv4 Data:').pack(padx=10,pady=10, anchor="w")
            data = format_multi_line(ipv4.data)
            Label(newWindow, text =data).pack(padx=10, pady=10, anchor="w")


    # function to apply the filter
    def apply_filter(self):
        global packets, get_ipv4_protocol, get_ipv4_protocol

        self.clear_scrollbar()
        filter = self.filter.get().upper()

        for packet in packets:
            proto, pkt = packet

            if proto == filter:
                src, dest = get_ipv4_src_dest(pkt)
                self.add_packet_button(get_ipv4_protocol(pkt), src, dest, pkt)
        
        print('filter applied')


    def clear_scrollbar(self):
        while len(self.packet_button) > 0:
            packet = self.packet_button.pop()
            packet.destroy()


    # function to remove the filter
    def remove_filter(self):

        self.entry_box_filter.delete(0, END)
        self.clear_scrollbar()

        for packet in packets:
            proto, pkt = packet

            src, dest = get_ipv4_src_dest(pkt)
            self.add_packet_button(get_ipv4_protocol(pkt), src, dest, pkt)
        
        print('Filter Removed')

    # function to stop the sniffer 
    def stop_capture(self):
        print('stop capture')



# Sniffer Class to implement the sniffer
class PacketSniffer():

    def __init__(self, guiobject=None):
        self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        self.pcap_capture = Pcap('capture.pcap')
        self.packets = []
        self.guiobj = guiobject


    # function to recieve the raw packets
    def sniff(self):
        while True:
            try:
                raw_data, addr = self.socket.recvfrom(65535)
                self.pcap_capture.write(raw_data)
                eth = Ethernet(raw_data)

                # IPv4
                if eth.proto == 8:
                    self.update_packet_list(eth)
                
                # Other Ethernet Data
                else:
                    self.update_packet_list(eth, True)

            except KeyboardInterrupt:
                print('\nSaving the capture file')
                self.pcap_capture.close()
                return

    # function to update the global packets list
    def update_packet_list(self, packet, ethernet_data=False):
        global packets, get_ipv4_src_dest, get_ipv4_protocol

        if not ethernet_data:
            src, dest = get_ipv4_src_dest(packet)
            packets.append((get_ipv4_protocol(packet), packet))
            self.guiobj.add_packet_button(get_ipv4_protocol(packet), src, dest, packet)

        else:
            src, dest = '', ''
            packets.append(('ETHERNET DATA', packet))
            self.guiobj.add_packet_button('ETHERNET DATA', src, dest, packet)


# main driver function
if __name__ == "__main__":
    root = Tk()
    gui = Sniffer_GUI(root)
    root.mainloop()
