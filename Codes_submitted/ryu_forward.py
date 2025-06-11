from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ipv4, in_proto, tcp
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types


class ryu_forward(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]


    def __init__(self, *args, **kwargs):
        super(ryu_forward, self).__init__(*args, **kwargs)
        self.mac_to_port= {}


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        set up default packetIn rule
        :param ev:
        :return:
        """
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow_default(datapath, 0, match, actions)


    def add_flow_default(self, datapath, priority, match, actions, buffer_id=None):
        """
        add flow without timeout
        :param datapath:
        :param priority:
        :param match:
        :param actions:
        :param buffer_id:
        :return:
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath,
                                    buffer_id=buffer_id,
                                    priority=priority,
                                    match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath,
                                    priority=priority,
                                    match=match,
                                    instructions=inst)
        datapath.send_msg(mod)


    def add_flow_specific(self, datapath, priority, match, actions, buffer_id=None):
        """
        add flow with timeout
        :param datapath:
        :param priority:
        :param match:
        :param actions:
        :param buffer_id:
        :return:
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath,
                                    buffer_id=buffer_id,
                                    priority=priority,
                                    match=match,
                                    instructions=inst,
                                    idle_timeout=5)
        else:
            mod = parser.OFPFlowMod(datapath=datapath,
                                    priority=priority,
                                    match=match,
                                    instructions=inst,
                                    idle_timeout=5)
        datapath.send_msg(mod)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """
        packetIn handling process
        :param ev:
        :return:
        """
        # extract packet
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt = packet.Packet(msg.data)
        # get physical port
        in_port = msg.match['in_port']
        # get ethernet data
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        src = eth.src
        dst = eth.dst
        # learn mac_port pair
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port
        # packetIn logger
        self.logger.info(f"\nPacket received.\n"
                         f"Switch ID: {dpid}\n"
                         f"Source MAC address: {src}\n"
                         f"Destination MAC address: {dst}\n"
                         f"Source port: {in_port}")
        # search for output physical port
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
        # define packetOut action
        actions = [parser.OFPActionOutput(out_port)]
        # formulate flow table rule
        if out_port != ofproto.OFPP_FLOOD:
            # ARP
            if eth.ethertype == ether_types.ETH_TYPE_ARP:
                self.logger.info(f"\nAdd ARP flow table rule\n"
                                 f"Message type: {ether_types.ETH_TYPE_ARP}\n"
                                 f"Source MAC address: {src}\n"
                                 f"Destination MAC address: {dst}\n"
                                 f"Source port: {in_port}")
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP,
                                        in_port=in_port,
                                        eth_dst=dst,
                                        eth_src=src)
            # IP
            if eth.ethertype == ether_types.ETH_TYPE_IP:
                ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
                ip_src = ipv4_pkt.src
                ip_dst = ipv4_pkt.dst
                ip_protocol = ipv4_pkt.proto
                # ICMP
                if ip_protocol == in_proto.IPPROTO_ICMP:
                    self.logger.info(f"\nAdd ICMP flow table rule\n"
                                     f"Message type: {ether_types.ETH_TYPE_IP}\n"
                                     f"IP protocol: {ip_protocol}\n"
                                     f"Source IP address: {ip_src}\n"
                                     f"Destination IP address: {ip_dst}\n"
                                     f"Source port: {in_port}")
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                            ip_proto=ip_protocol,
                                            ipv4_src=ip_src,
                                            ipv4_dst=ip_dst,
                                            in_port=in_port)
                # TCP
                elif ip_protocol == in_proto.IPPROTO_TCP:
                    tcp_pkt = pkt.get_protocol(tcp.tcp)
                    tcp_src_port = tcp_pkt.src_port
                    tcp_dst_port = tcp_pkt.dst_port
                    self.logger.info(f"\nAdd TCP flow table rule\n"
                                     f"Message type: {ether_types.ETH_TYPE_IP}\n"
                                     f"IP protocol: {ip_protocol}\n"
                                     f"Source IP address: {ip_src}\n"
                                     f"Destination IP address: {ip_dst}\n"
                                     f"Source TCP port: {tcp_src_port}\n"
                                     f"Destination TCP port: {tcp_dst_port}")
                    match = parser.OFPMatch(
                        eth_type=ether_types.ETH_TYPE_IP,
                        ip_proto=ip_protocol,
                        ipv4_src=ip_src,
                        ipv4_dst=ip_dst,
                        tcp_src=tcp_src_port,
                        tcp_dst=tcp_dst_port)
            # invoke add flow method
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow_specific(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow_specific(datapath, 1, match, actions)
        # check msg data
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        # define output packet
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=msg.buffer_id,
                                  in_port=in_port,
                                  actions=actions,
                                  data=data)
        # packetOut
        datapath.send_msg(out)
        # packetOut logger
        self.logger.info(f"\nPacket out.\n"
                         f"Destination MAC address: {dst}\n"
                         f"Destination port: {out_port}")