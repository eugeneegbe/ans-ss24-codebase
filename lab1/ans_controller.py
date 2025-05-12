"""
 Copyright 2024 Computer Networks Group @ UPB

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

      https://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 """

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3

from ryu.lib.packet import packet, ethernet, arp, ipv4, ether_types
from ryu.ofproto import ether

class LearningSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LearningSwitch, self).__init__(*args, **kwargs)

        # Here you can initialize the data structures you want to keep at the controller
        self.mac_to_port = {}

        # Router specific info
        self.port_to_own_mac = {
            1: "00:00:00:00:01:01",
            2: "00:00:00:00:01:02",
            3: "00:00:00:00:01:03"
        }
        # Router port (gateways) IP addresses assumed by the controller
        self.port_to_own_ip = {
            1: "10.0.1.1",
            2: "10.0.2.1",
            3: "192.168.1.1"
        }

        # ARP table ip_mac & ip port 
        self.ip_to_mac = {}
        self.ip_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        
        datapath = ev.msg.datapath
        of_proto = datapath.ofproto
        of_parser = datapath.ofproto_parser

        # Initial flow entry for matching misses
        match = of_parser.OFPMatch()
        actions = [of_parser.OFPActionOutput(of_proto.OFPP_CONTROLLER,
                                          of_proto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    # Add a flow entry to the flow-table
    def add_flow(self, datapath, priority, match, actions):
        of_proto = datapath.ofproto
        of_parser = datapath.ofproto_parser

        # Construct flow_mod message and send it
        inst = [of_parser.OFPInstructionActions(of_proto.OFPIT_APPLY_ACTIONS, actions)]
        mod = of_parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    # Handle the packet_in event
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        of_proto = datapath.ofproto
        of_parser = datapath.ofproto_parser

        # create packet from message data
        pkt = packet.Packet(msg.data)

        # extract the src
        # dest mac addresses from the ethernet protocol layer
        eth = pkt.get_protocol(ethernet.ethernet)
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        in_port = msg.match['in_port']


        self.logger.info('switch Learnt Mac and ports %s', self.mac_to_port)
        self.logger.info('Learnt gateway Ips port match %s', self.ip_to_mac)
        self.logger.info('Learnt IP -> MAC %s', self.ip_to_mac)

        # If it's a switch (s1 or s2): act as learning switch
        # Use datapath 1 and 2
        if dpid in [1, 2]:
            self.mac_to_port.setdefault(dpid, {})
            self.mac_to_port[dpid][src] = in_port

            # Case: dst mac is in mac_to_port
            # we get the outport
            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]

            # Else we flood
            else:
                out_port = of_proto.OFPP_FLOOD

            # we then add a flow
            actions = [of_parser.OFPActionOutput(out_port)]
            match = of_parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self.add_flow(datapath, 1, match, actions)


        # Case: Router (s3): act as IP router
        elif dpid == 3:
            
            # Check if its an Adress resolution (ARP)
            if eth.ethertype == ether_types.ETH_TYPE_ARP:
                arp_pkt = pkt.get_protocol(arp.arp)

                # ARP - REQUEST
                if arp_pkt.opcode == arp.ARP_REQUEST:
                    self.handle_arp_request(datapath, in_port, eth, arp_pkt)

                    return

                # ARP - REPLY
                # Keep track of IP and MAC for ARP REPLY
                elif arp_pkt.opcode == arp.ARP_REPLY:
                    self.ip_to_mac[arp_pkt.src_ip] = arp_pkt.src_mac
                    self.ip_to_port[arp_pkt.src_ip] = in_port
                    return

            # Packet is an IP packet
            elif eth.ethertype == ether_types.ETH_TYPE_IP:
                ip_pkt = pkt.get_protocol(ipv4.ipv4)
                src_ip = ip_pkt.src
                dst_ip = ip_pkt.dst
                self.ip_to_mac[src_ip] = src
                self.ip_to_port[src_ip] = in_port

                # block ext (192.168.1.x) from pinging internal hosts
                if src_ip.startswith("192.168.1.") and dst_ip.startswith("10.0."):
                    return

                # block ext <-> ser for TCP/UDP
                if ("192.168.1." in src_ip and dst_ip == "10.0.2.2") or ("192.168.1." in dst_ip and src_ip == "10.0.2.2"):
                    return

                # Find out port, src and dst mac to send ip packet
                if dst_ip in self.ip_to_mac and dst_ip in self.ip_to_port:
                    out_port = self.ip_to_port[dst_ip]
                    dst_mac = self.ip_to_mac[dst_ip]
                    src_mac = self.port_to_own_mac[out_port]

                    actions = [
                        of_parser.OFPActionSetField(eth_src=src_mac),
                        of_parser.OFPActionSetField(eth_dst=dst_mac),
                        of_parser.OFPActionOutput(out_port)
                    ]
                    match = of_parser.OFPMatch(
                        eth_type=ether_types.ETH_TYPE_IP,
                        ipv4_dst=dst_ip,
                        ipv4_src=src_ip
                    )
                    self.add_flow(datapath, 10, match, actions)


    def handle_arp_request(self, datapath, port, eth, arp_pkt):
        """
            
        """
        of_proto = datapath.ofproto
        of_parser = datapath.ofproto_parser

        target_ip = arp_pkt.dst_ip
        if target_ip not in self.port_to_own_ip.values():
            return

        for p, ip in self.port_to_own_ip.items():
            if ip == target_ip:
                target_mac = self.port_to_own_mac[p]

        # Create a new packet to be used as reply
        arp_reply = packet.Packet()
        arp_reply.add_protocol(ethernet.ethernet(
            ethertype=ether.ETH_TYPE_ARP,
            src=target_mac,
            dst=eth.src
        ))
        arp_reply.add_protocol(arp.arp(
            opcode=arp.ARP_REPLY,
            src_mac=target_mac,
            src_ip=target_ip,
            dst_mac=eth.src,
            dst_ip=arp_pkt.src_ip
        ))
        arp_reply.serialize()

        actions = [of_parser.OFPActionOutput(port)]

        # We will send the packet to the original requester
        out = of_parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=of_proto.OFP_NO_BUFFER,
                                  in_port=of_proto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=arp_reply.data)
        datapath.send_msg(out)
