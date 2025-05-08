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

from ryu.lib.packet import packet, ethernet, ethernet, arp


class LearningSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LearningSwitch, self).__init__(*args, **kwargs)

        # Here you can initialize the data structures you want to keep at the controller
        self.data_plane = {}
        self.known_ips = {}


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Initial flow entry for matching misses
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    # Add a flow entry to the flow-table
    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Construct flow_mod message and send it
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    # Handle the packet_in event
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath

        of_proto = datapath.ofproto
        of_parser = datapath.ofproto_parser
        dp_id = datapath.id
        source_port = msg.match['in_port']
    
        # create a packet using the event raw data
        pkt = packet.Packet(msg.data)
        pkt_header = pkt.get_protocols(ethernet.ethernet)

        try:
            ethernet_test = pkt_header[0]

        except:
            pass


        # TODO: Check if request header has 'arp' key
        if ethernet_test.ethertype == 2054:
            arp_info = pkt.get_protocols(arp.arp)[0]
            src_ip = arp_info.src_ip
            dst_ip = arp_info.dst_ip

            self.logger.info("arp packet info: %s", arp_info)
            self.known_ips.setdefault(dp_id, "")
            self.known_ips[dp_id] = dst_ip
            
            # Logg info for verification
            self.logger.info('ARP packket in from %s to %s line %s', src_ip, dst_ip, dp_id)
            
            if self.known_ips[dp_id] == dst_ip:
                new_dest_ip = dst_ip

            else:
                self.logger.info('destingation subnet not found so flooding ->>')
                new_dest_ip = of_proto.OFPP_FLOOD

            self.logger.info('ip to be formed', new_dest_ip)


            # In every case we create a flow
            actions = of_proto.OFPP_NORMAL

            if new_dest_ip != of_proto.OFPP_FLOOD:
                match = of_parser.OFPMatch(ipv4_src=src_ip)
                self.add_flow(datapath, 1, match, actions)
            else:
                match = of_parser.OFPMatch()
                self.add_flow(datapath, 0, match, actions)

        else:
            # no: check dest_mac in data_plane:

            source_port = msg.match['in_port']
            # get ethernet header
            eth_header = pkt.get_protocols(ethernet.ethernet)[0]

            # source and destination macs
            source_mac = eth_header.src
            dest_mac = eth_header.dst

            # Add a new structure for the dataplane entries
            self.data_plane.setdefault(dp_id, {})
            
            # Logg info for verification
            self.logger.info('Incoming packket in data path %s from %s to %s in_port %s',
                              dp_id, source_mac, dest_mac, source_port)
            
            # assign the inport of the source switch in datapatch
            # self-learning - avoid flooding
            self.data_plane[dp_id][source_mac] = source_port
            
            if dest_mac in self.data_plane[dp_id]:
                dest_port = self.data_plane[dp_id][dest_mac]

            else:

                self.logger.info('destingation mac not found back to controller ->>')
                dest_port = of_proto.OFPP_FLOOD

            # We have a record for the destination so we create an action
            actions = [of_parser.OFPActionOutput(dest_port)]

            # we are not flooding so we implement a soruce port match for the switch
            # and set its priority
            if dest_port != of_proto.OFPP_FLOOD:
                match = of_parser.OFPMatch(in_port=source_port)
                self.add_flow(datapath, 1, match, actions)
            else:
                match = of_parser.OFPMatch()
                self.add_flow(datapath, 0, match, actions)

        
        self.logger.info("known macs %s", self.data_plane)
        self.logger.info("known ips %s", self.known_ips)