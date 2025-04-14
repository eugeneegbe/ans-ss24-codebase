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

#!/usr/bin/python

from mininet.topo import Topo
from mininet.link import TCLink

class BridgeTopo(Topo):
    "Creat a bridge-like customized network topology according to Figure 1 in the lab0 description."

    def __init__(self):

        Topo.__init__(self)

        # Add the hosts and Switches
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')
        h4 = self.addHost('h4')

        # Add the switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')

        # Do the linking
        self.addLink(h1, s1, cls=TCLink, bw=15, delay=10) # e1
        self.addLink(h2, s1, cls=TCLink, bw=15, delay=10) # e2
        self.addLink(s1, s2, cls=TCLink, bw=20, delay=45) # e5
        self.addLink(s2, h3, cls=TCLink, bw=15, delay=10) # e3
        self.addLink(s2, h4, cls=TCLink, bw=15, delay=10) # e4

topos = {'bridge': (lambda: BridgeTopo())}
