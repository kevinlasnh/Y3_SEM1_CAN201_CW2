from mininet.cli import CLI
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch, Host
from mininet.term import makeTerm


def myTopo():
    # create net
    net = Mininet(autoSetMacs=False, build=False, ipBase='10.0.1.0/24')

    # add remote controller
    SDN_Controller = net.addController('c1', RemoteController)

    # add host
    Client = net.addHost('client', cls=Host, defaultRoute=None)
    Server1 = net.addHost('server_1', cls=Host, defaultRoute=None)
    Server2 = net.addHost('server_2', cls=Host, defaultRoute=None)

    # add switch
    SDN_Switch = net.addSwitch('s1', cls=OVSKernelSwitch, failMode='secure')

    # add link
    net.addLink(Client, SDN_Switch)
    net.addLink(Server1, SDN_Switch)
    net.addLink(Server2, SDN_Switch)

    # network build
    net.build()

    # assign IP address to interface of hosts
    Client.setIP(intf='client-eth0', ip='10.0.1.5/24')
    Server1.setIP(intf='server_1-eth0', ip='10.0.1.2/24')
    Server2.setIP(intf='server_2-eth0', ip='10.0.1.3/24')

    # assign mac to each interface
    Client.setMAC(intf="client-eth0", mac="00:00:00:00:00:03")
    Server1.setMAC(intf="server_1-eth0", mac="00:00:00:00:00:01")
    Server2.setMAC(intf="server_2-eth0", mac="00:00:00:00:00:02")

    # network start
    net.start()

    # start xterm
    net.terms += makeTerm(Client)
    net.terms += makeTerm(Server1)
    net.terms += makeTerm(Server2)
    net.terms += makeTerm(SDN_Switch)
    net.terms += makeTerm(SDN_Controller)

    # CLI mode running
    CLI(net)
    net.stop()


if __name__ == '__main__':
    myTopo()