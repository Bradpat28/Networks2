"""Custom topology example

Two directly connected switches plus a host for each switch:

   host --- switch --- switch --- host

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo

class MyTopo( Topo ):
    "Simple topology example."

    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )


        # Add hosts and switches
        leftHost = self.addHost( 'h1' )
        rightHost = self.addHost( 'h2' )
        midHost = self.addHost( 'h3' )
        centHost = self.addHost( 'h4' )

        leftSwitch = self.addSwitch( 's1' )
        rightSwitch = self.addSwitch( 's2' )
        midSwitch = self.addSwitch( 's3' )
        centSwitch = self.addSwitch( 's4' )

        # Add links

        self.addLink( leftSwitch, rightSwitch )
        self.addLink( rightSwitch, midSwitch)
        self.addLink( midSwitch, centSwitch )
        self.addLink( centSwitch, leftSwitch )

        self.addLink( leftHost, leftSwitch )
        self.addLink( rightSwitch, rightHost )
        self.addLink( midSwitch, midHost )
        self.addLink( centSwitch, centHost )



topos = { 'mytopo': ( lambda: MyTopo() ) }
