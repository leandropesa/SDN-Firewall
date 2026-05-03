from mininet.topo import Topo

DEF_NUM_SWITCHES = 3


class DynamicTopology(Topo):
    def build(self, number_switches=DEF_NUM_SWITCHES):
        number_switches = int(number_switches)

        s_left = self.addSwitch("s1")
        s_right = self.addSwitch("s{}".format(number_switches + 2))

        h1 = self.addHost("h1")
        h2 = self.addHost("h2")
        h3 = self.addHost("h3")
        h4 = self.addHost("h4")

        self.addLink(s_left, h1)
        self.addLink(s_left, h2)

        prev = s_left
        for i in range(2, number_switches + 2):
            s_mid = self.addSwitch("s{}".format(i))
            self.addLink(prev, s_mid)
            prev = s_mid

        self.addLink(prev, s_right)
        self.addLink(s_right, h3)
        self.addLink(s_right, h4)


topos = {
    "dynamicTopology": lambda n=DEF_NUM_SWITCHES: DynamicTopology(
        number_switches=int(n)
    )
}
