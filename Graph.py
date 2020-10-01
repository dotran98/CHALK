from matplotlib import pyplot as plt
from matplotlib.figure import Figure
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
import networkx as nx

class Graph(FigureCanvas):
    def __init__(self, system_list, parent=None):
        super(Graph, self).__init__(Figure())
        self.setParent(parent)
        [self.system_nodes, self.service_nodes] = self.collectNodes(system_list)
        self.figure = plt.figure()
        ax = plt.Axes(self.figure, [0., 0., 1., 1.])
        ax.set_axis_off()
        self.figure.add_axes(ax)
        self.canvas = FigureCanvas(self.figure)
        self.drawNetwork()

    def collectNodes(self, system_list):
        system_nodes = []
        service_nodes = []
        for system in system_list:
            inpt = 'System ' + str(system.SystemID), system.ip_address  # ID and IP
            # inpt = system.operatingSystem, system.ipAddress #OS and IP (not working)
            system_nodes.append(inpt)

            # collect the service nodes
            service_nodes.append(system.openPorts)
        return [system_nodes, service_nodes]

    def cleanseInput(list):
        clean = []
        xCounter = 0
        for x in list:
            clean.append([])
            temp1 = x
            for y in temp1:
                temp2 = y[0]
                clean[xCounter].append(temp2)
            xCounter += 1
        return clean

    def drawNetwork(self):
        G = nx.Graph()  # creates the graph object

        # adding the system nodes
        G.add_nodes_from(self.system_nodes)

        serviceList = cleanseInput(service_nodes)

        # loop through the services, one system at a time, each index in the service list is another system
        sys_count = 0
        for x in serviceList:
            tempList = x
            # for all the services being used by a system
            for y in tempList:
                G.add_edge(self.system_nodes[sys_count], y)
            sys_count = sys_count + 1

        # nx.draw(G, with_labels = True, size=300)

        pos = nx.spring_layout(G)

        nx.draw_networkx_nodes(G, pos, node_size=300, node_color='r')

        nx.draw_networkx_edges(G, pos)

        nx.draw_networkx_labels(G, pos, font_size=10, font_family='sans-serif')
