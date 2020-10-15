from matplotlib import pyplot as plt
from matplotlib.figure import Figure
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.backend_bases import MouseEvent
import networkx as nx

class Graph(FigureCanvas):

    def __init__(self, systemList, parent=None):
        super(Graph, self).__init__(Figure())
        self.setParent(parent)
        [self.system_nodes, self.service_nodes] = self.collectNodes(systemList)
        self.figure = plt.figure()
        ax = plt.Axes(self.figure, [0., 0., 1., 1.])
        #self.figure, ax = plt.subplots()
        ax.set_axis_off()
        self.figure.add_axes(ax)
        self.canvas = FigureCanvas(self.figure)
        self.node_positions = self.drawNetwork()

        # interactive nodes
        self.figure.canvas.mpl_connect('button_press_event', self.onClick)

    # implements the click functionality, when the user clicks it will check location of nodes
    def onClick(self, event):
        print('click detected')
        # if event.button == 1:
        #     print('you clicked a node')
        #     # check if the user is clicking within the area of a node
        #     for node in self.node_positions.values():
        #         if (event.xdata >= node[0]-0.05 & event.xdata <= node[0]+0.05 & event.ydata >= node[1]-0.05 & event.ydata <= node[1]+0.05):
        #             print('you clicked a node')
        #
        #
        #     #print('you pressed ')
        #     # check where the usr is clicking in relation to the position of the nodes
        # print('you pressed ', event.button, ' at ', event.xdata, ' and ', event.ydata)

    # collects all the info needed to display the nodes
    def collectNodes(self, systemList):
        system_nodes = []
        service_nodes = []
        for system in systemList:
            inpt = 'System ' + str(system.SystemID), system.ipAddress  # ID and IP
            # inpt = system.operatingSystem, system.ipAddress #OS and IP (not working)
            system_nodes.append(inpt)

            # collect the service nodes
            service_nodes.append(system.openPorts)
        return [system_nodes, service_nodes]

    # this function cleanses the input from dataAnalysis.py so that it is more readable
    # networkx can only handle hashed objects, so that data needs to be hashable
    def cleanseInput(self, list):
        clean = []
        xCounter = 0
        for x in list:
            clean.append([])
            temp1 = x[0]  # Tran added [0] next to x here
            for y in temp1:
                temp2 = y[0]
                clean[xCounter].append(temp2)
            xCounter += 1
        return clean

    def drawNetwork(self):
        G = nx.Graph()  # creates the graph object

        # adding the system nodes
        G.add_nodes_from(self.system_nodes)

        serviceList = self.cleanseInput(self.service_nodes)

        # loop through the services, one system at a time, each index in the service list is another system
        sys_count = 0
        for x in serviceList:
            tempList = x
            # for all the services being used by a system
            for y in tempList:
                G.add_node(y)

                G.add_edge(self.system_nodes[sys_count], y)
            sys_count = sys_count + 1

        # position layout for the nodes, edges and labels
        # pos is a dict which has keys as the node names and values as there coords
        # pos.values will return an array with the coords of node
        pos = nx.spring_layout(G)

        # draw the nodes on the graph
        nx.draw_networkx_nodes(G, pos, node_size=300, node_color='b')
        nx.draw_networkx_nodes(G, pos, nodelist = self.system_nodes, node_size=500, node_color='r')

        #draw the edges on the graph
        nx.draw_networkx_edges(G, pos)

        # draw the labels
        nx.draw_networkx_labels(G, pos, font_size=10, font_family='sans-serif')

        return pos
