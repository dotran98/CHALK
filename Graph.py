from matplotlib import pyplot as plt
from matplotlib.figure import Figure
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
import networkx as nx

class Graph(FigureCanvas):
    def __init__(self, parent=None):
        super(Graph, self).__init__(Figure())
        self.setParent(parent)

        self.figure = plt.figure()
        ax = plt.Axes(self.figure, [0., 0., 1., 1.])
        ax.set_axis_off()
        self.figure.add_axes(ax)
        self.canvas = FigureCanvas(self.figure)
        G = nx.Graph()

        G.add_edge('PC 1', 'Server A', weight=0.1)
        G.add_edge('Database', 'Server B', weight=0.6)
        G.add_edge('Server A', 'Server B', weight=0.1)
        G.add_edge('PC 1', 'Server B', weight=0.6)

        # logic for whether an edge is small or large, later used to determine if an edge will be filled or dashed out
        elarge = [(u, v) for (u, v, d) in G.edges(data=True) if d['weight'] > 0.5]
        esmall = [(u, v) for (u, v, d) in G.edges(data=True) if d['weight'] <= 0.5]

        # positions for all nodes
        pos = nx.spring_layout(G)

        # nodes
        nx.draw_networkx_nodes(G, pos, node_size=900)

        # edges
        nx.draw_networkx_edges(G, pos, edgelist=elarge, width=3, edge_color='r')
        nx.draw_networkx_edges(G, pos, edgelist=esmall, width=3, alpha=0.5, edge_color='b', style='dashed')

        # labels
        nx.draw_networkx_labels(G, pos, font_size=10, font_family='sans-serif')