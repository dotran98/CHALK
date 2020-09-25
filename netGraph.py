# netGraph creates the graph of the network
import matplotlib.pyplot as plt
import networkx as nx
import CHALK_dataAnalysis as da

# the index of system_nodes correlates to the index of service_nodes
system_nodes = [] #contains a list of nodes which are systems
service_nodes = [] #each index is a nested array of services running on that system

# creates the list of system nodes and their corresponding service nodes
def collectNodes(systemList):
    for system in systemList:
        inpt = 'System ' + str(system.SystemID), system.ipAddress #ID and IP
        #inpt = system.operatingSystem, system.ipAddress #OS and IP (not working)
        system_nodes.append(inpt)

        #collect the service nodes
        service_nodes.append(system.openPorts)

#not yet complete
def cleanseInput():
    return null


def drawNetwork():
    G = nx.Graph() #creates the graph object

    # adding the system nodes
    G.add_nodes_from(system_nodes)

    # this is temporary service data, the data needs to come through to this file cleaner than it does from dataAnalysis 2
    tempServiceList = [['"21:ftp"', '"22:ssh"', '"25:smtp"', '"53:domain"', '"80:http"', '"110:pop3"', '"143:imap"', '"389:idap"', '"443:https"', '"464:kpasswd5"', '"465:smtps"', '"587:submission"', '"749:kerberos-adm"', '"993:imaps"', '"995:pop3s"', '"3306:mysql"', '"7025:vmsvc-2"'],
    ['"21:ftp"', '"22:ssh"', '"25:smtp"', '"53:domain"', '"80:http"', '"995:pop3s"', '"3306:mysql"', '"7025:vmsvc-2"'],
    ['"21:ftp"', '"22:ssh"', '"80:http"', '"995:pop3s"', '"3306:mysql"', '"7025:vmsvc-2"']]

    # loop through the services, one system at a time, each index in the service list is another system
    sys_count = 0
    for x in tempServiceList:
        tempList = x
        # for all the services being used by a system
        for y in tempList:
            G.add_edge(system_nodes[sys_count], y)
        sys_count = sys_count + 1

    #nx.draw(G, with_labels = True, size=300)

    pos = nx.spring_layout(G)

    nx.draw_networkx_nodes(G, pos, node_size=300, node_color='r')

    nx.draw_networkx_edges(G, pos)

    nx.draw_networkx_labels(G, pos, font_size=10, font_family='sans-serif')

    plt.title('Network Map')
    plt.axis('off')

    plt.show() #display graph

# this will be intergrated with the GUI, to make the graph interective
def showData(id):
    if system.SystemID == id:
        print('System ID: ' + str(system.SystemID))
        print('IP Address: ' + system.ipAddress)
        print('Operating System: ' + system.operatingSystem)
        print('Number of Potential Vulnerabilities: ' + str(system.numberVulnerabilities))

def main():
    da.analyseNmapData() # takes the data from the file using dataAnalysis2
    #da.checkSystems()    # checks this has been done correctly
    collectNodes(da.systemList)
    drawNetwork()

main()
