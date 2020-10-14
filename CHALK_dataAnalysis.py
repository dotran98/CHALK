import csv
import nmap
import re

# Global variables
filename = "result.csv"
systemList = []
scanBoolean = True

# This is the basis for each system record that is found in the results file and
# represents a single system found on the network.
class systemObj:
    SystemID = 0
    ipAddress = ""
    operatingSystem = ""
    shortPorts = []
    openPorts = []
    numOpenPorts = 0
    openPortPercent = 0
    systemRanking = 0
    vulnerabilityPercent = 0.0
    numberVulnerabilities = 0
    vulnerabilities = []

# This function uses a regex pattern to pull the IP Address out of a row in the csv file.
# It is called by the dataAnalysis() function when dealing with both Nmap and vulnerability
# rows of data as required.
# Input: The required csv row is passed to the function.
# Ouput: Once the IP Address has been recorded, it is returned as a string.
def getIpAddress(rowString):
    ipAddress =""
    regex = '\d{1,3}[.]\d{1,3}[.]\d{1,3}[.]\d{1,3}'
    ipAddress = re.findall(regex, rowString)
    return str(ipAddress[0])

# This function calculates the SystemID attribute for a system object
# when it is created. A FOR loop is used to iterated through the known
# systems and find the largest SystemID value.
# Input: There is no variable input for the function, the global variable
# systemList is used to access each system object that has been created.
# Output: One is added to the highest SystemID value that was found.
def calcSystemId():
    highestId = 0
    if not systemList:
        highestId = -1
    for system in systemList:
        x = system.SystemID
        if x > highestId:
            highestId = x
    return highestId + 1

# This function stores a record (as a list) of all the open ports that are
# reported in a csv Nmap row for a particular system. The row is split by the
# char } to enable easier access to the required data, which is stored as a list.
# After the split, each list entry is searched for the regex pattern which and
# stored if a port is found.
# This is called by the analyseData() function when processing Nmap result rows.
# Input: The required csv row is passed to the function.
# Output: A list of ports in the format [Port Number, Port Name, Raw Data] for
# each port entry in the list.
def getPorts(rowString):
    regex = '[0-9]+[:][ ]'
    ports = []
    port = []
    temp = rowString.split("}")
    portName = ''
    for e in temp:
        x = str(e)
        if re.search(regex, x):
            a = str(re.findall(regex, x))
            port.append(a.replace(": ", "").replace("'", "").replace("]", "").replace("[", ""))
            charCount = 0
            portName = ''
            # The FOR loop is used to ensure that only the required information is stored for
            # each of the ports  found.
            for c in x:
                if c == ',':
                    charCount = charCount + 1
                if charCount == 4:
                    break
                if charCount == 3:
                        portName = portName + c
            # Append port number.
            port.append(portName.replace("'", "").replace("nam': ", "").replace(", ", ""))
            # Append port name.
            port.append(x.replace("tcp: {", "")[2:])
            # Append raw data for the port.
            ports.append(port)
            port = []
    return ports

# This function checks if a system with a passed IP Address is currently recorded in the
# systemList global variable.
# It is called by the analyseData() function when creating new system objects to ensure
# that there is no duplication of information.
# Input: An IP Address is passed to the function.
# Output: A boolean variable that indicates if a system with passed IP Address already
# exists or not.
def systemCheck(ipAddress):
    sys = False
    if len(systemList) > 0:
        for entry in systemList:
            if entry.ipAddress == ipAddress:
                sys = True
                print('System with Ip Address ' + ipAddress + ' already in the result list')
    return sys

# This function finds the list position of a system object in the global variable systemList
# with a particular IP Address. It is called by the analyseData() function when searching
# for a system to store its associated vulnerability information.
# Input: An IP Address is passed to the function.
# Output: A position value that is associated to the system that contains the IP Address.
def findPosition(ipAdd):
    position = 0
    for x in systemList:
        if int(x.ipAddress.replace(".", "")) - int(ipAdd) == 0:
            break
        else:
            position += 1
    return position

# This function is used to create a shorter open port record for a system without
# the raw data. It is called by the analyseData() function.
# Input: A list containing a systems open port information.
# Output: A shorter list with summary style port information. Each port entry
# in the list will have the format [portNumber:portName].
def shortList(lst):
    resList = []
    temp = lst[0]
    for x in temp:
        a = x[0]
        b = x[1]
        resList.append(str(a) + ":" + str(b).replace('name: ', ''))
    return resList

# This is the primary analysis function that deals with input data. It has no
# variable input or output and calls all other functions as required to create
# system objects populated with all relevant information.
def analyseData():
    global filename
    global systemList
    regex = '[0-9]+[:][ ]'

    # This enables the network scan code to be added here at a later date if required.
    # It determines either if the scan is run or data is accessed from a csv file.
    if scanBoolean == True:
        lineCount=0 #Remove this and write code to run the scanning code.
    else:
        filename = input("Enter the name of the file to import, including file path:")

    # Once the csv results file is open, relevant data is recorded in real time.
    with open(filename, mode='r') as csvFile:
        tempSystem = None
        ipAddress = ''
        ports = []
        rowCount = -1
        skipRows = False
        csvReader = csv.reader(csvFile)
        nmapRow = True
        recordFlag = 0
        vulnerableList = []
        tempAddress = ''
        for row in csvFile:
            rowCount += 1
            if re.search("VULNERABILITY SCAN RESULTS", row, re.IGNORECASE):
                nmapRow = False
            # If the row is bellow the NMAP SCAN RESULTS header but above the
            # VULNERABILITY SCAN RESULTS header in the csv.
            if nmapRow and re.search(regex, row):
                ipAddress = getIpAddress(row)
                # If system object doesnt already exist with the found ipAddress value.
                if not systemCheck(ipAddress):
                    tempSystem = systemObj()
                    tempSystem.ipAddress = ipAddress
                    tempSystem.SystemID = calcSystemId()
                    #tempSystem.operatingSystem = osDetect(ipAddress)
                    ports.append(getPorts(row))
                    tempSystem.openPorts = ports
                    tempSystem.shortPorts = shortList(tempSystem.openPorts)
                    tempSystem.numOpenPorts = len(tempSystem.shortPorts)
                    systemList.append(tempSystem)
                    print('System with IP Address: ' + ipAddress + ' added to the results list.')
                    ports = []
                    tempSystem = None
                    ipAddress = ''
            # If the row is bellow the VULNERABILITY SCAN RESULTS header in the csv.
            if not nmapRow:
                if str(row).__contains__("Target IP"):
                    tempAddress = getIpAddress(row)
                    vulnerableList.clear()
                elif str(row).__contains__("Start Time"):
                    recordFlag = 1
                elif str(row).__contains__("-----") or str(row).__contains__("items checked"):
                    continue
                elif str(row).__contains__("host(s)"):
                    recordFlag = 0
                elif str(row).__contains__("End Time"):
                    posn = findPosition(tempAddress.replace(".", ""))
                    if systemList[posn].ipAddress == tempAddress:
                        # This section was added as concatenation was occurring with the vulnerableList
                        # variable even though it was being appropriately cleared. I assume it has
                        # something to do with storing, retrieving and updating objects from a list
                        # and/or the implimentation of the code.
                        if len(systemList[posn].vulnerabilities) > 0:
                            temp = systemList[posn].vulnerabilities
                            temp.append(vulnerableList)
                            systemList[posn].vulnerabilities = temp
                            systemList[posn].numberVulnerabilities += len(vulnerableList) - 1
                        else:
                            systemList[posn].vulnerabilities = vulnerableList
                            systemList[posn].numberVulnerabilities += len(vulnerableList) - 1
                    vulnerableList = []
                elif recordFlag > 0:
                    vulnerableList.append(row[2:])
    # Rank every system object that has been created.
    for sys in systemList:
        sys.systemRanking = rankSystem(sys)

# This is used to assign a basic rank value to a system based on the number
# of open ports and vulnerabilities it has. It is called by the analyseData()
# function.
# Input: A system object is passed to the function.
# Output: A rank value with 1 being 100 or no vulnerabilities.
def rankSystem(sys):
    rank = 1
    rank -= (sys.numOpenPorts * 0.01)
    rank -= (sys.numberVulnerabilities * 0.05)
    return "%.2f" % rank

# This function uses Nmap to detect the operating system that is running on
# a system based on its IP Address.
def osDetect(ipAddress):
    nm = nmap.PortScanner()
    scan_range = nm.scan(hosts=ipAddress, arguments="-O")
    x = nm[ipAddress]['osmatch']
    os=x[0]
    return os['name']

# This function is used a check and prints to the terminal all of the
# information for the system objects that are stored in the global variable
# systemList.
# Input: A flag is currently input that determines the functions action. This
# enables additional testing actions to be developed and run as needed.
# Output: None. Only print to terminal actions.
def checkSystems(flag) -> object:
    for system in systemList:
        if flag == 'p':
            print('System ID: ' + str(system.SystemID))
            print('IP Address: ' + system.ipAddress)
            print('Operating System: ' + system.operatingSystem)
            print('Number of Potential Vulnerabilities: ' + str(system.numberVulnerabilities))
            print('Number of Ports Open: ' + str(system.numOpenPorts))
            print('Short Ports: ' + str(system.shortPorts))
            print('Open Ports: ' + str(system.openPorts))
            print('Vulnerabilities: ' + str(system.vulnerabilities))
            print('System Ranking: ' + str(system.systemRanking))

def main():
    analyseData()
    checkSystems("p")
    print(len(systemList))

main()
