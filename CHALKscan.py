import nmap
import socket
import subprocess
import re

class Scan:
    #function to get the IP of the host machine
    def getSourceIP(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('10.255.255.255', 1))
            IP = s.getsockname()[0]
        except Exception:
            IP = '127.0.0.1'
        finally:
            s.close()
        return IP


    #function to output successfully nmapped IP's to a temporary file for nikto to read in
    def extractSuccessfulIps(self):
        with open('temp.csv', 'r') as file:
            fi = file.readlines()

        re_ip = re.compile("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")

        for line in fi:
            ip = re.findall(re_ip,line)

        ip=list(set(ip))

        with open ('temp.txt','w') as f:
            for address in ip[1:]:
                f.write("%s\n" % address)


    #-----------------------------------------------------------
    #START OF MAIN CODE
    #-----------------------------------------------------------
    def run(self):
        #Get IP and subnet of device being run on
        hostIP= self.getSourceIP()

        #replace final octet for mass scanning
        hostIP='.'.join(hostIP.split('.')[:-1]+["0"])+"/24"

        #establish scanning
        nmScan = nmap.PortScanner()

        #save scan results into csv
        print(nmScan.scan(hostIP),file=open('temp.csv','a'))

        #save nmap results into csv
        subprocess.call(["echo 'NMAP SCAN RESULTS\n' > finalresult.csv && strings temp.csv  | awk -F 'scanstats' '{print$2}' >> finalresult.csv"], shell=True)

        #extract successfully nmapped IP's for Nikto
        self.extractSuccessfulIps()

        #perform vulnerability scan and output to csv
        subprocess.call(['echo "\nVULNERABILITY SCAN RESULTS \n" >> finalresult.csv && nikto -h temp.txt - | awk -F "Nikto" "{print$2}" >> temp2.csv && strings temp2.csv >> finalresult.csv'], shell=True)

        #clean up temporary files
        subprocess.call(["rm temp.txt && rm temp.csv && rm temp2.csv"], shell=True)
