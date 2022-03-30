import networkx as nx
import argparse
import json
import math
import markdown
import matplotlib.pyplot as plt
import pdfkit 
import pandoc
import subprocess
import os



class victimNode:

    def __init__(self, ip):

        # Init the variables
        self.ip = ip

        # a list of paths, sorted by weight
        self.compromisePaths = []

    def addPath(self, path):

        # If first path just append
        if(len(self.compromisePaths) == 0):
            self.compromisePaths.append(path)

        else:

            # Loop through the existing paths
            for i in range(0,len(self.compromisePaths)):

                # See if the weight of the new path is higher
                # If yes, insert into list
                if(path.weight > self.compromisePaths[i].weight):
                    self.compromisePaths.insert(i, path)
                    break

            # If it is the new worst path, insert at end
            else:
                self.compromisePaths.append(path)

    def CalculateScore(self):

        # Code goes here
        return True

class compromisePath:

    # Init vars
    def __init__(self):
        self.weight = 0
        self.path = []

    # Add to path
    def addToPath(self, node):
        self.path.append(node)

    # Increase weight of path
    def addToWeight(self, weight):
        self.weight += weight

    def addToPath(self, node, weight):
        self.weight += weight
        self.path.append(node)



class Network:

    attackingNode = ""

    # Init the diagram. Data is the json data.
    def __init__(self, data, victimNodes, attackingNode, triviumData):

        # Import the graph
        self.G = nx.readwrite.node_link_graph(json.loads(data))
        
        # Init the attacker and the victims
        self.victimNodes = []
        for victim in victimNodes:

            # Create a new victim node and add to list
            self.victimNodes.append(victimNode(victim))

        self.attackingNode = attackingNode

        self.triviumData = triviumData

    
    # Init without graph for testing
    #def __init__(self, victimNodes, attackingNode, triviumData):

        # Init the attacker and the victims
     #   self.victimNodes = []
      #  for victim in victimNodes:

            # Create a new victim node and add to list
       #     self.victimNodes.append(victimNode(victim))

#        self.attackingNode = attackingNode

 #       self.triviumData = triviumData


    def Sublimate(self):
        
        def edgeWeight(u, v, w):
            score = float(self.G.nodes[v]['distill_score'])
            if ((score) >= 1): score /= 10 # this is for testing, to get score in [0,1]
            return -math.log2(score)
        
        def ipToTid(ip):
            trivium_id = [id for id,attributes in self.G.nodes.items() if attributes['ip'] == ip][0]
            return trivium_id
        
        def tidToIp(tid):
            return self.G.nodes[tid]['ip']
        

        length, path = nx.single_source_dijkstra(self.G, source=ipToTid(self.attackingNode), weight=edgeWeight)


        for victim in self.victimNodes:
            trivium_id = ipToTid(victim.ip)
            if (trivium_id not in path.keys()):
                continue # there is no path

            path_to_victim = compromisePath()
            path_to_victim.addToWeight(2**-length[trivium_id])
            ipPath = list(map(tidToIp, path[trivium_id]))
            path_to_victim.path = ipPath[:-1]

            victim.addPath(path_to_victim)
            victim.path = ipPath
            
        return True


    def MarkdownExport(self, fileName):

        # Open the file and write the header
        f = open(fileName + ".md", "w")
        f.write("# " + self.triviumData['diagramName'] + " Attack Traversal Report\n")
        f.close()

        # State the attacking node
        f = open(fileName+".md", "a")
        f.write("## Attacking Node: " + self.attackingNode + '\n')

        # Loop through the victims
        for victim in self.victimNodes:
            f.write("## Victim Node: " + victim.ip + '\n')

            # Edge case: if there are no paths, print notice
            if(len(victim.compromisePaths) == 0):
                f.write('#### No Paths of Compromise for This Node\n')

            else:

                # For each victim, loop through the paths and print them
                for compromisePath in victim.compromisePaths:

                    # print the markdown formatting
                    f.write("#### ")

                    # loop through the ips in the path and print arrows between them
                    for ip in compromisePath.path:
                        f.write(ip)
                        f.write("->")

                    # At the end output the ip of the victim node
                    f.write(victim.ip + '\n')

                    # Output the weight and number of nodes
                    f.write("**Weight of Path:** {:.6f}\n\n".format(compromisePath.weight))
                    f.write("**Number of Nodes in Path:** " + str(len(compromisePath.path) + 1) + "\n\n")


        f.close()

    def MermaidExport(self, fileName):

        # Create the header of the document and the summary graph
        text = ""
        victimList = ""
        header = ('<script src="https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js"></script>\n')
        summaryGraph = "# "+ str(self.triviumData['diagramName']) + " Attack Traversal Report\n## Summary Graph\n~~~mermaid\nflowchart LR\n"
        summaryGraphCounter = {}

        # State the attacking node
        text += "## Attacking Node: " + self.attackingNode + '\n'

        # Loop through the victims
        for victim in self.victimNodes:
            text += ("## Victim Node: [" + victim.ip + "](##" + victim.ip + ')\n')

            # Edge case: if there are no paths, print notice
            if(len(victim.compromisePaths) == 0):
                text += '#### No Paths of Compromise for This Node\n'

            else:

                # For each victim, loop through the paths and print them
                for compromisePath in victim.compromisePaths:

                    # Temporary Variable to store the graph
                    temp = ""

                    # Create the mermaid graph
                    text += '~~~mermaid\nflowchart LR\n'

                    # loop through the ips in the path and print arrows between them
                    i = 0
                    for i in range(len(compromisePath.path) - 1):
                        temp += compromisePath.path[i]
                        temp += "-->"
                        temp += compromisePath.path[i+1] + "\n"

                        # Add one occurence to the node that is being accessed for the summaryGraph
                        if not compromisePath.path[i+1] in summaryGraphCounter:
                            summaryGraphCounter[compromisePath.path[i+1]] = 0

                        summaryGraphCounter[compromisePath.path[i+1]] += 1

                    # At the end output the path to the victim node
                    temp += compromisePath.path[len(compromisePath.path)-1]
                    temp += "-->"
                    temp += (victim.ip + '\n')

                    # Attach the temp graph to the diagram in both places
                    text += temp
                    summaryGraph += temp

                    # Output the weight and number of nodes
                    text += "~~~\n#### Weight of Path: {:.6f}\n\n".format(compromisePath.weight)
                    text += "#### Number of Nodes in Path: " + str(len(compromisePath.path) + 1) + "\n\n"

            # Add the victim to the list
            victimList += "\n##" + victim.ip + "CVES Report \n"
            cves = self.G.nodes[self.ipToTid(victim.ip)]['cve_info']

            for cve in cves:
                victimList += "["+cve+"](https://cve.mitre.org/cgi-bin/cvename.cgi?name="+cve+")\n\n"
        
                    
        
        # Finish formatting the summary graph

        # Find the node with the highest weight
        if len(summaryGraphCounter) != 0:
            top = max(summaryGraphCounter, key=summaryGraphCounter.get)
            top = summaryGraphCounter[top]

        # Loop through the nodes and apply the color weighting
        for node in summaryGraphCounter:

            redness = '{:02x}'.format(int(((summaryGraphCounter[node] / top) * -255) + 255))
            redval = "FF" + redness + redness
            summaryGraph += "classDef cl" + node.replace('.','') +" fill:#" + redval + ";\n"
            summaryGraph += "class " + node + " cl" + node.replace('.','') + ";\n"
        summaryGraph += "~~~\n\n"
        
        # Convert the text into mermaid markdown
        html = markdown.markdown((summaryGraph + text + victimList), extensions=['md_mermaid'])
        finalHtml = header + html

        # Write the markdown to disk
        f = open(fileName + ".md", "w")
        f.write((summaryGraph + text + victimList))
        f.close()


        # Write the html to disk
        f = open(fileName + ".html", "w")
        f.write(finalHtml)
        f.close()

        # Convert the markdown to pdf
        args = ['pandoc', (fileName + ".md"), '-o', (fileName + ".pdf"), '--filter=mermaid-filter.cmd']
        subprocess.Popen(args)


    # Utilies 
    def ipToTid(self, ip):
        trivium_id = [id for id,attributes in self.G.nodes.items() if attributes['ip'] == ip][0]
        return trivium_id


# Testing zone
def main():

    # initialize parser
    parser = argparse.ArgumentParser()

    # parse the arguements
    parser.add_argument("-m", "--model", type=str, help="Model Name")
    parser.add_argument("-d", "--diagram", type=str, help="Diagram Name")
    parser.add_argument("-i", "--input", type=str, help="Input ", required=True)
    parser.add_argument("-o", "--output", type=str, help="Nessus Files", required=True)
    parser.add_argument("-a", "--attacker", type=str, help="Override attacking nodes from diagram")
    parser.add_argument("-v", "--victim", type=str, help="Override victim nodes from diagram")
    args = parser.parse_args()
 
    # Create placeholder data
    triviumData = {}
    triviumData['diagramName'] = args.diagram
    victimNodes = [args.victim]
    attackingNode = args.attacker

    # Read in data
    f = open(args.input, "r")
    data = f.read()
    f.close()

    # Create test network
    testing = Network(data, victimNodes, attackingNode, triviumData)

    # Find paths to victims
    testing.Sublimate()

    # # Create two different paths
    # path1 = compromisePath()
    # path1.addToPath('10.0.0.4', 6)
    # path1.addToPath('10.0.0.7', 8)
    # path1.addToPath('10.2.2.57', 22)
    # path1.addToPath('10.2.2.58', 22)
    # path1.addToPath('10.0.0.8', 22)


    # path2 = compromisePath()
    # path2.addToPath('10.0.0.2', 12)
    # path2.addToPath('10.2.2.57', 22)
    # path2.addToPath('192.168.1.1', 30)
    # path2.addToPath('10.0.0.8', 6)

    # path3 = compromisePath()
    # path3.addToPath('10.0.0.6', 6)
    # path3.addToPath('10.2.2.58', 22)
    # path3.addToPath('10.0.0.8', 22)

    # # Add both paths to the first victim
    # # The second path has a higher weight
    # testing.victimNodes[0].addPath(path1)
    # testing.victimNodes[0].addPath(path2)
    # testing.victimNodes[0].addPath(path3)

    # Run the export function
    testing.MermaidExport(args.output)



if __name__ == "__main__":
    main()
