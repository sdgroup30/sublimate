import networkx as nx
import argparse
import json


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

        print(len(self.victimNodes))

    
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

        # Graph stuff goes here
        return True


    def Export(self, fileName):

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
                    f.write("**Weight of Path:** " + str(compromisePath.weight) + "\n\n")
                    f.write("**Number of Nodes in Path:** " + str(len(compromisePath.path) + 1) + "\n\n")


        f.close()

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

    # Create two different paths
    path1 = compromisePath()
    path1.addToPath('10.0.0.4', 6)
    path1.addToPath('10.0.0.7', 8)

    path2 = compromisePath()
    path2.addToPath('10.0.0.2', 12)
    path2.addToPath('10.2.2.57', 22)
    path2.addToPath('192.168.1.1', 30)

    # Add both paths to the first victim
    # The second path has a higher weight
    testing.victimNodes[0].addPath(path1)
    testing.victimNodes[0].addPath(path2)

    # Run the export function
    testing.Export(args.output)

if __name__ == "__main__":
    main()
