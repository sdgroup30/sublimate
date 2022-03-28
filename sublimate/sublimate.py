import networkx as nx
import argparse
import json
import math
import trivium


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
        
        def edgeWeight(u, v, w):
            score = self.G.nodes[v]['distill_score']
            if (score >= 1): score /= 10 # this is for testing, to get score in [0,1]
            return -math.log2(score)
        
        def ipToTid(ip):
            trivium_id = [id for id,attributes in self.G.nodes.items() if attributes['ip'] == ip][0]
            return trivium_id
        
        def tidToIp(tid):
            return self.G.nodes[tid]['ip']
        

        length, path = nx.single_source_dijkstra(self.G, source=ipToTid(self.attackingNode), weight=edgeWeight)


        for victim in self.victimNodes:
            trivium_id = ipToTid(victim.ip)
            if trivium_id not in path.keys():
                continue # there is no path

            path_to_victim = compromisePath()
            path_to_victim.addToWeight(2**-length[trivium_id])
            ipPath = list(map(tidToIp, path[trivium_id]))
            path_to_victim.path = ipPath[:-1]

            victim.addPath(path_to_victim)
            victim.path = ipPath
            
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
                    f.write("**Weight of Path:** {:.6f}\n\n".format(compromisePath.weight))
                    f.write("**Number of Nodes in Path:** " + str(len(compromisePath.path) + 1) + "\n\n")


        f.close()

# Testing zone
def main():

    # initialize parser
    parser = argparse.ArgumentParser()

    # parse the arguments
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

    # Read victim and attackers from Trivium
    if not args.victim or not args.attacker:
        if args.model and args.diagram:
            diagramData = trivium.api.element.get(args.model, element=args.diagram)
            ids = list(diagramData["custom"]["diagramContents"].keys())
            params = {'ids' : ','.join(ids)}
            elements = trivium.api.element.get(args.model, params=params)
            actorNodes = [e for e in elements if e['type'] == 'td.systems.actor']

            if not args.attacker:
                attackingActorNodes = [actor for actor in actorNodes if actor['name'].lower() == 'start']
                if len(attackingActorNodes) != 1:
                    print('error: the attacker must be labeled with an actor named \'start\' in the diagram')
                    exit()

                # Ignore additional actors called 'start' and additional edges to nodes
                startEdgeID = attackingActorNodes[0]['sourceOf'][0]
                startNode = [node for node in elements if startEdgeID in node['targetOf']][0]
                attackingNode = startNode['custom']['properties']['ip']['value']
            if not args.victim:
                victimActorNodes = [actor for actor in actorNodes if actor['name'].lower() == 'end']
                if len(victimActorNodes) != 1:
                    print('error: the victim must be labeled with an actor named \'end\' in the diagram')
                    exit()

                # Ignore additional actors called 'end' and additional edges to nodes
                startEdgeID = victimActorNodes[0]['sourceOf'][0]
                endNode = [node for node in elements if startEdgeID in node['targetOf']][0]
                victimNodes = [endNode['custom']['properties']['ip']['value']]

        else:
            print("error: attacker or victim nodes not specified")
            exit()

    # Read in data
    f = open(args.input, "r")
    data = f.read()
    f.close()

    # Create test network
    testing = Network(data, victimNodes, attackingNode, triviumData)

    # Find paths to victims
    testing.Sublimate()


    # Run the export function
    testing.Export(args.output)

if __name__ == "__main__":
    main()
