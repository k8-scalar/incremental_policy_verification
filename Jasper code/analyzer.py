from model import *
from parser import ConfigParser
from kubernetes import client, config
from kubernetes.config import ConfigException

try:
    config.load_incluster_config()
except ConfigException:
    config.load_kube_config()
api_instance = client.CoreV1Api()

def getNodesMap():
    nodes = api_instance.list_node()
    index_map_nodes = []
    for i, node in enumerate(nodes.items):
            index_map_nodes.append('{}:{}'.format(i,node.metadata.name))
    return index_map_nodes


def getVMIdWithPodId(podIdx, index_map_pods, index_map_nodes):
    i, podname = index_map_pods[podIdx].split(':')
    ret = api_instance.read_namespaced_pod(name=podname, namespace="test")
    for entry in index_map_nodes:
        index, name = entry.split(':')
        if name == ret.spec.node_name:
            return int(index)
    print("The node on which the pod is deployed could not be found!") 
    
def getVMNameWithPodId(podIdx, index_map_pods, index_map_nodes):
    i, podname = index_map_pods[podIdx].split(':')
    ret = api_instance.read_namespaced_pod(name=podname, namespace="test")
    for entry in index_map_nodes:
        index, name = entry.split(':')
        if name == ret.spec.node_name:
            return name
    print("The node on which the pod is deployed could not be found!") 

def getVMNameWithPodName(podname, index_map_nodes):
    print(podname)
    ret = api_instance.read_namespaced_pod(name=podname, namespace="test")
    for entry in index_map_nodes:
        index, name = entry.split(':')
        print(index, name)
        if name == ret.spec.node_name:
            return name
    print("The node on which the pod is deployed could not be found!") 

def getNameWithId(Idx, map):
    for entry in map:
        index, name = entry.split(':')
        if int(index) == Idx:
            return name
    else:
        print("ERROR: The index has no name linked to it") 

def getIdWithName(itemname, map):
    for entry in map:
        index, name = entry.split(':')
        if itemname == name:
            return int(index)
    else:
        print("ERROR: The name was not found in the map") 

class Analyzer:
    def __init__(self):
        self.reachabilitymatrix:ReachabilityMatrix = None
        self.VMmatrix = []
    
    def analyseEvent(self, event):
    # def analyseEventAndGenerateDelta(self):
        affectedVMconnections = Store()
        conflict_allow_too_much = []
        conflict_allow_too_little = []
        redundant_policies = []
        related_policies = []

        # DEBUGGING PURPOSES
        # print(f'Event: {event}')

        # An event happened so we can generate the new_reachabilitymatrix
        cp = ConfigParser('/home/ubuntu/current-cluster-objects/')
        new_containers, new_policies = cp.parse() 
        new_reachabilitymatrix = ReachabilityMatrix.build_matrix(new_containers, new_policies)# ,containers_talk_to_themselves=False, build_transpose_matrix=True)
    
       

        # Create a new vmMatrix with all zeros, the size of the amount of nodes
        index_map_nodes = getNodesMap()
        new_VMmatrix = [bitarray('0' * len(index_map_nodes)) for _ in range(len(index_map_nodes))]

        # Set the new_VMmatrix using the new_reachabilitymatrix's kanomatrix
        for i, row in enumerate(new_reachabilitymatrix.matrix):
            for j, value in enumerate(row):
                if value == True:
                    new_VMmatrix[getVMIdWithPodId(i, new_reachabilitymatrix.index_map_pods, index_map_nodes)][getVMIdWithPodId(j, new_reachabilitymatrix.index_map_pods, index_map_nodes)] = True
        # If this was the startup event to detect resources we can stop here.
        if event == {}:
            print('#  Startup kanoMatrix and VMmatrix established')
            print("#")
            self.reachabilitymatrix = new_reachabilitymatrix
            self.VMmatrix = new_VMmatrix
            
        else:
            #  Compute deltaKano = NewKanomatrix XOR Kanomatrix
            #     deltaKano[i,j] = 1 -> changed
            #     deltaKano[i,j] = 0 -> unchanged   
     

            # DEBUGGING PURPOSES
            # print(f'\nnew kanomatrix: {new_reachabilitymatrix.matrix}')
            # print(f'old kanomatrix: {self.reachabilitymatrix.matrix}')
            # print(f"old index map pods: {self.reachabilitymatrix.index_map_pods}\n")
          
            # OPTION 1:  a pod is added or created thus the generated matrix has different dimensions than the old one.
            if len(self.reachabilitymatrix.matrix) != len(new_reachabilitymatrix.matrix):

                # If we deleted a pod some policies might have become redundant and we must notify that VM connections need to be checked
                if event['custom'] == 'delete':
                    podId = getIdWithName(event['metadata']['name'], self.reachabilitymatrix.index_map_pods)
                    for i in range(len(self.reachabilitymatrix.index_map_pods)):
                            if self.reachabilitymatrix.matrix[podId][i]:
                                polsDir1 = self.reachabilitymatrix.resp_policies.get_items(podId, i)
                                redundant_policies.append(polsDir1)
                                # conflict_allow_too_much.append((podId, i))

                            if self.reachabilitymatrix.matrix[i][podId]:
                                polsDir2 = self.reachabilitymatrix.resp_policies.get_items(i, podId)
                                redundant_policies.append(polsDir2)
                                # conflict_allow_too_much.append((i, podId))


                elif event['custom'] == 'create':
                    podId = getIdWithName(event['metadata']['name'], new_reachabilitymatrix.index_map_pods)
                    for i in range(len(new_reachabilitymatrix.index_map_pods)):
                        if new_reachabilitymatrix.matrix[podId][i]:
                            polsDir1 = new_reachabilitymatrix.resp_policies.get_items(podId, i)
                            related_policies.append(polsDir1)                        
                        if new_reachabilitymatrix.matrix[i][podId]:
                            polsDir2 = new_reachabilitymatrix.resp_policies.get_items(i, podId)
                            related_policies.append(polsDir2)
                        
            # OPTION 1: The matrix sizes are the same (So any event except add/delete pods) so we can create the delta and find issues like this.
            else:

                #  create deltakano
                deltakano = [row1 ^ row2 for row1, row2 in zip(new_reachabilitymatrix.matrix, self.reachabilitymatrix.matrix)]

                # DEBUGGING PURPOSES
                # print(f'Deltakano: {deltakano}')

                # Add changes found in the delta to affectedVMConnections
                for i, row in enumerate(deltakano):
                    for j, value in enumerate(row):
                        if deltakano[i][j] == 1:
                            affectedVMconnections.add_item(getVMIdWithPodId(i, new_reachabilitymatrix.index_map_pods, index_map_nodes), getVMIdWithPodId(j, new_reachabilitymatrix.index_map_pods, index_map_nodes), (i, j))
                
                # Define whether the event makes conflicts and whether they allow too little or too much
                if (len(self.VMmatrix) == len(new_VMmatrix)):
                    for k in range(len(self.VMmatrix)):
                        for l in range(len(self.VMmatrix)):
                            if affectedVMconnections.get_items(k, l) != []:    
                                if self.VMmatrix[k][l] == 1 and new_VMmatrix[k][l] == 0:
                                    conflict_allow_too_much.append((k, l))
                                elif self.VMmatrix[k][l] == 0 and new_VMmatrix[k][l] == 1:
                                    conflict_allow_too_little.append((k, l))

            # Printing out the correct messages for too loose VMS
            noconflicts = True
            for (k, l) in conflict_allow_too_much:
                print(f"SGs might need attention: VM connection between nodes {getNameWithId(k, index_map_nodes)} and {getNameWithId(l, index_map_nodes)} might have become redundant! \nThe VM connection was needed for the following pod connections that are now removed due to the latest event:\n")
                for (pod1, pod2) in affectedVMconnections.get_items(k, l):
                    pols = self.reachabilitymatrix.resp_policies.get_items(pod1, pod2)
                    if len(pols) > 1:
                        pols_str = ", ".join(map(lambda id: getNameWithId(id, self.reachabilitymatrix.index_map_pols), pols[:-1])) + " and " + getNameWithId(pols[-1], self.reachabilitymatrix.index_map_pols)
                    elif len(pols) == 1:
                        pols_str = getNameWithId(pols[0], self.reachabilitymatrix.index_map_pols)
                    else:
                        pols_str = ""
                    print(f"   - {getNameWithId(pod1, self.reachabilitymatrix.index_map_pods)} connected to {getNameWithId(pod2, self.reachabilitymatrix.index_map_pods)} which was allowed by network policies {pols_str}")
                noconflicts = False

            # Printing out the correct messages for too restrictive VMS
            for (k, l) in conflict_allow_too_little:
                if (affectedVMconnections.get_items(k, l) != []):
                    print(f"SGs might need attention: VM connection between nodes {getNameWithId(k, index_map_nodes)} and {getNameWithId(l, index_map_nodes)} might be needed! \nThis VM connection is required by the following pod connections that are now possible due to the latest event:\n")
                    for (pod1, pod2) in affectedVMconnections.get_items(k, l):
                        pols = new_reachabilitymatrix.resp_policies.get_items(pod1, pod2)
                        if len(pols) > 1:
                            pols_str = ", ".join(map(lambda id: getNameWithId(id, new_reachabilitymatrix.index_map_pols), pols[:-1])) + " and " + getNameWithId(pols[-1], new_reachabilitymatrix.index_map_pols)
                        elif len(pols) == 1:
                            pols_str = getNameWithId(pols[0], new_reachabilitymatrix.index_map_pols)
                        else:
                            pols_str = ""
                        print(f"   - {getNameWithId(pod1, new_reachabilitymatrix.index_map_pods)} connected to {getNameWithId(pod2, new_reachabilitymatrix.index_map_pods)} which is possible due to network policies {pols_str}")
                else:
                    print(f"SGs might need attention: VM connection between nodes {getNameWithId(k, index_map_nodes)} and {getNameWithId(l, index_map_nodes)} might be needed due to the latest event\n ")
                noconflicts = False

            # Dont forget to print the redundant policies (when a pod is removed)
            if redundant_policies != []:
                unique_pols_set = set()
                for nr in redundant_policies:
                    unique_pols_set.update(nr)

                nodename = event['spec']['nodeName']
                print(f"\n Warning: VM connections with node {nodename} might have become redundant due to the latest event!\n")

                print(f"\n Because a pod was deleted the following existing NetworkPolicies are also redundant:\n")
                for pol in unique_pols_set:
                    print(f"   -{getNameWithId(pol, self.reachabilitymatrix.index_map_pols)}")
                print("\n  Deleting these is recommended")

            # And to print the related policies (when a pod is added)
            if related_policies != []:
                unique_pols_set = set()
                for nr in related_policies:
                    unique_pols_set.update(nr)
                print(f"\nWarning: A pod was added: the following policies that already existed are applicable to the new pod: \n")
                for pol in unique_pols_set:
                    print(f"   - {getNameWithId(pol, new_reachabilitymatrix.index_map_pols)}")
                print("\n  Make sure to review these for correctness\n")

            if noconflicts:
                print("This event had no direct impact on the current setup")
                print("No conflicts found in the new configuration!")


        self.reachabilitymatrix = new_reachabilitymatrix
        self.VMmatrix = new_VMmatrix

    def set_reachability_matrix(self, reachability_matrix):
        self.reachabilitymatrix = reachability_matrix

    def set_VM_matrix(self, VM_matrix):
        self.VMmatrix = VM_matrix 

if __name__ == '__main__':
    # Create a fake event for testing

    testevent= {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': 'blue-pod', 'namespace': 'test', 'labels': {'color': 'blue'}}, 'spec': {'nodeName': 'worker6'}, 'custom': 'create'}
    analyzer = Analyzer() 
    analyzer.analyseEvent(testevent)

