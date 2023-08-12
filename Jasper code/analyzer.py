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

def getNameWithId(Idx, map):
    for entry in map:
        index, name = entry.split(':')
        if int(index) == Idx:
            return name
    else:
        print("ERROR: The index has no name linked to it") 

class Analyzer:
    def __init__(self):
        self.reachabilitymatrix:ReachabilityMatrix = None
        self.VMmatrix = []

    def analyseEventAndGenerateDelta(self, event):
    # def analyseEventAndGenerateDelta(self):
            
        # DEBUGGING PURPOSES
        # print(f'Event: {event}')

        # An event happened so we can generate the new_reachabilitymatrix
        # Create a new vmMatrix with all zeros, the size of the amount of nodes
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

        if self.reachabilitymatrix == None or self.VMmatrix == []:
            print(' Startup kanoMatrix and VMmatrix established\n')
            self.reachabilitymatrix = new_reachabilitymatrix
            self.VMmatrix = new_VMmatrix
            
        else:
            #  Compute deltaKano = NewKanomatrix XOR Kanomatrix
            #     deltaKano[i,j] = 1 -> changed
            #     deltaKano[i,j] = 0 -> unchanged        
            deltakano = [row1 ^ row2 for row1, row2 in zip(new_reachabilitymatrix.matrix, self.reachabilitymatrix.matrix)]

            # DEBUGGING PURPOSES
            # print(f'new kanomatrix: {new_reachabilitymatrix.matrix}')
            # print(f'old kanomatrix: {self.reachabilitymatrix.matrix}')
            # print(f'Deltakano: {deltakano}')

            affectedVMconnections = Store()
            for i, row in enumerate(deltakano):
                for j, value in enumerate(row):
                    if deltakano[i][j] == 1:
                        affectedVMconnections.add_item(getVMIdWithPodId(i, new_reachabilitymatrix.index_map_pods, index_map_nodes), getVMIdWithPodId(j, new_reachabilitymatrix.index_map_pods, index_map_nodes), (i, j))
            
            # Here starts the verification process
            conflict_allow_too_much = []
            conflict_allow_too_little = []

            if (len(self.VMmatrix) == len(new_VMmatrix)):
                for k in range(len(self.VMmatrix)):
                    for l in range(len(self.VMmatrix)):
                        if affectedVMconnections.get_items(k, l) != []:    
                            if self.VMmatrix[k][l] == 1 and new_VMmatrix[k][l] == 0:
                                conflict_allow_too_much.append((k, l))
                            elif self.VMmatrix[k][l] == 0 and new_VMmatrix[k][l] == 1:
                                conflict_allow_too_little.append((k, l))

                noconflicts = True
                for (k, l) in conflict_allow_too_much:
                    print(f"SGs might need attention: VM connection between {getNameWithId(k, index_map_nodes)} and {getNameWithId(l, index_map_nodes)} might have become redundant! \nThe VM connection was needed for the following pod connections that are now removed due to the latest event:")
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

                for (k, l) in conflict_allow_too_little:
                    print(f"SGs might need attention: VM connection between nodes {getNameWithId(k, index_map_nodes)} and {getNameWithId(l, index_map_nodes)} might be needed! \nThis VM connection is required by the following pod connections that are now possible due to the latest event:")
                    for (pod1, pod2) in affectedVMconnections.get_items(k, l):
                        pols = new_reachabilitymatrix.resp_policies.get_items(pod1, pod2)
                        if len(pols) > 1:
                            pols_str = ", ".join(map(lambda id: getNameWithId(id, new_reachabilitymatrix.index_map_pols), pols[:-1])) + " and " + getNameWithId(pols[-1], new_reachabilitymatrix.index_map_pols)
                        elif len(pols) == 1:
                            pols_str = getNameWithId(pols[0], new_reachabilitymatrix.index_map_pols)
                        else:
                            pols_str = ""
                        print(f"   - {getNameWithId(pod1, new_reachabilitymatrix.index_map_pods)} connected to {getNameWithId(pod2, new_reachabilitymatrix.index_map_pods)} which is possible due to network policies {pols_str}")
                    noconflicts = False

                if noconflicts:
                    print("No conflicts found in the new configuration!")
            else:
                print("Nodes have been added or removed between this event and the previous one. This event will be disregarded but the node count has now been updated.")

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
    analyzer.analyseEventAndGenerateDelta(testevent)

    # analyzer.analyseEventAndGenerateDelta()
