import os
import random
import yaml
from collections import OrderedDict
#from ..kano.model import *
from model import *

class ConfigFiles:
    def __init__(self, directory='/ubuntu/home/current-cluster-objects', dir2='events', podN=5,nsN=5,policyN=5,podLL=5,nsLL=5,keyL=5,valueL=10,userL=5,selectedLL=3,allowNSLL=3,allowpodLL=3, nodeN=3):
        self.podN = podN
        self.nsN = nsN
        self.policyN = policyN
        self.podLL = podLL
        self.nsLL = nsLL
        self.keys = ["key"+str(i) for i in range(keyL)]
        self.values = ["value"+str(i) for i in range(valueL)]
        self.userL = userL
        self.users = ["user"+str(i) for i in range(userL)]
        self.selectedLL = selectedLL
        self.allowNSLL = allowNSLL
        self.allowpodLL = allowpodLL
        self.nodeN=["worker-"+str(i+1) for i in range (nodeN)]
        self.port=[80, 8080]
        self.protocol=["TCP", "http"]
        self.directory = directory
        self.dir2=dir2
        if not os.path.exists(directory):
            os.makedirs(directory)
        if not os.path.exists(dir2):
            os.makedirs(dir2)
        self.generatePods()
        # self.generateNamespaces()

    def generatePods(self):
        containers = []
        cnames=[]
        for i in range(self.podN):
            podName = "pod" + str(i)
            # nsName = random.choice(namespaces)
            labels = {}
            labels["User"] = random.choice(self.users)
            for l in range(random.randint(0, self.podLL-1)):
                labels[random.choice(self.keys)] = random.choice(self.values)
            nodeName = random.choice(self.nodeN)
            pod = Container(podName, labels, nodeName)
            containers.append(pod)

            y_pod = {}
            y_pod['apiVersion'] = 'v1'
            y_pod['kind'] = 'Pod'
            y_pod['metadata'] = {
                'name': podName,
                'namespace': 'default',
                'labels': labels
            }

            y_pod['spec']={
                'nodeName': nodeName,
                'containers':[{'image':'','name': labels["User"],'ports':[{'containerPort':random.choice(self.port), 'protocol':random.choice(self.protocol)}]}],
             }


            with open("{}/pod{}.yml".format(self.directory, i), 'w+') as f:
                f.write(yaml.dump(y_pod, default_flow_style=False, sort_keys=False))
            cnames.append(podName)


        ##Emulating kubectl watch to get nodes for each pod
        w_pod = [{
        'apiVersion': 'v1',
        'kind' : 'Pod',
        'metadata' : {
            'name': nam,
            'namespace': 'default'
        },

        'spec' :{
            'nodeName':random.choice(self.nodeN)
            }
        } for nam in cnames]

        with open("{}/podEvents.yaml".format(self.dir2), 'w+') as f: ##This event file is updated when there is any change in the pods
            f.write(yaml.dump_all(w_pod, default_flow_style=False, sort_keys=False))


        self.containers = containers
        return


    # def generateNamespaces(self):
    #     namespaces = []
    #     for i in range(self.nsN):
    #         nsName = "namespace" + str(i)
    #         labels = {}
    #         for l in range(random.randint(0, self.nsLL-1)):
    #             labels[random.choice(self.keys)] = random.choice(self.values)
    #         ns = Namespace(nsName, labels)
    #         namespaces.append(ns)
    #     self.namespaces = namespaces
    #     return

    def generateConfigFiles(self):
        for i in range(self.policyN):
            data = "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\n" + "metadata:\n  name: test-network-policy" +str(i) +"\n  namespace: default\n"
            data += "spec:\n  podSelector:\n    matchLabels:\n"

            # randomly select two containers
            candidates = random.sample(self.containers, 2)
            data += self.printLabels(candidates[0], "      ")

            ##Get seleceted pod's name and map its container port to the allowed port in the policy
            selPodName= candidates[0].name 
            with open("{}/{}.yml".format(self.directory, selPodName)) as f:
                parsed_yaml_file = yaml.load(f, Loader=yaml.FullLoader)
                ContPort=parsed_yaml_file.get('spec').get('containers')[0].get('ports')[0].get('containerPort')
                ContProtocol=parsed_yaml_file.get('spec').get('containers')[0].get('ports')[0].get('protocol')


            data += "  policyTypes:\n"
            choice = random.choice(["  ingress", "  egress"])
            if choice == "  ingress":
                data += "  - Ingress\n" + choice + ":\n  - from:\n"
            elif choice == "  egress":
                data += "  - Egress\n" + choice + ":\n  - to:\n"
            data +="    - podSelector:\n        matchLabels:\n"
            data += self.printLabels(candidates[1], "          ")
            data +="    ports:\n    - protocol: " + ContProtocol + "\n      port: " + str(ContPort)


            f = open(self.directory + "/policy" + str(i) + ".yml", "w")
            f.write(data)
            f.close()
        return

    def printLabels(self, container, indent):
        string = str(indent) + "User: " + str(container.getValueOrDefault("User", "")) + "\n"
        count = 0
        for key,value in container.getLabels().items():
            if count>=3:
                break
            if key == "User":
                continue
            string += str(indent) + str(key) + ": " + str(value) + "\n"
            count += 1
        return string

    def getPods(self):
        return self.containers


if __name__ == "__main__":
    config = ConfigFiles()
    config.generateConfigFiles()
