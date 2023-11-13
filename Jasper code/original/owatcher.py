from kubernetes import client, config, watch
from kubernetes.config import ConfigException
from urllib3.exceptions import ProtocolError
import concurrent.futures
import os
import yaml
from original.oparser import ConfigParser as CP

try:
   config.load_incluster_config()
except ConfigException:
   config.load_kube_config()


def pods(ns, oparser):
    pod_api_instance = client.CoreV1Api()
    pod_list = pod_api_instance.list_namespaced_pod(ns).items
    for pod in pod_list:
        podName = pod.metadata.name
        labels = pod.metadata.labels
        node_name=f"{pod.spec.node_name}"

        u_pod = {}

        u_pod['apiVersion'] = 'v1'
        u_pod['kind'] = 'Pod'
        u_pod['metadata'] = {
            'name': podName,
            'namespace': 'test',
            'labels': labels
        }

        u_pod['spec']={
            'nodeName':node_name
        }
        oparser.create_object(u_pod)
    return pods
            
def policies(ns, oparser):
    
    np_api_instance = client.NetworkingV1Api()
    policy_list = np_api_instance.list_namespaced_network_policy(ns).items
    for pol in policy_list:
        new_data = yaml.safe_load(os.popen("kubectl get networkpolicy {} -n test -o yaml".format(pol.metadata.name)).read())
        oparser.create_object(new_data)
        
            
def o_get_pods_and_policies(ns):
    oparser = CP()
    pods(ns, oparser)
    policies(ns, oparser)
    return(oparser.containers, oparser.policies)
