from kubernetes import client, config, watch
from kubernetes.config import ConfigException
from urllib3.exceptions import ProtocolError
import concurrent.futures
import os, sys
import yaml
from contextlib import contextmanager
from time import process_time

# Configure the client to use in-cluster config or local kube config file
try:
   config.load_incluster_config()
except ConfigException:
   config.load_kube_config()

pod_api_instance = client.CoreV1Api()
policy_api_instance = client.NetworkingV1Api()

@contextmanager
def timing_processtime(description: str) -> None:
    start = process_time()
    yield
    ellapsed_time = process_time() - start
    print(f"{description}: {ellapsed_time}")


def pods():
    w = watch.Watch()
    try:
        for event in w.stream(pod_api_instance.list_namespaced_pod, namespace = "test", timeout_seconds=0):
            updatedPod = event["object"]
            podName = updatedPod.metadata.name
            labels = updatedPod.metadata.labels
            filename="/home/ubuntu/current/src_dir/{}.yaml".format(podName)


            #if updatedPod.status.phase == "Running":
            #if event['type'] == "ADDED" and updatedPod.spec.node_name ==None:
            #if event['type'] =="MODIFIED" and updatedPod.status.phase == "PodScheduled":
            #The Pod is scheduled (“PodScheduled”" ‘.status.condition’ is true).

            '''if pod.metadata.deletion_timestamp != None and pod.status.phase == 'Running':
                state = 'Terminating'
            else:
                state = str(pod.status.phase) '''

            if event['type'] =="MODIFIED" and updatedPod.metadata.deletion_timestamp == None: # Avoid the MODIFIED on delete

                for cond in updatedPod.status.conditions:
                    if cond.type == "PodScheduled" and cond.status == "True":
                        if not os.path.exists(filename): #to avoid duplicates since modified is repeated on \
                            #updatedPod.status.conditions = ["Initialized","ContainersReady","Ready"] in addition to "PodScheduled"

                            node_name=f"{updatedPod.spec.node_name}"
                            print (f'Pod {podName} added on node {node_name}')

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

                            os.makedirs(os.path.dirname(filename), exist_ok=True)
                            with open(filename, 'w+') as f:
                                f.write(yaml.dump(u_pod, default_flow_style=False, sort_keys=False))
                            os.system('cp -a {} /home/ubuntu/current/data/'.format(filename))
                        else:
                            continue


            elif event['type'] == "DELETED":
                print (f'Pod {podName} has been romoved from the cluster')
                os.system('rm -f /home/ubuntu/current/data/{}.yaml'.format(podName))


    except ProtocolError:
        print("watchPodEvents ProtocolError, continuing..")

def policies():
    w = watch.Watch()
    try:
        for event in w.stream(policy_api_instance.list_namespaced_network_policy, namespace = "test", timeout_seconds=0):
            NewPol = event["object"]
            PolName = NewPol.metadata.name
            if PolName == "default-deny":
                print (f'Policy {PolName}')
                continue
            #with timing_processtime("Time taken: "):
            if event['type'] =="ADDED":
                print (f'Policy {PolName} added on on the cluster')
                filename="/home/ubuntu/current/src_dir/{}.yaml".format(PolName)
                os.makedirs(os.path.dirname(filename), exist_ok=True)
                with open(filename, 'w+') as f:
                    os.system("kubectl  get networkpolicy {} -n test -o yaml > {}".format(PolName, filename))
                os.system('cp -a {} /home/ubuntu/current/data/'.format(filename))
            elif event['type'] =="DELETED":
                print (f'Pod {PolName} has been romoved from the cluster')
                os.system('rm -f /home/ubuntu/current/data/{}.yaml'.format(PolName))
    except ProtocolError:
      print("watchPolicyEvents ProtocolError, continuing..")



if __name__ == "__main__":
    with concurrent.futures.ThreadPoolExecutor() as executor:
        p = executor.submit(pods)
        n = executor.submit(policies)

