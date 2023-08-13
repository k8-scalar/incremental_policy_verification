from kubernetes import client, config, watch
from kubernetes.config import ConfigException
from urllib3.exceptions import ProtocolError
import concurrent.futures
import os, sys
import yaml
from contextlib import contextmanager
from time import process_time
from analyzer import *
import sys
import time
import queue
import shutil

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

def colorize(text, color_code):
    return f"\033[{color_code}m{text}\033[0m"

def prettyprint_event(event):
    kind = event['kind']
    name = event['metadata']['name']

    if event['custom'] == "create":
        location = f"on node {event['spec']['nodeName']}" if kind == 'Pod' else ''
        print(colorize(f'\n{kind} {name} has been added {location}', '32'))#green

    elif event['custom'] == "delete":
        location = f"on node {event['spec']['nodeName']}" if kind == 'Pod' else ''
        print(colorize(f'\n{kind} {name} has been removed {location}', '31'))#red

    elif event['custom'] == "update":
        location = f"on node {event['spec']['nodeName']}" if kind == 'Pod' else ''
        print(colorize(f'\n{kind} {name} has been updated {location}', '33'))#orange

                    
def initial_loader():

    # Delete the entire contents of the folder to have a blank slate
    try:
        shutil.rmtree("/home/ubuntu/current-cluster-objects/")
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"An error occurred while deleting contents: {e}")

    # look at all the pods, write their file, and print their existence
    print("# " + colorize("======PODS======", '36'))
    for event in pod_api_instance.list_namespaced_pod("test").items:
        podName = event.metadata.name
        labels = event.metadata.labels
        node_name=f"{event.spec.node_name}"

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
        u_pod['custom']='create'

        filename="/home/ubuntu/current-cluster-objects/{}.yaml".format(podName)
        
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        with open(filename, 'w+') as f:
            f.write(yaml.dump(u_pod, default_flow_style=False, sort_keys=False))
        
        print("#  " + colorize(f'Pod {podName} currently exists on node {node_name}', '36'))

    # look at all the policies, write their file, and print their existence
    print("#")
    print("# " + colorize("======POLICIES======", '36'))

    for event in policy_api_instance.list_namespaced_network_policy("test").items:
        PolName = event.metadata.name
        filename="/home/ubuntu/current-cluster-objects/{}.yaml".format(PolName)
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        if not os.path.exists(filename):
            with open(filename, 'w+') as f:
                os.system("kubectl get networkpolicy {} -n test -o yaml > {}".format(PolName, filename))

        print("#  " + colorize(f'NetworkPolicy {PolName} currently exists on the cluster', '36'))

def pods():
    w = watch.Watch()
    try:
        for event in w.stream(pod_api_instance.list_namespaced_pod, namespace = "test", timeout_seconds=0):

            updatedPod = event["object"]
            podName = updatedPod.metadata.name
            labels = updatedPod.metadata.labels
            node_name=f"{updatedPod.spec.node_name}"
            filename="/home/ubuntu/current-cluster-objects/{}.yaml".format(podName)

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

         
            # Newly created pods
            if event['type'] == "MODIFIED" and updatedPod.metadata.deletion_timestamp == None :  # Avoid the MODIFIED on delete
                if updatedPod.status.pod_ip is not None:      
                        if not os.path.exists(filename):
                            u_pod['custom']='create'
                            os.makedirs(os.path.dirname(filename), exist_ok=True)
                            with open(filename, 'w+') as f:
                                f.write(yaml.dump(u_pod, default_flow_style=False, sort_keys=False))
                            event_queue.put(u_pod)
            
            # Modified pods
            elif event['type'] =="MODIFIED" and updatedPod.metadata.deletion_timestamp == None:  # Avoid the MODIFIED on delete

                for cond in updatedPod.status.conditions:
                    if cond.type == "PodScheduled" and cond.status == "True":
                        if not os.path.exists(filename):                            
                            u_pod['custom']='update'
                            os.makedirs(os.path.dirname(filename), exist_ok=True)
                            with open(filename, 'w+') as f:
                                f.write(yaml.dump(u_pod, default_flow_style=False, sort_keys=False))
                            os.system('cp -a {} /home/ubuntu/current-cluster-objects/'.format(filename))
                            event_queue.put(u_pod)
                        else:
                            continue

            # Deleted pods
            elif event['type'] =="DELETED" :
                u_pod['custom']='delete'
                os.system('rm -f /home/ubuntu/current-cluster-objects/{}.yaml'.format(podName))
                event_queue.put(u_pod)

    except ProtocolError:
        print("watchPodEvents ProtocolError, continuing..")

def policies():
    w = watch.Watch()
    try:
        for event in w.stream(policy_api_instance.list_namespaced_network_policy, namespace = "test", timeout_seconds=0):
            temp_NewPol = event["object"]
            NewPol = temp_NewPol.to_dict()
            PolName = NewPol['metadata']['name']
            if PolName == "default-deny":
                continue
            #with timing_processtime("Time taken: "):

            if event['type'] =="ADDED":
                NewPol['custom']='create'
                filename="/home/ubuntu/current-cluster-objects/{}.yaml".format(PolName)
                os.makedirs(os.path.dirname(filename), exist_ok=True)
                if not os.path.exists(filename):
                    with open(filename, 'w+') as f:
                        os.system("kubectl get networkpolicy {} -n test -o yaml > {}".format(PolName, filename))
                    event_queue.put(NewPol)
           

            elif event['type'] =="DELETED":
                NewPol['custom']='delete'
                os.system('rm -f /home/ubuntu/current-cluster-objects/{}.yaml'.format(PolName))
                event_queue.put(NewPol)

            elif event['type'] =="MODIFIED":
                NewPol['custom']='update'
                with open(filename, 'w+') as f:
                    os.system("kubectl get networkpolicy {} -n test -o yaml > {}".format(PolName, filename))
                os.system('cp -a {} /home/ubuntu/current-cluster-objects/'.format(filename))
                event_queue.put(NewPol)

    except ProtocolError:
      print("watchPolicyEvents ProtocolError, continuing..")




def consumer():
    try:
        while True:
            event = event_queue.get() # blocks if no event is present untill a new one arrives
            prettyprint_event(event)
            analyzer.analyseEvent(event)
            print("\n-------------------Waiting for next event-------------------")
            event_queue.task_done()
    except ProtocolError:
        print("Consumer ProtocolError, continuing..")
            

   

if __name__ == "__main__":
    print("\n##################################################################################")
    print("# Watching resources in namespace test")
    print("# resources will de displayed in color codes:")
    print(f"#   - {colorize('Cyan', '36')} = resources already existing on watcher startup. These don't trigger verification")
    print(f"#   - {colorize('Green', '32')} = newly created resources")
    print(f"#   - {colorize('Red', '31')} = deleted resources")
    print(f"#   - {colorize('Orange', '33')} = modified resources")


    # First get all the already existing resources on the cluster and save them in their files
    print("#")
    print("# STEP 1/2: clearing old files and detecting existing resources")
    print("#")

    initial_loader()
    print("#")
    print("# STEP 2/2: Creating base kanoMatrix and VMmatrix")
    print("#")

    analyzer = Analyzer()
    # Analyse one empty event to generate the baseline reachability and vm matrix 
    analyzer.analyseEvent({})

    print("# Startup phase complete, now watching for new events on the cluster:")
    print("##################################################################################\n")

    # Run the watcher
    event_queue = queue.Queue()

    with concurrent.futures.ThreadPoolExecutor() as executor:
        p = executor.submit(pods)
        n = executor.submit(policies)
        c = executor.submit(consumer)
        


