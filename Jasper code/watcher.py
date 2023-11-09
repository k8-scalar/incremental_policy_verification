from kubernetes import client, config, watch
from kubernetes.config import ConfigException
import argparse
from urllib3.exceptions import ProtocolError
import concurrent.futures
import os, sys
import yaml
from contextlib import contextmanager
from time import process_time
from analyzer import EventAnalyzer
import sys
import time
import queue
import shutil
from parser import ConfigParser
import traceback


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
        print(colorize(f'\n{kind} {name} has been added {location}\n', '32'))#green

    elif event['custom'] == "delete":
        location = f"on node {event['spec']['nodeName']}" if kind == 'Pod' else ''
        print(colorize(f'\n{kind} {name} has been removed {location}\n', '31'))#red

    elif event['custom'] == "update":
        location = f"on node {event['spec']['nodeName']}" if kind == 'Pod' else ''
        print(colorize(f'\n{kind} {name} has been updated {location}\n', '33'))#orange
        
def prettyprint_end_event(event):
    kind = event['kind']
    name = event['metadata']['name']

    text = colorize(f'\nFinished handling event for ', '36')#cyan
    if event['custom'] == "create":
        text += colorize('adding', '32')#green

    elif event['custom'] == "delete":
        text += colorize('removing', '31')#red

    elif event['custom'] == "update":
        text += colorize('updating', '33')#orange
    text += colorize(f' {kind} {name}', '36')#cyan
    print(text)
        
def initial_loader():
    init_pods = []
    init_pols = []
    

    # look at all the pods, write their file, and print their existence
    print("# ======PODS======")
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
        print(f"# Pod {podName} currently exists on node {node_name}")
        formatted_pod = analyzer.cp.create_object(u_pod)
        init_pods.append(formatted_pod)
        existing_pods.append(formatted_pod.name)

    # look at all the policies, write their file, and print their existence
    print("#")
    print("# ======POLICIES======")

    for event in policy_api_instance.list_namespaced_network_policy("test").items:
        PolName = event.metadata.name
        print(f"# NetworkPolicy {PolName} currently exists on the cluster")
        new_data = yaml.safe_load(os.popen("kubectl get networkpolicy {} -n test -o yaml".format(PolName)).read())
        formatted_pol = analyzer.cp.create_object(new_data)
        init_pols.append(formatted_pol)
        existing_pols.append(formatted_pol.name)
    return(init_pods, init_pols)

def pods():
    w = watch.Watch()
    try:
        for event in w.stream(pod_api_instance.list_namespaced_pod, namespace = "test", timeout_seconds=0):
            updatedPod = event["object"]
            podName = updatedPod.metadata.name
            labels = updatedPod.metadata.labels
            node_name=f"{updatedPod.spec.node_name}"
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

            # Modified and create pods
            if event['type'] =="MODIFIED" and updatedPod.metadata.deletion_timestamp == None: #File exists so it is a modify and avoid delete modify
                for cond in updatedPod.status.conditions:
                    if cond.type == "PodScheduled" and cond.status == "True":
                        # CREATED
                        if podName not in existing_pods:
                            if updatedPod.status.pod_ip is not None:
                                u_pod['custom']='create'
                                existing_pods.append(podName)
                                event_queue.put(u_pod)
                        # MODIFY
                        elif podName in existing_pods:
                            u_pod['custom']='update'
                            event_queue.put(u_pod)
                       

            # Deleted pods
            elif event['type'] =="DELETED" :
                if podName in existing_pods:
                    u_pod['custom']='delete'
                    existing_pods.remove(podName)
                    event_queue.put(u_pod)


    except ProtocolError:
        print("watchPodEvents ProtocolError, continuing..")

def policies():
    w = watch.Watch()
    try:
        for event in w.stream(policy_api_instance.list_namespaced_network_policy, namespace = "test", timeout_seconds=0):
            # print(event)
            temp_NewPol = event["object"]
            NewPol = temp_NewPol.to_dict()
            PolName = NewPol['metadata']['name']
            if PolName == "default-deny":
                continue
           
            if event['type'] =="ADDED":
                if PolName not in existing_pols:
                    NewPol['custom']='create'
                    event_queue.put(NewPol)
                    existing_pols.append(PolName)

            elif event['type'] =="DELETED":
                existing_pols.remove(PolName)
                NewPol['custom']='delete'
                event_queue.put(NewPol)

            elif event['type'] =="MODIFIED":
                NewPol['custom']='update'
                event_queue.put(NewPol)

    except ProtocolError:
      print("watchPolicyEvents ProtocolError, continuing..")

def consumer():
    try:
        while True:
            event = event_queue.get() # blocks if no event is present untill a new one arrives
            prettyprint_event(event)
            analyzer.analyseEvent(event)
            prettyprint_end_event(event)
            # print("\n\n\npols")
            # print(analyzer.kic.pols)
            # print("\n\n\npods")
            # print(analyzer.kic.pods)
            # print("\n\n\ndict pods")
            # print(analyzer.kic.reachabilitymatrix.dict_pods)
            # print("\n\n\ndict pols")
            # print(analyzer.kic.reachabilitymatrix.dict_pols)
            print("\n-------------------Waiting for next event-------------------")
            event_queue.task_done()
    except ProtocolError:
        print("Consumer ProtocolError, continuing..")
            

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Jasper's Kubernetes event watcher")
    
    # Add a flag for verbose output
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-s", "--startup", action="store_true", help="Enable startup analysis")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug outputs")

    args = parser.parse_args()
    analyzer = EventAnalyzer(args.verbose, args.debug)

    print("\n##################################################################################")
    print("# Watching resources in namespace test")
    print("# resources will de displayed in color codes:")
    print(f"#   - {colorize('Green', '32')} = newly created resources")
    print(f"#   - {colorize('Red', '31')} = deleted resources")
    print(f"#   - {colorize('Orange', '33')} = modified resources")


    # First get all the already existing resources on the cluster and save them in their files
    print("#")
    print("# STEP 1/2: Detecting existing resources")
    print("#")
    existing_pods = []
    existing_pols = []
    (init_pods, init_pols) = initial_loader()
    print("#")
    print("# STEP 2/2: Creating base kanoMatrix and VMmatrix")
    print("#")
    analyzer.startup(init_pods, init_pols)

    if args.startup:
        print("#")
        print("# STEP EXTRA: Checking startup for Security Group Conflicts")
        print("#")
        analyzer.analyseStartup()
        
    print("# Startup phase complete, now watching for new events on the cluster:")
    print("##################################################################################\n")


    # Run the watcher
    event_queue = queue.Queue()

    with concurrent.futures.ThreadPoolExecutor() as executor:
        p = executor.submit(pods)
        n = executor.submit(policies)
        c = executor.submit(consumer)
        exception = c.exception()
        # handle exceptional case
        if exception:
                print(exception)
                traceback.print_exception(type(exception), exception, exception.__traceback__)
      
            


