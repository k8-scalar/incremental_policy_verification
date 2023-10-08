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
        if len(event['changes']) > 0:
            for change in event['changes']: 
                print(colorize(f"  Change at {change['key']}: {change['old']} --> {change['new']} ", '33'))#orange
        print("")

def compare_values(old_value, new_value, changes, parent_key=""):
        if old_value != new_value:
            changes.append({
                "key": parent_key,
                "old": old_value,
                "new": new_value
            })

def compare_dicts(old_dict, new_dict, changes, parent_key=""):
    for key in old_dict.keys():
        old_value = old_dict[key]
        new_value = new_dict.get(key)
        current_key = f"{parent_key}.{key}" if parent_key else key

        if isinstance(old_value, dict) and isinstance(new_value, dict):
            compare_dicts(old_value, new_value, changes, current_key )
        elif isinstance(old_value, list) and isinstance(new_value, list):
            compare_lists(old_value, new_value, changes, current_key)
        else:
            compare_values(old_value, new_value, changes, current_key)

def compare_lists(old_list, new_list, parent_key, changes):
    for index, (old_item, new_item) in enumerate(zip(old_list, new_list)):
        if isinstance(old_item, dict) and isinstance(new_item, dict):
            compare_dicts(old_item, new_item, changes, f"{parent_key}[{index}]")
        elif isinstance(old_item, list) and isinstance(new_item, list):
            compare_lists(old_item, new_item, changes, f"{parent_key}[{index}]")
        else:
            compare_values(old_item, new_item, changes, f"{parent_key}[{index}]")

def find_spec_changes(old_data, new_data):
    changes = []
    old_spec = old_data['spec']
    new_spec = new_data['spec']
    compare_dicts(old_spec, new_spec, changes)
    return changes

def find_metadata_changes(old_data, new_data):
    changes = []
    old_spec = old_data['metadata']
    new_spec = new_data['metadata']
    compare_dicts(old_spec, new_spec, changes)
    return changes

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

            # Modified pods
            if event['type'] =="MODIFIED" and os.path.exists(filename) and updatedPod.metadata.deletion_timestamp == None: #File exists so it is a modify and avoid delete modify
                for cond in updatedPod.status.conditions:
                    if cond.type == "PodScheduled" and cond.status == "True":

                            with open(filename, "r") as file:
                                yaml_data = yaml.safe_load(file)

                            diff = find_metadata_changes(yaml_data, u_pod)

                            u_pod['changes'] = diff

                            u_pod['custom']='update'

                            os.makedirs(os.path.dirname(filename), exist_ok=True)
                            with open(filename, 'w+') as f:
                                f.write(yaml.dump(u_pod, default_flow_style=False, sort_keys=False))
                            event_queue.put(u_pod)

            # Newly created pods
            elif event['type'] == "MODIFIED" and updatedPod.metadata.deletion_timestamp == None:  # Avoid the MODIFIED on delete
                if updatedPod.status.pod_ip is not None:      
                        if not os.path.exists(filename):
                            u_pod['custom']='create'
                            os.makedirs(os.path.dirname(filename), exist_ok=True)
                            with open(filename, 'w+') as f:
                                f.write(yaml.dump(u_pod, default_flow_style=False, sort_keys=False))
                            event_queue.put(u_pod)
            
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
                filename="/home/ubuntu/current-cluster-objects/{}.yaml".format(PolName)
                with open(filename, "r") as file:
                    yaml_data = yaml.safe_load(file)

                new_data = yaml.safe_load(os.popen("kubectl get networkpolicy {} -n test -o yaml".format(PolName)).read())
        
                diff = find_spec_changes(yaml_data, new_data)
                NewPol['changes'] = diff

                with open(filename, 'w+') as f:
                    os.system("kubectl get networkpolicy {} -n test -o yaml > {}".format(PolName, filename))
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
    parser = argparse.ArgumentParser(description="My Python Script")
    
    # Add a flag for verbose output
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")

    args = parser.parse_args()
    analyzer = EventAnalyzer(args.verbose)

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

    analyzer.startup()

    print("# Startup phase complete, now watching for new events on the cluster:")
    print("##################################################################################\n")

    # Run the watcher
    event_queue = queue.Queue()

    with concurrent.futures.ThreadPoolExecutor() as executor:
        p = executor.submit(pods)
        n = executor.submit(policies)
        c = executor.submit(consumer)
        


