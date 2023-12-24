import array
from xmlrpc.client import boolean
from kubernetes import client, config, watch
from kubernetes.config import ConfigException
import argparse
from urllib3.exceptions import ProtocolError
import concurrent.futures
import os, sys
import yaml
import datetime
from analyzer import EventAnalyzer
import sys
import time
import queue
import traceback
import signal
import threading
import time
import tracemalloc


# Configure the client to use in-cluster config or local kube config file
try:
   config.load_incluster_config()
except ConfigException:
   config.load_kube_config()

# The different API for pods and policies respectively
pod_api_instance = client.CoreV1Api()
policy_api_instance = client.NetworkingV1Api()

# Simply colorizes a text using ANSI color codes
def colorize(text, color_code):
    return f"\033[{color_code}m{text}\033[0m"

# Prints the type of event that is caught in a corresponding color
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
        
# Prints the type of event that has been handled in a corresponding color
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

class EventWatcher:
    existing_pods: array 
    existing_pols: array
    event_queue: queue.Queue
    analyzer: EventAnalyzer
    stop: boolean
    podwatch: watch
    polwatch: watch
    def __init__(self, ns, verbose = False, debug = False, startup = False):
        self.stop = False
        self.existing_pods = []
        self.existing_pols = []
        self.elapsed_time = 0
        self.memory_usage = None
        self.analyzer = EventAnalyzer(verbose, debug)
        self.podwatch = watch.Watch()
        self.polwatch = watch.Watch()

        print("\n##################################################################################")
        print(f"# Watching resources in namespace {ns}")
        print("# resources will de displayed in color codes:")
        print(f"#   - {colorize('Green', '32')} = newly created resources")
        print(f"#   - {colorize('Red', '31')} = deleted resources")
        print(f"#   - {colorize('Orange', '33')} = modified resources")


        print("#")
        print("# STEP 1/2: Detecting existing resources")
        print("#")
        # First get all the already existing resources on the cluster
        (init_pods, init_pols) = self.initial_loader(ns, verbose)
        print("#")
        print("# STEP 2/2: Creating base kanoMatrix and VMmatrix")
        print("#")
        # Starting the analyzer will generate random sg groups and rules in the sgic and create the intial reachabilitymatrix
        self.analyzer.startup(init_pods, init_pols)

        if startup:
            print("#")
            print("# STEP EXTRA: Checking startup for Security Group Conflicts")
            print("#")
            self.analyzer.analyseStartup()
            
        print("# Startup phase complete")
        print("##################################################################################\n")

    # Main thread indicates whether or not this file is called directly or from another file, and guarantees that watcher will stop when requested
    def run(self, ns, main_thread=False):
        print("Starting to watch for new events on the cluster..\n\n")
        # Run the watcher
    
        self.event_queue = queue.Queue()

        # For correct interruption handling
        if main_thread:
            signal.signal(signal.SIGINT, self.handle_interrupt)
        # 3 simultaneously running threads
        with concurrent.futures.ThreadPoolExecutor() as executor:
            p = executor.submit(self.pods, ns)
            n = executor.submit(self.policies, ns)
            c = executor.submit(self.consumer)
            exception = c.exception()
            exception2 = n.exception()
            exception3 = p.exception()
            # handle exceptional case
            if exception:
                    print(exception)
                    traceback.print_exception(type(exception), exception, exception.__traceback__)
            if exception2:
                    print(exception2)
                    traceback.print_exception(type(exception2), exception2, exception2.__traceback__)
            if exception3:
                    print(exception3)
                    traceback.print_exception(type(exception3), exception3, exception3.__traceback__)
        
    def handle_interrupt(self, signum, frame):
        print("Terminating the event watcher...")
        self.stop_watching()
        sys.exit(0)

    def initial_loader(self, ns, verbose):
        init_pods = []
        init_pols = []

        # look at all the pods, write their file, and print their existence
        if verbose: 
            print("# ======PODS======")
        for event in pod_api_instance.list_namespaced_pod(ns).items:
            podName = event.metadata.name
            labels = event.metadata.labels
            node_name=f"{event.spec.node_name}"

            u_pod = {}
            u_pod['apiVersion'] = 'v1'
            u_pod['kind'] = 'Pod'
            u_pod['metadata'] = {
                'name': podName,
                'namespace': ns,
                'labels': labels     
            }
            u_pod['spec']={
                'nodeName':node_name
            }
            u_pod['custom']='create'
            if verbose: 
                print(f"# Pod {podName} currently exists on node {node_name}")
            formatted_pod = self.analyzer.cp.create_object(u_pod)
            init_pods.append(formatted_pod)
            self.existing_pods.append(formatted_pod.name)

        # look at all the policies, write their file, and print their existence
        if verbose:
            print("#")
            print("# ======POLICIES======")

        for event in policy_api_instance.list_namespaced_network_policy(ns).items:
            PolName = event.metadata.name
            if verbose:
                print(f"# NetworkPolicy {PolName} currently exists on the cluster")
            
            new_data = yaml.safe_load(os.popen("kubectl get networkpolicy {} -n {} -o yaml".format(PolName, ns)).read())
            while new_data == None:
                time.sleep(1)
                new_data = yaml.safe_load(os.popen("kubectl get networkpolicy {} -n {} -o yaml".format(PolName, ns)).read())
            formatted_pol = self.analyzer.cp.create_object(new_data)
            init_pols.append(formatted_pol)
            self.existing_pols.append(formatted_pol.name)
        return(init_pods, init_pols)

    # This method captures all events in the pod api, filters them and adds the final ones to the queue
    def pods(self, ns):
        while not self.stop:
            for event in self.podwatch.stream(pod_api_instance.list_namespaced_pod, namespace = ns, timeout_seconds=10):
                updatedPod = event["object"]
                podName = updatedPod.metadata.name
                labels = updatedPod.metadata.labels
                node_name=f"{updatedPod.spec.node_name}"
                u_pod = {}
                u_pod['apiVersion'] = 'v1'
                u_pod['kind'] = 'Pod'
                u_pod['metadata'] = {
                    'name': podName,
                    'namespace': ns,
                    'labels': labels     
                }
                u_pod['spec']={
                    'nodeName':node_name
                }
                # Modified and create pods
                if event['type'] =="MODIFIED" and updatedPod.metadata.deletion_timestamp == None: #File exists so it is a modify and avoid delete modify
                    if updatedPod.status:
                        if updatedPod.status.conditions:
                            for cond in updatedPod.status.conditions:
                                if cond.type == "PodScheduled" and cond.status == "True":
                                    # CREATED
                                    if podName not in self.existing_pods:
                                        if updatedPod.status.pod_ip is not None:
                                            u_pod['custom']='create'
                                            self.existing_pods.append(podName)
                                            self.event_queue.put(u_pod)
                                    
                                    else:
                                        if updatedPod.status.pod_ip is not None:
                                            u_pod['custom']='update'
                                            self.event_queue.put(u_pod)
                                
                                        

                # Deleted pods
                elif event['type'] =="DELETED" :
                    if podName in self.existing_pods:
                        u_pod['custom']='delete'
                        self.existing_pods.remove(podName)
                        self.event_queue.put(u_pod)
    
        print("STOPPING PODS")
        self.pods_started.clear()

    # This method captures all network policies in the policy api, filters them and adds the final ones to the queue
    def policies(self, ns):
        while not self.stop:
            for event in self.polwatch.stream(policy_api_instance.list_namespaced_network_policy, namespace = ns, timeout_seconds=10):
                # stop the loop gracefully
                temp_NewPol = event["object"]
                NewPol = temp_NewPol.to_dict()
                PolName = NewPol['metadata']['name']
        
                if PolName == "default-deny":
                    continue
            
                if event['type'] =="ADDED":
                    if PolName not in self.existing_pols:
                        NewPol['custom']='create'
                        self.event_queue.put(NewPol)
                        self.existing_pols.append(PolName)

                elif event['type'] =="DELETED":
                    if PolName in self.existing_pols:
                        self.existing_pols.remove(PolName)
                        NewPol['custom']='delete'
                        self.event_queue.put(NewPol)

                elif event['type'] =="MODIFIED":
                    if PolName in self.existing_pols:
                        NewPol['custom']='update'
                        self.event_queue.put(NewPol)

        print("STOPPING POLICIES")
        self.policies_started.clear()

    # The consumer takes events from the queue and passes them to the analyzer.
    def consumer(self):
        try:
            while not self.stop:
                event = self.event_queue.get() # blocks if no event is present untill a new one arrives
                if event is not None:
                    prettyprint_event(event)
                    self.analyzer.analyseEvent(event)
                    prettyprint_end_event(event)
                    print("\n-------------------Waiting for next event-------------------")
                    self.event_queue.task_done()
            print("STOPPING CONSUMER")
        except ProtocolError:
            print("Consumer ProtocolError, continuing..")

    def stop_watching(self):
        self.stop = True
        # Putting none in the queue will stop the consumer
        self.event_queue.put(None)
        self.podwatch.stop()
        self.polwatch.stop()



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Jasper's Kubernetes event watcher")
    parser.add_argument("namespace", type=str)
    # Add flags for verbose output, startup verification check and debug output
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-s", "--startup", action="store_true", help="Enable startup analysis")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug outputs")

    args = parser.parse_args()
    ew = EventWatcher(args.namespace, args.verbose, args.debug, args.startup)
    ew.run(args.namespace, True)
    
            


