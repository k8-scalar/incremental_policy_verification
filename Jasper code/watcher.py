import array
from sqlite3 import Time
from xmlrpc.client import Boolean, boolean
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
from parser import ConfigParser
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

class EventWatcher:
    existing_pods: array
    existing_pols: array
    event_queue: queue.Queue
    analyzer: EventAnalyzer
    stop: boolean
    event_detected: threading.Event # to signal when an event has been detected, for experiment purposes
    elapesed_time: int

    def __init__(self, verbose = False, debug = False, startup = False):
        self.stop = False
        self.existing_pods = []
        self.existing_pols = []
        self.event_detected = threading.Event()  # Create an event object
        self.elapesed_time = 0
        self.memory_usage = None
        self.analyzer = EventAnalyzer(verbose, debug) # to signal when an event has been detected, for experiment purposes

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
        (init_pods, init_pols) = self.initial_loader(verbose)
        print("#")
        print("# STEP 2/2: Creating base kanoMatrix and VMmatrix")
        print("#")
        self.analyzer.startup(init_pods, init_pols)

        if startup:
            print("#")
            print("# STEP EXTRA: Checking startup for Security Group Conflicts")
            print("#")
            self.analyzer.analyseStartup()
            
        print("# Startup phase complete")
        print("##################################################################################\n")

    def run(self, main_thread=False):
        print("Starting to watch for new events on the cluster..\n\n")
        # Run the watcher
        
        self.event_queue = queue.Queue()

        if main_thread:
            signal.signal(signal.SIGINT, self.handle_interrupt)

        with concurrent.futures.ThreadPoolExecutor() as executor:
            p = executor.submit(self.pods)
            n = executor.submit(self.policies)
            c = executor.submit(self.consumer)
            exception = c.exception()
            # handle exceptional case
            if exception:
                    print(exception)
                    traceback.print_exception(type(exception), exception, exception.__traceback__)
        
    def get_time_and_memory(self):
        return (self.elapesed_time, self.memory_usage)
    
    def handle_interrupt(self, signum, frame):
        print("Terminating the event watcher...")
        self.stop_watching()
        sys.exit(0)

    def initial_loader(self, verbose):
        init_pods = []
        init_pols = []

        # look at all the pods, write their file, and print their existence
        if verbose: 
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
            if verbose: 
                print(f"# Pod {podName} currently exists on node {node_name}")
            formatted_pod = self.analyzer.cp.create_object(u_pod)
            init_pods.append(formatted_pod)
            self.existing_pods.append(formatted_pod.name)

        # look at all the policies, write their file, and print their existence
        if verbose:
            print("#")
            print("# ======POLICIES======")

        for event in policy_api_instance.list_namespaced_network_policy("test").items:
            PolName = event.metadata.name
            if verbose:
                print(f"# NetworkPolicy {PolName} currently exists on the cluster")
            new_data = yaml.safe_load(os.popen("kubectl get networkpolicy {} -n test -o yaml".format(PolName)).read())
            formatted_pol = self.analyzer.cp.create_object(new_data)
            init_pols.append(formatted_pol)
            self.existing_pols.append(formatted_pol.name)
        return(init_pods, init_pols)

    def pods(self):
        w = watch.Watch()
        try:
            while not self.stop:
                for event in w.stream(pod_api_instance.list_namespaced_pod, namespace = "test", timeout_seconds=1):
                    # stop the loop gracefully
                    if self.stop:
                        break
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
                                if podName not in self.existing_pods:
                                    if updatedPod.status.pod_ip is not None:
                                        u_pod['custom']='create'
                                        self.existing_pods.append(podName)
                                        self.event_queue.put(u_pod)
                                # MODIFY
                                elif updatedPod.metadata != pod_api_instance.read_namespaced_pod(name=podName, namespace="test")['metadata']:
                                    u_pod['custom']='update'
                                    self.event_queue.put(u_pod)
                            

                    # Deleted pods
                    elif event['type'] =="DELETED" :
                        if podName in self.existing_pods:
                            u_pod['custom']='delete'
                            self.existing_pods.remove(podName)
                            self.event_queue.put(u_pod)
            print("STOPPING PODS")
        except ProtocolError:
            print("watchPodEvents ProtocolError, continuing..")

    def policies(self):
        w = watch.Watch()
        try:
            while not self.stop:
                for event in w.stream(policy_api_instance.list_namespaced_network_policy, namespace = "test", timeout_seconds=1):
                    # stop the loop gracefully
                    if self.stop:
                        break
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
                        self.existing_pols.remove(PolName)
                        NewPol['custom']='delete'
                        self.event_queue.put(NewPol)

                    elif event['type'] =="MODIFIED":
                        if temp_NewPol.metadata != policy_api_instance.read_namespaced_network_policy(name=PolName, namespace="test")['metadata']:
                            NewPol['custom']='update'
                            self.event_queue.put(NewPol)
            print("STOPPING POLICIES")
        except ProtocolError:
            print("watchPolicyEvents ProtocolError, continuing..")

    

    def consumer(self):
        try:
            while not self.stop:
                event = self.event_queue.get() # blocks if no event is present untill a new one arrives
                if event is not None:
                    prettyprint_event(event)

                    tracemalloc.start()
                    time_start = time.perf_counter() # Start the timer
                    self.analyzer.analyseEvent(event)
                    time_elapsed = time.perf_counter() - time_start # final computation time
                    current, peak = tracemalloc.get_traced_memory()
                    self.memory_usage = (current, peak)
                    tracemalloc.stop()
                    self.elapesed_time = time_elapsed

                    prettyprint_end_event(event)
                    print("\n-------------------Waiting for next event-------------------")
                    self.event_queue.task_done()
                    self.event_detected.set()  # Signal that an event has been detected, for experiment purposes
            print("STOPPING CONSUMER")
        except ProtocolError:
            print("Consumer ProtocolError, continuing..")

    def stop_watching(self):
        self.stop = True 
        self.event_queue.put(None)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Jasper's Kubernetes event watcher")
    
    # Add flags for verbose output, startup verification check and debug output
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-s", "--startup", action="store_true", help="Enable startup analysis")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug outputs")

    args = parser.parse_args()
    ew = EventWatcher(args.verbose, args.debug, args.startup)
    ew.run(True)
    
            


