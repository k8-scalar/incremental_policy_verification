import argparse
import random
from kubernetes import client, config
import time
import datetime
config.load_kube_config()
pod_api_instance = client.CoreV1Api()
np_api_instance = client.NetworkingV1Api()

def is_pod_deleted(pod_name, ns):
   
    try:
        pod_api_instance.read_namespaced_pod_status(pod_name, ns)
        return False
    except client.exceptions.ApiException as e:
        return True


def remove_random(removePod, ns):
    start_time = None
    if removePod:
        try: 
            pod_list = pod_api_instance.list_namespaced_pod(ns)
        except client.exceptions.ApiException as e:
            print(f"Failed retrieving pods from cluster: {e}")
        if pod_list.items:
            # Choose a random pod from the list
            random_pod = random.choice(pod_list.items)
            try:
                pod_api_instance.delete_namespaced_pod(name=random_pod.metadata.name, namespace=ns, body=client.V1DeleteOptions())
                start_time = datetime.datetime.now()
                print(f"Pod {random_pod.metadata.name} deleted successfully.")
            except client.exceptions.ApiException as e:
                print(f"Error deleting Pod {random_pod.metadata.name}: {e}")
    else:
        try: 
            policy_list = np_api_instance.list_namespaced_network_policy(ns)
        except client.exceptions.ApiException as e:
            print(f"Failed retrieving policies from cluster: {e}")
        if policy_list.items:
            # Choose a random policy from the list
            random_pol = random.choice(policy_list.items)
            try:
                np_api_instance.delete_namespaced_network_policy(name=random_pol.metadata.name, namespace=ns, body=client.V1DeleteOptions())
                start_time = datetime.datetime.now()
                print(f"Pod {random_pol.metadata.name} deleted successfully.")
            except client.exceptions.ApiException as e:
                print(f"Error deleting Pod {random_pol.metadata.name}: {e}")
    return start_time

def resetCluster(ns):
    delete_options = client.V1DeleteOptions(
        propagation_policy='Background',
        grace_period_seconds=0
    )
    # List all the pods in the namespace and delete them
    print("\n------------DELETING ALL PODS-------------")
    pod_failed = True
    while pod_failed:
        try:
            # Deleting all pods in the specified namespace
            pod_api_instance.delete_collection_namespaced_pod(namespace=ns, body=delete_options)
            print(f"Deleted all pods in namespace {ns}")
            pod_failed = False
        except Exception as e:
            print(f"Error deleting pods: {e}")
            time.sleep(8)

    # List all the policies and delete them
    print("\n------------DELETING ALL POLICIES-------------")
    pol_failed = True
    while pol_failed:
        try:
            # Deleting all pods in the specified namespace
            np_api_instance.delete_collection_namespaced_network_policy(namespace=ns, body=delete_options)
            print(f"Deleted all network policies in namespace {ns}")
            pol_failed = False
        except Exception as e:
            print(f"Error deleting network policies: {e}")
            time.sleep(8)

    
    print("\nMaking sure everything got removed correctly")

    pod_list = pod_api_instance.list_namespaced_pod(namespace=ns)
    while len(pod_list.items) != 0:
        time.sleep(10)
        pod_list = pod_api_instance.list_namespaced_pod(namespace=ns)

    policy_list = np_api_instance.list_namespaced_network_policy(namespace=ns)
    while len(policy_list.items) != 0:
        time.sleep(10)
        policy_list = np_api_instance.list_namespaced_network_policy(namespace=ns)
    print("\nSuccesfully deleted all pods and policies from the cluster")
 

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("namespace", type=str)
    args = parser.parse_args()
    resetCluster(args.namespace)