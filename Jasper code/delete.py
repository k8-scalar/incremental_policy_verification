import argparse
import random
from kubernetes import client, config
import time
config.load_kube_config()


def remove_random(removePod, ns):
    if removePod:
        pod_api_instance = client.CoreV1Api()
        try: 
            pod_list = pod_api_instance.list_namespaced_pod(ns)
        except client.exceptions.ApiException as e:
            print(f"Failed retrieving pods from cluster: {e}")
        if pod_list.items:
            # Choose a random pod from the list
            random_pod = random.choice(pod_list.items)
            try:
                pod_api_instance.delete_namespaced_pod(name=random_pod.metadata.name, namespace=ns, body=client.V1DeleteOptions())
                print(f"Pod {random_pod.metadata.name} deleted successfully.")
            except client.exceptions.ApiException as e:
                print(f"Error deleting Pod {random_pod.metadata.name}: {e}")
    else:
        np_api_instance = client.NetworkingV1Api()
        try: 
            policy_list = np_api_instance.list_namespaced_network_policy(ns)
        except client.exceptions.ApiException as e:
            print(f"Failed retrieving policies from cluster: {e}")
        if policy_list.items:
            # Choose a random policy from the list
            random_pol = random.choice(policy_list.items)
            try:
                np_api_instance.delete_namespaced_network_policy(name=random_pol.metadata.name, namespace=ns, body=client.V1DeleteOptions())
                print(f"Pod {random_pol.metadata.name} deleted successfully.")
            except client.exceptions.ApiException as e:
                print(f"Error deleting Pod {random_pol.metadata.name}: {e}")

def resetCluster(ns):
    pod_api_instance = client.CoreV1Api()
    np_api_instance = client.NetworkingV1Api()
    config.load_kube_config()
    delete_options = client.V1DeleteOptions(
        propagation_policy='Foreground',
        grace_period_seconds=0
    )
    # List all the pods in the namespace and delete them
    print("\n------------DELETING ALL PODS-------------")
    pod_list = pod_api_instance.list_namespaced_pod(namespace=ns)
    for pod in pod_list.items:
        try:    
            pod_api_instance.delete_namespaced_pod(pod.metadata.name, ns, body=delete_options)
        except client.exceptions.ApiException as e:
            print(f"Error deleting {pod.metadata.name}: {e}")

    # List all the policies and delete them
    print("\n------------DELETING ALL POLICIES-------------")
    policy_list = np_api_instance.list_namespaced_network_policy(namespace=ns)
    for policy in policy_list.items:
        try:
            np_api_instance.delete_namespaced_network_policy(policy.metadata.name, ns, body=delete_options)
        except client.exceptions.ApiException as e:
            print(f"Error deleting {policy.metadata.name}: {e}")
    
    # wait for it to be fully deleted to stop conflicts upon creation after
    while len(np_api_instance.list_namespaced_network_policy(namespace=ns).items) != 0 or len(pod_api_instance.list_namespaced_pod(namespace=ns).items) != 0:
        time.sleep(1)
    print("\nSuccesfully deleted all pods and policies from the cluster")
 

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("namespace", type=str)
    args = parser.parse_args()
    resetCluster(args.namespace)