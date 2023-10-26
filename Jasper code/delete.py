import argparse
import random
from kubernetes import client, config

config.load_kube_config()
pod_api_instance = client.CoreV1Api()
np_api_instance = client.NetworkingV1Api()

parser = argparse.ArgumentParser()
parser.add_argument("nr_of_pods")
parser.add_argument("nr_of_policies")
args = parser.parse_args()

print("\n------------PODS-------------")
for i in range(int(args.nr_of_pods)):
    try:
        pod_api_instance.delete_namespaced_pod(name=f"pod-{i}", namespace="test", body=client.V1DeleteOptions())
        print(f"Pod-{i} deleted successfully.")
    except client.exceptions.ApiException as e:
        print(f"Error deleting Pod-{i}: {e}")

print("\n------------POLICIES-------------")
for j in range(int(args.nr_of_policies)):
    try:
        np_api_instance.delete_namespaced_network_policy(name=f"policy-{j}", namespace="test")
        print(f"policy-{j} deleted successfully.")
    except client.exceptions.ApiException as e:
        print(f"Error deleting policy-{j}: {e}")