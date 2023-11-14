import argparse
import enum
from delete import resetCluster, remove_random
from deploy import deploy
from watcher import EventWatcher
import threading
import pandas as pd
from original.owatcher import *
from original.omodel import ReachabilityMatrix as RM
import time
import tracemalloc

    
from kubernetes import client, config
config.load_kube_config()

def colorize(text, color_code):
    return f"\033[{color_code}m{text}\033[0m"

if __name__ == "__main__":
    matrices = []
    o_matrices = []
    parser = argparse.ArgumentParser()
    parser.add_argument("nr_of_runs", type=int)
    parser.add_argument("nr_of_pods", type=int)
    parser.add_argument("nr_of_policies", type=int)
    parser.add_argument("namespace", type=str)
    parser.add_argument("key_limit", type=int)
    parser.add_argument("event_type", type=str)
    args = parser.parse_args()

    results = []
    failed_data = []

    print(colorize("RUNNING TESTS WITH FOLLOWING VARIABLES:",35))
    print(colorize(f"    -amount of runs: {args.nr_of_runs}", 35))
    print(colorize(f"    -nr of pods: {args.nr_of_pods}", 35))
    print(colorize(f"    -nr of policies: {args.nr_of_policies}", 35))
    print(colorize(f"    -namespace: {args.namespace}", 35))
    print(colorize(f"    -key limit: {args.key_limit}", 35))
    print(colorize(f"    -event_type: {args.event_type}", 35))

 
    for i in range(args.nr_of_runs):
        print(colorize(f"\n\n----------------------RUN {i}----------------------", 35))
        # STEP 1: Remove all pods and policies from cluster
        print(colorize("\nSTEP 1: Removing all pods and policies from cluster", 36))
        resetCluster(args.namespace)

        # STEP 2: Deploy the specified pods and policies given by the variables
        print(colorize("\nSTEP 2: Deploy the specified pods and policies given by the variables", 36))
        deploy(args.nr_of_pods, args.nr_of_policies, args.namespace, args.key_limit)

        # STEP 3: Start the watcher (non-verbose, non-debug, non-startupcheck)
        print(colorize("\nSTEP 3: Start the watcher", 36))
        # Create and start the EventWatcher in a separate thread
        ew = EventWatcher(False, False, False)
        # make sure the watcher is ready
        while len(ew.existing_pods) != args.nr_of_pods or len(ew.existing_pols) != args.nr_of_policies:
            time.sleep(1)
        ew_thread = threading.Thread(target=ew.run) 
        ew_thread.start()
        
        
        # STEP 4: execute event
        print(colorize(f"\nSTEP 4: execute event: {args.event_type}", 36))
        event = args.event_type
        if event == "addNP":
            deploy(0, 1, args.namespace, args.key_limit)
        elif event == "deleteNP":
            remove_random(False, args.namespace)
        elif event == "addPod":
            deploy(1, 0, args.namespace, args.key_limit)
        elif event == "deletePod":
            remove_random(True, args.namespace)

        else:
            raise Exception("Not a correct event type.")

        # STEP 5: Wait for the event to be handled
        print(colorize("\nSTEP 5: Wait for the event to be handled", 36))
        ew.event_detected.wait() # This makes the main thread wait for the ew_thread to finish

        # STEP 6: Get the processsing time and memory usage:
        print(colorize("\nSTEP 6: Get processing time and memory usage", 36))
        (elapsed_time, (current, peak)) = ew.get_time_and_memory()
        print(f"    increment method time usage: {elapsed_time} seconds")
        print(f"    increment method current memory usage is {current / 10**3}KB; Peak was {peak / 10**3}KB; Diff = {(peak - current) / 10**3}KB")
        
        # STEP 7: stop the watcher
        print(colorize("\nSTEP 7: stop the watcher", 36))
        ew.stop_watching()

        # STEP 8: Use original kano generation to get matrix and its processing time
        print(colorize("\nSTEP 8: Get original kano generation time and memory usage", 36))
       
        (ocontainers, opolicies) = o_get_pods_and_policies(args.namespace)
        tracemalloc.start()
        o_time_start = time.perf_counter() # Start the timer
        o_matrix = RM.build_matrix(ocontainers, opolicies)#, build_transpose_matrix=True)
        o_time_elapsed = time.perf_counter() - o_time_start # final computation time
        o_current, o_peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        
        print(f"generative method time usage: {o_time_elapsed} seconds")
        print(f"generative method current memory usage is {o_current / 10**3}KB; Peak was {o_peak / 10**3}KB; Diff = {(o_peak - o_current) / 10**3}KB")
        
        if o_matrix.matrix == ew.analyzer.kic.reachabilitymatrix.matrix:
            results.append({'Run Number': i, 'Elapsed Time - INCR (seconds)': elapsed_time, 'Mem start analyser - INCR (bytes)': (current), 'Mem peak analyser - INCR (bytes)': (peak), 'Mem Diff - INCR (bytes)': ((peak - current)), 'Elapsed Time - GEN (seconds)': o_time_elapsed, 'Mem start analyser - GEN (bytes)': (o_current), 'Mem peak analyser - GEN (bytes)': (o_peak), 'Mem Diff - GEN (bytes)': ((o_peak - o_current))})

        else:
            results.append({'Run Number': i, 'Elapsed Time - INCR (seconds)': 'ERROR', 'Mem start analyser - INCR (bytes)': 'ERROR', 'Mem peak analyser - INCR (bytes)': 'ERROR', 'Mem Diff - INCR (bytes)':'ERROR', 'Elapsed Time - GEN (seconds)': 'ERROR', 'Mem start analyser - GEN (bytes)': 'ERROR', 'Mem peak analyser - GEN (bytes)': 'ERROR', 'Mem Diff - GEN (bytes)': 'ERROR'})
            print("\no_matrix")
            for row in o_matrix.matrix:
                print(row)
            print("\nmatrix")
            for row in ew.analyzer.kic.reachabilitymatrix.matrix:
                print(row)
            break
   
    experiment_info = {
    'Number of Runs': args.nr_of_runs,
    'Number of Pods': args.nr_of_pods,
    'Number of Policies': args.nr_of_policies,
    'Namespace': args.namespace,
    'Key Limit': args.key_limit,
    'Event Type': args.event_type
    }
    results_df = pd.DataFrame(results)

    experiment_info_df = pd.DataFrame([experiment_info])

    with pd.ExcelWriter('results.xlsx', engine='xlsxwriter') as writer:
        experiment_info_df.to_excel(writer, sheet_name='Experiment_Info', index=False)  # Add the experiment info to a separate sheet

        results_df.to_excel(writer, sheet_name='Results', index=False)  # Add the results to another sheet
        results_df.to_excel('results.xlsx', index=False)
    
    print(colorize("ENDED TESTS WITH FOLLOWING VARIABLES:",35))
    print(colorize(f"    -amount of runs: {args.nr_of_runs}", 35))
    print(colorize(f"    -nr of pods: {args.nr_of_pods}", 35))
    print(colorize(f"    -nr of policies: {args.nr_of_policies}", 35))
    print(colorize(f"    -namespace: {args.namespace}", 35))
    print(colorize(f"    -key limit: {args.key_limit}", 35))
    print(colorize(f"    -event_type: {args.event_type}", 35))
