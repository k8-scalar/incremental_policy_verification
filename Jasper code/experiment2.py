import argparse
from delete import resetCluster, remove_random
from deploy import deploy
from watcher import EventWatcher
import threading
import pandas as pd
import time
import tracemalloc
import signal

    
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
    results2 = []

    print(colorize("RUNNING TESTS WITH FOLLOWING VARIABLES:",35))
    print(colorize(f"    -amount of runs: {args.nr_of_runs}", 35))
    print(colorize(f"    -nr of pods: {args.nr_of_pods}", 35))
    print(colorize(f"    -nr of policies: {args.nr_of_policies}", 35))
    print(colorize(f"    -namespace: {args.namespace}", 35))
    print(colorize(f"    -key limit: {args.key_limit}", 35))
    print(colorize(f"    -event_type: {args.event_type}", 35))

    i = 0
    while i < args.nr_of_runs:
        print(colorize(f"\n\n----------------------RUN {i}----------------------", 35))
        # STEP 1: Remove all pods and policies from cluster
        print(colorize("\nSTEP 1: Removing all pods and policies from cluster", 36))
        resetCluster(args.namespace)

        # STEP 2: Deploy the specified pods and policies given by the variables
        print(colorize("\nSTEP 2: Deploy the specified pods and policies given by the variables", 36))
        deploy(args.nr_of_pods, args.nr_of_policies, args.namespace, args.key_limit)


        tracemalloc.start()
        time_start = time.perf_counter() # Start the timer
       
        # STEP 3: Start the watcher (non-verbose, non-debug, non-startupcheck)
        print(colorize("\nSTEP 3: Start the watcher", 36))
        # Create and start the EventWatcher in a separate thread
        ew = EventWatcher(args.namespace, False, False, False)
        # make sure the watcher is ready
        
        ew_thread = threading.Thread(target=ew.run, args=(args.namespace,))
        ew_thread.start()
        while True:
            if hasattr(ew, 'event_detected') and ew:
                break
            time.sleep(0)
        while not ew.policies_started.wait():
            time.sleep(0)
        while not ew.pods_started.wait():
            time.sleep(0)

        #Save the processsing time and memory usage:
        ew_startup_time_elapsed = time.perf_counter() - time_start # final computation time
        ew_current, ew_peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        print(f"    Watcher startup time usage: {ew_startup_time_elapsed} seconds")
        print(f"    Watcher startup memory usage is {ew_current / 10**3}KB; Peak was {ew_peak / 10**3}KB; Diff = {(ew_peak - ew_current) / 10**3}KB")
        results.append({'Run Number': i, 'Elapsed Time (seconds)': ew_startup_time_elapsed, 'Mem start (bytes)': (ew_current), 'Mem peak (bytes)': (ew_peak), 'Mem Diff (bytes)': ((ew_peak - ew_current))})

        # STEP 4: execute event
        print(colorize(f"\nSTEP 4: execute event: {args.event_type}", 36))
        event = args.event_type
        if event == "addNP":
            start_time = deploy(0, 1, args.namespace, args.key_limit)
        elif event == "deleteNP":
            start_time = remove_random(False, args.namespace)
        elif event == "addPod":
            start_time = deploy(1, 0, args.namespace, args.key_limit)
        elif event == "deletePod":
            start_time = remove_random(True, args.namespace)

        else:
            raise Exception("Not a correct event type.")

        # STEP 5: Wait for the event to be handled
        print(colorize("\nSTEP 5: Wait for the event to be handled", 36))
        def timeout_handler(signum, frame):
            raise TimeoutError("Event handling exceeded time limit")

        timeout_seconds = 300
        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(timeout_seconds)
        
        try:
            ew.event_detected.wait() # This makes the main thread wait for the ew_thread to finish
            signal.alarm(0)

        except TimeoutError as e:
            print(colorize("\nEvent handling timed out. Restarting the current run.", 31))
            ew.stop_watching()  # Stop the watcher
            continue
        
        # STEP 6: Get and save processsing time and memory usage:
        print(colorize("\nSTEP 6: Get processing time and memory usage", 36))
        (consumer_time, end_time, (current, peak)) = ew.get_time_and_memory()
        total_difference = end_time - start_time
        analyse_difference = end_time - consumer_time
        detection_difference = consumer_time - start_time
        total_time = total_difference.total_seconds()
        analyse_time = analyse_difference.total_seconds()
        detection_time = detection_difference.total_seconds()

        print(f"    total time: {total_time} seconds")
        print(f"    Anlyzer time: {analyse_time} seconds")
        print(f"    detection time: {detection_time} seconds")
        print(f"    Anlyzer current memory usage is {current / 10**3}KB; Peak was {peak / 10**3}KB; Diff = {(peak - current) / 10**3}KB")

        results2.append({'Run Number': i, 'Total Time (seconds)': total_time, 'Detection Time (seconds)': detection_time, 'Analyzer Time (seconds)': analyse_time, 'Mem start (bytes)': (current), 'Mem peak (bytes)': (peak), 'Mem Diff (bytes)': ((peak - current))})

        # STEP 7: stop the watcher
        print(colorize("\nSTEP 7: stop the watcher", 36))
        ew.stop_watching()


        i += 1
   
    experiment_info = {
    'Number of Runs': args.nr_of_runs,
    'Number of Pods': args.nr_of_pods,
    'Number of Policies': args.nr_of_policies,
    'Namespace': args.namespace,
    'Key Limit': args.key_limit,
    'Event Type': args.event_type
    }
    results_df = pd.DataFrame(results)
    results2_df = pd.DataFrame(results2)

    experiment_info_df = pd.DataFrame([experiment_info])

    with pd.ExcelWriter('startup.xlsx', engine='xlsxwriter') as writer:
        experiment_info_df.to_excel(writer, sheet_name='Experiment_Info', index=False)  # Add the experiment info to a separate sheet

        results_df.to_excel(writer, sheet_name='Results', index=False)  # Add the results to another sheet
        results_df.to_excel('startup.xlsx', index=False)
    
    with pd.ExcelWriter('events.xlsx', engine='xlsxwriter') as writer:
        experiment_info_df.to_excel(writer, sheet_name='Experiment_Info', index=False)  # Add the experiment info to a separate sheet
        results2_df.to_excel(writer, sheet_name='Results', index=False)  # Add the results to another sheet
        results2_df.to_excel('events.xlsx', index=False)
    
    print(colorize("ENDED TESTS WITH FOLLOWING VARIABLES:",35))
    print(colorize(f"    -amount of runs: {args.nr_of_runs}", 35))
    print(colorize(f"    -nr of pods: {args.nr_of_pods}", 35))
    print(colorize(f"    -nr of policies: {args.nr_of_policies}", 35))
    print(colorize(f"    -namespace: {args.namespace}", 35))
    print(colorize(f"    -key limit: {args.key_limit}", 35))
    print(colorize(f"    -event_type: {args.event_type}", 35))
