import os
import pandas as pd
from scapy.all import rdpcap
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import subprocess
from sklearn.metrics import accuracy_score, classification_report

# --- 1. FEATURE EXTRACTION ---
def extract_features(pcap_path):
    try:
        # Incoming packets (from server)
        cmd_in = f"tshark -r {pcap_path} -Y 'ip.src==10.0.0.2' -T fields -e frame.time_relative -e frame.len 2>/dev/null"
        res_in = subprocess.check_output(cmd_in, shell=True).decode().strip().splitlines()
        
        # Outgoing packets (from client)
        cmd_out = f"tshark -r {pcap_path} -Y 'ip.src==10.0.0.1' -T fields -e frame.time_relative -e frame.len 2>/dev/null"
        res_out = subprocess.check_output(cmd_out, shell=True).decode().strip().splitlines()

        # Volume features
        in_sizes  = [int(r.split('\t')[1]) for r in res_in  if r and '\t' in r]
        out_sizes = [int(r.split('\t')[1]) for r in res_out if r and '\t' in r]
        in_bytes  = sum(in_sizes)
        out_bytes = sum(out_sizes)
        in_pkts   = len(in_sizes)
        out_pkts  = len(out_sizes)

        # Timing features (IAT on incoming packets)
        in_times = [float(r.split('\t')[0]) for r in res_in if r and '\t' in r]
        if len(in_times) >= 2:
            iats       = [in_times[i+1] - in_times[i] for i in range(len(in_times)-1)]
            iat_mean   = sum(iats) / len(iats)
            iat_range  = max(iats) - min(iats)
            iat_median = sorted(iats)[len(iats)//2]
        else:
            iat_mean = iat_range = iat_median = 0.0

        return [in_bytes, out_bytes, in_pkts, out_pkts, iat_mean, iat_range, iat_median]

    except Exception as e:
        print(f"    [WARN] Failed on {pcap_path}: {e}")
        return None
    

# --- 2. DATASET PREPARATION ---
def build_dataset(data_dir):
    features_list = []
    labels = []

    print(f"[*] Extracting features from {data_dir}...")
    for filename in os.listdir(data_dir):
        if filename.endswith(".pcap"):
            path = os.path.join(data_dir, filename)
            label = filename.split('_')[0]

            feat = extract_features(path)
            if feat:
                features_list.append(feat)
                labels.append(label)

    cols = ['in_bytes', 'out_bytes', 'in_pkts', 'out_pkts',
            'iat_mean', 'iat_range', 'iat_median']
    return pd.DataFrame(features_list, columns=cols), labels

# --- 3. TRAINING & EVALUATION ---
def train_and_evaluate():
    X, y = build_dataset("clean_dataset")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42)

    print(f"[*] Training Model 1 (Random Forest / k-FP)...")
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)

    print("\n" + "="*30)
    print(f"MODEL 1 ACCURACY (CLEAN): {accuracy * 100:.2f}%")
    print("="*30)
    print("\nDetailed Report:")
    print(classification_report(y_test, y_pred))

    return model  # return so eval_cross.py can reuse it

if __name__ == "__main__":
    train_and_evaluate()