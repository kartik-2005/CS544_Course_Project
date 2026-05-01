"""
eval_cross.py  —  Cross-dataset evaluation

This is the evaluation that actually measures whether STOB works.

Procedure:
  1. Train the model on CLEAN traffic (no defense).
  2. Test it on STOB-defended traffic.

If the defense works, accuracy should drop toward ~10%
(random chance for 10 classes). If it stays high, either:
  - The volume features still leak identity (padding/normalization bug), or
  - The timing jitter isn't strong enough to destroy IAT features.
"""

import os
import pandas as pd
from scapy.all import rdpcap
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report


def extract_features(pcap_path):
    try:
        packets = rdpcap(pcap_path)
    except:
        return None

    incoming_bytes = 0
    outgoing_bytes = 0
    incoming_packets = 0
    outgoing_packets = 0
    incoming_times = []

    for pkt in packets:
        if pkt.haslayer('IP'):
            size = len(pkt)
            if pkt['IP'].src == "10.0.0.2":
                incoming_bytes += size
                incoming_packets += 1
                incoming_times.append(float(pkt.time))
            else:
                outgoing_bytes += size
                outgoing_packets += 1

    if len(incoming_times) >= 2:
        iats = [incoming_times[i+1] - incoming_times[i]
                for i in range(len(incoming_times) - 1)]
        iat_mean   = sum(iats) / len(iats)
        iat_range  = max(iats) - min(iats)
        iat_median = sorted(iats)[len(iats) // 2]
    else:
        iat_mean = iat_range = iat_median = 0.0

    return [
        incoming_bytes, outgoing_bytes,
        incoming_packets, outgoing_packets,
        iat_mean, iat_range, iat_median,
    ]


COLS = ['in_bytes', 'out_bytes', 'in_pkts', 'out_pkts',
        'iat_mean', 'iat_range', 'iat_median']


def build_dataset(data_dir):
    features_list, labels = [], []
    print(f"[*] Loading {data_dir}...")
    for filename in os.listdir(data_dir):
        if not filename.endswith(".pcap"):
            continue
        feat = extract_features(os.path.join(data_dir, filename))
        if feat:
            features_list.append(feat)
            labels.append(filename.split('_')[0])
    return pd.DataFrame(features_list, columns=COLS), labels


if __name__ == "__main__":
    # Step 1: Train on clean data
    X_clean, y_clean = build_dataset("clean_dataset")
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_clean, y_clean)
    print(f"[*] Model trained on {len(y_clean)} clean samples.")

    # Step 2: Test on STOB-defended data
    X_stob, y_stob = build_dataset("stob_dataset")
    y_pred = model.predict(X_stob)

    acc = accuracy_score(y_stob, y_pred)
    print("\n" + "="*45)
    print(f"CROSS-EVAL ACCURACY (clean→stob): {acc * 100:.2f}%")
    print(f"  (Random baseline for 10 classes: 10.00%)")
    print("="*45)
    print("\nDetailed Report:")
    print(classification_report(y_stob, y_pred))

    # Interpretation hint
    if acc > 0.5:
        print("\n[!] Accuracy is still HIGH — defense is not working.")
        print("    Check: Are all sites fetching the same number of files?")
        print("    Check: Is stob_kern.o actually loaded? Run: tc filter show dev server-eth0 egress")
    elif acc > 0.2:
        print("\n[~] Accuracy is partially reduced — defense is partially working.")
    else:
        print("\n[✓] Accuracy is near random — STOB defense is effective.")