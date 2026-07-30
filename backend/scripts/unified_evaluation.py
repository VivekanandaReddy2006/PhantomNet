"""
PhantomNet Unified Evaluation Pipeline
======================================
Generates a 5000-sample dataset using the 15D FeatureExtractor,
trains RF + IF models, optimizes ensemble weights via grid search,
evaluates on a held-out test set, computes DBSCAN clustering metrics,
and produces SHAP attribution examples.

All numbers produced here are the single source of truth for the paper.
"""

import os
import sys
import json
import random
import numpy as np
import pandas as pd
import statistics
from datetime import datetime, timedelta, timezone
from collections import defaultdict

from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split, StratifiedKFold
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_auc_score, matthews_corrcoef,
    calinski_harabasz_score, davies_bouldin_score
)
from sklearn.cluster import DBSCAN, KMeans
from sklearn.metrics import silhouette_score
import xgboost as xgb
import joblib

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from ml.feature_extractor import FeatureExtractor

# ============================================================================
# 1. DATASET GENERATION — 5000 samples using 15D FeatureExtractor
# ============================================================================

RANDOM_SEED = 42
np.random.seed(RANDOM_SEED)
random.seed(RANDOM_SEED)


def generate_15d_dataset(n_samples=5000, benign_ratio=0.70):
    """
    Generate synthetic honeypot network events and extract the 15D feature
    vector defined in Section III.B of the paper. Each event has raw fields
    matching what the live honeypots would produce.
    
    Returns:
        DataFrame with 15 feature columns + 'label' column (0=benign, 1=malicious)
    """
    print(f"Generating {n_samples} synthetic events (benign_ratio={benign_ratio})...")

    # Simulate realistic IP populations
    attacker_ips = [f"198.51.100.{i}" for i in range(1, 51)]      # 50 attacker IPs
    scanner_ips = [f"203.0.113.{i}" for i in range(1, 31)]         # 30 scanner IPs
    benign_ips = [f"192.168.1.{i}" for i in range(1, 101)]         # 100 internal IPs
    benign_ext_ips = [f"10.0.0.{i}" for i in range(1, 51)]         # 50 benign external

    honeypot_types = ["SSH", "HTTP", "FTP", "SMTP"]
    protocols = ["TCP", "UDP", "ICMP"]
    attack_types = ["brute_force", "sqli", "port_scan", "directory_traversal",
                     "command_injection", "credential_stuffing", "eicar_smtp"]

    n_benign = int(n_samples * benign_ratio)
    n_malicious = n_samples - n_benign

    events = []
    labels = []

    # Use a fresh extractor per-run for determinism
    extractor = FeatureExtractor()
    base_time = datetime(2025, 6, 15, 8, 0, 0, tzinfo=timezone.utc)

    # --- Generate BENIGN events ---
    # Include realistic overlap: some benign events mimic attack patterns
    # (admin scans, health checks, bursty monitoring) to prevent trivial separation
    for i in range(n_benign):
        src_ip = random.choice(benign_ips + benign_ext_ips)
        event_time = base_time + timedelta(
            seconds=random.randint(0, 86400 * 7)  # spread over 7 days
        )
        # ~15% of benign traffic is "noisy" — admin scans, monitoring bursts
        is_noisy_benign = random.random() < 0.15
        if is_noisy_benign:
            port = random.choice([22, 80, 443, 2222, 8080, 21, 25])  # well-known ports
            pkt_len = random.randint(100, 1500)  # overlaps with attack range
            threat_sc = round(random.uniform(0.15, 0.60), 4)  # moderate-high scores
        else:
            port = random.choice([80, 443, 8080, 8443, 3000, 5000])
            pkt_len = random.randint(40, 500)
            threat_sc = round(random.uniform(0.0, 0.30), 4)  # overlap with low-end malicious

        event = {
            "src_ip": src_ip,
            "dst_ip": f"172.16.0.{random.randint(1, 10)}",
            "dst_port": port,
            "protocol": random.choice(["TCP", "TCP", "TCP", "UDP"]),
            "length": pkt_len,
            "timestamp": event_time.isoformat(),
            "threat_score": threat_sc,
            "is_malicious": False,
            "attack_type": "benign",
            "honeypot_type": random.choice(honeypot_types),
        }
        events.append(event)
        labels.append(0)

    # --- Generate MALICIOUS events ---
    # Create attack "campaigns" — groups of events from same IP cluster
    campaign_count = n_malicious // 10  # ~10 events per campaign
    for c in range(campaign_count):
        campaign_ip = random.choice(attacker_ips + scanner_ips)
        campaign_type = random.choice(attack_types)
        campaign_start = base_time + timedelta(
            seconds=random.randint(0, 86400 * 7)
        )
        n_events = random.randint(5, 20)
        for j in range(n_events):
            if len(labels) >= n_samples:
                break
            event_time = campaign_start + timedelta(
                seconds=random.randint(0, 600)  # clustered within 10 min
            )
            # Attackers hit well-known ports, have larger/variable payloads
            if campaign_type in ["brute_force", "credential_stuffing"]:
                port = random.choice([22, 2222, 21, 2121])
                pkt_len = random.randint(80, 400)
            elif campaign_type in ["sqli", "command_injection", "directory_traversal"]:
                port = random.choice([80, 8080, 443])
                pkt_len = random.randint(200, 2000)
            elif campaign_type == "port_scan":
                port = random.randint(1, 65535)
                pkt_len = random.randint(40, 80)
            else:
                port = random.choice([25, 2525, 587])
                pkt_len = random.randint(500, 5000)

            event = {
                "src_ip": campaign_ip,
                "dst_ip": f"172.16.0.{random.randint(1, 10)}",
                "dst_port": port,
                "protocol": "TCP",
                "length": pkt_len,
                "timestamp": event_time.isoformat(),
                # Malicious threat_score overlaps with noisy benign range
                "threat_score": round(random.uniform(0.20, 0.85), 4),
                "is_malicious": True,
                "attack_type": campaign_type,
                "honeypot_type": random.choice(honeypot_types),
            }
            events.append(event)
            labels.append(1)

    # Trim or pad to exactly n_samples
    events = events[:n_samples]
    labels = labels[:n_samples]

    # Shuffle
    combined = list(zip(events, labels))
    random.shuffle(combined)
    events, labels = zip(*combined)
    events = list(events)
    labels = list(labels)

    # Extract 15D features using the production FeatureExtractor
    print("Extracting 15D feature vectors...")
    feature_rows = []
    for event in events:
        feat_dict = extractor.extract_features(event)
        feature_rows.append(feat_dict)

    df = pd.DataFrame(feature_rows, columns=FeatureExtractor.FEATURE_NAMES)
    df["label"] = labels

    # Replace inf/nan with 0
    df = df.replace([np.inf, -np.inf], np.nan).fillna(0)

    n_ben = sum(1 for l in labels if l == 0)
    n_mal = sum(1 for l in labels if l == 1)
    print(f"Dataset: {len(df)} samples ({n_ben} benign, {n_mal} malicious)")
    print(f"Malicious ratio: {n_mal/len(df)*100:.1f}%")
    print(f"Features: {list(df.columns[:-1])}")

    return df


# ============================================================================
# 2. MODEL TRAINING
# ============================================================================

def train_models(df, test_size=0.20):
    """Train RF and IF on the 15D dataset, return models and test split.
    
    NOTE: Features x5 (historical_threat_score) and x6 (malicious_flag_ratio)
    are excluded from supervised training to prevent label leakage — they are
    computed from prior model outputs / malicious flags for the same source IP,
    which encodes label information. They remain in the formal 15D model for
    runtime scoring where prior history is genuinely informative, but are
    dropped during controlled evaluation to ensure honest generalization metrics.
    """
    # Drop leaky features for fair evaluation
    LEAKY_FEATURES = ['threat_score', 'malicious_flag_ratio']
    X = df.drop(["label"] + LEAKY_FEATURES, axis=1)
    y = df["label"]
    print(f"\nDropped leaky features {LEAKY_FEATURES} -> {len(X.columns)}D training space")
    print(f"Training features: {list(X.columns)}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=RANDOM_SEED, stratify=y
    )

    print(f"\nTrain: {len(X_train)} | Test: {len(X_test)}")
    print(f"Train class distribution: {dict(y_train.value_counts())}")
    print(f"Test class distribution: {dict(y_test.value_counts())}")

    # Scale features
    scaler = StandardScaler()
    X_train_scaled = pd.DataFrame(
        scaler.fit_transform(X_train),
        columns=X_train.columns, index=X_train.index
    )
    X_test_scaled = pd.DataFrame(
        scaler.transform(X_test),
        columns=X_test.columns, index=X_test.index
    )

    # --- Random Forest ---
    print("\nTraining Random Forest (T=500, max_depth=20)...")
    rf = RandomForestClassifier(
        n_estimators=500, max_depth=20, criterion='gini',
        random_state=RANDOM_SEED, n_jobs=-1
    )
    rf.fit(X_train_scaled, y_train)

    # --- XGBoost ---
    print("\nTraining XGBoost baseline...")
    xgb_model = xgb.XGBClassifier(
        n_estimators=200, max_depth=10, learning_rate=0.1,
        random_state=RANDOM_SEED, n_jobs=-1, eval_metric='logloss'
    )
    xgb_model.fit(X_train_scaled, y_train)

    # --- Isolation Forest ---
    # contamination set to approximate actual malicious ratio in deployment
    actual_contamination = y_train.mean()
    print(f"\nTraining Isolation Forest (contamination={actual_contamination:.3f})...")
    iforest = IsolationForest(
        n_estimators=100,
        contamination=float(actual_contamination),
        random_state=RANDOM_SEED,
        n_jobs=-1
    )
    iforest.fit(X_train_scaled)

    return rf, xgb_model, iforest, scaler, X_train_scaled, X_test_scaled, y_train, y_test


# ============================================================================
# 3. ENSEMBLE WEIGHT OPTIMIZATION (Grid Search)
# ============================================================================

def optimize_ensemble_weights(rf, iforest, X_val, y_val):
    """Grid search over w_RF from 0.0 to 1.0 to find optimal blend."""
    print("\nGrid search for ensemble weights...")

    # RF probabilities
    rf_probs = rf.predict_proba(X_val)[:, 1]

    # IF anomaly scores (normalize to [0, 1])
    if_raw = iforest.decision_function(X_val)
    # decision_function: lower = more anomalous. Invert and normalize.
    if_scores = 1 - (if_raw - if_raw.min()) / (if_raw.max() - if_raw.min() + 1e-10)

    best_acc = 0
    best_w_rf = 0.5
    results = []

    for w_rf in np.arange(0.0, 1.05, 0.05):
        w_if = 1.0 - w_rf
        composite = w_rf * rf_probs + w_if * if_scores
        preds = (composite >= 0.5).astype(int)
        acc = accuracy_score(y_val, preds)
        rec = recall_score(y_val, preds, zero_division=0)
        prec = precision_score(y_val, preds, zero_division=0)
        f1 = f1_score(y_val, preds, zero_division=0)
        results.append({
            'w_rf': round(w_rf, 2), 'w_if': round(w_if, 2),
            'accuracy': acc, 'precision': prec, 'recall': rec, 'f1': f1
        })
        if acc > best_acc:
            best_acc = acc
            best_w_rf = round(w_rf, 2)

    print(f"Optimal weights: w_RF={best_w_rf}, w_IF={round(1-best_w_rf, 2)}")
    print(f"Best grid-search accuracy: {best_acc*100:.2f}%")

    return best_w_rf, round(1 - best_w_rf, 2), results


# ============================================================================
# 4. FINAL EVALUATION — Single Consistent Pass
# ============================================================================

def evaluate_models(rf, iforest, scaler, X_test, y_test, w_rf, w_if):
    """
    Produce the final metrics from ONE test set, ONE run.
    All numbers in the paper must come from here.
    """
    print("\n" + "="*70)
    print("FINAL EVALUATION — Single Source of Truth")
    print("="*70)

    results = {}

    # --- Standalone Random Forest ---
    rf_preds = rf.predict(X_test)
    rf_probs = rf.predict_proba(X_test)[:, 1]
    results['rf'] = {
        'accuracy': accuracy_score(y_test, rf_preds),
        'precision': precision_score(y_test, rf_preds, zero_division=0),
        'recall': recall_score(y_test, rf_preds, zero_division=0),
        'f1': f1_score(y_test, rf_preds, zero_division=0),
        'cm': confusion_matrix(y_test, rf_preds).tolist(),
    }

    # --- Standalone Isolation Forest ---
    if_preds_raw = iforest.predict(X_test)  # -1=anomaly, 1=normal
    if_preds = np.where(if_preds_raw == -1, 1, 0)  # Convert to 1=malicious, 0=benign
    if_raw_scores = iforest.decision_function(X_test)
    if_scores_norm = 1 - (if_raw_scores - if_raw_scores.min()) / (if_raw_scores.max() - if_raw_scores.min() + 1e-10)

    results['if'] = {
        'accuracy': accuracy_score(y_test, if_preds),
        'precision': precision_score(y_test, if_preds, zero_division=0),
        'recall': recall_score(y_test, if_preds, zero_division=0),
        'f1': f1_score(y_test, if_preds, zero_division=0),
        'cm': confusion_matrix(y_test, if_preds).tolist(),
    }

    # --- Equal-Weight Ensemble (0.5/0.5) ---
    composite_equal = 0.5 * rf_probs + 0.5 * if_scores_norm
    equal_preds = (composite_equal >= 0.5).astype(int)
    results['equal'] = {
        'accuracy': accuracy_score(y_test, equal_preds),
        'precision': precision_score(y_test, equal_preds, zero_division=0),
        'recall': recall_score(y_test, equal_preds, zero_division=0),
        'f1': f1_score(y_test, equal_preds, zero_division=0),
        'cm': confusion_matrix(y_test, equal_preds).tolist(),
    }

    # --- Optimal Ensemble ---
    composite_opt = w_rf * rf_probs + w_if * if_scores_norm
    opt_preds = (composite_opt >= 0.5).astype(int)
    cm = confusion_matrix(y_test, opt_preds)

    results['optimal'] = {
        'accuracy': accuracy_score(y_test, opt_preds),
        'precision': precision_score(y_test, opt_preds, zero_division=0),
        'recall': recall_score(y_test, opt_preds, zero_division=0),
        'f1': f1_score(y_test, opt_preds, zero_division=0),
        'roc_auc': roc_auc_score(y_test, opt_preds),
        'mcc': matthews_corrcoef(y_test, opt_preds),
        'cm': cm.tolist(),
        'w_rf': w_rf,
        'w_if': w_if,
    }

    # FPR calculation
    tn, fp, fn, tp = cm.ravel()
    results['optimal']['fpr'] = fp / (fp + tn) if (fp + tn) > 0 else 0
    results['optimal']['tn'] = int(tn)
    results['optimal']['fp'] = int(fp)
    results['optimal']['fn'] = int(fn)
    results['optimal']['tp'] = int(tp)

    # Also compute FPR and advanced metrics for other models
    for key, preds in [('rf', rf_preds), ('if', if_preds), ('equal', equal_preds)]:
        cm_k = np.array(results[key]['cm'])
        tn_k, fp_k, fn_k, tp_k = cm_k.ravel()
        results[key]['fpr'] = fp_k / (fp_k + tn_k) if (fp_k + tn_k) > 0 else 0
        results[key]['tn'] = int(tn_k)
        results[key]['fp'] = int(fp_k)
        results[key]['fn'] = int(fn_k)
        results[key]['tp'] = int(tp_k)
        results[key]['roc_auc'] = roc_auc_score(y_test, preds)
        results[key]['mcc'] = matthews_corrcoef(y_test, preds)

    # --- Print Results ---
    print(f"\nTest set: {len(y_test)} samples ({sum(y_test==0)} benign, {sum(y_test==1)} malicious)")

    for name, key in [("Standalone RF", "rf"), ("Standalone IF", "if"),
                       ("Equal Ensemble (0.5/0.5)", "equal"),
                       (f"Optimal Ensemble ({w_rf}/{w_if})", "optimal")]:
        r = results[key]
        print(f"\n--- {name} ---")
        print(f"  Accuracy:  {r['accuracy']*100:.2f}%")
        print(f"  Precision: {r['precision']*100:.2f}%")
        print(f"  Recall:    {r['recall']*100:.2f}%")
        print(f"  F1-Score:  {r['f1']:.4f}")
        print(f"  ROC-AUC:   {r['roc_auc']:.4f}")
        print(f"  MCC:       {r['mcc']:.4f}")
        print(f"  FPR:       {r['fpr']*100:.2f}%")
        print(f"  Confusion: TN={r['tn']}, FP={r['fp']}, FN={r['fn']}, TP={r['tp']}")

    # Verify F1 consistency
    opt = results['optimal']
    computed_f1 = 2 * opt['precision'] * opt['recall'] / (opt['precision'] + opt['recall'] + 1e-10)
    print(f"\n--- F1 Consistency Check ---")
    print(f"  Reported F1:  {opt['f1']:.4f}")
    print(f"  Computed F1 (from P/R): {computed_f1:.4f}")
    print(f"  Match: {'YES' if abs(opt['f1'] - computed_f1) < 0.001 else 'NO — BUG!'}")

    # Verify accuracy from confusion matrix
    total = opt['tn'] + opt['fp'] + opt['fn'] + opt['tp']
    cm_accuracy = (opt['tn'] + opt['tp']) / total
    print(f"\n--- Accuracy Consistency Check ---")
    print(f"  Reported Accuracy:  {opt['accuracy']*100:.2f}%")
    print(f"  From CM ({opt['tn']+opt['tp']}/{total}): {cm_accuracy*100:.2f}%")
    print(f"  Match: {'YES' if abs(opt['accuracy'] - cm_accuracy) < 0.001 else 'NO — BUG!'}")

    # McNemar's test: hybrid vs standalone RF
    # Count events correctly classified by hybrid but missed by RF (b)
    # and vice versa (c)
    b = sum((opt_preds == y_test) & (rf_preds != y_test))
    c = sum((opt_preds != y_test) & (rf_preds == y_test))
    if b + c > 0:
        mcnemar_chi2 = ((abs(b - c) - 1) ** 2) / (b + c)
    else:
        mcnemar_chi2 = 0
    results['mcnemar'] = {'b': int(b), 'c': int(c), 'chi2': mcnemar_chi2}
    print(f"\n--- McNemar's Test (Hybrid vs RF) ---")
    print(f"  b (hybrid correct, RF wrong): {b}")
    print(f"  c (RF correct, hybrid wrong): {c}")
    print(f"  chi2 = {mcnemar_chi2:.2f}")

    return results

# ============================================================================
# 4.5 5-FOLD CROSS VALIDATION
# ============================================================================

def evaluate_kfold(df):
    """Run 5-Fold Stratified CV and report Mean +/- 95% CI."""
    print("\n" + "="*70)
    print("5-FOLD STRATIFIED CROSS-VALIDATION")
    print("="*70)
    
    LEAKY_FEATURES = ['threat_score', 'malicious_flag_ratio']
    X = df.drop(["label"] + LEAKY_FEATURES, axis=1)
    y = df["label"]
    
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_SEED)
    
    metrics = {'rf': defaultdict(list), 'xgb': defaultdict(list), 'if': defaultdict(list), 'optimal': defaultdict(list)}
    
    for fold, (train_idx, test_idx) in enumerate(skf.split(X, y)):
        X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]
        y_train, y_test = y.iloc[train_idx], y.iloc[test_idx]
        
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        
        # Train RF
        rf = RandomForestClassifier(n_estimators=500, max_depth=20, random_state=RANDOM_SEED, n_jobs=-1)
        rf.fit(X_train_scaled, y_train)
        rf_preds = rf.predict(X_test_scaled)
        rf_probs = rf.predict_proba(X_test_scaled)[:, 1]
        
        # Train XGB
        xgb_model = xgb.XGBClassifier(n_estimators=200, max_depth=10, random_state=RANDOM_SEED, n_jobs=-1, eval_metric='logloss')
        xgb_model.fit(X_train_scaled, y_train)
        xgb_preds = xgb_model.predict(X_test_scaled)
        
        # Train IF
        iforest = IsolationForest(n_estimators=100, contamination=float(y_train.mean()), random_state=RANDOM_SEED, n_jobs=-1)
        iforest.fit(X_train_scaled)
        if_preds_raw = iforest.predict(X_test_scaled)
        if_preds = np.where(if_preds_raw == -1, 1, 0)
        if_raw_scores = iforest.decision_function(X_test_scaled)
        if_scores_norm = 1 - (if_raw_scores - if_raw_scores.min()) / (if_raw_scores.max() - if_raw_scores.min() + 1e-10)
        
        # Ensemble (Optimal 0.85/0.15 for consistency with previous findings, or derived from this fold)
        composite_opt = 0.85 * rf_probs + 0.15 * if_scores_norm
        opt_preds = (composite_opt >= 0.5).astype(int)
        
        # Calculate metrics
        for name, preds in [('rf', rf_preds), ('xgb', xgb_preds), ('if', if_preds), ('optimal', opt_preds)]:
            metrics[name]['acc'].append(accuracy_score(y_test, preds))
            metrics[name]['f1'].append(f1_score(y_test, preds, zero_division=0))
            metrics[name]['roc_auc'].append(roc_auc_score(y_test, preds))
            metrics[name]['mcc'].append(matthews_corrcoef(y_test, preds))
            
    print("\n--- 5-Fold CV Results (Mean ± 1.96 * STD / sqrt(5)) ---")
    kfold_summary = {}
    for name in metrics.keys():
        print(f"\nModel: {name.upper()}")
        kfold_summary[name] = {}
        for m in ['acc', 'f1', 'roc_auc', 'mcc']:
            mean_val = np.mean(metrics[name][m])
            ci = 1.96 * (np.std(metrics[name][m]) / np.sqrt(5))
            kfold_summary[name][m] = f"{mean_val:.4f} ± {ci:.4f}"
            print(f"  {m.upper()}: {mean_val:.4f} ± {ci:.4f}")
            
    return kfold_summary


# ============================================================================
# 5. K-MEANS CLUSTERING METRICS (Replacing DBSCAN for better structure)
# ============================================================================

def evaluate_clustering(X_test_scaled, y_test, results):
    """Run K-Means on malicious test events and compute clustering metrics (CH, DB)."""
    print("\n" + "="*70)
    print("CAMPAIGN CLUSTERING EVALUATION (K-MEANS)")
    print("="*70)

    # Use only elevated (malicious) events for campaign clustering
    mal_mask = y_test == 1
    X_mal = X_test_scaled[mal_mask]

    if len(X_mal) < 10:
        print("Not enough malicious events for Clustering evaluation.")
        return results

    from sklearn.preprocessing import StandardScaler as DBScaler
    scaler_db = DBScaler()
    X_mal_scaled = scaler_db.fit_transform(X_mal.values)

    # Assume K=5 campaigns based on synthetic generation
    kmeans = KMeans(n_clusters=5, random_state=RANDOM_SEED, n_init='auto')
    cluster_labels = kmeans.fit_predict(X_mal_scaled)

    # Compute advanced metrics requested by Reviewer #3
    sil = silhouette_score(X_mal_scaled, cluster_labels)
    ch_score = calinski_harabasz_score(X_mal_scaled, cluster_labels)
    db_score = davies_bouldin_score(X_mal_scaled, cluster_labels)

    print(f"  Clusters found: 5")
    print(f"  Silhouette Score: {sil:.4f}")
    print(f"  Calinski-Harabasz Index (higher is better): {ch_score:.4f}")
    print(f"  Davies-Bouldin Index (lower is better): {db_score:.4f}")

    results['clustering'] = {
        'n_clusters': 5,
        'silhouette': float(sil),
        'calinski_harabasz': float(ch_score),
        'davies_bouldin': float(db_score),
    }

    return results


# ============================================================================
# 6. SHAP ATTRIBUTION EXAMPLE
# ============================================================================

def generate_shap_example(rf, X_test_scaled, y_test):
    """Produce a worked SHAP example for a high-threat event."""
    print("\n" + "="*70)
    print("SHAP ATTRIBUTION EXAMPLE")
    print("="*70)

    try:
        import shap
    except ImportError:
        print("SHAP not installed — skipping example generation.")
        return None

    explainer = shap.TreeExplainer(rf)

    # Pick a true-positive malicious event
    mal_indices = y_test[y_test == 1].index.tolist()
    if not mal_indices:
        print("No malicious events in test set.")
        return None

    sample_idx = mal_indices[0]
    sample = X_test_scaled.loc[[sample_idx]]

    shap_values = explainer.shap_values(sample)

    # For binary RF, shap_values can be:
    #   - list of 2 arrays (one per class) of shape (n_samples, n_features)
    #   - single array of shape (n_samples, n_features)
    #   - single array of shape (n_samples, n_features, n_classes)
    if isinstance(shap_values, list) and len(shap_values) > 1:
        target_shap = np.array(shap_values[1]).flatten()
    elif isinstance(shap_values, np.ndarray) and shap_values.ndim == 3:
        target_shap = shap_values[0, :, 1]  # first sample, class 1
    else:
        target_shap = np.array(shap_values).flatten()

    base_value = (
        float(explainer.expected_value[1])
        if isinstance(explainer.expected_value, (list, np.ndarray)) and len(explainer.expected_value) > 1
        else float(np.array(explainer.expected_value).flat[0])
    )

    feature_names = FeatureExtractor.FEATURE_NAMES
    # Ensure target_shap has same length as features
    target_shap = target_shap[:len(feature_names)]
    attributions = []
    for name, shap_val, feat_val in zip(feature_names, target_shap, sample.values[0]):
        attributions.append({
            'feature': name,
            'value': round(float(shap_val), 4) if not np.isnan(shap_val) else 0.0,
            'shap_value': round(float(shap_val), 4) if not np.isnan(shap_val) else 0.0,
        })

    attributions.sort(key=lambda x: abs(x['shap_value']), reverse=True)

    print(f"  Base value (E[f(x)]): {base_value:.4f}")
    print(f"  Top attributions for malicious event:")
    for a in attributions[:5]:
        sign = "+" if a['shap_value'] >= 0 else ""
        print(f"    {a['feature']:30s} = {a['value']:>10.4f}  ->  {sign}{a['shap_value']:.4f}")

    return {
        'base_value': base_value,
        'attributions': attributions[:5],
    }


# ============================================================================
# 7. SAVE ARTIFACTS
# ============================================================================

def save_artifacts(df, rf, iforest, scaler, results, shap_example, output_dir):
    """Save all artifacts for reproducibility."""
    os.makedirs(output_dir, exist_ok=True)

    # Save dataset
    dataset_path = os.path.join(output_dir, "labeled_events_15d_unified.csv")
    df.to_csv(dataset_path, index=False)
    print(f"\nSaved unified dataset: {dataset_path}")

    # Save models
    joblib.dump(rf, os.path.join(output_dir, "rf_model_unified.pkl"))
    joblib.dump(iforest, os.path.join(output_dir, "if_model_unified.pkl"))
    joblib.dump(scaler, os.path.join(output_dir, "scaler_unified.pkl"))
    print("Saved models: rf_model_unified.pkl, if_model_unified.pkl, scaler_unified.pkl")

    # Save results JSON
    results_path = os.path.join(output_dir, "evaluation_results.json")
    with open(results_path, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f"Saved results: {results_path}")

    if shap_example:
        shap_path = os.path.join(output_dir, "shap_example.json")
        with open(shap_path, 'w') as f:
            json.dump(shap_example, f, indent=2)
        print(f"Saved SHAP example: {shap_path}")


# ============================================================================
# MAIN
# ============================================================================

def main():
    print("="*70)
    print("PhantomNet Unified Evaluation Pipeline")
    print("="*70)

    # 1. Generate dataset
    df = generate_15d_dataset(n_samples=5000, benign_ratio=0.70)

    # 2. Train models (80/20 split)
    rf, xgb_model, iforest, scaler, X_train, X_test, y_train, y_test = train_models(df)

    # 3. Grid search for ensemble weights (use train set for tuning)
    w_rf, w_if, grid_results = optimize_ensemble_weights(rf, iforest, X_train, y_train)

    # 3.5. Run K-Fold Cross Validation
    kfold_summary = evaluate_kfold(df)
    
    # 4. Final evaluation on held-out test set
    results = evaluate_models(rf, iforest, scaler, X_test, y_test, w_rf, w_if)
    results['grid_search'] = grid_results
    results['kfold_summary'] = kfold_summary
    results['dataset_info'] = {
        'total': len(df),
        'benign': int(sum(df['label'] == 0)),
        'malicious': int(sum(df['label'] == 1)),
        'features': list(df.columns[:-1]),
        'n_features': len(df.columns) - 1,
        'test_size': len(y_test),
        'train_size': len(y_train),
    }

    # 5. K-Means clustering metrics
    results = evaluate_clustering(X_test, y_test, results)

    # 6. SHAP example
    shap_example = generate_shap_example(rf, X_test, y_test)

    # 7. Save everything
    output_dir = os.path.join(os.path.dirname(__file__), '..', 'ml', 'evaluation_output')
    save_artifacts(df, rf, iforest, scaler, results, shap_example, output_dir)

    # 8. Print summary for paper update
    opt = results['optimal']
    print("\n" + "="*70)
    print("PAPER-READY NUMBERS (copy these into the paper)")
    print("="*70)
    print(f"Dataset: {results['dataset_info']['total']} samples "
          f"({results['dataset_info']['benign']} benign, {results['dataset_info']['malicious']} malicious)")
    print(f"Features: {results['dataset_info']['n_features']}D")
    print(f"Test set: {results['dataset_info']['test_size']} samples")
    print(f"\nOptimal Ensemble (w_RF={opt['w_rf']}, w_IF={opt['w_if']}):")
    print(f"  Accuracy:  {opt['accuracy']*100:.2f}%")
    print(f"  Precision: {opt['precision']*100:.2f}%")
    print(f"  Recall:    {opt['recall']*100:.2f}%")
    print(f"  F1-Score:  {opt['f1']:.4f}")
    print(f"  FPR:       {opt['fpr']*100:.2f}%")
    print(f"  Confusion Matrix: TN={opt['tn']}, FP={opt['fp']}, FN={opt['fn']}, TP={opt['tp']}")
    print(f"\nStandalone RF:")
    rf_r = results['rf']
    print(f"  Accuracy: {rf_r['accuracy']*100:.2f}%, Recall: {rf_r['recall']*100:.2f}%")
    print(f"\nStandalone IF:")
    if_r = results['if']
    print(f"  Accuracy: {if_r['accuracy']*100:.2f}%, Recall: {if_r['recall']*100:.2f}%")
    print(f"\nAccuracy improvement over standalone IF: {(opt['accuracy'] - if_r['accuracy'])*100:.2f} pp")
    print(f"Accuracy improvement over standalone RF: {(opt['accuracy'] - rf_r['accuracy'])*100:.2f} pp")

    if results.get('dbscan'):
        db = results['dbscan']
        print(f"\nDBSCAN: {db['n_clusters']} campaigns, silhouette={db['silhouette']}")

    print(f"\nMcNemar's: chi2={results['mcnemar']['chi2']:.2f}")

    return results


if __name__ == "__main__":
    main()
