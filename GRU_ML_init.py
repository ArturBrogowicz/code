import torch
import torch.nn as nn
import torch.optim as optim
import pandas as pd
import numpy as np
import joblib
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                             f1_score, confusion_matrix)
from torch.utils.data import Dataset, DataLoader
from GRU_ML_model import GRUDDoSClassifier

DATA_PATH = "training_data/balanced_dataset.csv"
MODEL_SAVE_PATH = "training_results/gru_ddos_model.pth"
SCALER_SAVE_PATH = "training_results/scaler.save"

SEQUENCE_LENGTH = 15
BATCH_SIZE = 64
EPOCHS = 5
HIDDEN_SIZE = 64
NUM_LAYERS = 2

# Train/validation/test split ratios
TRAIN_RATIO = 0.70
VAL_RATIO = 0.15
TEST_RATIO = 0.15

# Column name aliases across CICFlowMeter dataset versions.
# All three major datasets (CIC-IDS-2017, CSE-CIC-IDS2018, CIC-UNSW-NB15)
# produce the same features but with slightly different column names.
# This mapping normalizes them to a canonical form.
FEATURE_ALIASES = {
    'Flow Duration':              ['Flow Duration'],
    'Total Fwd Packet':           ['Total Fwd Packet', 'Tot Fwd Pkts', 'Total Fwd Packets'],
    'Total Length of Fwd Packet':  ['Total Length of Fwd Packet', 'TotLen Fwd Pkts',
                                    'Total Length of Fwd Packets'],
    'Fwd Packet Length Mean':      ['Fwd Packet Length Mean', 'Fwd Pkt Len Mean'],
    'Flow Packets/s':              ['Flow Packets/s', 'Flow Pkts/s'],
    'SYN Flag Count':              ['SYN Flag Count', 'SYN Flag Cnt'],
}

# Metadata column aliases (not used as features, but needed for grouping/sorting)
IP_COL_ALIASES = ['Src IP', 'Source IP']
TIME_COL_ALIASES = ['Timestamp']
LABEL_COL_ALIASES = ['Label']


def find_column(df, aliases):
    """Find a column in the DataFrame by checking a list of known aliases.

    CICFlowMeter column names vary across dataset versions. This function
    handles the variation transparently, stripping leading/trailing whitespace
    from the DataFrame's column names before matching.
    """
    stripped = {c.strip(): c for c in df.columns}
    for alias in aliases:
        if alias in stripped:
            return stripped[alias]
    return None


def normalize_feature_columns(df):
    """Resolve 6 training features from the DataFrame using alias lookup.

    Returns:
        (selected_columns, canonical_names): Two parallel lists — the actual
        DataFrame column names and the canonical names we'll use internally.
    """
    selected = []
    canonical = []
    for canon_name, aliases in FEATURE_ALIASES.items():
        col = find_column(df, aliases)
        if col is None:
            raise ValueError(
                f"Required feature '{canon_name}' not found in dataset. "
                f"Tried aliases: {aliases}. "
                f"Available columns: {list(df.columns)}"
            )
        selected.append(col)
        canonical.append(canon_name)
    return selected, canonical


# ============================================================
# LOAD & CLEAN DATASET
# ============================================================

device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
print(f"[*] Using device: {device}")

print(f"[*] Loading data from {DATA_PATH}...")
if DATA_PATH.endswith('.parquet'):
    df = pd.read_parquet(DATA_PATH)
else:
    df = pd.read_csv(DATA_PATH, low_memory=False)

print(f"[*] Raw dataset: {len(df)} rows, {len(df.columns)} columns.")

# Strip whitespace from column names (CIC-IDS-2017 has leading spaces)
df.columns = df.columns.str.strip()

# Clean infinite/NaN values
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)
print(f"[*] After cleaning: {len(df)} rows.")

# ============================================================
# SORT BY SOURCE IP (if available) TO GROUP SEQUENCES PER CLIENT
# ============================================================

ip_col = find_column(df, IP_COL_ALIASES)
time_col = find_column(df, TIME_COL_ALIASES)

if ip_col:
    print(f"[*] Sorting data by '{ip_col}' to group sequences per client...")

    # FIX: Losowe przemieszanie całych bloków IP przed sortowaniem chronologicznym
    unique_ips = df[ip_col].unique()
    np.random.seed(42)
    np.random.shuffle(unique_ips)

    ip_order = {ip: i for i, ip in enumerate(unique_ips)}
    df['__ip_order'] = df[ip_col].map(ip_order)

    sort_cols = ['__ip_order']

    if time_col:
        sort_cols.append(time_col)
        df[time_col] = pd.to_datetime(df[time_col], errors='coerce')

    df = df.sort_values(by=sort_cols).reset_index(drop=True)
    df.drop(columns=['__ip_order'], inplace=True)
else:
    print("[-] Warning: Client IP column not found in dataset. Sequences might cross IPs!")
    print(f"    Searched for: {IP_COL_ALIASES}")

# LABELS — Binary classification: Benign=0, Attack=1
# ============================================================

label_col = find_column(df, LABEL_COL_ALIASES)
if label_col is None:
    raise ValueError(f"Missing label column! Searched for: {LABEL_COL_ALIASES}")

# Normalize label strings and apply binary mapping
label_values = df[label_col].astype(str).str.strip().str.lower()
labels = np.where(label_values == 'benign', 0, 1)

benign_count = np.sum(labels == 0)
attack_count = np.sum(labels == 1)
print(f"[*] Labels — Benign: {benign_count} ({benign_count/len(labels)*100:.1f}%), "
      f"Attack: {attack_count} ({attack_count/len(labels)*100:.1f}%)")

# Print attack type breakdown for thesis documentation
print("[*] Attack type distribution:")
for label_name, count in df[label_col].value_counts().items():
    print(f"    {label_name}: {count}")

# ============================================================
# FEATURE SELECTION — 6 ingress-observable features
# ============================================================

# Feature mapping to XDP telemetry inference (control_plane.py):
#   Flow Duration              → ktime_ns delta (now - first_seen_ns)
#   Total Fwd Packet           → telemetry_data.packet_count
#   Total Length of Fwd Packet → telemetry_data.byte_count
#   Fwd Packet Length Mean     → byte_count / packet_count
#   Flow Packets/s             → packet_count / flow_duration_s
#   SYN Flag Count             → telemetry_data.syn_count
selected_cols, canonical_names = normalize_feature_columns(df)
print(f"[*] Selected features ({len(selected_cols)}):")
for canon, actual in zip(canonical_names, selected_cols):
    if canon != actual:
        print(f"    {canon} (matched as '{actual}')")
    else:
        print(f"    {canon}")

features = df[selected_cols].values.astype(np.float64)
INPUT_SIZE = features.shape[1]
print(f"[*] INPUT_SIZE: {INPUT_SIZE}")

# ============================================================
# NORMALIZE
# ============================================================

print("[*] Normalizing data...")
scaler = StandardScaler()
features_scaled = scaler.fit_transform(features)

joblib.dump(scaler, SCALER_SAVE_PATH)

# ============================================================
# DATASET CLASS
# ============================================================

print("[*] Generating time sequences...")


class DynamicDDoSDataset(Dataset):
    """
    Dataset class for dynamically generating time-series sequences from network traffic data.
    """
    def __init__(self, data, labels, seq_length):
        """
        Initializes the dynamic dataset.

        Parameters:
        -----------
        data : numpy.ndarray
            The scaled feature array.
        labels : numpy.ndarray
            The binary target labels.
        seq_length : int
            The number of time steps in each sequence.
        """
        self.data = data
        self.labels = labels
        self.seq_length = seq_length

    def __len__(self):
        """
        Returns the total number of available sequences.
        """
        return len(self.data) - self.seq_length

    def __getitem__(self, idx):
        """
        Generates one sequence slice and its corresponding label on the fly.
        """
        x_seq = self.data[idx : (idx + self.seq_length)]
        y_label = self.labels[idx + self.seq_length - 1]
        return torch.tensor(x_seq, dtype=torch.float32), torch.tensor([y_label], dtype=torch.float32)


# ============================================================
# TRAIN/VAL/TEST SPLIT (chronological, no shuffling across splits)
# ============================================================

total_samples = len(features_scaled) - SEQUENCE_LENGTH
train_end = int(total_samples * TRAIN_RATIO)
val_end = int(total_samples * (TRAIN_RATIO + VAL_RATIO))

print(f"[*] Splitting dataset: train={train_end}, val={val_end - train_end}, test={total_samples - val_end}")

train_data = features_scaled[:train_end + SEQUENCE_LENGTH]
train_labels = labels[:train_end + SEQUENCE_LENGTH]

val_data = features_scaled[train_end:val_end + SEQUENCE_LENGTH]
val_labels = labels[train_end:val_end + SEQUENCE_LENGTH]

test_data = features_scaled[val_end:]
test_labels = labels[val_end:]

train_dataset = DynamicDDoSDataset(train_data, train_labels, SEQUENCE_LENGTH)
val_dataset = DynamicDDoSDataset(val_data, val_labels, SEQUENCE_LENGTH)
test_dataset = DynamicDDoSDataset(test_data, test_labels, SEQUENCE_LENGTH)

train_loader = DataLoader(train_dataset, batch_size=BATCH_SIZE, shuffle=True)
val_loader = DataLoader(val_dataset, batch_size=BATCH_SIZE, shuffle=False)
test_loader = DataLoader(test_dataset, batch_size=BATCH_SIZE, shuffle=False)

print(f"[*] Train sequences: {len(train_dataset)}, Val sequences: {len(val_dataset)}, "
      f"Test sequences: {len(test_dataset)}")

# ============================================================
# MODEL & TRAINING
# ============================================================

model = GRUDDoSClassifier(input_size=INPUT_SIZE, hidden_size=HIDDEN_SIZE, num_layers=NUM_LAYERS).to(device)
criterion = nn.BCEWithLogitsLoss()
optimizer = optim.Adam(model.parameters(), lr=0.001)


def evaluate_model(model, data_loader, criterion, dataset_name=""):
    """Run evaluation pass and compute classification metrics.

    Returns:
        dict with loss, accuracy, precision, recall, f1, and confusion_matrix.
    """
    model.eval()
    total_loss = 0
    all_preds = []
    all_labels = []

    with torch.no_grad():
        for batch_X, batch_y in data_loader:
            batch_X, batch_y = batch_X.to(device), batch_y.to(device)
            outputs = model(batch_X)
            loss = criterion(outputs, batch_y)
            total_loss += loss.item()

            probs = torch.sigmoid(outputs).cpu().numpy()
            preds = (probs >= 0.5).astype(int).flatten()
            all_preds.extend(preds)
            all_labels.extend(batch_y.cpu().numpy().astype(int).flatten())

    all_preds = np.array(all_preds)
    all_labels = np.array(all_labels)

    avg_loss = total_loss / len(data_loader)
    acc = accuracy_score(all_labels, all_preds)
    prec = precision_score(all_labels, all_preds, zero_division=0)
    rec = recall_score(all_labels, all_preds, zero_division=0)
    f1 = f1_score(all_labels, all_preds, zero_division=0)
    cm = confusion_matrix(all_labels, all_preds)

    if dataset_name:
        print(f"  [{dataset_name}] Loss: {avg_loss:.4f} | Acc: {acc:.4f} | "
              f"Prec: {prec:.4f} | Rec: {rec:.4f} | F1: {f1:.4f}")
        print(f"  [{dataset_name}] Confusion Matrix:\n{cm}")

    return {"loss": avg_loss, "accuracy": acc, "precision": prec,
            "recall": rec, "f1": f1, "confusion_matrix": cm}


print("[*] Starting training process...")
best_val_f1 = 0.0

for _epoch in range(EPOCHS):
    model.train()
    total_loss = 0
    for batch_X, batch_y in train_loader:
        batch_X, batch_y = batch_X.to(device), batch_y.to(device)

        optimizer.zero_grad()
        outputs = model(batch_X)
        loss = criterion(outputs, batch_y)
        loss.backward()
        optimizer.step()

        total_loss += loss.item()

    avg_loss = total_loss / len(train_loader)
    print(f"\nEpoch [{_epoch + 1}/{EPOCHS}], Train Loss: {avg_loss:.4f}")

    # Validation evaluation after each epoch
    val_metrics = evaluate_model(model, val_loader, criterion, dataset_name="Val")

    # Save best model based on validation F1
    if val_metrics["f1"] > best_val_f1:
        best_val_f1 = val_metrics["f1"]
        torch.save(model.state_dict(), MODEL_SAVE_PATH)
        print(f"  [*] New best model saved (Val F1: {best_val_f1:.4f})")

# Final evaluation on held-out test set using the best model
print("\n[*] Loading best model for final test evaluation...")
model.load_state_dict(torch.load(MODEL_SAVE_PATH, map_location=device))
print("=" * 60)
print("FINAL TEST SET EVALUATION")
print("=" * 60)
test_metrics = evaluate_model(model, test_loader, criterion, dataset_name="Test")

print(f"\n[+] Model saved to {MODEL_SAVE_PATH}")
print(f"[+] Scaler saved to {SCALER_SAVE_PATH}")
print(f"[+] Best validation F1: {best_val_f1:.4f}")
print(f"[+] Test F1: {test_metrics['f1']:.4f}")