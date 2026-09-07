import pandas as pd

SYN_PATH = "training_data/Syn.csv"
UNSW_PATH = "training_data/CICFlowMeter.csv"
OUTPUT_PATH = "training_data/balanced_dataset.csv"

# Zdefiniowanie 9 kluczowych kolumn, których wymaga GRU_ML_init.py
cols_syn = [
    'Source IP', 'Timestamp', 'Label',
    'Flow Duration', 'Total Fwd Packets', 'Total Length of Fwd Packets',
    'Fwd Packet Length Mean', 'Flow Packets/s', 'SYN Flag Count'
]

cols_unsw = [
    'Src IP', 'Timestamp', 'Label',
    'Flow Duration', 'Total Fwd Packet', 'Total Length of Fwd Packet',
    'Fwd Packet Length Mean', 'Flow Packets/s', 'SYN Flag Count'
]

# Wspólne, zunifikowane nazwy kolumn dla pliku wyjściowego
canonical_cols = [
    'Src IP', 'Timestamp', 'Label',
    'Flow Duration', 'Total Fwd Packet', 'Total Length of Fwd Packet',
    'Fwd Packet Length Mean', 'Flow Packets/s', 'SYN Flag Count'
]

CHUNK_SIZE = 100000
first_write = True

print("[*] Przetwarzanie pliku UNSW (Benign) w mniejszych paczkach...")
# Przetwarzanie strumieniowe pierwszego pliku
for chunk in pd.read_csv(UNSW_PATH, chunksize=CHUNK_SIZE, low_memory=False, on_bad_lines='skip'):
    chunk.columns = chunk.columns.str.strip()
    
    # Filtrujemy tylko ruch Benign
    benign_chunk = chunk[chunk['Label'].astype(str).str.strip().str.lower() == 'benign']
    
    if not benign_chunk.empty:
        try:
            benign_subset = benign_chunk[cols_unsw].copy()
            benign_subset.columns = canonical_cols
            benign_subset['Label'] = 'BENIGN'
            
            # Tworzymy nagłówek tylko przy pierwszym zapisie, potem dopisujemy
            mode = 'w' if first_write else 'a'
            benign_subset.to_csv(OUTPUT_PATH, mode=mode, header=first_write, index=False)
            first_write = False
        except KeyError as e:
            print(f"[-] Błąd kolumn w paczce (pomijam): {e}")

print("[*] Przetwarzanie pliku Syn w mniejszych paczkach...")
# Przetwarzanie strumieniowe drugiego pliku
for chunk in pd.read_csv(SYN_PATH, chunksize=CHUNK_SIZE, low_memory=False, on_bad_lines='skip'):
    chunk.columns = chunk.columns.str.strip()
    
    try:
        syn_subset = chunk[cols_syn].copy()
        syn_subset.columns = canonical_cols
        syn_subset['Label'] = 'Syn'
        
        # Dopisywanie do istniejącego pliku (zawsze 'a', bez nagłówka)
        syn_subset.to_csv(OUTPUT_PATH, mode='a', header=False, index=False)
    except KeyError as e:
            print(f"[-] Błąd kolumn w paczce (pomijam): {e}")

print(f"[+] Gotowe! Zbalansowany plik został utworzony w: {OUTPUT_PATH}")
