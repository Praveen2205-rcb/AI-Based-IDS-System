"""
load_data.py
============
Load UNSW-NB15 training and testing CSV files.
Returns both DataFrames unchanged — no transformations here.
"""
import os, sys
import pandas as pd

_SRC   = os.path.dirname(os.path.abspath(__file__))
_ROOT  = os.path.dirname(_SRC)
DATA_DIR = os.path.join(_ROOT, "data")

TRAIN_FILE = "UNSW_NB15_training-set.csv"
TEST_FILE  = "UNSW_NB15_testing-set.csv"


def load_datasets(train_path=None, test_path=None):
    train_path = train_path or os.path.join(DATA_DIR, TRAIN_FILE)
    test_path  = test_path  or os.path.join(DATA_DIR, TEST_FILE)

    for path, label in [(train_path, "Training"), (test_path, "Testing")]:
        if not os.path.exists(path):
            sys.exit("\n[ERROR] {} file not found: {}\n"
                     "Place CSVs inside data/\n".format(label, path))

    print("[load_data] Loading training set ...")
    df_train = pd.read_csv(train_path)
    print("[load_data] Loading testing set  ...")
    df_test  = pd.read_csv(test_path)

    for name, df in [("Training", df_train), ("Testing", df_test)]:
        print("\n  [{}] {:,} rows x {} cols".format(name, df.shape[0], df.shape[1]))
        if "label" in df.columns:
            for lbl, cnt in df["label"].value_counts().sort_index().items():
                tag = "Normal" if int(lbl) == 0 else "Attack"
                print("    label={} ({:<6}): {:>8,}  ({:.1f}%)".format(
                    lbl, tag, cnt, cnt/len(df)*100))
    print()
    return df_train, df_test