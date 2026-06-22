"""
smote_processing.py
===================
Apply SMOTE to the training set only.
Balanced arrays are returned in memory and passed directly to the ANN.
Optionally saves balanced dataset to data/train_smote.csv.
"""
import os
import numpy as np
import pandas as pd
from imblearn.over_sampling import SMOTE

_SRC  = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_SRC)
SMOTE_CSV = os.path.join(_ROOT, "data", "train_smote.csv")
SEED = 42


def apply_smote(X_train, y_train, save_csv=False, feature_columns=None):
    print("[smote] Applying SMOTE to training set ...")
    before = np.bincount(y_train)
    print("  Before — Normal: {:,}  Attack: {:,}  (ratio {:.1f}:1)".format(
        before[0], before[1], before[0]/max(before[1],1)))

    smote = SMOTE(random_state=SEED, n_jobs=-1)
    X_bal, y_bal = smote.fit_resample(X_train, y_train)

    after = np.bincount(y_bal)
    print("  After  — Normal: {:,}  Attack: {:,}  (balanced)".format(after[0], after[1]))
    print("  Synthetic samples generated: {:,}".format(after[1]-before[1]))
    print("  Total training samples:      {:,}".format(len(X_bal)))

    if save_csv:
        cols = feature_columns or ["f{}".format(i) for i in range(X_bal.shape[1])]
        df   = pd.DataFrame(X_bal, columns=cols)
        df["label"] = y_bal.astype(int)
        df.to_csv(SMOTE_CSV, index=False)
        print("  Saved -> {}".format(SMOTE_CSV))

    print("[smote] Done.\n")
    return X_bal, y_bal