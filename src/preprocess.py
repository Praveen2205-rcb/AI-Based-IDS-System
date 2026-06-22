"""
preprocess.py
=============
Full preprocessing pipeline:
  1. Drop non-predictive columns (id)
  2. Extract binary + multi-class labels
  3. Fill missing values using TRAINING medians only
  4. One-hot encode categorical columns (proto, service, state)
  5. Align train/test column sets
  6. Fit StandardScaler on training, transform both
  7. Save scaler params to models/scaler_params.npy for inference use
"""
import os
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler, LabelEncoder

_SRC  = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_SRC)

DROP_COLS      = ["id"]
CAT_COLS       = ["proto", "service", "state"]
LABEL_COL      = "label"
ATTACK_CAT_COL = "attack_cat"
SCALER_PARAMS  = os.path.join(_ROOT, "models", "scaler_params.npy")


def preprocess(df_train, df_test):
    print("[preprocess] Starting pipeline ...")

    # 1. Drop identifiers
    cols_to_drop = [c for c in DROP_COLS if c in df_train.columns]
    df_train = df_train.drop(columns=cols_to_drop)
    df_test  = df_test.drop(columns=cols_to_drop)
    print("  [1] Dropped: {}".format(cols_to_drop))

    # 2. Extract labels
    y_train_bin = df_train[LABEL_COL].astype(int).values
    y_test_bin  = df_test[LABEL_COL].astype(int).values

    le = LabelEncoder()
    all_cats = pd.concat([
        df_train[ATTACK_CAT_COL].fillna("Normal"),
        df_test[ATTACK_CAT_COL].fillna("Normal")
    ])
    le.fit(all_cats)
    y_train_cat    = le.transform(df_train[ATTACK_CAT_COL].fillna("Normal"))
    y_test_cat     = le.transform(df_test[ATTACK_CAT_COL].fillna("Normal"))
    attack_classes = list(le.classes_)

    df_train = df_train.drop(columns=[LABEL_COL, ATTACK_CAT_COL])
    df_test  = df_test.drop(columns=[LABEL_COL, ATTACK_CAT_COL])
    print("  [2] Labels extracted. Categories: {}".format(attack_classes))

    # 3. Fill missing values (training medians only)
    train_medians = df_train.median(numeric_only=True)
    df_train = df_train.fillna(train_medians)
    df_test  = df_test.fillna(train_medians)
    print("  [3] Missing values filled using training medians")

    # 4. One-hot encode
    cat_present = [c for c in CAT_COLS if c in df_train.columns]
    df_train = pd.get_dummies(df_train, columns=cat_present, dtype=np.uint8)
    df_test  = pd.get_dummies(df_test,  columns=cat_present, dtype=np.uint8)
    print("  [4] One-hot encoded: {}".format(cat_present))

    # 5. Align columns
    df_train, df_test = df_train.align(df_test, join="left", axis=1, fill_value=0)
    feature_columns   = list(df_train.columns)
    print("  [5] Feature columns after alignment: {}".format(len(feature_columns)))

    assert df_train.isnull().sum().sum() == 0
    assert list(df_train.columns) == list(df_test.columns)

    # 6. Scale
    X_train = df_train.values.astype(np.float32)
    X_test  = df_test.values.astype(np.float32)
    scaler  = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test  = scaler.transform(X_test)
    print("  [6] Scaled. X_train: {}  X_test: {}".format(X_train.shape, X_test.shape))

    # 7. Save scaler params for real-time inference use
    os.makedirs(os.path.dirname(SCALER_PARAMS), exist_ok=True)
    np.save(SCALER_PARAMS, {"mean": scaler.mean_, "scale": scaler.scale_})
    # Also save feature column names for exact inference matching
    feat_cols_path = os.path.join(os.path.dirname(SCALER_PARAMS), "feature_columns.npy")
    np.save(feat_cols_path, np.array(feature_columns))
    print("  [7b] Feature columns saved -> {}".format(feat_cols_path))
    print("  [7] Scaler params saved -> {}".format(SCALER_PARAMS))
    print("[preprocess] Done.\n")

    return {
        "X_train"         : X_train,
        "X_test"          : X_test,
        "y_train_bin"     : y_train_bin,
        "y_test_bin"      : y_test_bin,
        "y_train_cat"     : y_train_cat,
        "y_test_cat"      : y_test_cat,
        "attack_classes"  : attack_classes,
        "scaler"          : scaler,
        "feature_columns" : feature_columns,
    }