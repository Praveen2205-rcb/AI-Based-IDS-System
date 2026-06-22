"""
autoencoder_model.py
====================
Build, train, save, load and predict with the Autoencoder anomaly detector.

Trained ONLY on normal traffic (label=0).
Detects attacks via high reconstruction MSE.
Threshold = 95th-percentile MSE of normal training samples.
Saved to models/autoencoder_model.h5.
"""
import os
import numpy as np
from tensorflow.keras.models import Model, load_model
from tensorflow.keras.layers import Dense, Dropout, BatchNormalization, Input
from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau
from tensorflow.keras.optimizers import Adam

_SRC   = os.path.dirname(os.path.abspath(__file__))
_ROOT  = os.path.dirname(_SRC)
MODEL_PATH    = os.path.join(_ROOT, "models", "autoencoder_model.h5")
THRESHOLD_PCT = 95


def build_autoencoder(input_dim):
    inp = Input(shape=(input_dim,), name="input")
    x = Dense(128, activation="relu")(inp)
    x = BatchNormalization()(x)
    x = Dropout(0.20)(x)
    x = Dense(64, activation="relu")(x)
    x = BatchNormalization()(x)
    encoded = Dense(32, activation="relu", name="bottleneck")(x)
    x = Dense(64, activation="relu")(encoded)
    x = BatchNormalization()(x)
    x = Dropout(0.20)(x)
    x = Dense(128, activation="relu")(x)
    decoded = Dense(input_dim, activation="linear", name="reconstruction")(x)
    ae = Model(inp, decoded, name="Autoencoder_IDS")
    ae.compile(optimizer=Adam(1e-3), loss="mse")
    return ae


def train_autoencoder(X_train, y_train_bin, epochs=60, batch_size=512, val_split=0.15, save=True):
    X_normal = X_train[y_train_bin == 0]
    print("[autoencoder] Building Autoencoder ...")
    print("  Training on NORMAL samples only: {:,}".format(X_normal.shape[0]))

    ae = build_autoencoder(X_normal.shape[1])
    ae.summary()

    cbs = [
        EarlyStopping(monitor="val_loss", patience=6, restore_best_weights=True, verbose=1),
        ReduceLROnPlateau(monitor="val_loss", factor=0.5, patience=3, min_lr=1e-6, verbose=1),
    ]

    print("\n[autoencoder] Training ...")
    history = ae.fit(
        X_normal, X_normal,
        validation_split=val_split,
        epochs=epochs,
        batch_size=batch_size,
        callbacks=cbs,
        verbose=1,
    )

    # Compute threshold from normal training samples
    recon  = ae.predict(X_normal, verbose=0)
    errors = np.mean((X_normal - recon) ** 2, axis=1)
    threshold = float(np.percentile(errors, THRESHOLD_PCT))
    print("\n  Anomaly threshold ({}th-pct MSE): {:.6f}".format(THRESHOLD_PCT, threshold))

    # Save threshold alongside model
    threshold_path = MODEL_PATH.replace(".h5", "_threshold.npy")
    np.save(threshold_path, threshold)
    print("  Threshold saved -> {}".format(threshold_path))

    if save:
        os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
        ae.save(MODEL_PATH)
        print("[autoencoder] Model saved -> {}".format(MODEL_PATH))

    print("[autoencoder] Training complete.\n")
    return ae, history, threshold


def load_autoencoder(path=None):
    path = path or MODEL_PATH
    if not os.path.exists(path):
        raise FileNotFoundError("[autoencoder] No model at: {}".format(path))
    ae = load_model(path)
    # Load saved threshold
    thr_path = path.replace(".h5", "_threshold.npy")
    threshold = float(np.load(thr_path)) if os.path.exists(thr_path) else 0.020
    print("[autoencoder] Loaded. Threshold: {:.6f}".format(threshold))
    return ae, threshold


def predict_autoencoder(model, X, threshold):
    recon        = model.predict(X, verbose=0)
    recon_errors = np.mean((X - recon) ** 2, axis=1)
    y_pred       = (recon_errors > threshold).astype(int)
    return y_pred, recon_errors