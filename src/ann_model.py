"""
ann_model.py
============
Build, train, save, load and predict with the ANN classifier.

Architecture: Input → Dense(256,ReLU)+BN+Drop → Dense(128,ReLU)+BN+Drop
              → Dense(64,ReLU)+Drop → Dense(1,Sigmoid)

Trained on SMOTE-balanced data. Saved to models/ann_model.h5.
Loaded by ai_engine.py for real-time inference.
"""
import os
import numpy as np
from tensorflow.keras.models import Sequential, load_model
from tensorflow.keras.layers import Dense, Dropout, BatchNormalization
from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau
from tensorflow.keras.optimizers import Adam

_SRC   = os.path.dirname(os.path.abspath(__file__))
_ROOT  = os.path.dirname(_SRC)
MODEL_PATH = os.path.join(_ROOT, "models", "ann_model.h5")


def build_ann(input_dim):
    model = Sequential(name="ANN_IDS")
    model.add(Dense(256, activation="relu", input_shape=(input_dim,)))
    model.add(BatchNormalization())
    model.add(Dropout(0.30))
    model.add(Dense(128, activation="relu"))
    model.add(BatchNormalization())
    model.add(Dropout(0.30))
    model.add(Dense(64, activation="relu"))
    model.add(Dropout(0.20))
    model.add(Dense(1, activation="sigmoid"))
    model.compile(optimizer=Adam(1e-3), loss="binary_crossentropy", metrics=["accuracy"])
    return model


def train_ann(X_train, y_train, epochs=60, batch_size=512, val_split=0.15, save=True):
    print("[ann_model] Building ANN ...")
    model = build_ann(X_train.shape[1])
    model.summary()

    cbs = [
        EarlyStopping(monitor="val_loss", patience=6, restore_best_weights=True, verbose=1),
        ReduceLROnPlateau(monitor="val_loss", factor=0.5, patience=3, min_lr=1e-6, verbose=1),
    ]

    print("\n[ann_model] Training on {:,} SMOTE-balanced samples ...".format(len(X_train)))
    history = model.fit(
        X_train, y_train,
        validation_split=val_split,
        epochs=epochs,
        batch_size=batch_size,
        callbacks=cbs,
        verbose=1,
    )

    if save:
        os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
        model.save(MODEL_PATH)
        print("\n[ann_model] Saved -> {}".format(MODEL_PATH))

    print("[ann_model] Training complete.\n")
    return model, history


def load_ann(path=None):
    path = path or MODEL_PATH
    if not os.path.exists(path):
        raise FileNotFoundError("[ann_model] No model at: {}".format(path))
    return load_model(path)


def predict_ann(model, X, threshold=0.5):
    y_prob = model.predict(X, verbose=0).ravel()
    y_pred = (y_prob >= threshold).astype(int)
    return y_pred, y_prob