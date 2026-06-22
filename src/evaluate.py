"""
evaluate.py
===========
Compute metrics, generate plots, write reports, compare models.

Outputs saved to results/:
  ann_report.txt, autoencoder_report.txt
  confusion_matrix.png, learning_curves.png
  ae_error_distribution.png, model_comparison.png
"""
import os
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, confusion_matrix, classification_report,
)

_SRC  = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_SRC)
RESULTS_DIR = os.path.join(_ROOT, "results")

C = {"blue":"#2563EB","orange":"#D97706","red":"#DC2626","green":"#16A34A","bg":"#F8FAFC"}


def compute_metrics(y_true, y_pred):
    return {
        "accuracy"         : accuracy_score (y_true, y_pred),
        "precision"        : precision_score(y_true, y_pred, zero_division=0),
        "recall"           : recall_score   (y_true, y_pred, zero_division=0),
        "f1"               : f1_score       (y_true, y_pred, zero_division=0),
        "confusion_matrix" : confusion_matrix(y_true, y_pred),
    }


def save_report(name, metrics, y_true, y_pred, extra=""):
    os.makedirs(RESULTS_DIR, exist_ok=True)
    fp  = os.path.join(RESULTS_DIR, "{}_report.txt".format(name))
    cr  = classification_report(y_true, y_pred, target_names=["Normal","Attack"])
    cm  = metrics["confusion_matrix"]
    lines = [
        "="*65,
        "  {} -- EVALUATION REPORT".format(name.upper()),
        "="*65, "",
    ]
    if extra:
        lines += [extra, ""]
    lines += [
        "  Summary Metrics:",
        "    Accuracy  : {:.4f}  ({:.2f}%)".format(metrics["accuracy"],  metrics["accuracy"]*100),
        "    Precision : {:.4f}".format(metrics["precision"]),
        "    Recall    : {:.4f}".format(metrics["recall"]),
        "    F1-Score  : {:.4f}".format(metrics["f1"]),
        "",
        "  Confusion Matrix (TN FP / FN TP):",
        "    TN={:,}  FP={:,}".format(cm[0,0], cm[0,1]),
        "    FN={:,}  TP={:,}".format(cm[1,0], cm[1,1]),
        "",
        "  Full Classification Report:",
        cr, "="*65,
    ]
    text = "\n".join(lines)
    with open(fp, "w") as f:
        f.write(text)
    print("[evaluate] Report saved -> {}".format(fp))
    print("\n" + text + "\n")


def plot_confusion_matrices(cm_ann, cm_ae):
    os.makedirs(RESULTS_DIR, exist_ok=True)
    fp  = os.path.join(RESULTS_DIR, "confusion_matrix.png")
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.5), facecolor=C["bg"])
    for ax, cm, title, cmap in [
        (axes[0], cm_ann, "ANN — Confusion Matrix",        "Blues"),
        (axes[1], cm_ae,  "Autoencoder — Confusion Matrix","Oranges"),
    ]:
        ax.set_facecolor(C["bg"])
        sns.heatmap(cm, annot=True, fmt="d", cmap=cmap,
                    xticklabels=["Normal","Attack"],
                    yticklabels=["Normal","Attack"],
                    linewidths=0.5, linecolor="white",
                    annot_kws={"size":13,"weight":"bold"}, ax=ax)
        ax.set_xlabel("Predicted"); ax.set_ylabel("Actual")
        ax.set_title(title, fontsize=12, fontweight="bold", pad=10)
    plt.tight_layout()
    plt.savefig(fp, dpi=120, bbox_inches="tight")
    plt.close()
    print("[evaluate] Saved -> {}".format(fp))


def plot_learning_curves(ann_hist, ae_hist):
    os.makedirs(RESULTS_DIR, exist_ok=True)
    fp  = os.path.join(RESULTS_DIR, "learning_curves.png")
    fig, axes = plt.subplots(1, 3, figsize=(15, 4.5), facecolor=C["bg"])
    for ax in axes:
        ax.set_facecolor(C["bg"])
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        ax.grid(alpha=0.25, linestyle="--")

    axes[0].plot(ann_hist.history["loss"],     color=C["blue"],   lw=2, label="Train")
    axes[0].plot(ann_hist.history["val_loss"], color=C["red"],    lw=2, linestyle="--", label="Val")
    axes[0].set_title("ANN — Loss", fontweight="bold")
    axes[0].set_xlabel("Epoch"); axes[0].legend()

    axes[1].plot(ann_hist.history["accuracy"],     color=C["green"],  lw=2, label="Train")
    axes[1].plot(ann_hist.history["val_accuracy"], color=C["orange"], lw=2, linestyle="--", label="Val")
    axes[1].set_ylim(0, 1.05)
    axes[1].set_title("ANN — Accuracy", fontweight="bold")
    axes[1].set_xlabel("Epoch"); axes[1].legend()

    axes[2].plot(ae_hist.history["loss"],     color=C["blue"],  lw=2, label="Train MSE")
    axes[2].plot(ae_hist.history["val_loss"], color=C["red"],   lw=2, linestyle="--", label="Val MSE")
    axes[2].set_title("Autoencoder — Loss (MSE)", fontweight="bold")
    axes[2].set_xlabel("Epoch"); axes[2].legend()

    plt.suptitle("Training History", fontsize=13, fontweight="bold")
    plt.tight_layout()
    plt.savefig(fp, dpi=120, bbox_inches="tight")
    plt.close()
    print("[evaluate] Saved -> {}".format(fp))


def plot_reconstruction_errors(recon_errors, y_true, threshold):
    os.makedirs(RESULTS_DIR, exist_ok=True)
    fp  = os.path.join(RESULTS_DIR, "ae_error_distribution.png")
    fig, ax = plt.subplots(figsize=(10,5), facecolor=C["bg"])
    ax.set_facecolor(C["bg"])
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.hist(recon_errors[y_true==0], bins=120, alpha=0.65, color=C["blue"],  label="Normal", density=True)
    ax.hist(recon_errors[y_true==1], bins=120, alpha=0.65, color=C["red"],   label="Attack", density=True)
    ax.axvline(threshold, color="black", lw=2, linestyle="--",
               label="Threshold = {:.5f}".format(threshold))
    ax.set_xlabel("Reconstruction Error (MSE)")
    ax.set_ylabel("Density")
    ax.set_title("Autoencoder — Reconstruction Error Distribution", fontweight="bold")
    ax.legend(); ax.grid(axis="y", alpha=0.25, linestyle="--")
    plt.tight_layout()
    plt.savefig(fp, dpi=120)
    plt.close()
    print("[evaluate] Saved -> {}".format(fp))


def compare_models(ann_m, ae_m):
    os.makedirs(RESULTS_DIR, exist_ok=True)
    fp   = os.path.join(RESULTS_DIR, "model_comparison.png")
    keys = ["accuracy","precision","recall","f1"]
    lbls = ["Accuracy","Precision","Recall","F1-Score"]
    av   = [ann_m[k] for k in keys]
    bv   = [ae_m[k]  for k in keys]

    print("\n" + "="*55)
    print("  MODEL COMPARISON")
    print("="*55)
    print("  {:<14} {:>10} {:>14}".format("Metric","ANN","Autoencoder"))
    print("-"*55)
    for l, a, b in zip(lbls, av, bv):
        print("  {:<14} {:>10.4f} {:>14.4f}{}".format(l, a, b, " <--" if a>=b else ""))
    print("="*55+"\n")

    x = np.arange(len(lbls)); w = 0.35
    fig, ax = plt.subplots(figsize=(9,5), facecolor=C["bg"])
    ax.set_facecolor(C["bg"])
    b1 = ax.bar(x-w/2, av, w, label="ANN",         color=C["blue"],   edgecolor="white", lw=0.8)
    b2 = ax.bar(x+w/2, bv, w, label="Autoencoder", color=C["orange"], edgecolor="white", lw=0.8)
    for bars in (b1, b2):
        for bar in bars:
            h = bar.get_height()
            ax.text(bar.get_x()+bar.get_width()/2, h+0.004,
                    "{:.3f}".format(h), ha="center", va="bottom", fontsize=8.5, fontweight="bold")
    ax.set_ylim(0, 1.12); ax.set_xticks(x); ax.set_xticklabels(lbls, fontsize=11)
    ax.set_ylabel("Score"); ax.set_title("ANN vs Autoencoder — Performance", fontsize=13, fontweight="bold", pad=14)
    ax.legend(loc="lower right"); ax.spines["top"].set_visible(False); ax.spines["right"].set_visible(False)
    ax.grid(axis="y", alpha=0.25, linestyle="--")
    plt.tight_layout()
    plt.savefig(fp, dpi=120)
    plt.close()
    print("[evaluate] Saved -> {}".format(fp))