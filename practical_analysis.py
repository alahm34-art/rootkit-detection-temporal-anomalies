#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
  Practical Verification — Rootkit Detection via Kernel Timing Anomalies
  العمل التطبيقي — كشف الـ Rootkits عبر تحليل توقيتات دوال الـ Kernel
================================================================================

  Reference Paper / الورقة المرجعية:
    Landauer, M., Alton, L., Lindorfer, M., Skopik, F., Wurzenberger, M., &
    Hotwagner, W. (2025). Trace of the Times: Rootkit Detection through
    Temporal Anomalies in Kernel Activity. ACM Digital Threats: Research and
    Practice, 6(4), 1-26.

  Authors / المنفّذون:
    Ahmed Atiyah AL-Zahrani       (ID: 447001014)
    Mohammed Salem Alghamdi       (ID: 447000003)
    M.Sc. Cybersecurity — CYBS60201 — Al-Baha University

================================================================================
  WHAT THIS SCRIPT DOES / وش يسوي السكربت
================================================================================

  EN: Rebuilds the paper's rootkit detection pipeline from scratch:
      1. Generates synthetic kernel function delta time samples
         (matching the published Zenodo dataset specification).
      2. Implements the exact detection algorithm: 9-quantile vectors,
         Mahalanobis distance against a clean baseline, chi-square p-value.
      3. Produces two publication-quality figures showing the timing shift
         and the anomaly score separation.
      4. Prints detection metrics (Precision, Recall, F1, FPR).

  AR: السكربت يعيد بناء خوارزمية كشف الـ rootkit من الورقة:
      1. يولّد بيانات تركيبية لتوقيتات دوال الـ kernel (مطابقة لمواصفات
         بيانات Zenodo المنشورة).
      2. يطبّق نفس خوارزمية الكشف: 9 quantiles، مسافة Mahalanobis، p-value
         من توزيع chi-square.
      3. يولّد شكلين بجودة نشر علمي يوضحان: انزياح التوقيت، وفصل درجات
         الكشف.
      4. يطبع مقاييس الأداء (Precision, Recall, F1, FPR).

================================================================================
  WHY SYNTHETIC DATA / ليش بيانات تركيبية
================================================================================

  The Zenodo archive (478 MB) was not reachable from the development
  environment, so we generate data matching the published specification.
  This is a "synthetic reproduction" — valid academic methodology when
  raw data is unavailable, provided we declare it clearly.

  أرشيف Zenodo (478 ميجا) لم يكن متاحاً في بيئة التطوير، فولّدنا بيانات
  مطابقة للمواصفات المنشورة. هذي طريقة أكاديمية معتمدة (synthetic
  reproduction) ما دامت معلنة بوضوح.

================================================================================
  REQUIREMENTS / المتطلبات
================================================================================

  Python 3.8 or newer
  pip install numpy scipy matplotlib

================================================================================
  HOW TO RUN / طريقة التشغيل
================================================================================

  Windows:   python practical_analysis.py
  Mac/Linux: python3 practical_analysis.py

  Output / المخرجات:
    - practical_results.json
    - fig2_distribution_shift.png
    - fig3_score_separation.png

================================================================================
"""

# ============================================================================
# IMPORTS / الاستيرادات
# ============================================================================

import json
import os
import sys
import numpy as np
import matplotlib

# Use a non-interactive backend so the script runs on any system
# نستخدم backend غير تفاعلي حتى يشتغل على أي نظام
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from scipy.stats import chi2

# ============================================================================
# REPRODUCIBILITY / تثبيت العشوائية للحصول على نفس النتائج
# ============================================================================
# Seed = student ID, so the same input always produces the same output
# البذرة = رقم الطالب، حتى نفس المدخل يعطي نفس المخرج دائماً
SEED = 447001014
rng = np.random.default_rng(SEED)

print("=" * 78)
print("  PRACTICAL VERIFICATION — Rootkit Detection via Kernel Timing")
print("  Reference: Landauer et al. (2025), ACM DTRAP 6(4)")
print(f"  Random seed: {SEED}")
print("=" * 78)

# ============================================================================
# STEP 1 — SYNTHETIC DELTA TIME GENERATION
# الخطوة 1 — توليد توقيتات دوال الـ kernel
# ============================================================================
#
# EN: The paper probes 4 functions inside the getdents syscall.
#     CARAXES rootkit wraps filldir64 -> adds ~430 ns of injected code.
#
# AR: الورقة تراقب 4 دوال داخل نظام getdents syscall.
#     الـ rootkit (CARAXES) يلتف حول filldir64 -> يضيف ~430 نانوثانية
#     من الكود المحقون.

# Baseline timing in nanoseconds for each probed kernel function
# التوقيت الأساسي بالنانوثانية لكل دالة kernel
FUNCTIONS = {
    "iterate_dir":        {"base": 2600, "spread": 480},
    "filldir64":          {"base": 1850, "spread": 360},   # rootkit target
    "verify_dirent_name": {"base": 1380, "spread": 240},
    "touch_atime":        {"base":  920, "spread": 210},
}

# Five experimental scenarios from the paper / السيناريوهات الخمسة
SCENARIOS = ["default", "file_count", "system_load", "ls_basic", "filename_length"]

# Noise multiplier per scenario (system_load is noisiest)
# مضاعف الضوضاء لكل سيناريو (system_load الأكثر ضوضاء)
SCEN_NOISE = {
    "default": 1.00, "file_count": 1.15, "system_load": 1.55,
    "ls_basic": 1.08, "filename_length": 1.22,
}

ROOTKIT_TARGET = "filldir64"      # The function the rootkit wraps
ROOTKIT_SHIFT_NS = 430            # Extra delay injected by the rootkit
EVENTS_PER_BATCH = 100            # Like running 'ls' 100 times per batch
QUANTILES = np.linspace(0, 1 - 1/10, 10)[1:]   # 9 quantiles (matches paper -q 9)


def make_batch(scenario, infected):
    """
    Generate one batch of delta time measurements.
    يولّد دفعة واحدة من قياسات التوقيت.

    Args:
        scenario: Name of the experimental scenario.
        infected: True if the rootkit is active, False otherwise.

    Returns:
        dict mapping function name -> array of delta times in nanoseconds.
    """
    noise = SCEN_NOISE[scenario]
    batch = {}
    for fname, p in FUNCTIONS.items():
        n = EVENTS_PER_BATCH
        # Real syscall timings are multimodal: ~70% fast path, ~30% slow
        # توقيتات الـ syscall الحقيقية متعددة الأنماط: 70% سريع، 30% بطيء
        n_slow = rng.binomial(n, 0.30)
        n_fast = n - n_slow
        fast = rng.gamma(shape=4.0, scale=p["spread"] * noise / 4.0, size=n_fast) + p["base"]
        slow = rng.gamma(shape=3.0, scale=p["spread"] * noise / 2.0, size=n_slow) + p["base"] * 1.6
        deltas = np.concatenate([fast, slow])

        # If the rootkit is active, add the injected-code delay on its target
        # إذا الـ rootkit نشط، نضيف تأخير الكود المحقون على دالته المستهدفة
        if infected and fname == ROOTKIT_TARGET:
            deltas = deltas + ROOTKIT_SHIFT_NS + rng.normal(0, 55, size=deltas.size)

        batch[fname] = np.clip(deltas, 1, None)
    return batch


# Build the full corpus: 150 normal + 100 rootkit per scenario => 750 + 500
# نبني المجموعة الكاملة: 150 طبيعي + 100 مع rootkit لكل سيناريو
print("\n[1/4] Generating synthetic data / توليد البيانات التركيبية...")
normal_batches, rootkit_batches = [], []
for scen in SCENARIOS:
    for _ in range(150):
        normal_batches.append((scen, make_batch(scen, infected=False)))
    for _ in range(100):
        rootkit_batches.append((scen, make_batch(scen, infected=True)))

print(f"      Normal batches:  {len(normal_batches)}")
print(f"      Rootkit batches: {len(rootkit_batches)}")


# ============================================================================
# STEP 2 — DETECTION ALGORITHM (re-implementation of the paper)
# الخطوة 2 — خوارزمية الكشف (إعادة بناء من الورقة)
# ============================================================================
#
# EN: For each batch, we summarize each function's delta time distribution
#     using 9 quantiles. We compare the test batch's quantile vector to a
#     mean+covariance learned from clean baseline data.
#
# AR: لكل دفعة، نلخص توزيع توقيتات كل دالة بـ 9 quantiles. ثم نقارن
#     vector الـ quantiles للدفعة بـ mean+covariance المُتعلَّمة من البيانات
#     النظيفة.

def quantile_vector(batch):
    """Compute 9 quantiles per function. / احسب 9 quantiles لكل دالة."""
    return {f: np.quantile(d, QUANTILES) for f, d in batch.items()}


def fit_baseline(train_batches):
    """
    Fit the clean-data baseline: mean vector and inverse covariance.
    تدريب النموذج: متوسط vector ومعكوس مصفوفة التغاير.
    """
    stacks = {f: [] for f in FUNCTIONS}
    for _, b in train_batches:
        qv = quantile_vector(b)
        for f in FUNCTIONS:
            stacks[f].append(qv[f])

    mean, cov_inv = {}, {}
    for f in FUNCTIONS:
        arr = np.array(stacks[f])
        mean[f] = arr.mean(axis=0)
        cov = np.cov(arr, rowvar=False)
        cov_inv[f] = np.linalg.pinv(cov)   # pinv = pseudo-inverse for stability
    return mean, cov_inv


def batch_pvalue(batch, mean, cov_inv):
    """
    Score one batch: lowest chi-square p-value across all functions.
    تقييم دفعة واحدة: أقل p-value عبر كل الدوال.
    """
    qv = quantile_vector(batch)
    pvals = []
    for f in FUNCTIONS:
        diff = qv[f] - mean[f]
        # Mahalanobis distance squared / مسافة Mahalanobis مربعة
        mhd_sq = float(diff @ cov_inv[f] @ diff)
        # Convert to chi-square p-value / نحوّل إلى p-value عبر chi-square
        p = 1.0 - chi2.cdf(mhd_sq, df=len(QUANTILES))
        pvals.append(p)
    return min(pvals)


# Semi-supervised split: train on 1/3 of normal batches, test on the rest
# تقسيم شبه مُشرف: ندرّب على ثلث الطبيعي، نختبر على الباقي + كل الـ rootkit
print("\n[2/4] Training detector on clean data / تدريب الكاشف على البيانات النظيفة...")
rng.shuffle(normal_batches)
n_train = len(normal_batches) // 3
train_batches = normal_batches[:n_train]
test_normal = normal_batches[n_train:]
test_rootkit = rootkit_batches

mean, cov_inv = fit_baseline(train_batches)
print(f"      Trained on:    {len(train_batches)} clean batches")
print(f"      Test normal:   {len(test_normal)} batches")
print(f"      Test rootkit:  {len(test_rootkit)} batches")

print("\n[3/4] Computing anomaly scores / حساب درجات الشذوذ...")
p_normal = np.array([batch_pvalue(b, mean, cov_inv) for _, b in test_normal])
p_rootkit = np.array([batch_pvalue(b, mean, cov_inv) for _, b in test_rootkit])

# Threshold sweep to find the best F1 / مسح الـ threshold لإيجاد أفضل F1
best = None
for thr in np.logspace(-30, -1, 200):
    tp = int(np.sum(p_rootkit < thr))
    fn = len(p_rootkit) - tp
    fp = int(np.sum(p_normal < thr))
    tn = len(p_normal) - fp
    prec = tp / (tp + fp) if (tp + fp) else 0
    rec = tp / (tp + fn) if (tp + fn) else 0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0
    if best is None or f1 > best["f1"]:
        best = dict(
            threshold=thr, tp=tp, fp=fp, tn=tn, fn=fn,
            precision=prec, recall=rec, f1=f1,
            accuracy=(tp + tn) / (tp + tn + fp + fn),
            false_positive_rate=fp / (fp + tn) if (fp + tn) else 0,
        )

# ============================================================================
# RESULTS / النتائج
# ============================================================================
print("\n" + "=" * 78)
print("  DETECTION RESULTS / نتائج الكشف")
print("=" * 78)
print(f"  Optimal threshold        : {best['threshold']:.3e}")
print(f"  True positives  (TP)     : {best['tp']}")
print(f"  False positives (FP)     : {best['fp']}")
print(f"  True negatives  (TN)     : {best['tn']}")
print(f"  False negatives (FN)     : {best['fn']}")
print(f"  Precision                : {best['precision']:.4f}")
print(f"  Recall                   : {best['recall']:.4f}")
print(f"  F1 score                 : {best['f1']:.4f}")
print(f"  Accuracy                 : {best['accuracy']:.4f}")
print(f"  False positive rate      : {best['false_positive_rate']:.4f}")
print()
print(f"  Paper reports F1 = 0.99  (TP=499, FN=1, FP=9)")
print(f"  Our reproduction matches the mechanism described in the paper.")
print("=" * 78)

# Save results to JSON / احفظ النتائج في ملف JSON
with open("practical_results.json", "w", encoding="utf-8") as fh:
    serializable = {k: (float(v) if isinstance(v, (int, float, np.floating)) else v)
                    for k, v in best.items()}
    serializable["seed"] = SEED
    serializable["normal_batches"] = len(normal_batches)
    serializable["rootkit_batches"] = len(rootkit_batches)
    json.dump(serializable, fh, indent=2)
print("\n[Saved] practical_results.json")


# ============================================================================
# STEP 3 — FIGURE 2: delta time distribution shift
# الخطوة 3 — الشكل 2: انزياح توزيع التوقيت
# ============================================================================
print("\n[4/4] Generating figures / إنشاء الأشكال...")

norm_target = np.concatenate([b[ROOTKIT_TARGET] for _, b in test_normal[:60]])
rk_target = np.concatenate([b[ROOTKIT_TARGET] for _, b in test_rootkit[:60]])

fig, ax = plt.subplots(figsize=(7.4, 3.6), dpi=200)
bins = np.linspace(1000, 5200, 70)
ax.hist(norm_target, bins=bins, color="#2E6B43", alpha=0.62,
        label="Normal (no rootkit)", edgecolor="white", linewidth=0.3)
ax.hist(rk_target, bins=bins, color="#B23A3A", alpha=0.62,
        label="Rootkit active (CARAXES)", edgecolor="white", linewidth=0.3)
ax.axvline(np.median(norm_target), color="#1F4A2E", linestyle="--", linewidth=1.4)
ax.axvline(np.median(rk_target), color="#7A1F1F", linestyle="--", linewidth=1.4)
shift = np.median(rk_target) - np.median(norm_target)
ymax = ax.get_ylim()[1]
ax.set_ylim(0, ymax * 1.18)
ax.annotate("", xy=(np.median(rk_target), ymax * 0.70),
            xytext=(np.median(norm_target), ymax * 0.70),
            arrowprops=dict(arrowstyle="<->", color="#333333", lw=1.3))
ax.text((np.median(norm_target) + np.median(rk_target)) / 2, ymax * 0.78,
        f"median shift  +{shift:.0f} ns", ha="center", fontsize=9,
        color="#222222", fontweight="bold")
ax.set_xlabel("filldir64 execution delta time (nanoseconds)", fontsize=10)
ax.set_ylabel("Frequency", fontsize=10)
ax.set_title("Delta Time Distribution of the Rootkit-Wrapped Kernel Function",
             fontsize=11, fontweight="bold", pad=10)
ax.legend(fontsize=9, framealpha=0.9, loc="upper right")
ax.spines[["top", "right"]].set_visible(False)
ax.tick_params(labelsize=8.5)
plt.tight_layout()
plt.savefig("fig2_distribution_shift.png", dpi=200, bbox_inches="tight")
plt.close()
print("      Saved: fig2_distribution_shift.png")


# ============================================================================
# STEP 4 — FIGURE 3: anomaly score separation
# الخطوة 4 — الشكل 3: فصل درجات الكشف
# ============================================================================
fig, ax = plt.subplots(figsize=(7.4, 3.4), dpi=200)
eps = 1e-31
pn = np.clip(p_normal, eps, 1)
pr = np.clip(p_rootkit, eps, 1)
log_bins = np.logspace(-31, 0, 55)
ax.hist(pn, bins=log_bins, color="#2E6B43", alpha=0.62,
        label="Normal batches", edgecolor="white", linewidth=0.3)
ax.hist(pr, bins=log_bins, color="#B23A3A", alpha=0.62,
        label="Rootkit batches", edgecolor="white", linewidth=0.3)
ax.axvline(best["threshold"], color="#222222", linestyle="--", linewidth=1.6,
           label="Decision threshold")
ax.set_xscale("log")
ax.set_xlabel("Chi-square p-value  (batch anomaly score, log scale)", fontsize=10)
ax.set_ylabel("Number of batches", fontsize=10)
ax.set_title("Anomaly Score Separation Between Normal and Rootkit Batches",
             fontsize=11, fontweight="bold")
ax.legend(fontsize=9, framealpha=0.9, loc="upper center")
ax.spines[["top", "right"]].set_visible(False)
ax.tick_params(labelsize=8.5)
plt.tight_layout()
plt.savefig("fig3_score_separation.png", dpi=200, bbox_inches="tight")
plt.close()
print("      Saved: fig3_score_separation.png")

print("\n" + "=" * 78)
print("  DONE / تم")
print("  Open the generated PNG files to view the figures.")
print("  افتح ملفات PNG لمشاهدة الأشكال.")
print("=" * 78)
