import os
import json
import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, mean_squared_error, r2_score, confusion_matrix
import joblib

from backend.services.ai_intelligence.dataset import generate_synthetic_findings

def train_and_evaluate():
    print("🚀 Initiating Vorota AI Training Pipeline...")

    # 1. Dataset Generation
    df = generate_synthetic_findings(n_samples=15000)

    # 2. Preprocessing
    # Features for models
    categorical_cols = ['scanner_type', 'asset_criticality', 'exposure_level']
    numeric_cols = ['cvss_score', 'exploit_available', 'confidence_score']

    # One-hot encode categorical features
    df_encoded = pd.get_dummies(df, columns=categorical_cols, drop_first=True)
    
    # Define X and Y sets
    X = df_encoded.drop(columns=['finding_id', 'true_risk_score', 'is_false_positive'])
    feature_names = X.columns.tolist()
    
    y_risk = df_encoded['true_risk_score']
    y_fp = df_encoded['is_false_positive']

    # Train, Val, Test split (70, 15, 15)
    # First split 70/30
    X_train, X_temp, y_risk_train, y_risk_temp, y_fp_train, y_fp_temp = train_test_split(
        X, y_risk, y_fp, test_size=0.3, random_state=42
    )
    # Then split 30 into 15/15
    X_val, X_test, y_risk_val, y_risk_test, y_fp_val, y_fp_test = train_test_split(
        X_temp, y_risk_temp, y_fp_temp, test_size=0.5, random_state=42
    )

    print(f"Data Split -> Train: {len(X_train)}, Val: {len(X_val)}, Test: {len(X_test)}")

    # 3. Model 1: Risk Regressor (XGBoost)
    print("\n[ Model 1 ] Training Risk Scoring Regressor...")
    risk_model = xgb.XGBRegressor(
        n_estimators=200,
        learning_rate=0.05,
        max_depth=5,
        random_state=42
    )
    risk_model.fit(X_train, y_risk_train, eval_set=[(X_val, y_risk_val)], verbose=False)

    # Predict & Eval Risk Model
    risk_preds = risk_model.predict(X_test)
    mse = mean_squared_error(y_risk_test, risk_preds)
    r2 = r2_score(y_risk_test, risk_preds)
    print(f"  Risk Model Performance (Test):")
    print(f"  - RMSE: {np.sqrt(mse):.3f}")
    print(f"  - R2 Score: {r2:.3f}")

    # 4. Model 2: FP Classifier (XGBoost)
    print("\n[ Model 2 ] Training False Positive Classifier...")
    fp_model = xgb.XGBClassifier(
        n_estimators=200,
        learning_rate=0.05,
        max_depth=5,
        scale_pos_weight=(len(y_fp_train) - y_fp_train.sum()) / y_fp_train.sum(), # Handle class imbalance
        random_state=42
    )
    fp_model.fit(X_train, y_fp_train, eval_set=[(X_val, y_fp_val)], verbose=False)

    # Predict & Eval FP Model
    fp_preds = fp_model.predict(X_test)
    acc = accuracy_score(y_fp_test, fp_preds)
    prec = precision_score(y_fp_test, fp_preds)
    rec = recall_score(y_fp_test, fp_preds)
    f1 = f1_score(y_fp_test, fp_preds)
    cm = confusion_matrix(y_fp_test, fp_preds)

    print(f"  FP Filter Performance (Test):")
    print(f"  - Accuracy:  {acc:.2%}")
    print(f"  - Precision: {prec:.2%}")
    print(f"  - Recall:    {rec:.2%}")
    print(f"  - F1 Score:  {f1:.3f}")
    print(f"  - Confusion Matrix:\n{cm}")

    # 5. Export Models and Metadata
    print("\n💾 Saving models to disk...")
    # Get current dir format
    current_dir = os.path.dirname(os.path.abspath(__file__))
    model_dir = os.path.join(current_dir, 'models')
    os.makedirs(model_dir, exist_ok=True)

    risk_model_path = os.path.join(model_dir, 'risk_scorer_xgb.joblib')
    fp_model_path = os.path.join(model_dir, 'fp_classifier_xgb.joblib')
    meta_path = os.path.join(model_dir, 'model_metadata.json')

    joblib.dump(risk_model, risk_model_path)
    joblib.dump(fp_model, fp_model_path)

    # Save feature names so live pipeline maps inputs correctly
    with open(meta_path, 'w') as f:
        json.dump({
            "feature_names": feature_names,
            "categorical_cols": categorical_cols,
            "numeric_cols": numeric_cols,
            "fp_metrics": {
                "precision": prec,
                "recall": rec,
                "f1": f1
            }
        }, f, indent=4)

    print("[OK] Training Pipeline Complete! Standardized files saved in `models/` directory.")


if __name__ == "__main__":
    train_and_evaluate()
