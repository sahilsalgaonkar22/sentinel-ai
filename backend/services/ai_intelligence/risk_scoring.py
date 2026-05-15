import os
import logging
import pandas as pd
import numpy as np

logger = logging.getLogger(__name__)

try:
    import joblib
    import xgboost as xgb
    XGB_AVAILABLE = True
except ImportError:
    XGB_AVAILABLE = False

current_dir = os.path.dirname(os.path.abspath(__file__))
model_path = os.path.join(current_dir, 'models', 'risk_scorer_xgb.joblib')
meta_path = os.path.join(current_dir, 'models', 'model_metadata.json')

class RiskScorer:
    def __init__(self):
        self.model = None
        self.feature_names = None
        self.categorical_cols = None
        self.numeric_cols = None
        self.model_version = "risk_v1.0"
        self.model_hash = "fallback"
        
        # Load model and metadata if available
        self.reload()

    def _compute_hash(self, path):
        import hashlib
        hasher = hashlib.sha256()
        with open(path, 'rb') as afile:
            buf = afile.read(65536)
            while len(buf) > 0:
                hasher.update(buf)
                buf = afile.read(65536)
        return hasher.hexdigest()

    def reload(self):
        if not XGB_AVAILABLE or not os.path.exists(model_path) or not os.path.exists(meta_path):
            return False
            
        import json
        try:
            # Safe reload: load into temporary vars first
            new_model = joblib.load(model_path)
            with open(meta_path, 'r') as f:
                new_meta = json.load(f)
            
            # Switch only if loading succeeded
            self.model = new_model
            self.feature_names = new_meta['feature_names']
            self.categorical_cols = new_meta.get('categorical_cols', [])
            self.numeric_cols = new_meta.get('numeric_cols', [])
            self.model_version = new_meta.get('model_version', 'risk_v1.0')
            self.model_hash = self._compute_hash(model_path)
            logger.info("ai.risk_model_loaded version=%s", self.model_version)
            return True
        except Exception as e:
            logger.warning("ai.risk_model_load_failed error=%s", e)
            return False

    def get_version_info(self):
        return {"model_version": self.model_version, "hash": self.model_hash}

    def _fallback_score(self, cvss_score, asset_criticality, exploit_available):
        base_score = float(cvss_score) if cvss_score else 4.0
        if exploit_available: base_score *= 1.2
        if asset_criticality == 'high': base_score *= 1.5
        elif asset_criticality == 'critical': base_score *= 2.0
        return min(10.0, base_score)

    def calculate(self, feature_dict):
        """
        Calculates risk score based on provided features dict:
        Required keys (can have nulls): cvss_score, exploit_available, confidence_score, scanner_type, asset_criticality, exposure_level
        """
        # If AI model is missing or fails, fallback to rules
        if not self.model or not self.feature_names:
            return self._fallback_score(
                feature_dict.get('cvss_score', 0),
                feature_dict.get('asset_criticality', 'low'),
                feature_dict.get('exploit_available', 0)
            )

        # Build single-row dataframe to match training one-hot encoding
        try:
            df = pd.DataFrame([feature_dict])
            # Ensure proper dtypes
            df['cvss_score'] = df['cvss_score'].astype(float).fillna(0.0)
            df['exploit_available'] = df['exploit_available'].astype(int).fillna(0)
            df['confidence_score'] = df['confidence_score'].astype(float).fillna(1.0)
            
            # One hot encode dynamically matching training cols
            df_encoded = pd.get_dummies(df, columns=[c for c in self.categorical_cols if c in df.columns])
            
            # Reconstruct the exact feature layout from training metadata
            X = pd.DataFrame(columns=self.feature_names)
            for col in self.feature_names:
                if col in df_encoded.columns:
                    X[col] = df_encoded[col]
                else:
                    X[col] = 0 # Default if column was not created during dummy mapping of single row

            score = self.model.predict(X)[0]
            return float(np.clip(score, 0.0, 10.0))

        except Exception as e:
            logger.error("ai.risk_scoring_inference_error error=%s", e)
            return self._fallback_score(
                feature_dict.get('cvss_score', 0),
                feature_dict.get('asset_criticality', 'low'),
                feature_dict.get('exploit_available', 0)
            )

risk_scorer = RiskScorer()
