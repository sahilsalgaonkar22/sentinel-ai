import os
import logging
import pandas as pd

logger = logging.getLogger(__name__)

try:
    import joblib
    XGB_AVAILABLE = True
except ImportError:
    XGB_AVAILABLE = False

from backend.services.ai_intelligence.llm_client import llm_client

current_dir = os.path.dirname(os.path.abspath(__file__))
model_path = os.path.join(current_dir, 'models', 'fp_classifier_xgb.joblib')
meta_path = os.path.join(current_dir, 'models', 'model_metadata.json')


class FalsePositiveFilter:
    def __init__(self):
        self.prompt_template = (
            "Analyze the following security finding and determine if it is a false positive.\n\n"
            "Finding Details:\n{finding_details}\n\n"
            "Is this a false positive? Respond with only 'true' or 'false'."
        )
        self.model = None
        self.feature_names = None
        self.categorical_cols = None
        self.numeric_cols = None
        
        if XGB_AVAILABLE and os.path.exists(model_path) and os.path.exists(meta_path):
            import json
            try:
                self.model = joblib.load(model_path)
                with open(meta_path, 'r') as f:
                    meta = json.load(f)
                    self.feature_names = meta['feature_names']
                    self.categorical_cols = meta.get('categorical_cols', [])
                    self.numeric_cols = meta.get('numeric_cols', [])
                logger.info("ai.fp_classifier_loaded")
            except Exception as e:
                logger.warning("ai.fp_model_load_failed error=%s", e)

    def check(self, feature_dict, raw_finding_str=None):
        """
        Uses XGBoost to predict if finding is a false positive. 
        Falls back to LLM Prompt or rules if model not available.
        """
        if not self.model or not self.feature_names:
            # Rules-based fallback: low CVSS + low confidence = likely FP
            cvss = float(feature_dict.get('cvss_score', 5.0))
            confidence = float(feature_dict.get('confidence_score', 0.9))
            exploit = bool(feature_dict.get('exploit_available', False))
            exposure = feature_dict.get('exposure_level', 'internal')

            # Heuristic: low confidence + low CVSS + no exploit + internal = probable FP
            fp_score = 0.0
            if cvss < 3.0: fp_score += 0.35
            if confidence < 0.4: fp_score += 0.30
            if not exploit: fp_score += 0.15
            if exposure == 'internal': fp_score += 0.10

            is_fp = fp_score > 0.5
            return is_fp, round(fp_score, 3)
            
        try:
            df = pd.DataFrame([feature_dict])
            df['cvss_score'] = df['cvss_score'].astype(float).fillna(0.0)
            df['exploit_available'] = df['exploit_available'].astype(int).fillna(0)
            df['confidence_score'] = df['confidence_score'].astype(float).fillna(1.0)
            
            df_encoded = pd.get_dummies(df, columns=[c for c in self.categorical_cols if c in df.columns])
            
            X = pd.DataFrame(columns=self.feature_names)
            for col in self.feature_names:
                if col in df_encoded.columns:
                    X[col] = df_encoded[col]
                else:
                    X[col] = 0
            
            # predict probabilities
            probs = self.model.predict_proba(X)[0]
            # [Prob_Negative, Prob_Positive] -> 1 is True FP
            is_fp = bool(probs[1] > 0.5) 
            return is_fp, float(probs[1])

        except Exception as e:
            logger.error("ai.fp_inference_error error=%s", e)
            return False, 0.0

false_positive_filter = FalsePositiveFilter()
