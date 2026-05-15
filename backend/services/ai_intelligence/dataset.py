import pandas as pd
import numpy as np
import random

def generate_synthetic_findings(n_samples=15000):
    print(f"Generating {n_samples} synthetic vulnerability findings...")
    np.random.seed(42)
    random.seed(42)

    data = {
        'finding_id': [f"FND-{i:06d}" for i in range(1, n_samples + 1)],
        'scanner_type': np.random.choice(['nmap', 'nikto', 'zap', 'trivy', 'bandit', 'masscan'], n_samples, p=[0.2, 0.1, 0.15, 0.25, 0.2, 0.1]),
        'cvss_score': np.random.uniform(0.0, 10.0, n_samples).round(1),
        'exploit_available': np.random.choice([0, 1], n_samples, p=[0.75, 0.25]),
        'asset_criticality': np.random.choice(['low', 'medium', 'high', 'critical'], n_samples, p=[0.4, 0.3, 0.2, 0.1]),
        'exposure_level': np.random.choice(['internal', 'external', 'dmz'], n_samples, p=[0.6, 0.3, 0.1]),
        'confidence_score': np.random.uniform(0.3, 1.0, n_samples).round(2),
    }

    df = pd.DataFrame(data)

    # Map categorical features for scoring logic
    crit_map = {'low': 1, 'medium': 3, 'high': 6, 'critical': 10}
    exp_map = {'internal': 1, 'dmz': 5, 'external': 10}

    # Generate Target: Risk Score
    # Base is CVSS, modified by criticality, exposure, and exploitability
    def calc_true_risk(row):
        score = row['cvss_score'] * 0.4
        score += crit_map[row['asset_criticality']] * 0.2
        score += exp_map[row['exposure_level']] * 0.2
        score += (row['exploit_available'] * 2.5) # High boost if exploitable
        
        # Add some random noise for realism
        noise = np.random.normal(0, 0.5)
        final_score = np.clip(score + noise, 0.0, 10.0)
        return final_score

    df['true_risk_score'] = df.apply(calc_true_risk, axis=1).round(2)

    # Generate Target: Is False Positive (FP)
    # Lower confidence = higher chance of FP
    # Certain scanners (like static analysis 'bandit' or generic 'nikto') might yield more FPs
    def is_fp(row):
        prob = 0.1 # Base 10%
        if row['confidence_score'] < 0.6: prob += 0.4
        if row['scanner_type'] in ['bandit', 'nikto']: prob += 0.2
        if row['cvss_score'] < 3.0: prob += 0.1 # Low severity noise
        
        prob = np.clip(prob, 0.0, 1.0)
        return 1 if random.random() < prob else 0

    df['is_false_positive'] = df.apply(is_fp, axis=1)

    print("Dataset generation complete.")
    return df

if __name__ == "__main__":
    df = generate_synthetic_findings()
    df.to_csv('synthetic_findings.csv', index=False)
    print(f"Saved {len(df)} records. FP Rate: {df['is_false_positive'].mean():.2%}. Mean Risk: {df['true_risk_score'].mean():.1f}")
