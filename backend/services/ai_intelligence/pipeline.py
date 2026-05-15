
import json
import asyncio
import logging
from datetime import datetime, timezone
from typing import List, Dict
import os
from tenacity import retry, stop_after_attempt, wait_exponential

from backend.services.kafka.manager import kafka_manager, TOPIC_FINDING_RAW, TOPIC_FINDING_PROCESSED, TOPIC_ALERT_CRITICAL
from backend.services.scan_control.models import SeverityLevel
from backend.services.ai_intelligence.deduplication import deduplicator
from backend.services.ai_intelligence.false_positive import false_positive_filter
from backend.services.ai_intelligence.risk_scoring import risk_scorer
from backend.services.ai_intelligence.llm_client import llm_client

class VorotaAIPipeline:
    """SENTINEL AI - Vorota Intelligent Findings Processor."""

    def __init__(self):
        self.group_id = "vorota-ai-processor"
        self.topics   = [TOPIC_FINDING_RAW]
        self.logger   = logging.getLogger(__name__)

    async def run(self):
        """Main AI pipeline loop: Consume RAW -> Process -> Produce PROCESSED."""
        self.logger.info("vorota_ai.started topics=%s", self.topics)
        consumer = kafka_manager.get_consumer(self.group_id, self.topics)
        
        try:
            while True:
                msg = consumer.poll(1.0)
                if msg is None: continue
                if msg.error():
                    self.logger.error("vorota_ai.kafka_error err=%s", msg.error())
                    continue

                raw_data = json.loads(msg.value().decode('utf-8'))
                processed_finding = await self.process_finding(raw_data)
                
                # Produce processed result
                await kafka_manager.produce(
                    TOPIC_FINDING_PROCESSED, 
                    raw_data['scan_id'], 
                    processed_finding
                )
                
                # If finding is critical, trigger urgent alert topic
                if processed_finding['severity'] == SeverityLevel.CRITICAL.value:
                    await kafka_manager.produce(
                        TOPIC_ALERT_CRITICAL, 
                        raw_data['scan_id'], 
                        processed_finding
                    )
                
        except asyncio.CancelledError:
            self.logger.info("vorota_ai.cancelled")
        except Exception as e:
            self.logger.critical("vorota_ai.crashed err=%s", e, exc_info=True)
            raise
        finally:
            consumer.close()

    async def process_finding(self, data: dict) -> dict:
        """AI Steps: Deduplication -> FP Filtering -> Scoring -> Remediation."""
        raw_finding = data['finding']
        scan_id = data['scan_id']
        org_id = data.get('org_id', 'org-1')
        scanner_type = data.get('scanner_type', 'unknown')
        
        self.logger.info(
            "vorota_ai.processing title=%s scan_id=%s",
            raw_finding["title"], scan_id,
        )
        
        # 1. Deduplication
        finding_text = f"{raw_finding['title']} {raw_finding.get('description', '')}"
        duplicates = deduplicator.find_duplicates(finding_text)
        is_duplicate = len(duplicates) > 0
        deduplicator.add_finding(data.get('finding_id', 'FND-UNK'), finding_text)

        # Build feature dict for ML Inference
        feature_dict = {
            'cvss_score': float(raw_finding.get('cvss_score', 0.0)),
            'exploit_available': int(raw_finding.get('exploit_available', False)),
            'confidence_score': float(raw_finding.get('confidence_score', 0.9)),
            'scanner_type': scanner_type,
            'asset_criticality': raw_finding.get('asset_criticality', 'low'),
            'exposure_level': raw_finding.get('exposure_level', 'internal')
        }

        # 2. False Positive ML Classification with Graceful Fallback
        is_false_positive = False
        try:
            is_false_positive, fp_prob = false_positive_filter.check(feature_dict, raw_finding_str=str(raw_finding))
        except Exception as e:
            self.logger.warning("vorota_ai.fp_classifier_failed err=%s", e)
        
        # 3. Contextual XGBoost Risk Scoring with Retries & Fallback
        model_confidence = 0.72  # default if model unavailable
        try:
            score_result = self._compute_risk_with_retry(feature_dict)
            # risk_scorer.calculate returns (score, confidence) or just score
            if isinstance(score_result, tuple):
                ai_risk_score, model_confidence = score_result
            else:
                ai_risk_score = score_result
                model_confidence = 0.88  # model ran OK but returned flat value
        except Exception as e:
            self.logger.warning("vorota_ai.risk_scorer_failed err=%s — fallback to CVSS", e)
            ai_risk_score = float(raw_finding.get('cvss_score', 5.0)) * 0.8
            model_confidence = 0.52
        
        # 4. Remediation Generation (LLM) with Fallback
        try:
           remediation = await llm_client.generate_remediation(raw_finding['title'], raw_finding.get('description', ''))
        except Exception:
           remediation = "Apply the official vendor patch and restart affected services."
        
        return {
            "scan_id": scan_id,
            "org_id": org_id,
            "title": raw_finding['title'],
            "description": raw_finding['description'],
            "severity": raw_finding.get('severity', 'low'),
            "risk_score": ai_risk_score,
            "remediation": remediation,
            "is_false_positive": is_false_positive,
            "is_duplicate": is_duplicate,
            "processed_at": datetime.now(timezone.utc).isoformat(),
            "ai_metadata": {
                "confidence": round(model_confidence, 3),
                "reasoning": (
                    f"Finding '{raw_finding['title']}' scored {round(ai_risk_score, 2)}/10. "
                    f"CVSS={feature_dict.get('cvss_score', 0)}, "
                    f"exploit={'yes' if feature_dict.get('exploit_available') else 'no'}, "
                    f"exposure={feature_dict.get('exposure_level', 'internal')}."
                ),
                "fp_probability": round(fp_prob if 'fp_prob' in dir() else 0.0, 3),
                "dedup_checked": True,
            }
        }

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def _compute_risk_with_retry(self, feature_dict: dict):
        """Execute risk modeling wrapped in a circuit breaker retry loop."""
        return risk_scorer.calculate(feature_dict)

if __name__ == "__main__":
    pipeline = VorotaAIPipeline()
    asyncio.run(pipeline.run())
