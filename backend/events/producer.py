"""
SENTINEL AI — Legacy Kafka Producer (FIX-3: REMOVED)

This module is intentionally tombstoned.

The legacy KafkaProducer class (which silently no-oped and printed
"MOCK KAFKA PRODUCE:" when confluent_kafka was absent) has been deleted.

ALL Kafka producing MUST go through:
    from backend.services.kafka.manager import kafka_manager
    await kafka_manager.produce(topic, key, value)

kafka_manager raises RuntimeError if confluent_kafka is not installed —
no silent failure, no mock fallback.

Importing anything from this module will raise ImportError immediately
to surface accidental usage of the old code path during development.
"""

raise ImportError(
    "backend.events.producer is tombstoned. "
    "Use: from backend.services.kafka.manager import kafka_manager"
)
