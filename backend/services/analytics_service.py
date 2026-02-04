"""
Project: AegisCore
Module: Telemetry Analytics
Description:
    Computes real-time statistical distributions from the telemetry stream.
    Provides the Data Presentation Layer with aggregated insights.
"""

from typing import List, Dict, Any
from backend.core.database import db as persistence_layer
from backend.core.config import config

class MetricPipeline:
    """
    Aggregation pipeline that transforms raw event streams into
    consumable dashboard metrics.
    """

    @classmethod
    def compile_dashboard_intelligence(cls) -> Dict[str, Any]:
        """
        Main aggregations entry point.
        Compiles: Threat Feed, Risk Distribution, Vector Distribution, and Geo-map data.
        """
        # 1. Retrieve Raw Telemetry Window
        telemetry_window = persistence_layer.fetch_data(limit=config.MAX_HISTORY_LIMIT)
        
        # 2. Compute Derivative Metrics
        # Note: We pass the raw window for fallback calculation if the DB aggregation fails/is unavailable
        risk_histogram = cls._compute_risk_histogram(telemetry_window)
        vector_histogram = cls._compute_vector_histogram(telemetry_window)
        geo_distribution = cls._compute_geo_distribution(telemetry_window)
        
        # 3. Extract High-Priority Signals
        priority_alerts = cls._filter_priority_signals(telemetry_window)

        # 4. Enriched Context (ML Artifacts)
        model_features = cls._retrieve_static_artifact(config.FEATURES_PATH, [])
        model_metrics = cls._retrieve_static_artifact(config.METRICS_PATH, {})
        
        return {
            "threats": telemetry_window,
            "risk_summary": risk_histogram,
            "attack_types": vector_histogram,
            "geo_stats": geo_distribution,
            "critical_alerts": priority_alerts,
            "features": model_features,
            "metrics": model_metrics
        }

    @classmethod
    def _compute_risk_histogram(cls, fallback_dataset: List[Dict]) -> List[Dict]:
        """
        Quantifies the distribution of severity levels.
        """
        db_handle = persistence_layer.get_db()
        
        # Strategy A: Database-Native Aggregation (High Performance)
        if db_handle is not None:
            try:
                pipeline = [
                    {"$project": {
                        "severity_label": {
                            "$switch": {
                                "branches": [
                                    {"case": {"$gte": ["$risk_score", 80]}, "then": "Critical"},
                                    {"case": {"$gte": ["$risk_score", 60]}, "then": "High"},
                                    {"case": {"$gte": ["$risk_score", 30]}, "then": "Medium"}
                                ],
                                "default": "Low"
                            }
                        }
                    }},
                    {"$group": {"_id": "$severity_label", "count": {"$sum": 1}}}
                ]
                cursor = db_handle[config.COLLECTION_NAME].aggregate(pipeline)
                results = {doc["_id"]: doc["count"] for doc in cursor}
                
                # Zero-fill missing buckets
                for bucket in ["Critical", "High", "Medium", "Low"]:
                    results.setdefault(bucket, 0)
                    
                return [{"name": k, "value": v} for k, v in results.items()]
            except Exception as e:
                print(f"[Analytics] Pipeline Error: {e}")

        # Strategy B: Application-Layer Aggregation (Fallback)
        buckets = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for event in fallback_dataset:
            score = event.get('risk_score', 0)
            if score >= 80: buckets["Critical"] += 1
            elif score >= 60: buckets["High"] += 1
            elif score >= 30: buckets["Medium"] += 1
            else: buckets["Low"] += 1
            
        return [{"name": k, "value": v} for k, v in buckets.items()]

    @classmethod
    def _compute_vector_histogram(cls, fallback_dataset: List[Dict]) -> List[Dict]:
        """
        Quantifies attack vectors (Predicted Labels).
        """
        db_handle = persistence_layer.get_db()
        
        if db_handle is not None:
            try:
                pipeline = [{"$group": {"_id": "$predicted_label", "count": {"$sum": 1}}}]
                cursor = db_handle[config.COLLECTION_NAME].aggregate(pipeline)
                return [{"name": doc["_id"], "value": doc["count"]} for doc in cursor]
            except Exception:
                pass
                
        # Fallback
        counts = {}
        for event in fallback_dataset:
            label = event.get('predicted_label', 'Unknown')
            counts[label] = counts.get(label, 0) + 1
        return [{"name": k, "value": v} for k, v in counts.items()]

    @classmethod
    def _compute_geo_distribution(cls, fallback_dataset: List[Dict]) -> List[Dict]:
        """
        Aggregates events by source country.
        """
        db_handle = persistence_layer.get_db()
        
        if db_handle is not None:
            try:
                pipeline = [{"$group": {"_id": "$source_country", "count": {"$sum": 1}}}]
                cursor = db_handle[config.COLLECTION_NAME].aggregate(pipeline)
                return [{"id": doc["_id"], "value": doc["count"]} for doc in cursor if doc["_id"]]
            except Exception:
                pass
                
        # Fallback
        counts = {}
        for event in fallback_dataset:
            country = event.get('source_country', 'UNK')
            counts[country] = counts.get(country, 0) + 1
        return [{"id": k, "value": v} for k, v in counts.items()]

    @staticmethod
    def _filter_priority_signals(stream: List[Dict], cap: int = 3) -> List[Dict]:
        """
        Identifies the most critical active incidents for immediate display.
        """
        signals = []
        for event in stream:
            is_critical = event.get('risk_score', 0) >= 80
            is_unresolved = event.get('status') != 'Resolved'
            
            if is_critical and is_unresolved:
                signals.append(event)
                if len(signals) >= cap:
                    break
        return signals

    @staticmethod
    def _retrieve_static_artifact(filepath: str, default_val: Any) -> Any:
        import json, os
        try:
            if os.path.exists(filepath):
                with open(filepath, 'r') as f:
                    return json.load(f)
        except Exception:
            pass
        return default_val

# Legacy Export Name
analytics_service = MetricPipeline()

# Alias for API compatibility
analytics_service.get_dashboard_summary = MetricPipeline.compile_dashboard_intelligence
