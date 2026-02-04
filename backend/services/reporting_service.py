"""
Project: SentinAI NetGuard
Module: Automated Reporting
Description:
    Aggregates daily security metrics into a JSON report.
"""
import os
import json
import logging
from datetime import datetime, timedelta
from collections import Counter
from backend.core.database import db
from backend.services.analytics_service import analytics_service

# Configuration
REPORT_DIR = os.path.join(os.getcwd(), "backend", "reports")
os.makedirs(REPORT_DIR, exist_ok=True)

class ReportingService:
    
    @staticmethod
    def _get_severity_label(risk_score: float) -> str:
        if risk_score >= 80: return "Critical"
        if risk_score >= 60: return "High"
        if risk_score >= 30: return "Medium"
        return "Low"

    @classmethod
    def generate_report(cls, target_date: str = None) -> dict:
        """
        Generates a summary report for a specific date (YYYY-MM-DD).
        """
        if not target_date:
            target_date = datetime.now().strftime("%Y-%m-%d")

        # Define time window (00:00:00 to 23:59:59)
        start_time = f"{target_date} 00:00:00"
        end_time = f"{target_date} 23:59:59"

        # 1. Fetch Events
        events = db.query_events_by_timerange(start_time, end_time)
        
        if not events:
            return {
                "date": target_date,
                "status": "No Data",
                "summary": {"total_incidents": 0}
            }

        # 2. Key Metrics Aggregation
        total_count = len(events)
        severity_counts = Counter()
        attack_vectors = Counter()
        source_ips = Counter()
        
        high_risk_events = []

        for event in events:
            # Severity
            score = event.get('risk_score', 0)
            severity = cls._get_severity_label(score)
            severity_counts[severity] += 1
            
            # Vector
            vector = event.get('predicted_label', 'Unknown')
            attack_vectors[vector] += 1
            
            # Source IP
            src = event.get('source_ip', 'Unknown')
            source_ips[src] += 1
            
            # Collect Criticals
            if score >= 80:
                high_risk_events.append({
                    "id": event.get('id'),
                    "timestamp": event.get('timestamp'),
                    "src_ip": src,
                    "risk_score": score,
                    "type": vector
                })

        # 3. Construct Report
        report = {
            "metadata": {
                "report_id": f"RPT-{target_date.replace('-', '')}",
                "generated_at": datetime.now().isoformat(),
                "target_date": target_date
            },
            "summary": {
                "total_incidents": total_count,
                "severity_distribution": dict(severity_counts),
                "top_attack_vectors": dict(attack_vectors.most_common(5)),
                "top_offenders": dict(source_ips.most_common(5))
            },
            "critical_threats": high_risk_events[:10]  # Top 10 criticals
        }

        # 4. Persist
        cls.save_report(report)
        return report

    @classmethod
    def save_report(cls, report: dict):
        filename = f"report_{report['metadata']['target_date']}.json"
        filepath = os.path.join(REPORT_DIR, filename)
        try:
            with open(filepath, 'w') as f:
                json.dump(report, f, indent=2)
        except Exception as e:
            print(f"Failed to save report: {e}")

    @classmethod
    def get_report(cls, date_str: str) -> dict:
        filename = f"report_{date_str}.json"
        filepath = os.path.join(REPORT_DIR, filename)
        
        if os.path.exists(filepath):
            try:
                with open(filepath, 'r') as f:
                    return json.load(f)
            except Exception:
                return {"error": "Corrupt report file"}
        
        return {"error": "Report not found"}

reporting_service = ReportingService()
