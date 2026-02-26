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
        target_ips = Counter() # New: Affected Assets
        status_counts = Counter() # New: Resolution Status
        
        high_risk_events = []
        detailed_log = [] # New: Full Audit Trail

        for event in events:
            # Severity
            score = event.get('risk_score', 0)
            severity = cls._get_severity_label(score)
            severity_counts[severity] += 1
            
            # Vector
            vector = event.get('predicted_label', 'Unknown')
            attack_vectors[vector] += 1
            
            # Source & Target
            src = event.get('source_ip', 'Unknown')
            dst = event.get('destination_ip', 'Unknown')
            source_ips[src] += 1
            target_ips[dst] += 1
            
            # Status
            status = event.get('status', 'Active')
            status_counts[status] += 1
            
            # Detailed Entry
            log_entry = {
                "id": event.get('id'),
                "timestamp": event.get('timestamp'),
                "type": vector,
                "source": src,
                "target": dst,
                "status": status,
                "risk_score": score,
                "severity": severity
            }
            detailed_log.append(log_entry)

            # Collect Criticals
            if score >= 80:
                high_risk_events.append(log_entry)

        # 3. Construct Report
        report = {
            "metadata": {
                "report_id": f"RPT-{target_date.replace('-', '')}",
                "generated_at": datetime.now().isoformat(),
                "target_date": target_date
            },
            "summary": {
                "total_incidents": total_count,
                "resolved_incidents": status_counts.get('Resolved', 0),
                "active_incidents": status_counts.get('Active', 0),
                "severity_distribution": dict(severity_counts),
                "top_attack_vectors": dict(attack_vectors.most_common(5)),
                "top_offenders": dict(source_ips.most_common(5)),
                "top_targets": dict(target_ips.most_common(5)) # New: Affected Victims
            },
            "critical_threats": high_risk_events,
            "detailed_log": detailed_log # New: Full List
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
