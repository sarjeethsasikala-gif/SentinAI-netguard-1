"""
Project: AegisCore
Module: Incident Management Service
Description:
    Orchestrates the lifecycle of Security Incidents (Alerts).
    Provides capability to Retrieve, Triage (Resolve), and Mitigate (Block)
    detected anomalies.
"""

from typing import List, Optional, Dict
from backend.core.database import db as persistence_gateway

class IncidentLifecycleManager:
    """
    Business Logic Layer for Security Operations.
    """

    class Status:
        ACTIVE = 'Active'
        RESOLVED = 'Resolved'
        ALL = 'All'

    @classmethod
    def retrieve_incident_feed(cls, limit: int = 100, lifecycle_state: Optional[str] = None, start_time: str = None, end_time: str = None) -> List[Dict]:
        """
        Fetches the operational event feed with optional state filtering and time range.
        """
        # Fetch raw telemetry from persistence layer
        if start_time and end_time:
            raw_telemetry = persistence_gateway.query_security_events_by_timerange(start_time, end_time)
        else:
            raw_telemetry = persistence_gateway.fetch_data(limit=limit)
        
        # Helper: Normalize filter input
        target_state = lifecycle_state.lower() if lifecycle_state else 'all'
        
        if target_state == 'all':
            return raw_telemetry
            
        # Determine strict filter criterion
        is_searching_resolved = (target_state == 'resolved')
        
        filtered_events = []
        for event in raw_telemetry:
            # Normalize event status (Default to Active if field missing)
            event_status = event.get('status', cls.Status.ACTIVE)
            
            if is_searching_resolved:
                if event_status == cls.Status.RESOLVED:
                    filtered_events.append(event)
            else:
                # 'Active' implies anything NOT Resolved
                if event_status != cls.Status.RESOLVED:
                    filtered_events.append(event)
                    
        return filtered_events

    @classmethod
    def triage_incident(cls, incident_id: str) -> Optional[Dict]:
        """
        Transitions an incident state from Active -> Resolved.
        """
        # Retrieve full dataset to locate the record
        # In a production SQL/NoSQL env, this would be `UPDATE ... WHERE id = ...`
        dataset = persistence_gateway.fetch_data(limit=None)
        
        target_record = None
        mutation_occurred = False
        
        for record in dataset:
            if record.get('id') == incident_id:
                # Apply State Transition
                record['status'] = cls.Status.RESOLVED
                target_record = record
                mutation_occurred = True
                break
        
        if mutation_occurred:
            # Commit Transaction
            persistence_gateway.save_fallback(dataset)
            return target_record
            
        return None

    @classmethod
    def invoke_mitigation_protocol(cls, incident_id: str) -> bool:
        """
        Executing active countermeasures (e.g. Firewall Rules).
        Currently simulated.
        """
        # TODO: Integrate with Palo Alto / Cisco ASA APIs
        # For prototype scope, acknowledge the command was received.
        return True

# Singleton Export with Legacy Compatibility Name
threat_service = IncidentLifecycleManager()

# Alias methods to match old API if they differ in signature 
# (Here signatures match mostly, but we map them explicitly to be safe)
threat_service.get_recent_threats = IncidentLifecycleManager.retrieve_incident_feed
threat_service.resolve_threat = IncidentLifecycleManager.triage_incident
threat_service.block_threat_source = IncidentLifecycleManager.invoke_mitigation_protocol
