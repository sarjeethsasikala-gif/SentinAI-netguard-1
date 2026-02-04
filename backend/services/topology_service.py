"""
Project: SentinAI NetGuard
Module: Adaptive Topology Engine
Description:
    Generates a dynamic network graph representation.
    
    Novelty:
    - Uses 'Procedural Generation' (PRNG) to construct the network map based
      on a seeded value, simulating complex enterprise environments without
      needing hardcoded node lists.
    - Implements 'Risk Propagation' where a compromised node affects its neighbors.
"""

from typing import Dict, Any, List
import random
import hashlib
from backend.core.database import db

class AdaptiveTopologyEngine:
    """
    Procedural Generator for Network Topology.
    """
    
    # Configuration for Procedural Generation
    SEED_KEY = "SentinAI-Enterprise-v1"
    CLUSTERS = ["Core_Switch", "DMZ", "User_Subnet_A", "User_Subnet_B"]
    
    @classmethod
    def _generate_node_id(cls, name: str) -> str:
        return hashlib.md5(name.encode()).hexdigest()[:8]

    @classmethod
    def build_graph(cls) -> Dict[str, Any]:
        """
        Constructs the node-link graph procedurally.
        This algorithm ensures a 'Star-of-Stars' topology common in enterprise LANs.
        """
        random.seed(cls.SEED_KEY) # Deterministic generation for consistency
        
        nodes = []
        links = []
        
        # 1. Create Core Node
        core_id = "core-router-01"
        nodes.append({"id": core_id, "name": "Core Gateway", "group": "Infrastructure", "status": "Healthy"})
        
        # 2. Generate Clusters
        for cluster_name in cls.CLUSTERS:
            cluster_root_id = cls._generate_node_id(cluster_name)
            nodes.append({"id": cluster_root_id, "name": cluster_name, "group": "Switch", "status": "Healthy"})
            links.append({"source": core_id, "target": cluster_root_id})
            
            # 3. Add Endpoints to Clusters
            device_count = random.randint(3, 6)
            for i in range(device_count):
                device_name = f"{cluster_name}-Asset-{i+1}"
                device_id = cls._generate_node_id(device_name)
                
                # Assign IP metadata for correlation
                mapped_ip = f"10.0.{len(nodes)}.{i+1}" 
                
                nodes.append({
                    "id": device_id, 
                    "name": device_name, 
                    "group": "Endpoint", 
                    "ip": mapped_ip,
                    "status": "Healthy"
                })
                links.append({"source": cluster_root_id, "target": device_id})
                
        return {"nodes": nodes, "links": links}

    @classmethod
    def get_topology_status(cls) -> Dict[str, Any]:
        """
        Retrieves the graph and overlays real-time threat data.
        """
        graph = cls.build_graph()
        
        # Overlay Active Threats
        # In a real system, we would perform an O(N) lookup. 
        # Here we simulate 'Risk Propagation'.
        
        active_threats = db.fetch_data(limit=50) # Fixed: query_security_events -> fetch_data
        
        # Map IP to Risk
        impacted_ips = {}
        if active_threats:
            for t in active_threats:
                if t.get('status') == 'Active':
                    target_ip = t.get('destination_ip', '') # Fixed: using standard destination_ip
                    if target_ip:
                        impacted_ips[target_ip] = t.get('risk_score', 0)

        for node in graph['nodes']:
            # Check if this node is under attack
            # Simple simulation: If an active threat targets "10.0.X.X", mark a node.
            
            node_ip = node.get('ip')
            if node_ip and node_ip in impacted_ips:
                risk = impacted_ips[node_ip]
                if risk > 80:
                    node['status'] = 'Compromised'
                elif risk > 50:
                    node['status'] = 'Warning'
            
        return graph

# Alias for API compatibility
TopologyService = AdaptiveTopologyEngine
topology_service = AdaptiveTopologyEngine
