import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { Server, Shield, Router, Database, Monitor, Smartphone, AlertTriangle } from 'lucide-react';

const NetworkTopology = () => {
    const [topology, setTopology] = useState({ nodes: [], links: [] });
    const [selectedNode, setSelectedNode] = useState(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const fetchTopology = async () => {
            try {
                const res = await axios.get('http://localhost:8000/api/network/topology');
                setTopology(res.data);
                setLoading(false);
            } catch (err) {
                console.error("Failed to load topology", err);
            }
        };
        fetchTopology();
    }, []);

    // Sync selectedNode with latest topology data to keep details panel live
    useEffect(() => {
        if (selectedNode) {
            const updatedNode = topology.nodes.find(n => n.id === selectedNode.id);
            if (updatedNode) {
                setSelectedNode(updatedNode);
            }
        }
    }, [topology]);

    const getNodeIcon = (type) => {
        switch (type) {
            case 'Firewall': return <Shield size={24} color="var(--accent)" />;
            case 'Router': return <Router size={24} color="var(--warning)" />;
            case 'Switch': return <Server size={24} color="var(--text-secondary)" />;
            case 'Database': return <Database size={24} color="var(--critical)" />;
            case 'Server': return <Server size={24} color="var(--success)" />;
            case 'Client': return <Monitor size={24} color="var(--text-primary)" />;
            default: return <Smartphone size={24} color="var(--text-primary)" />;
        }
    };

    const getStatusColor = (status) => {
        if (status === 'Compromised') return 'var(--critical)';
        if (status === 'Warning') return 'var(--warning)';
        return 'var(--success)'; // Healthy
    };

    if (loading) return <div className="card">Loading Topology...</div>;

    return (
        <div className="card topology-card" style={{ height: '450px', display: 'flex', gap: '20px' }}>
            <div style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
                <h2><Router size={20} /> Network Topology</h2>
                <div style={{ flex: 1, position: 'relative', overflow: 'hidden' }}>
                    <svg width="100%" height="100%" viewBox="0 0 500 400">
                        <defs>
                            <marker id="arrowhead" markerWidth="10" markerHeight="7" refX="28" refY="3.5" orient="auto">
                                <polygon points="0 0, 10 3.5, 0 7" fill="var(--border)" />
                            </marker>
                        </defs>
                        {/* Links */}
                        {topology.links.map((link, i) => {
                            const source = topology.nodes.find(n => n.id === link.source);
                            const target = topology.nodes.find(n => n.id === link.target);
                            if (!source || !target) return null;
                            return (
                                <line
                                    key={i}
                                    x1={source.x} y1={source.y}
                                    x2={target.x} y2={target.y}
                                    stroke="var(--border)"
                                    strokeWidth="2"
                                />
                            );
                        })}

                        {/* Nodes */}
                        {topology.nodes.map((node) => (
                            <foreignObject
                                x={node.x - 60}
                                y={node.y - 25}
                                width="120"
                                height="80"
                                key={node.id}
                                style={{ overflow: 'visible' }}
                            >
                                <div style={{
                                    display: 'flex',
                                    flexDirection: 'column',
                                    alignItems: 'center',
                                    justifyContent: 'center',
                                    height: '100%',
                                    width: '100%'
                                }}>
                                    <div
                                        className="topology-node"
                                        onClick={() => setSelectedNode(node)}
                                        style={{
                                            width: '50px', height: '50px',
                                            background: 'var(--card-bg)',
                                            border: `2px solid ${getStatusColor(node.status)}`,
                                            borderRadius: '50%',
                                            display: 'flex', justifyContent: 'center', alignItems: 'center',
                                            cursor: 'pointer',
                                            position: 'relative', /* CRITICAL for badge positioning */
                                            boxShadow: node.status === 'Compromised' ? '0 0 15px rgba(244, 63, 94, 0.5)' : 'none',
                                            animation: node.status === 'Compromised' ? 'pulse-border 2s infinite' : 'none',
                                            transform: selectedNode?.id === node.id ? 'scale(1.1)' : 'scale(1)'
                                        }}
                                    >
                                        {getNodeIcon(node.type)}
                                        {node.threats > 0 && (
                                            <div style={{
                                                position: 'absolute', top: -5, right: -5,
                                                background: 'var(--critical)', color: 'white',
                                                borderRadius: '50%', width: '18px', height: '18px',
                                                fontSize: '10px', display: 'flex', alignItems: 'center', justifyContent: 'center',
                                                fontWeight: 'bold',
                                                boxShadow: '0 2px 4px rgba(0,0,0,0.5)',
                                                border: '2px solid var(--card-bg)'
                                            }}>
                                                {node.threats}
                                            </div>
                                        )}
                                    </div>
                                    <div style={{
                                        textAlign: 'center',
                                        fontSize: '10px',
                                        marginTop: '5px',
                                        color: 'var(--text-secondary)',
                                        width: '100%',
                                        whiteSpace: 'nowrap',
                                        overflow: 'hidden',
                                        textOverflow: 'ellipsis'
                                    }}>
                                        {node.type}
                                    </div>
                                </div>
                            </foreignObject>
                        ))}
                    </svg>
                </div>
                {/* Legend */}
                <div style={{ display: 'flex', gap: '15px', justifyContent: 'center', marginTop: '10px', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                    <span style={{ display: 'flex', alignItems: 'center', gap: '5px' }}><div style={{ width: 8, height: 8, borderRadius: '50%', background: 'var(--success)' }}></div> Healthy</span>
                    <span style={{ display: 'flex', alignItems: 'center', gap: '5px' }}><div style={{ width: 8, height: 8, borderRadius: '50%', background: 'var(--warning)' }}></div> Warning</span>
                    <span style={{ display: 'flex', alignItems: 'center', gap: '5px' }}><div style={{ width: 8, height: 8, borderRadius: '50%', background: 'var(--critical)' }}></div> Compromised</span>
                </div>
            </div>

            {/* Details Panel */}
            {selectedNode && (
                <div style={{
                    width: '200px',
                    borderLeft: '1px solid var(--border)',
                    paddingLeft: '20px',
                    display: 'flex',
                    flexDirection: 'column',
                    animation: 'slideIn 0.3s ease'
                }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '15px' }}>
                        <h3 style={{ margin: 0, fontSize: '1rem', color: 'var(--text-primary)' }}>Node Details</h3>
                        <button
                            onClick={() => setSelectedNode(null)}
                            style={{ background: 'none', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer' }}
                        >
                            ✕
                        </button>
                    </div>

                    <div style={{ marginBottom: '20px' }}>
                        <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>ID</div>
                        <div style={{ fontWeight: 600 }}>{selectedNode.id}</div>
                    </div>

                    <div style={{ marginBottom: '20px' }}>
                        <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>IP Address</div>
                        <div style={{ fontFamily: 'monospace', background: 'rgba(255,255,255,0.05)', padding: '2px 6px', borderRadius: '4px', display: 'inline-block' }}>
                            {selectedNode.ip}
                        </div>
                    </div>

                    <div style={{ marginBottom: '20px' }}>
                        <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Status</div>
                        <div style={{
                            color: getStatusColor(selectedNode.status),
                            fontWeight: 600,
                            display: 'flex', alignItems: 'center', gap: '6px'
                        }}>
                            {selectedNode.status === 'Compromised' && <AlertTriangle size={14} />}
                            {selectedNode.status}
                        </div>
                    </div>

                    {selectedNode.threats > 0 && (
                        <div style={{
                            padding: '10px',
                            background: 'rgba(244, 63, 94, 0.1)',
                            border: '1px solid var(--critical)',
                            borderRadius: '8px'
                        }}>
                            <div style={{ fontSize: '0.75rem', color: 'var(--critical)', fontWeight: 600, marginBottom: '4px' }}>
                                Active Threat
                            </div>
                            <div style={{ fontSize: '0.9rem', color: 'var(--text-primary)' }}>
                                {selectedNode.latest_threat}
                            </div>
                        </div>
                    )}
                </div>
            )}
        </div>
    );
};

export default NetworkTopology;
