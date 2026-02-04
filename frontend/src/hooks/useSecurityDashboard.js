/**
 * Project: SentinAI NetGuard
 * Module: Security Dashboard Hook
 * Description: A custom React Hook that acts as the Presentation Layer Controller.
 *              Manages polling synchronization, state aggregation, and interaction logic
 *              for the Security Operation Center (SOC) Dashboard.
 * License: MIT / Academic Use Only
 */
import { useState, useEffect, useRef } from 'react';
import axios from 'axios';

const API_BASE = 'http://localhost:8000/api';

export const useSecurityDashboard = (isAuthenticated, dateFilter = null) => {
    // State Containers for Telemetry Data
    const [threats, setThreats] = useState([]);
    const [riskStats, setRiskStats] = useState([]);
    const [metrics, setMetrics] = useState(null);
    const [history, setHistory] = useState([]);
    const [features, setFeatures] = useState([]);
    const [attackTypes, setAttackTypes] = useState([]);
    const [criticalAlerts, setCriticalAlerts] = useState([]);

    // UI Logic State
    const [loading, setLoading] = useState(true);
    const [highRiskCount, setHighRiskCount] = useState(0);
    const [alert, setAlert] = useState(null);

    // Polling Reference to detect new telemetry events
    const lastThreatTimestamp = useRef(null);

    const synchronizeTelemetry = async () => {
        try {
            // Fetch Aggregated Dashboard Summary
            const res = await axios.get(`${API_BASE}/dashboard/summary`);
            const telemetryPayload = res.data;

            // Safe Destructuring with Defaults
            const {
                threats = [],
                risk_summary = [],
                metrics = null,
                history = [],
                features = [],
                attack_types = [],
                critical_alerts = []
            } = telemetryPayload || {};

            setThreats(threats);
            setRiskStats(risk_summary);
            setMetrics(metrics);
            setHistory(history);
            setFeatures(features);
            setAttackTypes(attack_types);
            setCriticalAlerts(critical_alerts);

            // Override threats if date filter is active
            if (dateFilter) {
                const start = `${dateFilter} 00:00:00`;
                const end = `${dateFilter} 23:59:59`;
                try {
                    const filteredRes = await axios.get(`${API_BASE}/threats`, {
                        params: { start_time: start, end_time: end }
                    });
                    const filteredThreats = filteredRes.data;
                    setThreats(filteredThreats);

                    // Re-calculate aggregations client-side for the filtered view
                    const riskCounts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
                    const typeCounts = {};

                    filteredThreats.forEach(t => {
                        // Risk
                        const score = t.risk_score;
                        if (score >= 80) riskCounts.Critical++;
                        else if (score >= 60) riskCounts.High++;
                        else if (score >= 30) riskCounts.Medium++;
                        else riskCounts.Low++;

                        // Type
                        const label = t.predicted_label;
                        typeCounts[label] = (typeCounts[label] || 0) + 1;
                    });

                    setRiskStats(Object.keys(riskCounts).map(k => ({ name: k, value: riskCounts[k] })));
                    setAttackTypes(Object.keys(typeCounts).map(k => ({ name: k, value: typeCounts[k] })));
                    setCriticalAlerts(filteredThreats.filter(t => t.risk_score >= 80));

                } catch (e) {
                    console.error("Filtered fetch failed", e);
                    const msg = e.response?.data?.detail || e.message;
                    setAlert({ type: 'error', message: `Filter failed: ${msg}` });
                }
            }

            // Calculate aggregated risk metric
            const critical = risk_summary.find(s => s.name === 'Critical')?.value || 0;
            const high = risk_summary.find(s => s.name === 'High')?.value || 0;
            setHighRiskCount(critical + high);

            // Real-time Alert Trigger Logic
            if (threats.length > 0) {
                const latestEvent = threats[0];
                if (latestEvent.timestamp !== lastThreatTimestamp.current) {
                    lastThreatTimestamp.current = latestEvent.timestamp;
                    if (latestEvent.risk_score >= 80) {
                        setAlert({
                            type: 'critical',
                            message: `Critical Anomaly Detected: ${latestEvent.predicted_label} from Source ${latestEvent.source_ip}`
                        });
                    }
                }
            }

            setLoading(false);
        } catch (error) {
            console.error("[Dashboard] Telemetry Sync Failure:", error);
            setAlert({ type: 'error', message: "Connection lost. Retrying..." });
        } finally {
            setLoading(false);
        }
    };

    const resolveThreat = async (id) => {
        try {
            await axios.post(`${API_BASE}/threats/${id}/resolve`);
            // Optimistic update
            setThreats(prev => prev.map(t => t.id === id ? { ...t, status: 'Resolved' } : t));
            setCriticalAlerts(prev => prev.filter(t => t.id !== id));
            setAlert({ type: 'success', message: 'Incident marked as resolved.' });
        } catch (err) {
            console.error("Resolution Failed:", err);
            setAlert({ type: 'error', message: 'Failed to resolve threat.' });
        }
    };

    const blockIP = async (id, ip) => {
        try {
            await axios.post(`${API_BASE}/threats/${id}/block`);
            setAlert({ type: 'success', message: `IP ${ip} blocked successfully.` });
        } catch (err) {
            setAlert({ type: 'error', message: 'Block action failed.' });
        }
    };

    useEffect(() => {
        if (!isAuthenticated) return;

        synchronizeTelemetry();

        // --- WebSocket Integration (Real-Time Push) ---
        const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${wsProtocol}//localhost:8000/ws/dashboard`;
        const socket = new WebSocket(wsUrl);

        socket.onopen = () => {
            console.log("[Dashboard] WebSocket Connected");
        };

        socket.onmessage = (event) => {
            try {
                const message = JSON.parse(event.data);
                if (message.type === 'THREAT_DETECTED') {
                    const threat = message.data;

                    // 1. Instant "WhatsApp-style" Pop
                    setAlert({
                        type: threat.risk_score >= 80 ? 'critical' : 'warning',
                        message: `Active Threat Detected: ${threat.predicted_label} (${threat.source_ip})`
                    });

                    // 2. Update Data Stream
                    setThreats(prev => [threat, ...prev]);

                    // 3. Update Stats (Optimistic)
                    setRiskStats(prev => {
                        const newStats = [...prev];
                        const key = threat.risk_score >= 80 ? 'Critical' :
                            threat.risk_score >= 60 ? 'High' :
                                threat.risk_score >= 30 ? 'Medium' : 'Low';
                        const idx = newStats.findIndex(s => s.name === key);
                        if (idx >= 0) newStats[idx].value++;
                        return newStats;
                    });
                }
            } catch (err) {
                console.error("WS Message Error", err);
            }
        };

        socket.onclose = () => {
            console.log("[Dashboard] WebSocket Disconnected. Polling will take over.");
        };

        // Fallback Polling (Keep existing logic for robustness)
        const interval = setInterval(() => {
            if (document.visibilityState === 'visible' && socket.readyState !== WebSocket.OPEN) {
                synchronizeTelemetry();
            }
        }, 5000);

        return () => {
            clearInterval(interval);
            socket.close();
        };
    }, [isAuthenticated, dateFilter]);

    return {
        threats,
        riskStats,
        metrics,
        history,
        features,
        attackTypes,
        criticalAlerts,
        loading,
        highRiskCount,
        alert,
        setAlert, // Export setter for clearing toasts
        actions: {
            resolveThreat,
            blockIP
        }
    };
};
