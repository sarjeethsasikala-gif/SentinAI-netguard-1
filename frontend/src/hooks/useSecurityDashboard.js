/**
 * Project: SentinAI NetGuard
 * Module: Security Dashboard Hook
 * Description: A custom React Hook that acts as the Presentation Layer Controller.
 *              Manages polling synchronization, state aggregation, and interaction logic
 *              for the Security Operation Center (SOC) Dashboard.
 * License: MIT / Academic Use Only
 */
import { useState, useEffect, useRef } from 'react';
import api from '../api/axiosConfig';

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
    const isMounted = useRef(true);

    const synchronizeTelemetry = async () => {
        try {
            // Fetch Aggregated Dashboard Summary
            const res = await api.get(`/dashboard/summary`);
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

            if (!isMounted.current) return;

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
                    const filteredRes = await api.get(`/threats`, {
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
                        const label = t.predicted_label || t.label || 'Unknown';
                        typeCounts[label] = (typeCounts[label] || 0) + 1;
                    });

                    setRiskStats(Object.keys(riskCounts).map(k => ({ name: k, value: riskCounts[k] })));
                    setAttackTypes(Object.keys(typeCounts).map(k => ({ name: k, value: typeCounts[k] })));
                    setCriticalAlerts(filteredThreats.filter(t => t.risk_score >= 80));

                    // Update High Risk Count for filtered view
                    setHighRiskCount(riskCounts.Critical + riskCounts.High);

                } catch (e) {
                    console.error("Filtered fetch failed", e);
                    const msg = e.response?.data?.detail || e.message;
                    setAlert({ type: 'error', message: `Filter failed: ${msg}` });
                }
            } else {
                // Calculate aggregated risk metric (Global)
                const critical = risk_summary.find(s => s.name === 'Critical')?.value || 0;
                const high = risk_summary.find(s => s.name === 'High')?.value || 0;
                setHighRiskCount(critical + high);
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
            await api.post(`/threats/${id}/resolve`);
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
            await api.post(`/threats/${id}/block`);
            setAlert({ type: 'success', message: `IP ${ip} blocked successfully.` });
        } catch (err) {
            setAlert({ type: 'error', message: 'Block action failed.' });
        }
    };

    useEffect(() => {
        if (!isAuthenticated) return;

        synchronizeTelemetry();

        // --- WebSocket Integration (Real-Time Push) ---
        // Dynamically determine WebSocket URL based on current window location
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const host = window.location.host; // includes port
        const wsUrl = `${protocol}//${host}/ws/dashboard`;

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

                    // 4. Update Header Metrics
                    if (threat.risk_score >= 60) {
                        setHighRiskCount(prev => prev + 1);
                    }
                }
            } catch (err) {
                console.error("WS Message Error", err);
            }
        };

        socket.onclose = () => {
            console.log("[Dashboard] WebSocket Disconnected. Polling will take over.");
        };

        return () => {
            isMounted.current = false;
            socket.close();
        };
    }, [isAuthenticated, dateFilter]);

    const [storageMode, setStorageMode] = useState('local');

    const fetchSystemMode = async () => {
        try {
            const res = await api.get(`/system/mode`);
            setStorageMode(res.data.mode);
        } catch (e) {
            console.error("Failed to fetch system mode", e);
        }
    };

    const toggleStorageMode = async () => {
        const newMode = storageMode === 'cloud' ? 'local' : 'cloud';
        try {
            const res = await api.post(`/system/mode`, { mode: newMode });
            setStorageMode(res.data.mode);
            setAlert({ type: 'success', message: `Switched to ${newMode === 'cloud' ? 'Cloud' : 'Local'} Storage` });
            // Refresh data from new source
            synchronizeTelemetry();
        } catch (e) {
            const msg = e.response?.data?.detail || "Switch failed";
            setAlert({ type: 'error', message: msg });
        }
    };

    useEffect(() => {
        fetchSystemMode();
    }, []);

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
            blockIP,
            toggleStorageMode,
            storageMode
        }
    };
};
