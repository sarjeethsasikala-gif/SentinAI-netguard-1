import React, { useEffect, useState } from 'react';
import { ComposableMap, Geographies, Geography } from 'react-simple-maps';
import { scaleLinear } from 'd3-scale';
import axios from 'axios';
import { Globe } from 'lucide-react';

const geoUrl = "https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json";

const ThreatMap = ({ theme }) => {
    const [data, setData] = useState([]);

    useEffect(() => {
        const fetchData = async () => {
            try {
                const res = await axios.get('http://localhost:8000/api/stats/geo');
                setData(res.data);
            } catch (err) {
                console.error("Error loading geo stats", err);
            }
        };
        fetchData();
    }, []);

    const maxValue = Math.max(...data.map(d => d.value), 10); // Standardize scale

    // Theme Colors
    const isDark = theme === 'dark';
    const baseColor = isDark ? "#21262d" : "#e5e7eb";
    const hoverColor = isDark ? "#38BDF8" : "#0969DA";
    const strokeColor = isDark ? "#30363D" : "#d1d5db";
    const emptyColor = isDark ? "#161b22" : "#f3f4f6";

    const colorScale = scaleLinear()
        .domain([0, maxValue])
        .range([emptyColor, "#F43F5E"]);

    return (
        <div className="card" style={{ minHeight: '400px', display: 'flex', flexDirection: 'column' }}>
            <h2><Globe size={20} color="var(--accent)" style={{ marginRight: '8px' }} /> Global Threat Origins</h2>
            <div style={{ flex: 1, position: 'relative' }}>
                <ComposableMap
                    projection="geoMercator"
                    projectionConfig={{ scale: 120, center: [0, 30] }}
                    style={{ width: "100%", height: "100%" }}
                >
                    <Geographies geography={geoUrl}>
                        {({ geographies }) =>
                            geographies.map((geo) => {
                                const d = data.find((s) => s.id === geo.id || s.id === geo.properties.ISO_A3);
                                return (
                                    <Geography
                                        key={geo.rsmKey}
                                        geography={geo}
                                        fill={d ? colorScale(d.value) : baseColor}
                                        stroke={strokeColor}
                                        strokeWidth={0.5}
                                        style={{
                                            default: { outline: "none", transition: "all 0.3s" },
                                            hover: { fill: hoverColor, outline: "none", cursor: 'pointer' },
                                            pressed: { outline: "none" },
                                        }}
                                        title={d ? `${geo.properties.name}: ${d.value} Threats` : geo.properties.name}
                                    />
                                );
                            })
                        }
                    </Geographies>
                </ComposableMap>

                {/* Legend */}
                <div style={{
                    position: 'absolute',
                    bottom: 20,
                    left: 20,
                    background: 'var(--card-bg)',
                    padding: '10px',
                    borderRadius: '8px',
                    border: '1px solid var(--border)',
                    boxShadow: '0 4px 6px rgba(0,0,0,0.1)'
                }}>
                    <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '5px' }}>Threat Intensity</div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
                        <div style={{ width: '10px', height: '10px', background: baseColor }}></div>
                        <span style={{ fontSize: '10px', color: 'var(--text-primary)' }}>Low</span>
                        <div style={{ width: '40px', height: '4px', background: `linear-gradient(to right, ${baseColor}, #F43F5E)` }}></div>
                        <span style={{ fontSize: '10px', color: 'var(--text-primary)' }}>High</span>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default ThreatMap;
