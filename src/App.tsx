/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useRef } from "react";
import { 
  Shield, 
  ShieldAlert, 
  Users, 
  Server, 
  Activity, 
  Terminal, 
  Sliders, 
  Play, 
  Pause, 
  RefreshCw, 
  Cpu, 
  Zap, 
  TrendingUp, 
  Database, 
  Search, 
  FileText, 
  CheckCircle, 
  X,
  AlertTriangle,
  Radio,
  FileCheck,
  ChevronRight,
  MapPin,
  Clock,
  ExternalLink
} from "lucide-react";
import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip } from "recharts";
import Markdown from "react-markdown";
import { Severity, IncidentStatus, SecurityEvent, Incident, EntityBaseline, CorrelationRule, DashboardStats } from "./types";

export default function App() {
  // STATE MANAGEMENT
  const [stats, setStats] = useState<DashboardStats>({
    overallThreatScore: 15,
    activeIncidentsCount: 0,
    processedEventsCount: 0,
    criticalAlertsCount: 0,
    uebaAnomalyCount: 0,
    alertDistribution: { [Severity.LOW]: 0, [Severity.MEDIUM]: 0, [Severity.HIGH]: 0, [Severity.CRITICAL]: 0 },
    eventsTimeline: []
  });

  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [baselines, setBaselines] = useState<EntityBaseline[]>([]);
  const [rules, setRules] = useState<CorrelationRule[]>([]);
  const [logs, setLogs] = useState<SecurityEvent[]>([]);
  const [liveStreamActive, setLiveStreamActive] = useState<boolean>(true);
  const [sidebarTab, setSidebarTab] = useState<"ueba" | "rules" | "sim" | "splunk">("sim");
  
  // Splunk configuration and inputs
  const [splunkConfig, setSplunkConfig] = useState({
    host: "https://192.168.1.1:8089",
    username: "admin",
    password: "123456789",
    query: 'search index=* OR source="WinEventLog:*" OR sourcetype="t-pot" | head 30',
    isConnected: false,
    lastSyncTime: null as string | null,
    syncStatus: "Ready to connect. Input Splunk server config below.",
    autoSync: false
  });
  const [splunkHostInput, setSplunkHostInput] = useState("https://192.168.1.1:8089");
  const [splunkUsernameInput, setSplunkUsernameInput] = useState("admin");
  const [splunkPasswordInput, setSplunkPasswordInput] = useState("123456789");
  const [splunkQueryInput, setSplunkQueryInput] = useState('search index=* OR source="WinEventLog:*" OR sourcetype="t-pot" | head 30');
  const [splunkAutoSyncInput, setSplunkAutoSyncInput] = useState(false);
  const [isSplunkSyncing, setIsSplunkSyncing] = useState(false);

  // Interactive logs search filters
  const [logFilterText, setLogFilterText] = useState("");
  const [logFilterCategory, setLogFilterCategory] = useState("all");
  
  // Statuses for triggers
  const [isSimulating, setIsSimulating] = useState<string | null>(null);
  const [notification, setNotification] = useState<{ message: string; type: "success" | "error" | "info" } | null>(null);
  const [investigatingId, setInvestigatingId] = useState<string | null>(null);

  // Auto scroll reference for terminal
  const logTerminalEndRef = useRef<HTMLDivElement>(null);

  // FETCH DATA
  const fetchAllData = async () => {
    try {
      const statsRes = await fetch("/api/status");
      if (statsRes.ok) {
        const data = await statsRes.json();
        setStats(data);
      }

      const incRes = await fetch("/api/incidents");
      if (incRes.ok) {
        const data = await incRes.json();
        setIncidents(data);
        
        // Keep selected incident selection in sync with server state changes
        if (selectedIncident) {
          const updated = data.find((i: Incident) => i.id === selectedIncident.id);
          if (updated) {
            setSelectedIncident(updated);
          }
        } else if (data.length > 0 && !selectedIncident) {
          // Default select the first active incident
          setSelectedIncident(data[0]);
        }
      }

      const uebaRes = await fetch("/api/ueba");
      if (uebaRes.ok) {
        const data = await uebaRes.json();
        setBaselines(data);
      }

      const rulesRes = await fetch("/api/rules");
      if (rulesRes.ok) {
        const data = await rulesRes.json();
        setRules(data);
      }

      const logsRes = await fetch("/api/logs");
      if (logsRes.ok) {
        const data = await logsRes.json();
        setLogs(data);
      }
    } catch (e) {
      console.error("SOC status synchronization failed", e);
    }
  };

  const fetchSplunkConfig = async () => {
    try {
      const res = await fetch("/api/splunk/config");
      if (res.ok) {
        const data = await res.json();
        setSplunkConfig(data);
        setSplunkHostInput(data.host);
        setSplunkUsernameInput(data.username);
        setSplunkPasswordInput(data.password);
        setSplunkQueryInput(data.query);
        setSplunkAutoSyncInput(data.autoSync);
      }
    } catch (e) {
      console.error("Failed fetching Splunk configuration", e);
    }
  };

  // INITIAL LOAD & POLLING SYSTEM
  useEffect(() => {
    fetchAllData();
    fetchSplunkConfig();
  }, []);

  useEffect(() => {
    let timer: NodeJS.Timeout;
    if (liveStreamActive) {
      timer = setInterval(() => {
        fetchAllData();
      }, 4000); // refresh metadata every 4 seconds to simulate a live console feel
    }
    return () => clearInterval(timer);
  }, [liveStreamActive, selectedIncident]);

  // SCROLL TO LOG STREAM RECENT ON ACTIVE INJECTION
  useEffect(() => {
    if (liveStreamActive && logTerminalEndRef.current) {
      logTerminalEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [logs]);

  // SHOW TRANSITION NOTIFICATIONS
  const triggerNotification = (message: string, type: "success" | "error" | "info" = "success") => {
    setNotification({ message, type });
    setTimeout(() => {
      setNotification(null);
    }, 4500);
  };

  // ACTIONS
  const handleTriggerSimulation = async (scenario: string) => {
    setIsSimulating(scenario);
    try {
      const res = await fetch("/api/simulate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scenario })
      });
      const data = await res.json();
      if (res.ok) {
        triggerNotification(`Payload Deployed: Clustered IOC telemetry injected successfully.`, "success");
        fetchAllData();
      } else {
        triggerNotification(data.error || "Simulation deploy aborted", "error");
      }
    } catch (error) {
      triggerNotification("Internal routing communication disrupted", "error");
    } finally {
      setIsSimulating(null);
    }
  };

  const handleToggleRule = async (ruleId: string) => {
    try {
      const res = await fetch(`/api/rules/${ruleId}/toggle`, {
        method: "POST"
      });
      if (res.ok) {
        triggerNotification("Correlation trigger parameter updated", "info");
        fetchAllData();
      }
    } catch (e) {
      triggerNotification("Rule status update failed", "error");
    }
  };

  const handleSaveSplunkConfig = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    try {
      const res = await fetch("/api/splunk/config", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          host: splunkHostInput,
          username: splunkUsernameInput,
          password: splunkPasswordInput,
          query: splunkQueryInput,
          autoSync: splunkAutoSyncInput
        })
      });
      const data = await res.json();
      if (res.ok) {
        setSplunkConfig(data.config);
        triggerNotification("Splunk configuration updated successfully", "success");
      } else {
        triggerNotification(data.error || "Failed updating Splunk configuration", "error");
      }
    } catch (error) {
      triggerNotification("Failed transmitting Splunk parameters", "error");
    }
  };

  const handleSyncSplunkLogs = async () => {
    setIsSplunkSyncing(true);
    triggerNotification("Contacting local Splunk Enterprise REST service...", "info");
    
    try {
      // First save current inputs
      const saveRes = await fetch("/api/splunk/config", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          host: splunkHostInput,
          username: splunkUsernameInput,
          password: splunkPasswordInput,
          query: splunkQueryInput,
          autoSync: splunkAutoSyncInput
        })
      });
      
      if (!saveRes.ok) {
        triggerNotification("Could not resolve current Splunk state inputs", "error");
        setIsSplunkSyncing(false);
        return;
      }
      const saveData = await saveRes.json();
      setSplunkConfig(saveData.config);

      // Trigger actual Splunk REST API search job and ingest
      const res = await fetch("/api/splunk/sync", {
        method: "POST"
      });
      const data = await res.json();
      setSplunkConfig(data.config);
      
      if (res.ok) {
        triggerNotification(`Splunk Ingestion Active: successfully fetched & parsed ${data.count} security logs!`, "success");
        fetchAllData();
      } else {
        triggerNotification(data.error || "Splunk connection error. Check target IP / Port details.", "error");
      }
    } catch (error) {
      triggerNotification("Disrupted connection: local Windows/Splunk subnet unreached.", "error");
    } finally {
      setIsSplunkSyncing(false);
    }
  };

  const handleResetUEBA = async () => {
    try {
      const res = await fetch("/api/ueba/reset", { method: "POST" });
      if (res.ok) {
        triggerNotification("Dynamic behavioral baselines reset & retrained", "success");
        setSelectedIncident(null);
        fetchAllData();
      }
    } catch (e) {
      triggerNotification("Baseline reset failed", "error");
    }
  };

  const handleUpdateIncidentStatus = async (id: string, newStatus: string) => {
    try {
      const res = await fetch(`/api/incidents/${id}/status`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: newStatus })
      });
      if (res.ok) {
        triggerNotification(`Incident ${id} updated to status ${newStatus}`, "success");
        fetchAllData();
      }
    } catch (e) {
      triggerNotification("Incident status modification failed", "error");
    }
  };

  const handleStartInvestigation = async (id: string) => {
    setInvestigatingId(id);
    triggerNotification("Dispatching automated AI Hunt Agent to construct telemetry...", "info");
    try {
      const res = await fetch(`/api/incidents/${id}/investigate`, {
        method: "POST"
      });
      const data = await res.json();
      if (data.success) {
        triggerNotification(`Forensic Hunt finished. Actionable report generated.`, "success");
        fetchAllData();
      } else {
        triggerNotification(data.error || "Gemini investigation returned analysis warnings.", "error");
      }
    } catch (error) {
      triggerNotification("Failed contacting Gemini core agent services.", "error");
    } finally {
      setInvestigatingId(null);
    }
  };

  // HELPERS
  const getSeverityBadgeClass = (severity: Severity) => {
    switch (severity) {
      case Severity.CRITICAL:
        return "bg-rose-950/40 text-rose-400 border border-rose-500/30 font-mono text-xs";
      case Severity.HIGH:
        return "bg-amber-950/40 text-amber-400 border border-amber-500/30 font-mono text-xs";
      case Severity.MEDIUM:
        return "bg-blue-950/40 text-blue-400 border border-blue-500/30 font-mono text-xs";
      default:
        return "bg-slate-800/60 text-slate-400 border border-slate-700 font-mono text-xs";
    }
  };

  const getThreatScoreColorClass = (score: number) => {
    if (score >= 80) return "text-rose-500 font-bold font-mono";
    if (score >= 50) return "text-amber-500 font-bold font-mono";
    return "text-cyber-emerald font-bold font-mono";
  };

  // Filter logs list on client side for easy filtering in the stream tab
  const filteredLogs = logs.filter(l => {
    const textMatch = l.message.toLowerCase().includes(logFilterText.toLowerCase()) || 
                      l.host.toLowerCase().includes(logFilterText.toLowerCase()) || 
                      l.user.toLowerCase().includes(logFilterText.toLowerCase()) || 
                      l.sourceIp.includes(logFilterText);
    
    if (logFilterCategory === "all") return textMatch;
    return textMatch && l.category.toLowerCase() === logFilterCategory.toLowerCase();
  });

  return (
    <div className="min-h-screen bg-cyber-charcoal-950 text-slate-100 flex flex-col font-sans selection:bg-teal-500/20">
      
      {/* GLOBAL SYSTEM NOTIFICATION BANNER */}
      {notification && (
        <div className={`fixed top-4 right-4 z-50 p-4 rounded-lg shadow-xl border backdrop-blur-md flex items-center gap-3 transition-all transform duration-300 md:max-w-md ${
          notification.type === "success" 
            ? "bg-emerald-950/80 text-emerald-300 border-emerald-500/40" 
            : notification.type === "error" 
            ? "bg-rose-950/80 text-rose-300 border-rose-500/40" 
            : "bg-slate-900/95 text-sky-300 border-sky-500/40"
        }`}>
          {notification.type === "success" ? <CheckCircle className="w-5 h-5 flex-shrink-0" /> : <AlertTriangle className="w-5 h-5 flex-shrink-0" />}
          <div className="text-sm font-medium">{notification.message}</div>
          <button className="text-slate-400 hover:text-white" onClick={() => setNotification(null)}>
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* HEADER CONTROLS BANNER */}
      <header className="border-b border-cyber-charcoal-800 bg-cyber-charcoal-900/90 py-3.5 px-6 sticky top-0 z-30 backdrop-blur-md flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-gradient-to-br from-rose-500 to-rose-700 text-white rounded-md shadow-md animate-pulse">
            <Shield className="w-5 h-5" id="header_shield_logo" />
          </div>
          <div>
            <h1 className="text-lg font-bold tracking-tight text-white flex items-center gap-2">
              AI SECURITY OPERATIONS CENTER <span className="text-xs bg-rose-500/10 text-rose-400 border border-rose-500/20 px-1.5 py-0.5 rounded uppercase font-mono">T-3 Core Agent</span>
            </h1>
            <p className="text-xs text-slate-400">Autonomous Correlation Platform & Behavioral Intelligence Hub</p>
          </div>
        </div>

        {/* SYSTEM STATUS GAUGES */}
        <div className="flex flex-wrap items-center gap-x-6 gap-y-2">
          {/* OVERALL MITIGATION INDEX */}
          <div className="flex items-center gap-3 bg-slate-950/40 border border-cyber-charcoal-800 rounded-lg p-2 px-3.5">
            <Radio className={`w-4 h-4 ${stats.overallThreatScore >= 70 ? "text-rose-500 animate-pulse" : stats.overallThreatScore >= 40 ? "text-amber-500" : "text-cyber-emerald"}`} />
            <div>
              <p className="text-[10px] text-slate-500 uppercase font-mono leading-none">Security Level</p>
              <div className="flex items-center gap-2.5 mt-1">
                <span className={`text-base font-bold font-mono ${stats.overallThreatScore >= 70 ? "text-rose-400" : stats.overallThreatScore >= 40 ? "text-amber-400" : "text-cyber-emerald"}`}>
                  {stats.overallThreatScore}%
                </span>
                <span className={`text-[10px] font-mono px-1 rounded uppercase ${
                  stats.overallThreatScore >= 70 ? "bg-rose-500/10 text-rose-400" : stats.overallThreatScore >= 40 ? "bg-amber-500/10 text-amber-400" : "bg-emerald-500/10 text-emerald-400"
                }`}>
                  {stats.overallThreatScore >= 70 ? "CRITICAL THREAT" : stats.overallThreatScore >= 45 ? "WARNING" : "STABLE OPS"}
                </span>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-5 text-xs text-slate-400">
            <div className="text-center">
              <span className="block text-white font-bold text-base font-mono leading-none">{stats.activeIncidentsCount}</span>
              <span className="text-[10px] text-slate-500">Active Incidents</span>
            </div>
            <div className="text-center border-l border-cyber-charcoal-800 pl-4">
              <span className="block text-rose-400 font-bold text-base font-mono leading-none">{stats.criticalAlertsCount}</span>
              <span className="text-[10px] text-slate-500">Critical Alerts</span>
            </div>
            <div className="text-center border-l border-cyber-charcoal-800 pl-4">
              <span className="block text-amber-400 font-bold text-base font-mono leading-none">{stats.uebaAnomalyCount}</span>
              <span className="text-[10px] text-slate-500">UEBA Anomalies</span>
            </div>
            <div className="text-center border-l border-cyber-charcoal-800 pl-4">
              <span className="block text-slate-300 font-bold text-base font-mono leading-none">{stats.processedEventsCount}</span>
              <span className="text-[10px] text-slate-500">Total Telemetry</span>
            </div>
          </div>

          {/* STREAM TOGGLER */}
          <div className="flex items-center gap-2 pl-2">
            <button 
              onClick={() => {
                setLiveStreamActive(!liveStreamActive);
                triggerNotification(liveStreamActive ? "Log Streaming paused." : "Real-time background correlation resumed.", "info");
              }}
              className={`flex items-center gap-1.5 p-1.5 px-3 rounded text-xs font-medium border font-mono transition-colors duration-150 ${
                liveStreamActive 
                  ? "bg-teal-950/20 text-cyber-emerald border-teal-500/30 hover:bg-teal-950/40"
                  : "bg-slate-800/50 text-slate-400 border-slate-700 hover:bg-slate-800"
              }`}
            >
              {liveStreamActive ? (
                <>
                  <span className="w-2 h-2 rounded-full bg-cyber-emerald animate-ping" />
                  LIVE FEEDS
                </>
              ) : (
                <>
                  <span className="w-2 h-2 rounded-full bg-slate-500" />
                  PAUSED
                </>
              )}
            </button>
            
            <button
              onClick={fetchAllData}
              title="Sync metrics"
              className="p-2 border border-cyber-charcoal-800 bg-cyber-charcoal-900 rounded hover:bg-slate-800 transition-colors text-slate-400 hover:text-white"
            >
              <RefreshCw className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </header>

      {/* DASHBOARD TIMELINE GRAPH ACCENT */}
      {stats.eventsTimeline && stats.eventsTimeline.length > 0 && (
        <div className="bg-cyber-charcoal-900/40 border-b border-cyber-charcoal-800/60 p-2 px-6 flex items-center justify-between gap-12 text-xs">
          <div className="w-48 text-slate-400 flex-shrink-0 flex items-center gap-1.5">
            <TrendingUp className="w-4.5 h-4.5 text-rose-500" />
            <span>Operational Traffic Feed Load</span>
          </div>
          <div className="h-10 flex-grow max-w-4xl">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={stats.eventsTimeline} margin={{ top: 2, right: 10, left: 10, bottom: 2 }}>
                <defs>
                  <linearGradient id="colorCount" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.2}/>
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0}/>
                  </linearGradient>
                  <linearGradient id="colorCorrelated" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.21}/>
                    <stop offset="95%" stopColor="#3b82f6" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <XAxis dataKey="time" hide />
                <YAxis hide />
                <Tooltip 
                  contentStyle={{ backgroundColor: "#0d121c", borderColor: "#1a2333", color: "#f8fafc" }}
                  labelClassName="text-slate-500 font-mono text-[10px]"
                />
                <Area type="monotone" dataKey="count" name="Syslog Traffic" stroke="#ef4444" strokeWidth={1} fillOpacity={1} fill="url(#colorCount)" />
                <Area type="monotone" dataKey="countCorrelated" name="Correlated Incidents" stroke="#3b82f6" strokeWidth={1} fillOpacity={1} fill="url(#colorCorrelated)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
          <div className="text-right text-[10px] text-slate-500 font-mono hidden md:block">
            ACTIVE CORRELATION BUFFERS: 12H WINDOW SLICE
          </div>
        </div>
      )}

      {/* DASHBOARD WORKSPACE GRID PANELS */}
      <main className="flex-grow flex flex-col lg:flex-row divide-y lg:divide-y-0 lg:divide-x divide-cyber-charcoal-800 overflow-hidden h-[calc(100vh-112px)]">
        
        {/* PANEL 1: INCIDENT QUEUE CENTER (LEFT COLUMN) */}
        <section className="w-full lg:w-80 flex flex-col bg-cyber-charcoal-900/60 overflow-y-auto">
          <div className="p-4 border-b border-cyber-charcoal-800 bg-cyber-charcoal-900/80 sticky top-0 z-10 flex items-center justify-between">
            <h2 className="text-xs font-bold tracking-wider text-slate-300 font-mono uppercase flex items-center gap-1.5">
              <ShieldAlert className="w-4 h-4 text-rose-500" />
              Incidents Queue
              <span className="ml-[2px] bg-rose-500/10 text-rose-400 border border-rose-500/20 text-[10px] font-normal px-1 rounded-full font-mono">
                {incidents.length}
              </span>
            </h2>
            <div className="text-[10px] text-slate-500 font-mono">
              Auto-Priority sorted
            </div>
          </div>

          <div className="p-3 bg-cyber-charcoal-900/30 border-b border-cyber-charcoal-800">
            <div className="bg-slate-950/60 border border-cyber-charcoal-800 rounded p-1.5 flex items-center gap-2">
              <Search className="w-3.5 h-3.5 text-slate-500 flex-shrink-0" />
              <input 
                type="text" 
                placeholder="Lookup incident entity ID..." 
                className="bg-transparent border-0 outline-none text-xs text-slate-200 placeholder-slate-600 w-full"
                onChange={(e) => {
                  const val = e.target.value.toLowerCase();
                  if (!val) {
                    setIncidents(incidents);
                  } else {
                    // search logic fallback
                  }
                }}
              />
            </div>
          </div>

          {/* INCIDENT TILES */}
          <div className="flex-grow divide-y divide-cyber-charcoal-800">
            {incidents.length === 0 ? (
              <div className="p-8 text-center text-slate-500 text-xs">
                <Shield className="w-8 h-8 mx-auto text-slate-700 mb-3" />
                <p>No active security threat incidents detected.</p>
                <p className="mt-1 text-[10px] text-slate-600">Simulate alert vectors to test rule analysis.</p>
              </div>
            ) : (
              incidents.map((inc) => {
                const isSelected = selectedIncident?.id === inc.id;
                return (
                  <button
                    key={inc.id}
                    onClick={() => setSelectedIncident(inc)}
                    className={`w-full p-4 text-left leading-normal block hover:bg-slate-800/40 relative outline-none focus:bg-slate-800/40 transition-all ${
                      isSelected 
                        ? "bg-cyber-charcoal-800/80 border-l-[3px] border-rose-500" 
                        : "bg-transparent"
                    }`}
                  >
                    <div className="flex items-center justify-between gap-1 mb-1">
                      <span className="font-mono text-[10px] text-blue-400 font-bold">{inc.id}</span>
                      <span className="text-[10px] text-slate-500 font-mono">
                        {new Date(inc.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                      </span>
                    </div>

                    <h3 className="text-xs font-semibold text-slate-200 line-clamp-2 leading-snug mb-2 font-sans">
                      {inc.name}
                    </h3>

                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-1.5">
                        <span className={`px-1.5 py-0.5 rounded text-[9px] font-medium tracking-wide uppercase ${getSeverityBadgeClass(inc.severity)}`}>
                          {inc.severity}
                        </span>
                        <span className="text-[10px] text-slate-400 bg-slate-950/40 px-1 py-0.5 rounded font-mono border border-cyber-charcoal-800">
                          {inc.attackStage}
                        </span>
                      </div>

                      <div className="flex items-center gap-1">
                        <span className="text-[10px] text-slate-500 font-mono">Risk:</span>
                        <span className={`text-[11px] ${getThreatScoreColorClass(inc.score)}`}>
                          {inc.score}
                        </span>
                      </div>
                    </div>

                    {/* STATUS DECORATIONS */}
                    <div className="mt-2.5 pt-2 border-t border-slate-800/50 flex justify-between items-center text-[10px] text-slate-500">
                      <span className={`flex items-center gap-1 ${inc.status === IncidentStatus.ACTIVE ? "text-rose-400 animate-pulse" : inc.status === IncidentStatus.INVESTIGATING ? "text-amber-400" : "text-emerald-400"}`}>
                        <span className={`w-1.5 h-1.5 rounded-full ${inc.status === IncidentStatus.ACTIVE ? "bg-rose-500" : inc.status === IncidentStatus.INVESTIGATING ? "bg-amber-500" : "bg-emerald-500"}`} />
                        {inc.status}
                      </span>
                      {inc.automaticInvestigationStatus === "Completed" && (
                        <span className="text-teal-400 font-mono flex items-center gap-0.5 border border-teal-500/10 bg-teal-500/5 px-1 rounded text-[9px]">
                          <FileCheck className="w-3 h-3" /> IA-REPORT
                        </span>
                      )}
                    </div>
                  </button>
                );
              })
            )}
          </div>
        </section>

        {/* PANEL 2: MAIN-STAGE workspace AREA (CENTER PANEL) */}
        <section className="flex-grow flex flex-col min-w-0 bg-cyber-charcoal-950 overflow-y-auto">
          {selectedIncident ? (
            <div className="flex flex-col h-full">
              {/* INCIDENT META HEADER */}
              <div className="p-6 border-b border-cyber-charcoal-800 bg-cyan-950/5 relative">
                <div className="absolute top-0 right-0 w-80 h-32 bg-rose-500/5 rounded-full filter blur-3xl pointer-events-none" />
                
                <div className="flex flex-wrap items-center justify-between gap-4 mb-4">
                  <div className="flex items-center gap-2">
                    <span className="bg-rose-500/10 text-rose-400 border border-rose-500/20 p-1.5 rounded-lg">
                      <ShieldAlert className="w-5 h-5" />
                    </span>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs text-blue-400 font-bold">{selectedIncident.id}</span>
                        <span className="text-slate-600">•</span>
                        <span className="text-xs text-slate-400 flex items-center gap-1">
                          <Clock className="w-3 h-3 text-slate-500" />
                          Opened {new Date(selectedIncident.timestamp).toLocaleString()}
                        </span>
                      </div>
                      <h2 className="text-lg font-bold text-white mt-0.5 leading-snug">
                        {selectedIncident.name}
                      </h2>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    <span className="text-xs text-slate-500 font-mono">Status Action:</span>
                    <select
                      value={selectedIncident.status}
                      onChange={(e) => handleUpdateIncidentStatus(selectedIncident.id, e.target.value)}
                      className="bg-slate-900 border border-cyber-charcoal-800 text-xs text-slate-200 rounded p-1.5 px-3 outline-none hover:border-slate-700"
                    >
                      <option value={IncidentStatus.ACTIVE}>Active Alert</option>
                      <option value={IncidentStatus.INVESTIGATING}>Under Hunt Review</option>
                      <option value={IncidentStatus.CLOSED}>Mitigated / Closed</option>
                    </select>
                  </div>
                </div>

                <p className="text-sm text-slate-300 leading-relaxed max-w-4xl bg-slate-900/30 border border-cyber-charcoal-800/40 p-3 rounded">
                  {selectedIncident.description}
                </p>

                {/* VISUAL MITRE & ENTITY FOOTER GAUGES */}
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mt-4 pt-4 border-t border-cyber-charcoal-800/60 text-xs">
                  <div>
                    <span className="block text-[10px] text-slate-500 uppercase font-mono tracking-wider">Compromised Targets</span>
                    <div className="mt-1.5 flex flex-wrap gap-1">
                      {selectedIncident.affectedEntities.hosts.map((host) => (
                        <div key={host} className="flex items-center gap-1 bg-slate-900 border border-slate-800 px-2 py-0.5 rounded font-mono text-[11px] text-yellow-400">
                          <Server className="w-3 h-3 text-slate-500" />
                          {host}
                        </div>
                      ))}
                      {selectedIncident.affectedEntities.users.map((usr) => (
                        <div key={usr} className="flex items-center gap-1 bg-slate-900 border border-slate-800 px-2 py-0.5 rounded font-mono text-[11px] text-teal-400">
                          <Users className="w-3 h-3 text-slate-500" />
                          {usr}
                        </div>
                      ))}
                    </div>
                  </div>

                  <div>
                    <span className="block text-[10px] text-slate-500 uppercase font-mono tracking-wider">MITRE ATT&CK Matrix Alignment</span>
                    <div className="mt-1.5 flex flex-wrap gap-1">
                      {selectedIncident.mitreMapping.map((map) => (
                        <div key={map.id} className="flex flex-col bg-slate-900/80 border border-red-500/20 px-2 py-1 rounded">
                          <span className="text-[10px] text-rose-400 font-bold">{map.tactic}</span>
                          <span className="text-[9px] text-slate-400 font-mono italic leading-none">{map.technique} ({map.id})</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="bg-slate-950/40 p-2.5 rounded border border-cyber-charcoal-800/80 flex items-center justify-between">
                    <div>
                      <span className="block text-[10px] text-slate-500 uppercase font-mono uppercase">Calculated Incident Score</span>
                      <span className="text-xl font-extrabold font-mono text-slate-200 mt-1 block">
                        {selectedIncident.score}/100
                      </span>
                    </div>
                    <div className={`text-xs font-bold px-2 py-1 rounded uppercase font-mono ${
                      selectedIncident.score >= 80 ? "bg-red-500/10 text-red-400 border border-red-500/20" : "bg-amber-500/10 text-amber-400 border border-amber-500/20"
                    }`}>
                      {selectedIncident.score >= 80 ? "Critical Threat" : "High Alert"}
                    </div>
                  </div>
                </div>
              </div>

              {/* CORE INVESTIGATION LABS */}
              <div className="flex-grow p-6 grid grid-cols-1 md:grid-cols-2 gap-6 items-start divide-y md:divide-y-0 md:divide-x divide-cyber-charcoal-800">
                
                {/* SUBCOLUMN A: CORRELATED TRACE TIMELINE */}
                <div className="space-y-4">
                  <h3 className="text-xs font-bold tracking-wider text-slate-400 uppercase font-mono flex items-center gap-1.5">
                    <Database className="w-4 h-4 text-slate-500" />
                    Correlated Security Trace IOCs
                    <span className="text-[10px] bg-slate-800 px-1.5 py-0.5 rounded text-slate-400 font-mono">
                      {selectedIncident.events.length}
                    </span>
                  </h3>

                  <div className="space-y-3 max-h-[50vh] overflow-y-auto pr-2">
                    {selectedIncident.events.map((e, index) => (
                      <div key={e.id} className="p-3 bg-cyber-charcoal-900 border border-cyber-charcoal-800/80 rounded relative hover:border-slate-700 transition">
                        <div className="flex items-center justify-between gap-2 mb-1.5 text-[10px]">
                          <span className="bg-slate-950/60 px-1.5 py-0.5 rounded text-blue-400 font-mono font-semibold">
                            {e.category} | {e.eventType}
                          </span>
                          <span className="text-slate-500 font-mono">
                            {new Date(e.timestamp).toLocaleTimeString()}
                          </span>
                        </div>

                        <p className="text-xs text-slate-200 font-mono leading-relaxed word-break-all">
                          {e.message}
                        </p>

                        <div className="mt-2 pt-2 border-t border-slate-800/50 flex flex-wrap justify-between items-center text-[10px] text-slate-400 gap-2">
                          <div className="flex items-center gap-1 font-mono">
                            <span className="text-slate-500">Source:</span> <span className="text-slate-300">{e.sourceIp}</span>
                            <ChevronRight className="w-2.5 h-2.5 text-slate-600" />
                            <span className="text-slate-500">Host:</span> <span className="text-yellow-400/85">{e.host}</span>
                          </div>
                          
                          <div className="flex items-center gap-1 font-mono">
                            <span className="text-slate-500">Score:</span> 
                            <span className={getThreatScoreColorClass(e.score)}>{e.score}</span>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>

                  {/* ACTIVE CONTAINMENT MITIGATIONS */}
                  {selectedIncident.suggestedPlaybook && selectedIncident.suggestedPlaybook.length > 0 && (
                    <div className="p-4 bg-slate-900/60 border border-cyber-charcoal-800 rounded">
                      <h4 className="text-[11px] font-bold tracking-wider text-slate-300 font-mono uppercase mb-2 flex items-center gap-1">
                        <Sliders className="w-3.5 h-3.5 text-cyan-400 animate-spin" />
                        Tactical Containment Playbook
                      </h4>
                      <p className="text-[10px] text-slate-400 mb-3">Contain the threat immediate vector. Click a containment play to activate sandbox policies.</p>
                      <div className="space-y-1.5">
                        {selectedIncident.suggestedPlaybook.map((play, index) => (
                          <button
                            key={index}
                            onClick={() => {
                              triggerNotification(`Playbook Action Activated: "${play}". Block policies deployed.`, "success");
                              if (selectedIncident.status === IncidentStatus.ACTIVE) {
                                handleUpdateIncidentStatus(selectedIncident.id, IncidentStatus.CLOSED);
                              }
                            }}
                            className="w-full text-left p-2 rounded bg-slate-950/60 border border-slate-800 hover:border-cyan-500/40 hover:bg-slate-900 group flex items-center justify-between text-xs transition duration-150 relative"
                          >
                            <span className="text-slate-300 group-hover:text-cyan-400 flex items-center gap-1.5 font-mono text-[11px]">
                              <span className="text-slate-600">[{index+1}]</span> {play}
                            </span>
                            <span className="text-[11px] text-cyan-400 bg-cyan-950 px-1 py-0.5 rounded font-mono tracking-wider opacity-0 group-hover:opacity-100 transition-opacity">
                              EXECUTE
                            </span>
                          </button>
                        ))}
                      </div>
                    </div>
                  )}
                </div>

                {/* SUBCOLUMN B: AI AUTOMATED INVESTIGATIONS (GEMINI STAGE) */}
                <div className="space-y-4 pt-6 md:pt-0 md:pl-6">
                  <div className="flex items-center justify-between">
                    <h3 className="text-xs font-bold tracking-wider text-slate-400 uppercase font-mono flex items-center gap-1.5">
                      <Cpu className="w-4 h-4 text-emerald-400" />
                      AI Automatic Investigator Agent
                    </h3>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono ${
                      selectedIncident.automaticInvestigationStatus === "Completed" 
                        ? "bg-teal-950/45 text-cyber-emerald border border-teal-500/20" 
                        : selectedIncident.automaticInvestigationStatus === "In Progress" 
                        ? "bg-amber-950/40 text-amber-400 border border-amber-500/20 animate-pulse"
                        : "bg-slate-800 text-slate-400"
                    }`}>
                      {selectedIncident.automaticInvestigationStatus}
                    </span>
                  </div>

                  {/* AI STATUS HUB & CORE REQUESTS */}
                  <div className="bg-gradient-to-r from-cyber-charcoal-900 to-slate-900 p-5 rounded-lg border border-cyber-charcoal-800 space-y-4">
                    <div className="flex items-start gap-3">
                      <div className="p-2.5 bg-emerald-500/10 text-cyber-emerald border border-emerald-500/20 rounded-md">
                        <Zap className="w-5 h-5" />
                      </div>
                      <div>
                        <h4 className="text-xs font-bold text-white uppercase font-mono">Gemini AI Cyber Threat Hunter</h4>
                        <p className="text-xs text-slate-400 mt-1 leading-relaxed">
                          Analyze the entire incident cluster context, trace logs, source IPs networks, and UEBA normal baselines. Produces full forensic playbook reports, chronological attack sequencing, and active mitigations recommendations using <code className="text-cyber-emerald font-mono text-[11px]">gemini-3.5-flash</code>.
                        </p>
                      </div>
                    </div>

                    <button
                      disabled={investigatingId !== null}
                      onClick={() => handleStartInvestigation(selectedIncident.id)}
                      className="w-full bg-gradient-to-r from-emerald-500 to-teal-600 hover:from-emerald-400 hover:to-teal-500 text-white font-mono text-xs font-bold uppercase p-2.5 rounded-lg shadow-md hover:shadow-cyan-500/10 flex items-center justify-center gap-2 transition duration-200"
                    >
                      {investigatingId === selectedIncident.id ? (
                        <>
                          <RefreshCw className="w-4 h-4 animate-spin text-white" />
                          GEMINI IS INVESTIGATING... PLEASE WAIT
                        </>
                      ) : (
                        <>
                          <Zap className="w-4 h-4 text-yellow-300" />
                          ACTIVATE AI THREAT HUNTER RUN
                        </>
                      )}
                    </button>
                    
                    {/* LOADING REASSURANCES */}
                    {investigatingId === selectedIncident.id && (
                      <div className="p-3 bg-slate-950/45 rounded-lg border border-teal-500/10 text-[11px] text-teal-400/90 font-mono space-y-1.5 animate-pulse">
                        <p className="flex items-center gap-1.5"><span className="w-1.5 h-1.5 rounded-full bg-emerald-400" /> Parsing correlated endpoint log headers...</p>
                        <p className="flex items-center gap-1.5"><span className="w-1.5 h-1.5 rounded-full bg-emerald-400" /> Querying MITRE ATT&CK tactics indexes...</p>
                        <p className="flex items-center gap-1.5"><span className="w-1.5 h-1.5 rounded-full bg-emerald-400" /> Checking user behavior baseline timezone variances...</p>
                        <p className="text-[10px] text-slate-500 italic mt-1 leading-normal">Our AI Hunt agent searches logs to isolate attacker footholds and generate immediate remediation strategies.</p>
                      </div>
                    )}
                  </div>

                  {/* REPORT SPACE */}
                  {selectedIncident.aiInvestigationReport ? (
                    <div className="space-y-2">
                      <div className="flex items-center justify-between bg-slate-900 p-2.5 rounded border border-cyber-charcoal-800">
                        <span className="text-[11px] font-mono text-slate-400 flex items-center gap-1">
                          <FileText className="w-3.5 h-3.5 text-cyber-emerald" />
                          Generated Threat Intelligence Bulletin
                        </span>
                        <span className="text-[10px] text-slate-500 font-mono select-none uppercase">
                          Tier 3 Verified
                        </span>
                      </div>

                      {/* ENCLOSED MARKDOWN DESIGN */}
                      <div className="p-4 bg-slate-950 border border-cyber-charcoal-800/80 rounded-lg text-slate-300 overflow-y-auto max-h-[42vh] scrollbar-thin scrollbar-thumb-cyber-charcoal-800">
                        <div className="markdown-body text-xs leading-relaxed space-y-4 font-mono font-normal">
                          <Markdown>{selectedIncident.aiInvestigationReport}</Markdown>
                        </div>
                      </div>
                    </div>
                  ) : (
                    <div className="border border-dashed border-cyber-charcoal-800 p-6 rounded text-center text-slate-500 text-xs">
                      <FileCheck className="w-8 h-8 text-slate-700 mx-auto mb-2" />
                      No AI analysis file compiled yet. Click above to trigger the automated investigation report.
                    </div>
                  )}

                </div>

              </div>
            </div>
          ) : (
            <div className="flex-grow flex flex-col justify-center items-center text-center p-12 text-slate-500 text-xs">
              <ShieldAlert className="w-12 h-12 text-slate-700 mb-4" />
              <h3 className="text-base font-bold text-slate-300">No Target Incident Selected</h3>
              <p className="mt-1">Please select an Incident from the left queue to commence analysis.</p>
            </div>
          )}
        </section>

        {/* PANEL 3: TELEMETRY & BASES WORKSPACE (RIGHT SIDEBAR) */}
        <section className="w-full lg:w-96 flex flex-col bg-cyber-charcoal-900/90 overflow-y-auto">
          {/* BAR MENU NAVIGATION */}
          <div className="flex border-b border-cyber-charcoal-800/80 sticky top-0 bg-cyber-charcoal-900 z-10 text-[10px] text-slate-400">
            <button
              onClick={() => setSidebarTab("sim")}
              className={`flex-grow p-2.5 text-center border-b-[2px] font-mono uppercase font-bold tracking-wider outline-none transition-colors ${
                sidebarTab === "sim" 
                  ? "border-red-500 text-red-400 bg-red-500/5 font-semibold" 
                  : "border-transparent text-slate-400 hover:text-slate-200"
              }`}
            >
              Simulate
            </button>
            <button
              onClick={() => setSidebarTab("splunk")}
              className={`flex-grow p-2.5 text-center border-b-[2px] font-mono uppercase font-bold tracking-wider outline-none transition-colors ${
                sidebarTab === "splunk" 
                  ? "border-cyan-500 text-cyan-400 bg-cyan-500/5 font-semibold" 
                  : "border-transparent text-slate-400 hover:text-slate-200"
              }`}
            >
              Splunk
            </button>
            <button
              onClick={() => setSidebarTab("ueba")}
              className={`flex-grow p-2.5 text-center border-b-[2px] font-mono uppercase font-bold tracking-wider outline-none transition-colors ${
                sidebarTab === "ueba" 
                  ? "border-teal-500 text-cyber-emerald bg-teal-500/5 font-semibold" 
                  : "border-transparent text-slate-400 hover:text-slate-200"
              }`}
            >
              UEBA
            </button>
            <button
              onClick={() => setSidebarTab("rules")}
              className={`flex-grow p-2.5 text-center border-b-[2px] font-mono uppercase font-bold tracking-wider outline-none transition-colors ${
                sidebarTab === "rules" 
                  ? "border-yellow-500 text-amber-400 bg-amber-500/5 font-semibold" 
                  : "border-transparent text-slate-400 hover:text-slate-200"
              }`}
            >
              Rules ({rules.length})
            </button>
          </div>

          <div className="flex-grow flex flex-col min-h-0">
            {/* TAB A: LOG SIMULATION TOOLS */}
            {sidebarTab === "sim" && (
              <div className="p-4 flex flex-col h-full space-y-4">
                <div className="bg-red-500/10 p-3 rounded border border-red-500/20 text-xs">
                  <h4 className="font-bold text-red-400 font-mono uppercase mb-1">Scenario Simulation Pad</h4>
                  <p className="text-slate-400 leading-normal">
                    Manually trigger active advanced cyber attack threat scenarios. The Correlation Engine aggregates logs in real-time, mapping endpoints to active vectors instantly.
                  </p>
                </div>

                <div className="space-y-2">
                  <button
                    disabled={isSimulating !== null}
                    onClick={() => handleTriggerSimulation("ransomware")}
                    className="w-full bg-slate-950/60 border border-red-500/30 hover:border-red-500 text-left p-3 rounded-lg relative hover:bg-slate-900 group transition duration-150"
                  >
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs font-bold text-rose-400 font-mono">APT Ransomware Chain Campaign</span>
                      <span className="text-[9px] bg-red-500/10 text-red-400 font-mono border border-red-500/20 px-1 py-0.5 rounded">
                        Severity: CRITICAL
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-400 leading-normal">
                      Simulates workstation compromise, remote credential escalation, domain controllers takeover attempts, database host access pivots, and bulk cryptographic files encryption (T1486).
                    </p>
                    {isSimulating === "ransomware" && (
                      <div className="absolute inset-0 bg-slate-950/70 flex items-center justify-center rounded-lg text-xs font-mono text-rose-400">
                        <RefreshCw className="w-4 h-4 animate-spin mr-2" /> Inbound Payload...
                      </div>
                    )}
                  </button>

                  <button
                    disabled={isSimulating !== null}
                    onClick={() => handleTriggerSimulation("exfil")}
                    className="w-full bg-slate-950/60 border border-slate-800 hover:border-slate-500 text-left p-3 rounded-lg relative hover:bg-slate-900 group transition duration-150"
                  >
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs font-bold text-amber-400 font-mono">Insider Threat Data Exfiltration</span>
                      <span className="text-[9px] bg-amber-500/15 text-amber-400 font-mono border border-amber-500/20 px-1 py-0.5 rounded">
                        Severity: HIGH
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-400 leading-normal">
                      Fires cron authentication abnormalities, databases secure tables querying, local compression backups dumps, and outbound transmissions to a Tor VPS (T1048).
                    </p>
                    {isSimulating === "exfil" && (
                      <div className="absolute inset-0 bg-slate-950/70 flex items-center justify-center rounded-lg text-xs font-mono text-amber-400">
                        <RefreshCw className="w-4 h-4 animate-spin mr-2" /> Dumping Secure PII...
                      </div>
                    )}
                  </button>

                  <button
                    disabled={isSimulating !== null}
                    onClick={() => handleTriggerSimulation("stuffing")}
                    className="w-full bg-slate-950/60 border border-slate-800 hover:border-slate-500 text-left p-3 rounded-lg relative hover:bg-slate-900 group transition duration-150"
                  >
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs font-bold text-blue-400 font-mono">Credential Stuffing Deployment</span>
                      <span className="text-[9px] bg-blue-500/10 text-blue-400 font-mono border border-blue-500/20 px-1 py-0.5 rounded">
                        Severity: HIGH
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-400 leading-normal">
                      Triggers repetitive Kerberos authentication ticket failures followed immediately by anomalous login anomalies on core active directory hosts.
                    </p>
                    {isSimulating === "stuffing" && (
                      <div className="absolute inset-0 bg-slate-950/70 flex items-center justify-center rounded-lg text-xs font-mono text-blue-400">
                        <RefreshCw className="w-4 h-4 animate-spin mr-2" /> Executing Spray...
                      </div>
                    )}
                  </button>
                </div>
                
                {/* GLOBAL LIVE SYS RECENT FEED LOGS UNDERNEATH */}
                <div className="flex-grow flex flex-col bg-slate-950 rounded border border-cyber-charcoal-800 overflow-hidden h-[30vh]">
                  <div className="p-2.5 bg-cyber-charcoal-900 border-b border-cyber-charcoal-800 flex items-center justify-between text-[11px] text-slate-400 font-mono">
                    <span className="flex items-center gap-1 text-slate-300">
                      <Terminal className="w-3.5 h-3.5 text-cyber-emerald" />
                      Live Stream Event Buffer ({filteredLogs.length})
                    </span>
                    <button 
                      onClick={() => {
                        setLogs([]);
                        triggerNotification("Live logs buffer cleared.", "info");
                      }}
                      className="text-slate-600 hover:text-slate-300 cursor-pointer text-[10px]"
                    >
                      Clear
                    </button>
                  </div>
                  
                  {/* SEARCH STREAM */}
                  <div className="p-2 border-b border-cyber-charcoal-800 bg-cyber-charcoal-900/30 flex gap-2">
                    <input 
                      type="text"
                      value={logFilterText}
                      placeholder="Keyword filter logs..."
                      onChange={(e) => setLogFilterText(e.target.value)}
                      className="bg-slate-950 border border-cyber-charcoal-800 text-[10px] text-slate-300 rounded px-2 py-1 flex-grow outline-none placeholder-slate-600 font-mono"
                    />
                    <select
                      value={logFilterCategory}
                      onChange={(e) => setLogFilterCategory(e.target.value)}
                      className="bg-slate-950 border border-cyber-charcoal-800 text-[10px] text-slate-300 rounded px-1 text-xs outline-none font-mono"
                    >
                      <option value="all">All</option>
                      <option value="auth">Auth</option>
                      <option value="firewall">Firewall</option>
                      <option value="host">Host</option>
                      <option value="endpoint">Endpoint</option>
                    </select>
                  </div>

                  {/* STREAM TERMINAL */}
                  <div className="flex-grow overflow-y-auto p-2 font-mono text-[9px] text-slate-400 space-y-1.5 scrollbar-thin">
                    {filteredLogs.length === 0 ? (
                      <p className="text-slate-600 italic p-4 text-center">Empty log queue trace...</p>
                    ) : (
                      filteredLogs.map((log) => (
                        <div key={log.id} className="hover:bg-slate-900/60 p-1 rounded transition flex items-start gap-1">
                          <span className="text-[8px] text-slate-600 mt-[1px] flex-shrink-0">
                            [{new Date(log.timestamp).toLocaleTimeString()}]
                          </span>
                          <span className={`font-semibold mr-1 flex-shrink-0 ${
                            log.severity === Severity.CRITICAL ? "text-rose-400 font-bold" : log.severity === Severity.HIGH ? "text-amber-400 font-bold" : "text-blue-400"
                          }`}>
                            [{log.category}]
                          </span>
                          <span className="text-slate-300 word-break-all break-all">{log.message}</span>
                          {log.matchedRuleId && (
                            <span className="text-[8px] bg-red-950/30 text-rose-400 border border-red-500/20 px-1 rounded flex-shrink-0 ml-auto select-none uppercase tracking-wide">
                              MATCHED: {log.matchedRuleId}
                            </span>
                          )}
                        </div>
                      ))
                    )}
                    <div ref={logTerminalEndRef} />
                  </div>
                </div>
              </div>
            )}

            {/* TAB: SPLUNK ENTERPRISE INTEGRATION */}
            {sidebarTab === "splunk" && (
              <div className="p-4 flex flex-col h-full space-y-4">
                <div className="bg-cyan-950/20 border border-cyan-500/20 p-3.5 rounded-lg text-xs">
                  <h4 className="font-bold text-cyan-400 font-mono uppercase mb-1 flex items-center gap-1.5">
                    <Database className="w-4 h-4 text-cyan-400" />
                    Splunk Connector
                  </h4>
                  <p className="text-slate-400 leading-normal">
                    Securely pulls and correlates native Windows system security logs, Forwarders, T-Pot logs from your local Splunk Enterprise REST service interface.
                  </p>
                  
                  {/* LOCALHOST ALERT FOR ELEGANCE */}
                  <div className="mt-2 text-[10px] text-amber-400 bg-amber-950/10 border border-amber-500/10 p-2 rounded leading-relaxed">
                    <strong>Note:</strong> Since <code>192.168.1.1</code> is a private network IP, the hosted cloud preview won't reach it directly. For live local subnets, use Ngrok/tunnels or run this React build locally on your system!
                  </div>
                </div>

                {/* CONNECTION STATUS */}
                <div className="bg-slate-950/60 p-3 rounded-lg border border-cyber-charcoal-800 text-[11px] font-mono leading-relaxed space-y-1">
                  <div className="flex justify-between">
                    <span className="text-slate-500">Node Status:</span>
                    <span className={`font-bold uppercase ${splunkConfig.isConnected ? "text-cyber-emerald" : "text-amber-500"}`}>
                      {splunkConfig.isConnected ? "● Connected (Live)" : "● Ready / Standby"}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Sync Status:</span>
                    <span className="text-slate-300 truncate max-w-[180px]" title={splunkConfig.syncStatus}>{splunkConfig.syncStatus}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Last Synced:</span>
                    <span className="text-slate-300">
                      {splunkConfig.lastSyncTime ? new Date(splunkConfig.lastSyncTime).toLocaleTimeString() : "Never"}
                    </span>
                  </div>
                </div>

                {/* FORM INPUTS */}
                <form onSubmit={handleSaveSplunkConfig} className="space-y-3.5 text-xs">
                  <div className="space-y-1">
                    <label className="text-[10px] text-slate-500 uppercase font-mono tracking-wider">Splunk Enterprise URL</label>
                    <input 
                      type="text" 
                      value={splunkHostInput} 
                      onChange={(e) => setSplunkHostInput(e.target.value)}
                      placeholder="e.g. https://192.168.1.1:8089"
                      className="w-full bg-slate-950 border border-cyber-charcoal-800 rounded p-2 text-slate-200 focus:border-cyan-500 font-mono" 
                    />
                  </div>

                  <div className="grid grid-cols-2 gap-2">
                    <div className="space-y-1">
                      <label className="text-[10px] text-slate-500 uppercase font-mono tracking-wider">Username</label>
                      <input 
                        type="text" 
                        value={splunkUsernameInput} 
                        onChange={(e) => setSplunkUsernameInput(e.target.value)}
                        className="w-full bg-slate-950 border border-cyber-charcoal-800 rounded p-2 text-slate-200 focus:border-cyan-500 font-mono" 
                      />
                    </div>
                    <div className="space-y-1">
                      <label className="text-[10px] text-slate-500 uppercase font-mono tracking-wider">Password</label>
                      <input 
                        type="password" 
                        value={splunkPasswordInput} 
                        onChange={(e) => setSplunkPasswordInput(e.target.value)}
                        className="w-full bg-slate-950 border border-cyber-charcoal-800 rounded p-2 text-slate-200 focus:border-cyan-500 font-mono" 
                      />
                    </div>
                  </div>

                  <div className="space-y-1">
                    <label className="text-[10px] text-slate-500 uppercase font-mono tracking-wider">Search Pipeline Query</label>
                    <textarea 
                      value={splunkQueryInput} 
                      onChange={(e) => setSplunkQueryInput(e.target.value)}
                      rows={3}
                      className="w-full bg-slate-950 border border-cyber-charcoal-800 rounded p-2 text-slate-200 focus:border-cyan-500 font-mono text-[11px]" 
                    />
                  </div>

                  <div className="flex items-center justify-between p-2 rounded bg-slate-900 border border-cyber-charcoal-800">
                    <div className="flex flex-col">
                      <span className="font-semibold text-slate-300 text-[11px]">Auto Syslog Ingest</span>
                      <span className="text-[9px] text-slate-500 font-mono">Poll telemetry every 30s</span>
                    </div>
                    <input 
                      type="checkbox" 
                      checked={splunkAutoSyncInput}
                      onChange={(e) => setSplunkAutoSyncInput(e.target.checked)}
                      className="w-4 h-4 accent-cyan-500 cursor-pointer"
                    />
                  </div>

                  <div className="grid grid-cols-2 gap-2.5 pt-1">
                    <button
                      type="submit"
                      className="bg-slate-900 hover:bg-slate-800 border border-cyber-charcoal-800 hover:border-slate-700 text-slate-200 text-xs font-mono py-2 px-3 rounded font-bold uppercase cursor-pointer"
                    >
                      Save Config
                    </button>
                    <button
                      type="button"
                      disabled={isSplunkSyncing}
                      onClick={handleSyncSplunkLogs}
                      className="bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white text-xs font-mono py-2 px-3 rounded font-bold uppercase flex items-center justify-center gap-1.5 cursor-pointer shadow-lg shadow-cyan-500/10"
                    >
                      {isSplunkSyncing ? (
                        <>
                          <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                          Ingesting...
                        </>
                      ) : (
                        <>
                          <RefreshCw className="w-3.5 h-3.5" />
                          Sync Logs
                        </>
                      )}
                    </button>
                  </div>
                </form>

                {/* HELPFUL WINDOWS EVENT EXTREME REFERENCE PRESETS */}
                <div className="pt-2">
                  <span className="block text-[10px] text-slate-500 uppercase font-mono tracking-wider mb-2">Preset Search Templates</span>
                  <div className="space-y-1.5 text-[10px] font-mono">
                    <button
                      type="button"
                      onClick={() => setSplunkQueryInput('search index=* OR source="WinEventLog:*" OR sourcetype="t-pot" | head 30')}
                      className="w-full text-left p-1.5 rounded bg-slate-950/40 border border-slate-800 hover:border-cyan-500/30 text-slate-400 hover:text-cyan-400 flex items-center justify-between"
                    >
                      <span>Unified System Logs (Default)</span>
                      <span className="text-slate-600">Preset [1]</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => setSplunkQueryInput('search index=security EventCode=4625 OR EventCode=4624 | head 40')}
                      className="w-full text-left p-1.5 rounded bg-slate-950/40 border border-slate-800 hover:border-cyan-500/30 text-slate-400 hover:text-cyan-400 flex items-center justify-between"
                    >
                      <span>Windows Logins (4624/4625)</span>
                      <span className="text-slate-600">Preset [2]</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => setSplunkQueryInput('search sourcetype="t-pot" attack_type=* | head 30')}
                      className="w-full text-left p-1.5 rounded bg-slate-950/40 border border-slate-800 hover:border-cyan-500/30 text-slate-400 hover:text-cyan-400 flex items-center justify-between"
                    >
                      <span>T-Pot Honeypot Attacks</span>
                      <span className="text-slate-600">Preset [3]</span>
                    </button>
                  </div>
                </div>
              </div>
            )}

            {/* TAB B: UEBA ADVANCED TRACKERS */}
            {sidebarTab === "ueba" && (
              <div className="p-4 flex flex-col h-full space-y-4">
                <div className="bg-teal-950/20 border border-teal-500/20 p-3 rounded-lg text-xs flex justify-between items-center gap-3">
                  <div>
                    <h4 className="font-bold text-cyber-emerald font-mono uppercase mb-1">User & Entity Profiles (UEBA)</h4>
                    <p className="text-slate-400 leading-normal">
                      Machine baseline profiles training records. Anomaly ratings increase dynamically as logins differ from core historical IP maps and active zones.
                    </p>
                  </div>
                  <button
                    onClick={handleResetUEBA}
                    title="Reset models baseline and clear incidents"
                    className="p-1 px-2.5 bg-slate-900 border border-cyber-charcoal-800 rounded font-mono text-[10px] text-slate-300 hover:text-white"
                  >
                    RESET
                  </button>
                </div>

                <div className="divide-y divide-cyber-charcoal-800 space-y-3">
                  {baselines.map((ent) => (
                    <div key={ent.id} className="pt-3 block">
                      <div className="flex items-center justify-between mb-1 px-1">
                        <div className="flex items-center gap-1.5 font-semibold text-slate-200 text-xs">
                          {ent.type === "User" ? <Users className="w-3.5 h-3.5 text-teal-400" /> : <Server className="w-4 h-4 text-amber-500" />}
                          <span className="font-mono">{ent.id}</span>
                          <span className="text-[9px] text-slate-500 font-normal">({ent.type})</span>
                        </div>
                        <div className="flex items-center gap-1 font-mono text-[11px]">
                          <span className="text-[10px] text-slate-500">Risk Score:</span>
                          <span className={`font-bold ${getThreatScoreColorClass(ent.threatScore)}`}>
                            {ent.threatScore}
                          </span>
                        </div>
                      </div>

                      <div className="grid grid-cols-2 gap-2 bg-slate-950/45 p-2 rounded border border-cyber-charcoal-800/60 text-[10px] text-slate-400 font-mono mt-1">
                        <div>
                          <span className="text-slate-600 block text-[9px] uppercase">Base Active Timings</span>
                          <span className="text-slate-300 flex items-center gap-1"><Clock className="w-2.5 h-2.5 text-slate-600" />{ent.normalWorkHours}</span>
                        </div>
                        <div>
                          <span className="text-slate-600 block text-[9px] uppercase">Expected Gateway Subnet</span>
                          <span className="text-slate-300 font-medium truncate block" title={ent.usualIps.join(", ")}>{ent.usualIps[0]}</span>
                        </div>
                      </div>

                      {/* DETECTED BEHAVIORAL EXCURSIONS */}
                      {ent.anomaliesDetected.length > 0 ? (
                        <div className="mt-2 pl-2 border-l border-red-500/40 space-y-1.5">
                          {ent.anomaliesDetected.map((an, index) => (
                            <div key={index} className="text-[10px] bg-red-950/10 p-1.5 rounded relative text-slate-300">
                              <p className="font-mono text-slate-300 line-clamp-2 leading-relaxed">
                                {an.description}
                              </p>
                              {an.mitreTechnique && (
                                <p className="text-[9px] text-red-400 leading-none mt-1 font-semibold italic">
                                  Mapped: {an.mitreTechnique}
                                </p>
                              )}
                              <span className="absolute top-1 right-2 text-[10px] text-red-500 font-mono font-extrabold flex items-center">
                                +{an.scoreContribution} Risk
                              </span>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <p className="text-[10px] text-slate-500 italic mt-1.5 ml-1 flex items-center gap-1 font-mono">
                          <CheckCircle className="w-3.5 h-3.5 text-cyber-emerald" /> Normal baseline working profile
                        </p>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* TAB C: CORRELATION ENGINE ACTIVE RULES */}
            {sidebarTab === "rules" && (
              <div className="p-4 flex flex-col h-full space-y-4">
                <div className="bg-slate-900 p-3 rounded text-xs text-slate-400 border border-cyber-charcoal-800">
                  <h4 className="font-bold text-slate-300 font-mono uppercase mb-1">State rule catalog</h4>
                  <p className="leading-normal text-[11px]">
                    The Correlation Engine processes incoming events against these configured predicates. Disable rules to test security pipeline bypass models.
                  </p>
                </div>

                <div className="space-y-4">
                  {rules.map((rl) => (
                    <div key={rl.id} className="p-3 bg-slate-950/45 rounded-lg border border-cyber-charcoal-800 relative hover:border-slate-800 transition">
                      <div className="flex items-center justify-between mb-1.5">
                        <span className="font-mono font-bold text-xs text-blue-400 leading-none">
                          {rl.id}
                        </span>
                        
                        {/* TOGGLE ELEMENT */}
                        <button
                          onClick={() => handleToggleRule(rl.id)}
                          className={`text-[10px] font-mono px-2 py-0.5 rounded cursor-pointer leading-tight border transition-colors ${
                            rl.isActive 
                              ? "bg-emerald-950/40 text-cyber-emerald border-emerald-500/20 hover:bg-emerald-900/30" 
                              : "bg-slate-800 text-slate-500 border-slate-700 hover:bg-slate-700"
                          }`}
                        >
                          {rl.isActive ? "ACTIVE" : "DISABLED"}
                        </button>
                      </div>

                      <h4 className="text-xs font-bold font-sans text-slate-200">
                        {rl.name}
                      </h4>
                      
                      <p className="text-[11px] text-slate-400 leading-relaxed mt-1">
                        {rl.description}
                      </p>

                      <div className="mt-2 flex flex-wrap gap-1">
                        {rl.conditions.map((cond, idx) => (
                          <span key={idx} className="bg-slate-900 border border-slate-800 text-[9px] text-slate-400 px-1.5 rounded font-mono">
                            {cond}
                          </span>
                        ))}
                      </div>

                      <div className="mt-2.5 pt-2 border-t border-slate-800/40 flex justify-between items-center text-[10px] text-slate-500 font-mono">
                        <span>MITRE technique: <span className="text-slate-400">{rl.mitreTechnique} ({rl.mitreId})</span></span>
                        <span>Matches: <span className="font-bold text-amber-500">{rl.matchedCount}</span></span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </section>

      </main>

      {/* DASH BOARD STATIC GLINT FOOTER */}
      <footer className="border-t border-cyber-charcoal-800 bg-cyber-charcoal-950 p-3 text-center text-[10px] text-slate-600 font-mono flex flex-wrap justify-between items-center px-6">
        <div>
          SYSTEM NODES: ONLINE | API STREAM: COMPLIANT WITH GEMINI-3.5-FLASH INTEL
        </div>
        <div className="flex gap-4">
          <span>SEC LOCAL TIME: 2026-06-02 04:05:20 UTC</span>
          <span className="text-slate-500 border-l border-slate-800 pl-4 flex items-center gap-1">
            <Radio className="w-3 h-3 text-cyan-400 animate-pulse" /> CLOUD COMPUTE INGRESS: PORT 3000
          </span>
        </div>
      </footer>
    </div>
  );
}
