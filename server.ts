/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import express from "express";
import path from "path";
import dotenv from "dotenv";
import { createServer as createViteServer } from "vite";
import { GoogleGenAI } from "@google/genai";
import { Severity, IncidentStatus, SecurityEvent, Incident, EntityBaseline, CorrelationRule, DashboardStats } from "./src/types.js";

// Ensure environment variables are loaded
dotenv.config();

const app = express();
const PORT = 3000;

app.use(express.json());

// Initialize Lazy Gemini Client safely
let aiClient: any = null;
function getGeminiClient() {
  if (!aiClient) {
    const apiKey = process.env.GEMINI_API_KEY;
    if (apiKey && apiKey !== "MY_GEMINI_API_KEY" && apiKey !== "") {
      aiClient = new GoogleGenAI({
        apiKey: apiKey,
        httpOptions: {
          headers: {
            'User-Agent': 'aistudio-build',
          }
        }
      });
    } else {
      console.warn("GEMINI_API_KEY is not defined or is a placeholder. AI Investigations will fall back to local rule-based analysis reports.");
    }
  }
  return aiClient;
}

// ==========================================
// SOC STATE DATABASE (In-Memory)
// ==========================================
let allEvents: SecurityEvent[] = [];
let allIncidents: Incident[] = [];
let ueBaselines: EntityBaseline[] = [];
let correlationRules: CorrelationRule[] = [];

// Track system timeline configuration (last 12 hours)
let eventsCountHistory: { time: string; count: number; countCorrelated: number }[] = [];

// Initialize standard Rules
function initCorrelationRules() {
  correlationRules = [
    {
      id: "RULE_BRUTE_FORCE",
      name: "Credential Stuffing / Authentication Brute Force",
      description: "Detects 3 or more failed authentication attempts followed by a login failure or success for the same user name within a short window.",
      severity: Severity.HIGH,
      mitreTactic: "Credential Access",
      mitreTechnique: "Brute Force: Credential Stuffing",
      mitreId: "T1110.004",
      conditions: ["EventType: Authentication", "Status: Failed", "Frequency: >=3 in 5m"],
      windowMinutes: 5,
      triggerThreshold: 3,
      isActive: true,
      matchedCount: 0
    },
    {
      id: "RULE_PRIV_ESC",
      name: "Unauthorized Administrative Group Addition",
      description: "Detects executing suspicious commandlines targeting local or domain administrative groups commandlines (e.g. net group /add).",
      severity: Severity.CRITICAL,
      mitreTactic: "Privilege Escalation",
      mitreTechnique: "Domain Policy Modification",
      mitreId: "T1484",
      conditions: ["EventType: ProcessExecution", "Command contains: 'Domain Admins' OR 'admin' OR '/add'"],
      windowMinutes: 10,
      triggerThreshold: 1,
      isActive: true,
      matchedCount: 0
    },
    {
      id: "RULE_LAT_MOVE",
      name: "Unusual SSH or WinRM Lateral Pivot",
      description: "Detects communication pivots from low-risk corporate endpoint to production databases or infrastructure on sensitive ports (22, 5985/6).",
      severity: Severity.HIGH,
      mitreTactic: "Lateral Movement",
      mitreTechnique: "Remote Services: SSH/WinRM",
      mitreId: "T1021.004",
      conditions: ["EventType: NetworkConnection", "Destination Port: 22 or 5985", "Target Host: prod-*"],
      windowMinutes: 15,
      triggerThreshold: 1,
      isActive: true,
      matchedCount: 0
    },
    {
      id: "RULE_RANSOMWARE",
      name: "Ransomware Behavior - Bulk File Operations",
      description: "Detects rapid sequence of file modification and deletion events on sensitive directories indicating cryptographic payload encryption.",
      severity: Severity.CRITICAL,
      mitreTactic: "Impact",
      mitreTechnique: "Data Encrypted for Impact",
      mitreId: "T1486",
      conditions: ["EventType: FileAccess", "Action: Write/Modify", "Volume: >50 in 1m"],
      windowMinutes: 1,
      triggerThreshold: 10,
      isActive: true,
      matchedCount: 0
    },
    {
      id: "RULE_DATA_EXFIL",
      name: "Anomalous Outbound Data Exfiltration",
      description: "Detects high-volume outbound network bandwidth transmission to unrecognized overseas IP addresses or Tor nodes.",
      severity: Severity.HIGH,
      mitreTactic: "Exfiltration",
      mitreTechnique: "Exfiltration Over Alternative Protocol",
      mitreId: "T1048",
      conditions: ["EventType: NetworkConnection", "Outbound Bytes: >100MB", "Target IP: Unverified"],
      windowMinutes: 10,
      triggerThreshold: 1,
      isActive: true,
      matchedCount: 0
    }
  ];
}

// Initialize User & Host Entity Behavior profiles (UEBA baselines)
function initUEBABaselines() {
  ueBaselines = [
    {
      id: "admin_superuser",
      type: "User",
      displayName: "admin_superuser (Admin Account)",
      threatScore: 12,
      normalWorkHours: "08:00 - 18:00",
      usualIps: ["10.0.1.15", "10.0.1.18"],
      frequentActions: ["Service Deployment", "Log Purge", "DB query execution"],
      anomaliesDetected: [],
      department: "Information Security",
      lastSeen: new Date().toISOString()
    },
    {
      id: "jsmith",
      type: "User",
      displayName: "John Smith (HR Specialist)",
      threatScore: 5,
      normalWorkHours: "09:00 - 17:00",
      usualIps: ["10.100.22.41"],
      frequentActions: ["Portal check-in", "Email client access", "Doc download"],
      anomaliesDetected: [],
      department: "Human Resouces",
      lastSeen: new Date().toISOString()
    },
    {
      id: "db_service_acc",
      type: "User",
      displayName: "db_service_acc (Automated Database Account)",
      threatScore: 8,
      normalWorkHours: "24/7 Continuous",
      usualIps: ["10.0.2.20"],
      frequentActions: ["Read SQL Server", "Batch replication"],
      anomaliesDetected: [],
      department: "Core Devops & Analytics",
      lastSeen: new Date().toISOString()
    },
    {
      id: "corp-laptop-smith",
      type: "Host",
      displayName: "corp-laptop-smith (Corporate Workstation)",
      threatScore: 10,
      normalWorkHours: "09:00 - 18:00",
      usualIps: ["10.100.22.41"],
      frequentActions: ["HTTP Browser access", "Office productivity application execution", "Samba storage mapping"],
      anomaliesDetected: [],
      operatingSystem: "Windows 11 Enterprise",
      lastSeen: new Date().toISOString()
    },
    {
      id: "prod-db-01",
      type: "Host",
      displayName: "prod-db-01 (Database Cluster Core)",
      threatScore: 15,
      normalWorkHours: "24/7 Continuous",
      usualIps: ["10.0.2.20", "10.0.2.21"],
      frequentActions: ["Database query processing", "Database replication synchronization"],
      anomaliesDetected: [],
      operatingSystem: "Ubuntu Server 22.04 LTS",
      lastSeen: new Date().toISOString()
    },
    {
      id: "domain-controller-01",
      type: "Host",
      displayName: "domain-controller-01 (Active Directory Service)",
      threatScore: 8,
      normalWorkHours: "24/7 Continuous",
      usualIps: ["10.0.1.10"],
      frequentActions: ["Kerberos ticketing", "LDAP queries", "Group Policy assignment"],
      anomaliesDetected: [],
      operatingSystem: "Windows Server 2022 Datacenter",
      lastSeen: new Date().toISOString()
    }
  ];
}

// Fill background events & historical logs
function loadBackgroundState() {
  const now = new Date();
  
  // Create last 12 hours timeline data
  eventsCountHistory = [];
  for (let i = 12; i > 0; i--) {
    const d = new Date(now.getTime() - i * 60 * 60 * 1000);
    const timeStr = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    eventsCountHistory.push({
      time: timeStr,
      count: Math.floor(Math.random() * 40) + 10,
      countCorrelated: Math.floor(Math.random() * 5)
    });
  }

  // Create standard legacy security alerts so the dashboard starts with interesting, realistic content!
  const yesterday = new Date(now.getTime() - 24 * 60 * 60 * 1000);
  
  const setupEvents: SecurityEvent[] = [
    {
      id: "e-init-1",
      timestamp: new Date(yesterday.getTime() + 10 * 60 * 1000).toISOString(),
      sourceIp: "192.168.4.15",
      destIp: "10.0.1.10",
      user: "jsmith",
      host: "corp-laptop-smith",
      eventType: "Authentication",
      severity: Severity.LOW,
      message: "Successful authentication for user 'jsmith' from corporate workstation.",
      category: "Auth",
      score: 15
    },
    {
      id: "e-init-2",
      timestamp: new Date(yesterday.getTime() + 20 * 60 * 1000).toISOString(),
      sourceIp: "10.100.22.41",
      destIp: "10.0.2.20",
      user: "db_service_acc",
      host: "prod-db-01",
      eventType: "NetworkConnection",
      severity: Severity.MEDIUM,
      message: "Persistent keep-alive TCP connection established to Database Server.",
      category: "Endpoint",
      score: 30
    }
  ];

  allEvents = [...setupEvents];
}

// Initialize Everything
initCorrelationRules();
initUEBABaselines();
loadBackgroundState();

// ==========================================
// SOC CORE ENGINES
// ==========================================

/**
 * THREAT SCORING ENGINE
 * Evaluates the compound Threat score for an Incident or Entity
 */
function calculateIncidentThreatScore(events: SecurityEvent[]): number {
  if (events.length === 0) return 0;
  
  let baseScore = 0;
  let maxWeight = 0;
  
  events.forEach(e => {
    let weight = e.score;
    if (e.severity === Severity.CRITICAL) weight += 15;
    if (e.severity === Severity.HIGH) weight += 10;
    if (e.severity === Severity.MEDIUM) weight += 5;
    
    baseScore += weight;
    if (weight > maxWeight) maxWeight = weight;
  });

  // Logarithmic-styled risk amplification (more events of suspicious nature = higher overall threat score, capped at 100)
  const averageFactor = baseScore / events.length;
  const countAmplifier = Math.min(25, (events.length - 1) * 6);
  let finalCalculatedScore = Math.round(Math.max(maxWeight, averageFactor) + countAmplifier);
  
  return Math.min(100, Math.max(0, finalCalculatedScore));
}

/**
 * RE-EVALUATE AND MAP SYSTEM-WIDE STATS
 */
function getSystemDashboardStats(): DashboardStats {
  const activeIncidents = allIncidents.filter(inc => inc.status !== IncidentStatus.CLOSED);
  
  // System wide threat index represents the maximum incident score or high average of active problems
  let overallThreatScore = 15; // default calm baseline
  if (activeIncidents.length > 0) {
    const maxScore = Math.max(...activeIncidents.map(i => i.score));
    const averageScore = activeIncidents.reduce((s, i) => s + i.score, 0) / activeIncidents.length;
    overallThreatScore = Math.min(100, Math.round((maxScore * 0.7) + (averageScore * 0.3)));
  }

  // Count alert distributions
  const distribution: Record<Severity, number> = {
    [Severity.LOW]: 0,
    [Severity.MEDIUM]: 0,
    [Severity.HIGH]: 0,
    [Severity.CRITICAL]: 0
  };

  allEvents.forEach(e => {
    distribution[e.severity]++;
  });

  // Calculate critical parameters
  const activeCount = allIncidents.filter(i => i.status === IncidentStatus.ACTIVE).length;
  const criticalCount = activeIncidents.filter(i => i.severity === Severity.CRITICAL).length;
  const uebaAnomalies = ueBaselines.reduce((acc, current) => acc + current.anomaliesDetected.length, 0);

  return {
    overallThreatScore,
    activeIncidentsCount: activeCount,
    processedEventsCount: allEvents.length,
    criticalAlertsCount: criticalCount,
    uebaAnomalyCount: uebaAnomalies,
    alertDistribution: distribution,
    eventsTimeline: eventsCountHistory
  };
}

/**
 * CORRELATION ENGINE Core implementation
 * Takes a security log, runs rules, checks timeframes, builds security Incidents.
 */
function dispatchEventToCorrelationEngine(newEvent: SecurityEvent) {
  allEvents.unshift(newEvent); // Add to beginning of live stream queue
  if (allEvents.length > 300) {
    allEvents.pop(); // Keep manageable buffer in memory
  }

  // Update System timeline stats
  if (eventsCountHistory.length > 0) {
    eventsCountHistory[eventsCountHistory.length - 1].count++;
  }

  let matchedRule: CorrelationRule | undefined;

  // Let's sweep active correlation rules
  for (const rule of correlationRules) {
    if (!rule.isActive) continue;

    let isMatch = false;

    // Rule 1: Brute force checking
    if (rule.id === "RULE_BRUTE_FORCE" && newEvent.eventType === "Authentication") {
      const isFailedLogin = newEvent.message.toLowerCase().includes("failed") || newEvent.severity === Severity.HIGH;
      if (isFailedLogin) {
        // Look back at recent events for the same user name in window frame
        const timeframeLimit = new Date(new Date(newEvent.timestamp).getTime() - rule.windowMinutes * 60 * 1000);
        const relatedFailures = allEvents.filter(e => 
          e.eventType === "Authentication" &&
          e.user === newEvent.user &&
          new Date(e.timestamp) >= timeframeLimit &&
          e.message.toLowerCase().includes("failed")
        );

        if (relatedFailures.length >= rule.triggerThreshold) {
          isMatch = true;
        }
      }
    }

    // Rule 2: Privilege Escalation
    if (rule.id === "RULE_PRIV_ESC" && newEvent.eventType === "ProcessExecution") {
      const isCommandSuspicious = newEvent.message.includes("Domain Admins") || 
                                 newEvent.message.includes("net group") || 
                                 newEvent.message.toLowerCase().includes("mimikatz") || 
                                 newEvent.message.toLowerCase().includes("privilege::debug");
      if (isCommandSuspicious) {
        isMatch = true;
      }
    }

    // Rule 3: Lateral movement ssh/winrm
    if (rule.id === "RULE_LAT_MOVE" && newEvent.eventType === "NetworkConnection") {
      const isPivotPort = newEvent.message.includes("port 22") || 
                           newEvent.message.includes("port 5985") || 
                           newEvent.message.toLowerCase().includes("winrm") ||
                           newEvent.message.toLowerCase().includes("lateral movement");
      if (isPivotPort && newEvent.host.startsWith("prod-")) {
        isMatch = true;
      }
    }

    // Rule 4: Ransomware encrypted
    if (rule.id === "RULE_RANSOMWARE" && newEvent.eventType === "FileAccess") {
      // Rapid modifications
      const timeframeLimit = new Date(new Date(newEvent.timestamp).getTime() - rule.windowMinutes * 60 * 1000);
      const hostWrites = allEvents.filter(e =>
        e.eventType === "FileAccess" &&
        e.host === newEvent.host &&
        new Date(e.timestamp) >= timeframeLimit &&
        (e.message.toLowerCase().includes("encrypt") || e.message.toLowerCase().includes("delete") || e.message.toLowerCase().includes("wrote"))
      );

      if (hostWrites.length >= rule.triggerThreshold) {
        isMatch = true;
      }
    }

    // Rule 5: Exfiltration high-volume
    if (rule.id === "RULE_DATA_EXFIL" && newEvent.eventType === "NetworkConnection") {
      const isLargeTransit = newEvent.message.includes("GB") || 
                             (newEvent.message.includes("MB") && parseFloat(newEvent.message) > 200) ||
                             newEvent.message.toLowerCase().includes("exfiltration") ||
                             newEvent.message.toLowerCase().includes("outbound data transferred");
      if (isLargeTransit) {
        isMatch = true;
      }
    }

    if (isMatch) {
      matchedRule = rule;
      rule.matchedCount++;
      break;
    }
  }

  // If a correlation rule triggered, we either append this log to an existing related incident, or create a new incident!
  if (matchedRule) {
    newEvent.matchedRuleId = matchedRule.id;
    newEvent.mitreTactic = matchedRule.mitreTactic;
    newEvent.mitreTechnique = matchedRule.mitreTechnique;
    newEvent.mitreId = matchedRule.mitreId;

    if (eventsCountHistory.length > 0) {
      eventsCountHistory[eventsCountHistory.length - 1].countCorrelated++;
    }

    // Pivot logic: find active incidents matching the same main anchor (User or Host) within last 30 minutes
    const windowStart = new Date(new Date(newEvent.timestamp).getTime() - 30 * 60 * 1000);
    const existingInc = allIncidents.find(inc => 
      inc.status !== IncidentStatus.CLOSED &&
      new Date(inc.timestamp) >= windowStart &&
      (inc.affectedEntities.users.includes(newEvent.user) || inc.affectedEntities.hosts.includes(newEvent.host))
    );

    if (existingInc) {
      // Append event to existing incident
      existingInc.events.unshift(newEvent);
      
      // Update threat details
      existingInc.score = calculateIncidentThreatScore(existingInc.events);
      
      // Append entities securely
      if (newEvent.user && !existingInc.affectedEntities.users.includes(newEvent.user)) {
        existingInc.affectedEntities.users.push(newEvent.user);
      }
      if (newEvent.host && !existingInc.affectedEntities.hosts.includes(newEvent.host)) {
        existingInc.affectedEntities.hosts.push(newEvent.host);
      }

      // Append MITRE tactics if unique
      const hasMitre = existingInc.mitreMapping.some(m => m.id === matchedRule?.mitreId);
      if (!hasMitre && matchedRule) {
        existingInc.mitreMapping.push({
          tactic: matchedRule.mitreTactic,
          technique: matchedRule.mitreTechnique,
          id: matchedRule.mitreId
        });
      }

      // Elevate overall severity if a critical rule just injected
      if (matchedRule.severity === Severity.CRITICAL) {
        existingInc.severity = Severity.CRITICAL;
      } else if (matchedRule.severity === Severity.HIGH && existingInc.severity !== Severity.CRITICAL) {
        existingInc.severity = Severity.HIGH;
      }

      // Add to incident suggested playbooks
      if (matchedRule.id === "RULE_PRIV_ESC" && !existingInc.suggestedPlaybook?.includes("Isolate Host Administrative Privileges")) {
        existingInc.suggestedPlaybook?.push("Revoke temporary domain group modification tokens");
        existingInc.suggestedPlaybook?.push("Audit active directory replication metadata");
      }
      if (matchedRule.id === "RULE_RANSOMWARE" && !existingInc.suggestedPlaybook?.includes("Isolate Host and Terminate Processes")) {
        existingInc.suggestedPlaybook?.unshift("Isolate host prod-db-01 off logical subnets");
        existingInc.suggestedPlaybook?.push("Rollback snapshot volumes on cluster root");
      }

    } else {
      // Create brand new Correlated Incident!
      const incidentId = `INC-${1000 + allIncidents.length + 1}`;
      
      // Select appropriate Stage
      let stage = "Execution";
      if (matchedRule.id === "RULE_BRUTE_FORCE") stage = "Initial Access";
      if (matchedRule.id === "RULE_PRIV_ESC") stage = "Privilege Escalation";
      if (matchedRule.id === "RULE_LAT_MOVE") stage = "Lateral Movement";
      if (matchedRule.id === "RULE_RANSOMWARE") stage = "Impact";
      if (matchedRule.id === "RULE_DATA_EXFIL") stage = "Exfiltration";

      const newIncident: Incident = {
        id: incidentId,
        name: `AI Correlated: Suspected ${matchedRule.mitreTactic} targeting ${newEvent.host}`,
        description: `Correlation Engine triggered rule '${matchedRule.name}' with event details: ${newEvent.message}. Active tracking initiated for endpoint entities.`,
        status: IncidentStatus.ACTIVE,
        severity: matchedRule.severity,
        score: calculateIncidentThreatScore([newEvent]),
        timestamp: newEvent.timestamp,
        events: [newEvent],
        mitreMapping: [
          {
            tactic: matchedRule.mitreTactic,
            technique: matchedRule.mitreTechnique,
            id: matchedRule.mitreId
          }
        ],
        affectedEntities: {
          users: newEvent.user ? [newEvent.user] : [],
          hosts: newEvent.host ? [newEvent.host] : []
        },
        attackStage: stage,
        automaticInvestigationStatus: "Pending",
        suggestedPlaybook: [
          "Establish secondary network telemetry tracking",
          "Acquire volatile endpoint memory snapshots",
          "Verify host endpoint threat configuration agents status"
        ]
      };

      allIncidents.unshift(newIncident);
    }

    // UEBA ENGAGEMENT: Let's registry dynamic anomalies on the baseline profiles
    const relatedEntity = ueBaselines.find(b => b.id === newEvent.user || b.id === newEvent.host);
    if (relatedEntity) {
      relatedEntity.threatScore = Math.min(100, relatedEntity.threatScore + (newEvent.severity === Severity.CRITICAL ? 35 : newEvent.severity === Severity.HIGH ? 20 : 10));
      relatedEntity.lastSeen = newEvent.timestamp;
      
      const containsAnomaly = relatedEntity.anomaliesDetected.some(a => a.description.includes(matchedRule?.mitreTechnique || ""));
      if (!containsAnomaly) {
        relatedEntity.anomaliesDetected.unshift({
          timestamp: newEvent.timestamp,
          description: `Behavior Deviation: Triggered correlated rule detection - ${matchedRule.name}`,
          scoreContribution: newEvent.severity === Severity.CRITICAL ? 35 : 20,
          mitreTechnique: matchedRule.mitreTechnique
        });
      }
    }
  } else {
    // Normal UEBA profiling checks (e.g. access time alerts or geographic anomalies)
    // Let's see if user is acting outside normal office working hours to flag mild behavior anomalies!
    const logHour = new Date(newEvent.timestamp).getUTCHours();
    const isLateNight = logHour < 7 || logHour > 19;
    
    if (newEvent.user) {
      const userProfile = ueBaselines.find(b => b.id === newEvent.user && b.type === "User");
      if (userProfile) {
        userProfile.lastSeen = newEvent.timestamp;
        
        if (isLateNight && !userProfile.normalWorkHours.includes("24/7 continuous") && userProfile.anomaliesDetected.length === 0) {
          userProfile.threatScore = Math.min(100, userProfile.threatScore + 12);
          userProfile.anomaliesDetected.push({
            timestamp: newEvent.timestamp,
            description: `Timezone/Hour Violation: Active session initiated at hour ${logHour}:00 UTC (expected core office window)`,
            scoreContribution: 12
          });
        }
      }
    }
  }
}

// SIMULATE SECURITY SCENARIOS
function triggerScenarioSimulation(scenarioType: string) {
  const now = new Date();
  
  if (scenarioType === "ransomware") {
    console.log("Simulating: APT Cyber Threat Ransomware Sequence...");
    
    // Inject steps 1 by 1 with slight delay triggers to showcase the dashboard in action
    const event1: SecurityEvent = {
      id: `e-rw-${Date.now()}-1`,
      timestamp: new Date(now.getTime() - 4 * 60 * 1000).toISOString(),
      sourceIp: "185.190.140.23",
      destIp: "10.100.22.41",
      user: "jsmith",
      host: "corp-laptop-smith",
      eventType: "Authentication",
      severity: Severity.MEDIUM,
      message: "Unusual persistent brute attempt. Account jsmith session initiated from unverified residential subnet.",
      category: "Auth",
      score: 45
    };

    const event2: SecurityEvent = {
      id: `e-rw-${Date.now()}-2`,
      timestamp: new Date(now.getTime() - 3 * 60 * 1000).toISOString(),
      sourceIp: "10.100.22.41",
      destIp: "10.0.1.10",
      user: "jsmith",
      host: "corp-laptop-smith",
      eventType: "ProcessExecution",
      message: "Process Spawned: curl.exe fetched remote encrypted payload 'updater.bin' to local temp directory.",
      category: "Endpoint",
      severity: Severity.HIGH,
      score: 65
    };

    const event3: SecurityEvent = {
      id: `e-rw-${Date.now()}-3`,
      timestamp: new Date(now.getTime() - 2 * 60 * 1000).toISOString(),
      sourceIp: "10.100.22.41",
      destIp: "10.0.1.10",
      user: "admin_superuser",
      host: "domain-controller-01",
      eventType: "ProcessExecution",
      message: "Privilege escalation detected: net group 'Domain Admins' /add jsmith was run by hijacked agent.",
      category: "Host",
      severity: Severity.CRITICAL,
      score: 90
    };

    const event4: SecurityEvent = {
      id: `e-rw-${Date.now()}-4`,
      timestamp: new Date(now.getTime() - 1 * 60 * 1000).toISOString(),
      sourceIp: "10.100.22.41",
      destIp: "10.0.2.20",
      user: "admin_superuser",
      host: "prod-db-01",
      eventType: "NetworkConnection",
      message: "WinRM lateral command pivot connected port 5985 from compromised workstation.",
      category: "Firewall",
      severity: Severity.HIGH,
      score: 80
    };

    // Fast-firing encryption logs (Ransomware rule trigger)
    const event5: SecurityEvent = {
      id: `e-rw-${Date.now()}-5`,
      timestamp: now.toISOString(),
      sourceIp: "10.0.1.10",
      destIp: "10.0.2.20",
      user: "admin_superuser",
      host: "prod-db-01",
      eventType: "FileAccess",
      message: "Critical Warning: Over 122 host files renamed to .decrypted_locked extension in C:\\Data",
      category: "Host",
      severity: Severity.CRITICAL,
      score: 95
    };

    // Dispatches
    dispatchEventToCorrelationEngine(event1);
    dispatchEventToCorrelationEngine(event2);
    dispatchEventToCorrelationEngine(event3);
    dispatchEventToCorrelationEngine(event4);
    dispatchEventToCorrelationEngine(event5);

  } else if (scenarioType === "exfil") {
    console.log("Simulating: Insider Threat / Data Exfiltration sequence...");
    
    const event1: SecurityEvent = {
      id: `e-ex-${Date.now()}-1`,
      timestamp: new Date(now.getTime() - 30 * 60 * 1000).toISOString(),
      sourceIp: "10.0.2.20",
      destIp: "84.21.32.90",
      user: "db_service_acc",
      host: "prod-db-01",
      eventType: "Authentication",
      severity: Severity.MEDIUM,
      message: "Database service account logged in during non-typical system cron windows (03:15 UTC timezone drift).",
      category: "Auth",
      score: 40
    };

    const event2: SecurityEvent = {
      id: `e-ex-${Date.now()}-2`,
      timestamp: new Date(now.getTime() - 15 * 60 * 1000).toISOString(),
      sourceIp: "10.0.2.20",
      destIp: "84.21.32.90",
      user: "db_service_acc",
      host: "prod-db-01",
      eventType: "NetworkConnection",
      message: "High volume SQL query execution dumped secure PII database tables into systemic storage directory.",
      category: "Database",
      severity: Severity.HIGH,
      score: 75
    };

    const event3: SecurityEvent = {
      id: `e-ex-${Date.now()}-3`,
      timestamp: now.toISOString(),
      sourceIp: "10.0.2.20",
      destIp: "185.39.22.100", // Tor VPS IP
      user: "db_service_acc",
      host: "prod-db-01",
      eventType: "NetworkConnection",
      message: "Exfiltration Alert: 1.45 GB of secure database archives compressed and uploaded outbound to untrusted VPS.",
      category: "NetworkConnection",
      severity: Severity.CRITICAL,
      score: 92
    };

    dispatchEventToCorrelationEngine(event1);
    dispatchEventToCorrelationEngine(event2);
    dispatchEventToCorrelationEngine(event3);

  } else if (scenarioType === "stuffing") {
    console.log("Simulating: Credential stuffing campaign...");

    for (let i = 1; i <= 4; i++) {
      const failedEvent: SecurityEvent = {
        id: `e-cs-${Date.now()}-${i}`,
        timestamp: new Date(now.getTime() - (5 - i) * 60 * 1000).toISOString(),
        sourceIp: "198.51.100.12",
        destIp: "10.0.1.10",
        user: "jsmith",
        host: "domain-controller-01",
        eventType: "Authentication",
        severity: Severity.LOW,
        message: `Kerberos login failure for user 'jsmith' - STATUS_WRONG_PASSWORD (Attempt ${i}/3)`,
        category: "Auth",
        score: 25
      };
      dispatchEventToCorrelationEngine(failedEvent);
    }

    const successEvent: SecurityEvent = {
      id: `e-cs-${Date.now()}-success`,
      timestamp: now.toISOString(),
      sourceIp: "198.51.100.12",
      destIp: "10.0.1.10",
      user: "jsmith",
      host: "domain-controller-01",
      eventType: "Authentication",
      severity: Severity.HIGH,
      message: "Alert: Successful Kerberos authentication for 'jsmith' immediately following 4 failed password attempts from unverified outside IP.",
      category: "Auth",
      score: 75
    };
    dispatchEventToCorrelationEngine(successEvent);
  }
}

// Periodically generate quiet background firewall events to make the dashboard feel active and real!
let simulatorTimer: NodeJS.Timeout | null = null;
function startQuietTelemetryProducer() {
  if (simulatorTimer) clearInterval(simulatorTimer);
  
  simulatorTimer = setInterval(() => {
    const categories = ["Firewall", "Host", "Endpoint", "Auth"];
    const users = ["jsmith", "admin_superuser", "db_service_acc", "unknown", "system"];
    const hosts = ["corp-laptop-smith", "prod-db-01", "domain-controller-01", "dev-worker-03"];
    
    const cat = categories[Math.floor(Math.random() * categories.length)];
    const usr = users[Math.floor(Math.random() * users.length)];
    const hst = hosts[Math.floor(Math.random() * hosts.length)];
    
    let type = "NetworkConnection";
    if (cat === "Auth") type = "Authentication";
    if (cat === "Host") type = "ProcessExecution";
    if (cat === "Endpoint") type = "FileAccess";
    
    const randomEvent: SecurityEvent = {
      id: `e-rnd-${Math.floor(Math.random() * 900000) + 100000}`,
      timestamp: new Date().toISOString(),
      sourceIp: `10.100.${Math.floor(Math.random() * 50) + 10}.${Math.floor(Math.random() * 200) + 5}`,
      destIp: `10.0.${Math.floor(Math.random() * 5) + 1}.${Math.floor(Math.random() * 200) + 5}`,
      user: usr,
      host: hst,
      eventType: type,
      severity: Severity.LOW,
      message: `System baseline traffic processing: Routine security check verified integrity on cluster segment.`,
      category: cat,
      score: Math.floor(Math.random() * 15) + 2
    };

    dispatchEventToCorrelationEngine(randomEvent);
  }, 10000); // every 10 seconds add a telemetry trace
}
startQuietTelemetryProducer();


// ==========================================
// SPLUNK ENTERPRISE INTEGRATION ENGINE
// ==========================================
// Bypass self-signed SSL certificate issues globally in node for local Splunk Enterprise servers (192.168.1.1, etc.)
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

let splunkConfig = {
  host: process.env.SPLUNK_HOST || "https://192.168.1.1:8089",
  username: process.env.SPLUNK_USERNAME || "admin",
  password: process.env.SPLUNK_PASSWORD || "123456789",
  query: process.env.SPLUNK_QUERY || 'search index=* OR source="WinEventLog:*" OR sourcetype="t-pot" | head 30',
  isConnected: false,
  lastSyncTime: null as string | null,
  syncStatus: "Ready to connect. Input Splunk server config below." as string,
  autoSync: false
};

// Background auto sync timer
let splunkSyncTimer: NodeJS.Timeout | null = null;

// Convert raw Splunk records to SecurityEvent
function mapSplunkEventToSOC(splunkRecord: any, index: number): SecurityEvent {
  const timestamp = splunkRecord._time 
    ? new Date(splunkRecord._time).toISOString() 
    : new Date().toISOString();

  // Try parsing fields or raw message
  const rawMessage = splunkRecord._raw || JSON.stringify(splunkRecord);
  const host = splunkRecord.host || splunkRecord.ComputerName || splunkRecord.dest || "192.168.1.1";
  const user = splunkRecord.user || splunkRecord.Account_Name || splunkRecord.username || "unknown_user";
  const sourceIp = splunkRecord.src_ip || splunkRecord.IpAddress || splunkRecord.src || "192.168.1.100";
  const destIp = splunkRecord.dest_ip || splunkRecord.dest || "192.168.1.1";
  
  // Try to determine event type
  let eventType = "NetworkConnection";
  let category = splunkRecord.sourcetype || splunkRecord.source || "SplunkLog";
  let severity = Severity.LOW;
  let score = 10;

  const lowerRaw = rawMessage.toLowerCase();
  if (lowerRaw.includes("failed") || lowerRaw.includes("failure") || splunkRecord.EventCode === "4625" || lowerRaw.includes("wrong password")) {
    eventType = "Authentication";
    category = "Auth";
    severity = Severity.HIGH;
    score = 55;
  } else if (lowerRaw.includes("login") || lowerRaw.includes("logon") || lowerRaw.includes("success") || splunkRecord.EventCode === "4624") {
    eventType = "Authentication";
    category = "Auth";
    severity = Severity.LOW;
    score = 15;
  } else if (lowerRaw.includes("process") || lowerRaw.includes("executable") || lowerRaw.includes("command") || lowerRaw.includes("run")) {
    eventType = "ProcessExecution";
    category = "Host";
    score = 25;
  } else if (lowerRaw.includes("write") || lowerRaw.includes("encrypt") || lowerRaw.includes("delete") || lowerRaw.includes("filesystem")) {
    eventType = "FileAccess";
    category = "Endpoint";
    score = 30;
  }

  // Elevate severity based on keyword hits (T-Pot honeypot attacks, ransomware, mimicatz, etc.)
  if (lowerRaw.includes("mimikatz") || lowerRaw.includes("brute") || lowerRaw.includes("cobalt strike") || lowerRaw.includes("honeypot") || lowerRaw.includes("t-pot") || lowerRaw.includes("attack")) {
    severity = Severity.CRITICAL;
    score = 90;
  } else if (lowerRaw.includes("unauthorized") || lowerRaw.includes("privilege") || lowerRaw.includes("admin") || lowerRaw.includes("added")) {
    severity = Severity.HIGH;
    score = 70;
  }

  return {
    id: `splunk-${Date.now()}-${index}`,
    timestamp,
    sourceIp,
    destIp,
    user,
    host,
    eventType,
    severity,
    message: `[Splunk Sync] ${rawMessage.slice(0, 300)}${rawMessage.length > 300 ? "..." : ""}`,
    category,
    score
  };
}

// Perform active Splunk REST queries
async function performSplunkSync() {
  const { host: splunkHost, username, password, query } = splunkConfig;
  
  splunkConfig.syncStatus = "Initiating authentication...";
  try {
    // 1. Authenticate & Obtain session key
    const loginUrl = `${splunkHost}/services/auth/login?output_mode=json`;
    const authRes = await fetch(loginUrl, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ username, password })
    });

    if (!authRes.ok) {
      const errText = await authRes.text();
      throw new Error(`Auth failed (${authRes.status}): ${errText}`);
    }

    const authData = await authRes.json();
    const sessionKey = authData.sessionKey;
    if (!sessionKey) {
      throw new Error("Invalid response from Splunk. No sessionKey received.");
    }

    splunkConfig.syncStatus = "Running search query...";
    
    // 2. Submit Search Job
    const searchUrl = `${splunkHost}/services/search/jobs?output_mode=json`;
    const searchBody = new URLSearchParams();
    searchBody.append("search", query.startsWith("search") ? query : `search ${query}`);
    searchBody.append("exec_mode", "blocking"); // Wait for completing result

    const jobRes = await fetch(searchUrl, {
      method: "POST",
      headers: {
        "Authorization": `Splunk ${sessionKey}`,
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: searchBody
    });

    if (!jobRes.ok) {
      const errText = await jobRes.text();
      throw new Error(`Failed to submit search job (${jobRes.status}): ${errText}`);
    }

    const jobData = await jobRes.json();
    const sid = jobData.sid;
    if (!sid) {
      throw new Error("No SID returned for the search job.");
    }

    splunkConfig.syncStatus = "Retrieving results data...";

    // 3. Fetch search job results
    const resultsUrl = `${splunkHost}/services/search/jobs/${sid}/results?output_mode=json&count=50`;
    const resultsRes = await fetch(resultsUrl, {
      method: "GET",
      headers: {
        "Authorization": `Splunk ${sessionKey}`
      }
    });

    if (!resultsRes.ok) {
      const errText = await resultsRes.text();
      throw new Error(`Failed to fetch job results (${resultsRes.status}): ${errText}`);
    }

    const resultsData = await resultsRes.json();
    const records = resultsData.results || [];
    
    splunkConfig.syncStatus = `Ingested ${records.length} records successfully.`;
    splunkConfig.isConnected = true;
    splunkConfig.lastSyncTime = new Date().toISOString();

    // Map each Splunk record, ingestion and trigger core Correlation Engine
    records.slice().reverse().forEach((record: any, idx: number) => {
      const newSOCEvent = mapSplunkEventToSOC(record, idx);
      dispatchEventToCorrelationEngine(newSOCEvent);
    });

    return records.length;
  } catch (err: any) {
    console.error("Splunk Enterprise Integration error:", err);
    splunkConfig.isConnected = false;
    splunkConfig.syncStatus = `Failed: ${err?.message || "Internal connection error"}`;
    throw err;
  }
}


// ==========================================
// API ROUTING ENDPOINTS
// ==========================================

// GET current Splunk configuration status
app.get("/api/splunk/config", (req, res) => {
  res.json(splunkConfig);
});

// POST to update Splunk configuration
app.post("/api/splunk/config", (req, res) => {
  const { host, username, password, query, autoSync } = req.body;
  if (host) splunkConfig.host = host;
  if (username) splunkConfig.username = username;
  if (password) splunkConfig.password = password;
  if (query) splunkConfig.query = query;
  if (autoSync !== undefined) {
    splunkConfig.autoSync = autoSync;
    
    // Manage background poller
    if (autoSync) {
      if (splunkSyncTimer) clearInterval(splunkSyncTimer);
      splunkSyncTimer = setInterval(async () => {
        try {
          console.log("[Splunk Poller] Executing scheduled syslog sync query...");
          await performSplunkSync();
        } catch (e) {
          console.error("[Splunk Poller] Scheduled sync failed", e);
        }
      }, 30000); // Poll every 30 seconds
    } else {
      if (splunkSyncTimer) {
        clearInterval(splunkSyncTimer);
        splunkSyncTimer = null;
      }
    }
  }

  res.json({ success: true, config: splunkConfig });
});

// POST to trigger an manual active sync session
app.post("/api/splunk/sync", async (req, res) => {
  try {
    const recordsCount = await performSplunkSync();
    res.json({ success: true, count: recordsCount, config: splunkConfig });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err?.message || "Internal Splunk Integration Connection Error", config: splunkConfig });
  }
});

// GET dashboard health and metric analytics
app.get("/api/status", (req, res) => {
  res.json(getSystemDashboardStats());
});

// GET list of recent raw events / syslog
app.get("/api/logs", (req, res) => {
  res.json(allEvents);
});

// GET active correlated incidents
app.get("/api/incidents", (req, res) => {
  res.json(allIncidents);
});

// GET specific incident detail report
app.get("/api/incidents/:id", (req, res) => {
  const inc = allIncidents.find(i => i.id === req.params.id);
  if (!inc) {
    return res.status(404).json({ error: "Incident not found" });
  }
  res.json(inc);
});

// POST to update incident status (Acknowledge, Mitigate, Close)
app.post("/api/incidents/:id/status", (req, res) => {
  const { status } = req.body;
  const inc = allIncidents.find(i => i.id === req.params.id);
  if (!inc) {
    return res.status(404).json({ error: "Incident not found" });
  }
  
  if (Object.values(IncidentStatus).includes(status)) {
    inc.status = status as IncidentStatus;
    res.json({ success: true, updatedIncident: inc });
  } else {
    res.status(400).json({ error: "Invalid status state" });
  }
});

// GET all user/host entity profiles with anomaly rankings
app.get("/api/ueba", (req, res) => {
  res.json(ueBaselines);
});

// POST to refresh/reset UEBA system baselines
app.post("/api/ueba/reset", (req, res) => {
  initUEBABaselines();
  allIncidents = allIncidents.filter(inc => inc.severity === Severity.LOW); // quiet down active incidents
  allEvents = allEvents.slice(0, 10);
  res.json({ success: true, message: "UEBA baseline profile systems reset and retrained.", baselines: ueBaselines });
});

// GET correlation rules configuration
app.get("/api/rules", (req, res) => {
  res.json(correlationRules);
});

// POST toggle or configure rule status
app.post("/api/rules/:id/toggle", (req, res) => {
  const r = correlationRules.find(rule => rule.id === req.params.id);
  if (!r) {
    return res.status(404).json({ error: "Correlation definition rule not found" });
  }
  r.isActive = !r.isActive;
  res.json({ success: true, updatedRule: r });
});

// POST to inject custom/scenarios alerts
app.post("/api/simulate", (req, res) => {
  const { scenario } = req.body;
  if (!scenario) {
    return res.status(400).json({ error: "No scenario key defined" });
  }
  triggerScenarioSimulation(scenario);
  res.json({ success: true, message: `Scenario '${scenario}' processed. Check dashboard queues immediately.` });
});


/**
 * POST /api/incidents/:id/investigate
 * AUTOMATIC INVESTIGATION USING GEMINI API
 * Acts as the Tier-3 Smart Cyber Hunt Analyst. Runs standard or advanced reports.
 */
app.post("/api/incidents/:id/investigate", async (req, res) => {
  const incident = allIncidents.find(i => i.id === req.params.id);
  if (!incident) {
    return res.status(404).json({ error: "Incident not found in active security queue" });
  }

  incident.automaticInvestigationStatus = "In Progress";
  
  try {
    const ai = getGeminiClient();
    
    if (!ai) {
      // Fallback model if no API key is specified (Rule Based Simulated Report generator)
      setTimeout(() => {
        incident.automaticInvestigationStatus = "Completed";
        incident.aiInvestigationReport = `### 🕵️‍♂️ (Simulated Analyst) AI Automated SOC Investigation: ${incident.id}

**Incident Classification:** ${incident.name}
**Assigned Threat Severity:** ${incident.severity} (Score: ${incident.score}/100)
**Current Timeline Epoch:** ${new Date(incident.timestamp).toLocaleString()}

---

#### Executive Summary
This incident represents clusters of suspicious activity originating on correlated endpoints. The network triggers correlate with established patterns mapped in corporate threat matrices. Security parameters indicate immediate investigation is required.

#### Analyzed IOC Evidence & logs
* Affected Hosts: ${incident.affectedEntities.hosts.join(", ")}
* Attacked Users: ${incident.affectedEntities.users.join(", ")}
* Total Evidence Indicators Correlated: ${incident.events.length} logs
${incident.events.map(e => `  - **[${e.category}]** (Severity: ${e.severity}) (IP: ${e.sourceIp}) — *${e.message}*`).join("\n")}

---

#### MITRE ATT&CK Matrix Mapping
* **Current Stage:** ${incident.attackStage}
${incident.mitreMapping.map(m => `* **Tactic:** ${m.tactic} | **Technique:** \`${m.technique}\` (ID: ${m.id})`).join("\n")}

---

#### Recommended SOC Playbook Response Commands
1. **Host Isolation:** Restrict external outbound traffic on \`${incident.affectedEntities.hosts.join(", ")}\` immediately.
2. **Account Audit:** Enforce enterprise multi-factor authentication reset on user credentials: \`${incident.affectedEntities.users.join(", ")}\`.
3. **Endpoint Cleanse:** Execute deep persistent file scans looking for unknown executable paths in Temp folders.
`;
        res.json({ success: true, updatedIncident: incident });
      }, 1500);
      return;
    }

    // Construct prompt containing incident context, logs, and baselines
    const entitiesDetailed = incident.affectedEntities.hosts.map(h => {
      const b = ueBaselines.find(e => e.id === h);
      return b ? `Host "${h}" details: OS "${b.operatingSystem}", usual IPs [${b.usualIps.join(", ")}], threat level: ${b.threatScore}/100` : `Host "${h}"`;
    }).join("\n") + "\n" + incident.affectedEntities.users.map(u => {
      const b = ueBaselines.find(e => e.id === u);
      return b ? `User "${u}" details: Department "${b.department}", timezone hours "${b.normalWorkHours}", threat level: ${b.threatScore}/100` : `User "${u}"`;
    }).join("\n");

    const promptText = `Provide a comprehensive Tier-3 Cybersecurity Incident Response Investigation Report in Markdown format.
You are the advanced AI Security Specialist operating within Google Cloud AI SOC Platform.

INCIDENT TO INVESTIGATE:
Incident ID: ${incident.id}
Name/Threat: ${incident.name}
Severity: ${incident.severity} (Calculated Threat Score: ${incident.score}/100)
Detected Attack Stage: ${incident.attackStage}
MITRE ATT&CK Mapped: ${JSON.stringify(incident.mitreMapping)}

AFFECTED ENTITIES CONTEXT & BEHAVIOR (UEBA BASELINES):
${entitiesDetailed}

CORRELATED EVIDENCE LOGS (Total: ${incident.events.length}):
${JSON.stringify(incident.events.map(e => ({
  time: e.timestamp,
  category: e.category,
  type: e.eventType,
  source: e.sourceIp,
  dest: e.destIp,
  user: e.user,
  message: e.message,
  score: e.score
})), null, 2)}

INSTRUCTIONS:
Compose a professional, structured, and realistic security report for active SOC Analysts. Use high-contrast headers, lists, and bold text. The markdown report MUST include:
1. **Title Banner**: High-tech Analyst Header including Incident UUID and Attack Stage.
2. **Executive Summary**: A summary describing the attack scenario, chronological timeline flow, security impact assessment, and threat intent (e.g. Ransomware, Insider threat, or credential harvesting).
3. **Evidence Reconstruction**: Detailed analysis of the correlated IOC logs. Explain how they connect together (e.g. step-by-step from initial credential brute-forcing to lateral network movement to ultimate objective impact). Mention specific IPs, file actions, and compromised systems.
4. **UEBA Anomalies Correlation**: Describe how the attacker's activity deviated from the normal working timezone or IP ranges defined in the baseline profiles.
5. **MITRE ATT&CK Matrix Alignment**: Highlighting the specific tactics and techniques used.
6. **Remediation & Action Plan**: Detail 4-5 immediate actionable response recommendations, stating exactly what command or containment processes the SOC team must run.

Keep a professional, highly analytical, objective tone. Do not mention that you are a Gemini model. Speak as the AI Security Operations Hunter. Ready, write the report in clean Markdown format:`;

    const response = await ai.models.generateContent({
      model: "gemini-3.5-flash",
      contents: promptText,
    });

    incident.aiInvestigationReport = response.text || "Automatic investigation succeeded, but returned blank report.";
    incident.automaticInvestigationStatus = "Completed";
    
    // Add additional AI action playbooks dynamically!
    incident.suggestedPlaybook = [
      "Quarantine endpoints via endpoint agent",
      "Revoke Azure AD / Kerberos Session Tickets globally",
      "Validate integrity of volume backups on database clusters",
      "Deploy localized blocklists on perimeter boundary gateways",
      "Trigger enterprise credentials lock sequence for affected accounts"
    ];

    res.json({ success: true, updatedIncident: incident });

  } catch (error: any) {
    console.error("Gemini automatic investigation error:", error);
    incident.automaticInvestigationStatus = "Failed";
    incident.aiInvestigationReport = `### ❌ Automatic AI Hunt Specialist Failure

**Error Context:** Unable to request threat details from Gemini AI API.
**Primary Cause:** ${error?.message || "Communication disruption to Google GenAI server endpoints."}

*Please verify the GEMINI_API_KEY is correctly added to your Secrets Config in the Settings panel.*`;
    res.json({ success: false, error: error?.message, updatedIncident: incident });
  }
});


// ==========================================
// BOOTSTRAP SOCKETS AND SERVER LOCKS
// ==========================================
async function startSOCServer() {
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  // Start Server binding to standard required specs
  app.listen(PORT, "0.0.0.0", () => {
    console.log(`AI SOC Full-Stack server is actively hosting on port ${PORT}`);
  });
}

startSOCServer().catch((err) => {
  console.error("SOC service initialization faulted", err);
});
