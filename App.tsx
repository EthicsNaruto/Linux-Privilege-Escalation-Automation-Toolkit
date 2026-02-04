
import React, { useState, useEffect, useMemo } from 'react';
import { AuditReport, Severity, Finding } from './types';
import { ICONS, PYTHON_TOOLKIT_CODE } from './constants';
import { Dashboard } from './components/Dashboard';
import { FindingCard } from './components/FindingCard';
import { SecurityAI } from './services/geminiService';
import { LiveMonitor } from './components/LiveMonitor';

const MOCK_REPORT: AuditReport = {
  timestamp: new Date().toISOString(),
  system_info: {
    user: "auditor",
    uid: 1001,
    gid: 1001,
    groups: ["auditor", "sudo", "docker"],
    os: "Ubuntu 22.04 LTS",
    kernel: "5.15.0-101-generic",
    arch: "x86_64",
    is_root: false
  },
  findings: [
    {
      name: "Vulnerable SUID: /usr/bin/find",
      description: "The 'find' binary has the SUID bit set. This allows any user to execute shell commands with root privileges via the -exec flag.",
      severity: Severity.CRITICAL,
      detection_method: "Filesystem walk and stat bit check",
      impact: "Instant full privilege escalation to root user.",
      mitigation: "Remove SUID bit: chmod u-s /usr/bin/find",
      module: "SUID_SCAN"
    },
    {
      name: "World-Writable /etc/passwd",
      description: "The system password file is misconfigured with 666 permissions, allowing any user to add or modify user accounts.",
      severity: Severity.CRITICAL,
      detection_method: "os.access(W_OK) check",
      impact: "Attacker can create a root-level user by modifying the file.",
      mitigation: "Correct permissions: chmod 644 /etc/passwd",
      module: "WEAK_PERMS"
    },
    {
      name: "Writable Service Binary: backup.service",
      description: "The systemd service 'backup.service' runs as root, but its target binary '/usr/local/bin/backup-sync' is writable by the current user.",
      severity: Severity.CRITICAL,
      detection_method: "Systemd parsing + os.access(W_OK) check",
      impact: "User can replace the binary to execute arbitrary code as root upon service restart or next execution.",
      mitigation: "Restrict write access: chown root:root /usr/local/bin/backup-sync && chmod 755 /usr/local/bin/backup-sync",
      module: "SVC_AUDIT"
    },
    {
      name: "Service Binary User Owned: database.service",
      description: "Service 'database.service' binary '/opt/db/start.sh' is owned by non-root user 'dbadmin'.",
      severity: Severity.HIGH,
      detection_method: "Systemd parsing + stat.st_uid check",
      impact: "Owner 'dbadmin' can swap the binary to execute malicious code as root on service restart.",
      mitigation: "chown root:root /opt/db/start.sh",
      module: "SVC_AUDIT"
    },
    {
      name: "Sudo NOPASSWD: vim",
      description: "User allowed to run '/usr/bin/vim' as root without password.",
      severity: Severity.CRITICAL,
      detection_method: "sudo -l parsing",
      impact: "GTFOBins vector: 'vim' can spawn a root shell or allow arbitrary file write/read.",
      mitigation: "Restrict command in sudoers or require password authentication.",
      module: "SUDO_AUDIT"
    },
    {
      name: "Insecure Service PATH: data-monitor.service",
      description: "The 'data-monitor.service' (running as root) defines an Environment PATH that includes '/tmp/bin', which is world-writable.",
      severity: Severity.HIGH,
      detection_method: "Systemd Environment parsing",
      impact: "Allows for binary hijacking. An attacker can place a malicious binary in /tmp/bin to be executed by the service.",
      mitigation: "Remove writable directories from the service PATH environment variable.",
      module: "SVC_AUDIT"
    },
    {
      name: "Writable Cron Script: /etc/cron.daily/log-rotate",
      description: "A daily cron job executes '/opt/scripts/rotate.sh' as root, but the script file is writable by the 'auditor' user.",
      severity: Severity.CRITICAL,
      detection_method: "Cron parsing + recursive permission check",
      impact: "User can modify the cron script to gain root access during the next daily execution.",
      mitigation: "Ensure all scripts in /etc/cron.* are owned by root and not writable by others.",
      module: "CRON_AUDIT"
    },
    {
      name: "Legacy Kernel (Potential DirtyPipe)",
      description: "Detected kernel version 5.15.0 which may be vulnerable to CVE-2022-0847 (DirtyPipe).",
      severity: Severity.HIGH,
      detection_method: "Kernel version regex match",
      impact: "Possible arbitrary file overwrite as root via splice system call exploitation.",
      mitigation: "Update to kernel 5.16.11, 5.15.25, 5.10.102 or newer.",
      module: "KERNEL_AUDIT"
    },
    {
      name: "Docker Group Membership",
      description: "The current user is a member of the 'docker' group, which is effectively equivalent to root access.",
      severity: Severity.MEDIUM,
      detection_method: "os.getgroups() check",
      impact: "User can run privileged containers and mount the host filesystem to escalate privileges.",
      mitigation: "Remove user from docker group and use sudo for docker commands if necessary.",
      module: "SYSTEM_INFO"
    }
  ]
};

const App: React.FC = () => {
  const [report, setReport] = useState<AuditReport>(MOCK_REPORT);
  const [activeTab, setActiveTab] = useState<'dashboard' | 'findings' | 'live' | 'code' | 'ai'>('dashboard');
  const [aiAnalysis, setAiAnalysis] = useState<string>('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [customKernelInput, setCustomKernelInput] = useState('');
  const [manualCheckResult, setManualCheckResult] = useState<Finding | null>(null);

  // Filter States
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState<Severity | 'ALL'>('ALL');
  const [moduleFilter, setModuleFilter] = useState<string | 'ALL'>('ALL');

  const aiService = useMemo(() => new SecurityAI(), []);

  const runAiAnalysis = async () => {
    setIsAnalyzing(true);
    const result = await aiService.analyzeFindings(report.findings);
    setAiAnalysis(result || "Error generating analysis.");
    setIsAnalyzing(false);
  };

  const handleManualKernelCheck = () => {
    const patterns = [
      { regex: /^2\./, name: "Legacy Kernel (2.x)", sev: Severity.HIGH, impact: "Unsupported kernel version with numerous known exploits." },
      { regex: /^3\./, name: "Legacy Kernel (3.x)", sev: Severity.HIGH, impact: "Outdated kernel likely missing modern security mitigations." },
      { regex: /^4\.[0-9]\./, name: "Old Kernel (4.x)", sev: Severity.MEDIUM, impact: "Likely vulnerable to local privilege escalation vectors like Dirty COW." },
      { regex: /^5\.15\./, name: "DirtyPipe Candidate", sev: Severity.HIGH, impact: "Versions around 5.15.0 may be vulnerable to CVE-2022-0847." }
    ];

    const match = patterns.find(p => p.regex.test(customKernelInput));
    if (match) {
      setManualCheckResult({
        name: match.name,
        description: `Manual check for version '${customKernelInput}' matched a known vulnerable pattern.`,
        severity: match.sev,
        detection_method: "Manual version regex verification",
        impact: match.impact,
        mitigation: "Verify against latest CVE databases and upgrade immediately.",
        module: "KERNEL_AUDIT"
      });
    } else {
      setManualCheckResult(null);
      alert(`No basic vulnerable patterns matched for kernel version: ${customKernelInput}`);
    }
  };

  const uniqueModules = useMemo(() => {
    return Array.from(new Set(report.findings.map(f => f.module))).sort();
  }, [report.findings]);

  const filteredFindings = useMemo(() => {
    return report.findings.filter(f => {
      const matchesSearch = 
        f.name.toLowerCase().includes(searchTerm.toLowerCase()) || 
        f.description.toLowerCase().includes(searchTerm.toLowerCase());
      const matchesSeverity = severityFilter === 'ALL' || f.severity === severityFilter;
      const matchesModule = moduleFilter === 'ALL' || f.module === moduleFilter;
      return matchesSearch && matchesSeverity && matchesModule;
    });
  }, [report.findings, searchTerm, severityFilter, moduleFilter]);

  return (
    <div className="min-h-screen flex flex-col h-screen overflow-hidden">
      {/* Sidebar Navigation */}
      <div className="flex flex-1 overflow-hidden">
        <aside className="w-64 border-r border-zinc-800 bg-zinc-950 hidden md:flex flex-col">
          <div className="p-6 border-b border-zinc-800 flex items-center gap-3">
            <ICONS.Shield className="w-8 h-8 text-emerald-500" />
            <span className="font-bold text-lg tracking-tight">LynxAudit</span>
          </div>
          
          <nav className="flex-1 p-4 space-y-2">
            {[
              { id: 'dashboard', label: 'Overview', icon: <ICONS.Cpu className="w-5 h-5" /> },
              { id: 'findings', label: 'Detection Logs', icon: <ICONS.Alert className="w-5 h-5" /> },
              { id: 'live', label: 'Live Monitor', icon: <ICONS.Activity className="w-5 h-5" /> },
              { id: 'code', label: 'Export Toolkit', icon: <ICONS.Code className="w-5 h-5" /> },
              { id: 'ai', label: 'Security AI', icon: <ICONS.Terminal className="w-5 h-5" /> },
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                className={`w-full flex items-center gap-3 px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                  activeTab === tab.id 
                    ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' 
                    : 'text-zinc-400 hover:text-white hover:bg-zinc-900'
                }`}
              >
                {tab.icon}
                {tab.label}
              </button>
            ))}
          </nav>

          <div className="p-4 border-t border-zinc-800">
            <div className="bg-zinc-900 rounded-lg p-3">
              <p className="text-[10px] text-zinc-500 uppercase font-bold mb-1">Audit Status</p>
              <div className="flex items-center gap-2">
                <div className={`w-2 h-2 ${activeTab === 'live' ? 'bg-emerald-500 animate-pulse' : 'bg-zinc-500'} rounded-full`}></div>
                <span className="text-xs text-zinc-300">{activeTab === 'live' ? 'Capturing Logs' : 'Idle'}</span>
              </div>
            </div>
          </div>
        </aside>

        {/* Main Content Area */}
        <main className="flex-1 overflow-y-auto bg-black p-4 md:p-8 flex flex-col">
          <header className="mb-8 flex flex-col md:flex-row md:items-center justify-between gap-4 shrink-0">
            <div>
              <h1 className="text-2xl font-bold text-white">Security Audit Interface</h1>
              <p className="text-zinc-400 text-sm mt-1">
                Automated Linux Enumeration and Privilege Escalation Risk Detection.
              </p>
            </div>
            <div className="flex items-center gap-3">
               <button 
                onClick={() => window.print()}
                className="bg-zinc-900 hover:bg-zinc-800 border border-zinc-800 px-4 py-2 rounded-lg text-sm font-medium flex items-center gap-2 transition-all"
              >
                <ICONS.Document className="w-4 h-4" />
                Export PDF
              </button>
              <button className="bg-emerald-600 hover:bg-emerald-500 px-4 py-2 rounded-lg text-sm font-medium shadow-lg shadow-emerald-900/20 flex items-center gap-2 transition-all">
                <ICONS.Search className="w-4 h-4" />
                New Audit
              </button>
            </div>
          </header>

          <div className="flex-1 min-h-0">
            {activeTab === 'dashboard' && (
              <div className="space-y-8 pb-12">
                <Dashboard report={report} />
                
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
                  {/* Manual Kernel Check Utility */}
                  <div className="bg-zinc-900 border border-zinc-800 p-6 rounded-xl">
                     <h3 className="text-zinc-400 text-sm font-semibold uppercase mb-4 flex items-center gap-2">
                      <ICONS.Search className="w-4 h-4 text-emerald-500" />
                      Manual Kernel Verifier
                    </h3>
                    <p className="text-zinc-500 text-xs mb-4">Test a specific kernel version (e.g. 4.4.0) against the toolkit's vulnerable pattern signature engine.</p>
                    <div className="flex gap-2">
                      <input 
                        type="text" 
                        placeholder="e.g. 4.4.0-generic"
                        className="bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-sm text-zinc-200 flex-1 outline-none focus:border-emerald-500/50 transition-colors"
                        value={customKernelInput}
                        onChange={(e) => setCustomKernelInput(e.target.value)}
                      />
                      <button 
                        onClick={handleManualKernelCheck}
                        className="bg-zinc-800 hover:bg-zinc-700 px-4 py-2 rounded-lg text-xs font-bold transition-all border border-zinc-700"
                      >
                        VERIFY
                      </button>
                    </div>
                    {manualCheckResult && (
                      <div className="mt-6 border-t border-zinc-800 pt-4 animate-in fade-in slide-in-from-top-2 duration-300">
                        <FindingCard finding={manualCheckResult} />
                      </div>
                    )}
                  </div>

                  <div className="bg-zinc-900 border border-zinc-800 p-6 rounded-xl flex flex-col justify-center">
                     <h3 className="text-zinc-400 text-sm font-semibold uppercase mb-2">Audit Version</h3>
                     <span className="text-zinc-100 font-mono text-xl">LynxAudit v1.5.0</span>
                     <p className="text-zinc-500 text-xs mt-2">Enhanced: Real-time Live Monitoring Simulation.</p>
                  </div>
                </div>

                <div className="grid grid-cols-1 gap-4">
                   <h2 className="text-lg font-bold text-zinc-200 mt-4 mb-2">Priority Findings</h2>
                   <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      {report.findings.slice(0, 4).map((f, i) => (
                        <FindingCard key={i} finding={f} />
                      ))}
                   </div>
                </div>
              </div>
            )}

            {activeTab === 'findings' && (
              <div className="space-y-6 pb-12">
                <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 bg-zinc-900 p-6 rounded-xl border border-zinc-800 sticky top-0 z-10 shadow-xl shadow-black">
                   <div className="flex-1 space-y-4">
                     <h2 className="text-xl font-bold flex items-center gap-2">
                       <ICONS.Alert className="w-6 h-6 text-emerald-500" />
                       Detection Logs
                       <span className="text-xs font-mono bg-zinc-800 px-2 py-0.5 rounded text-zinc-400">
                         {filteredFindings.length} of {report.findings.length}
                       </span>
                     </h2>
                     
                     <div className="relative group">
                       <ICONS.Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-500 group-focus-within:text-emerald-500 transition-colors" />
                       <input 
                         type="text" 
                         placeholder="Search findings by name, description, or module..."
                         className="w-full bg-zinc-950 border border-zinc-800 rounded-lg pl-10 pr-4 py-2 text-sm text-zinc-200 outline-none focus:border-emerald-500/50 transition-all"
                         value={searchTerm}
                         onChange={(e) => setSearchTerm(e.target.value)}
                       />
                     </div>
                   </div>

                   <div className="flex flex-wrap gap-3">
                     <div className="flex flex-col gap-1">
                       <label className="text-[10px] uppercase font-bold text-zinc-500 px-1">Severity</label>
                       <select 
                         className="bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-xs text-zinc-300 outline-none focus:border-emerald-500/50 transition-colors"
                         value={severityFilter}
                         onChange={(e) => setSeverityFilter(e.target.value as any)}
                       >
                         <option value="ALL">All Severities</option>
                         {Object.values(Severity).map(sev => (
                           <option key={sev} value={sev}>{sev}</option>
                         ))}
                       </select>
                     </div>

                     <div className="flex flex-col gap-1">
                       <label className="text-[10px] uppercase font-bold text-zinc-500 px-1">Module</label>
                       <select 
                         className="bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-xs text-zinc-300 outline-none focus:border-emerald-500/50 transition-colors"
                         value={moduleFilter}
                         onChange={(e) => setModuleFilter(e.target.value)}
                       >
                         <option value="ALL">All Modules</option>
                         {uniqueModules.map(mod => (
                           <option key={mod} value={mod}>{mod}</option>
                         ))}
                       </select>
                     </div>
                     
                     <button 
                       onClick={() => {
                         setSearchTerm('');
                         setSeverityFilter('ALL');
                         setModuleFilter('ALL');
                       }}
                       className="bg-zinc-800 hover:bg-zinc-700 text-zinc-400 hover:text-white h-[34px] self-end px-3 rounded-lg text-xs font-bold transition-all border border-zinc-700"
                       title="Clear all filters"
                     >
                       RESET
                     </button>
                   </div>
                </div>

                <div className="grid grid-cols-1 gap-4 min-h-[400px]">
                  {filteredFindings.length > 0 ? (
                    filteredFindings.map((f, i) => (
                      <FindingCard key={i} finding={f} />
                    ))
                  ) : (
                    <div className="flex flex-col items-center justify-center py-20 text-zinc-500 space-y-4">
                      <ICONS.Search className="w-12 h-12 opacity-20" />
                      <div className="text-center">
                        <p className="text-lg font-medium text-zinc-400">No matching detections found</p>
                        <p className="text-sm">Try adjusting your filters or search query.</p>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}

            {activeTab === 'live' && (
              <div className="h-full pb-8">
                <LiveMonitor findings={report.findings} />
              </div>
            )}

            {activeTab === 'code' && (
              <div className="bg-zinc-900 border border-zinc-800 rounded-xl overflow-hidden flex flex-col h-full max-h-[600px]">
                <div className="px-4 py-2 border-b border-zinc-800 bg-zinc-950 flex justify-between items-center">
                  <div className="flex items-center gap-2">
                    <ICONS.Code className="w-4 h-4 text-emerald-500" />
                    <span className="text-xs font-mono text-zinc-500">lynx_audit.py</span>
                  </div>
                  <button 
                    onClick={() => navigator.clipboard.writeText(PYTHON_TOOLKIT_CODE)}
                    className="text-xs text-emerald-400 hover:text-emerald-300 font-bold"
                  >
                    COPY CODE
                  </button>
                </div>
                <pre className="p-4 overflow-auto mono text-xs text-emerald-500/80 leading-relaxed scrollbar-thin scrollbar-thumb-zinc-700">
                  <code>{PYTHON_TOOLKIT_CODE}</code>
                </pre>
              </div>
            )}

            {activeTab === 'ai' && (
              <div className="space-y-6 pb-12">
                <div className="bg-zinc-900 border border-zinc-800 p-8 rounded-xl text-center">
                  <ICONS.Terminal className="w-12 h-12 text-emerald-500 mx-auto mb-4" />
                  <h2 className="text-xl font-bold mb-2">Advanced Risk Analysis</h2>
                  <p className="text-zinc-400 max-w-lg mx-auto mb-6">
                    Leverage Gemini Pro to analyze the audit findings, identify complex privilege escalation chains, and generate SOC-ready mitigation playbooks.
                  </p>
                  <button 
                    onClick={runAiAnalysis}
                    disabled={isAnalyzing}
                    className="bg-emerald-600 hover:bg-emerald-500 px-6 py-2 rounded-full font-bold transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    {isAnalyzing ? 'Processing Audit Data...' : 'Generate AI Insights'}
                  </button>
                </div>

                {aiAnalysis && (
                  <div className="bg-zinc-900 border border-emerald-500/30 p-6 rounded-xl animate-in fade-in slide-in-from-bottom-4 duration-500">
                    <h3 className="flex items-center gap-2 text-emerald-400 font-bold mb-4">
                      <ICONS.Shield className="w-5 h-5" />
                      Strategic Remediation Report
                    </h3>
                    <div className="prose prose-invert max-w-none text-zinc-300 text-sm whitespace-pre-wrap font-mono leading-relaxed">
                      {aiAnalysis}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </main>
      </div>

      {/* Footer / Status Bar */}
      <footer className="h-8 border-t border-zinc-800 bg-zinc-950 px-4 flex items-center justify-between text-[10px] text-zinc-500 font-mono shrink-0">
        <div className="flex gap-4">
          <span>HOST: {report.system_info.os}</span>
          <span>KERNEL: {report.system_info.kernel}</span>
          {activeTab === 'live' && <span className="text-emerald-500 animate-pulse">STREAMING LIVE DATA</span>}
        </div>
        <div>
          &copy; 2024 LYNXAUDIT SECURITY SOLUTIONS • INTERNAL USE ONLY
        </div>
      </footer>
    </div>
  );
};

export default App;
