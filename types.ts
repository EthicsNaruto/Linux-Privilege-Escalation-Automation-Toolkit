
export enum Severity {
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH',
  CRITICAL = 'CRITICAL'
}

export interface Finding {
  name: string;
  description: string;
  severity: Severity;
  detection_method: string;
  impact: string;
  mitigation: string;
  module: string;
}

export interface SecurityEvent {
  id: string;
  timestamp: string;
  type: 'AUTH' | 'FILE' | 'EXEC' | 'SYS';
  message: string;
  severity: Severity;
}

export interface SystemInfo {
  user: string;
  uid: number;
  gid: number;
  groups: string[];
  os: string;
  kernel: string;
  arch: string;
  is_root: boolean;
}

export interface AuditReport {
  timestamp: string;
  system_info: SystemInfo;
  findings: Finding[];
}
