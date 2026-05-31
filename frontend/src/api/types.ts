export interface Case {
  id: number;
  case_number: string;
  title: string;
  investigator: string;
  description: string;
  created_at: string;
}

export interface DetectedDevice {
  dev_path: string;
  name: string;
  serial: string;
  bus: string;
  size_bytes: number;
  fs_type: string;
  is_removable: boolean;
  details: Record<string, unknown>;
}

export interface Device {
  id: number;
  case_id: number | null;
  dev_path: string;
  name: string;
  serial: string;
  bus: string;
  size_bytes: number;
  fs_type: string;
  is_removable: boolean;
  read_only: boolean;
  state: string;
  details: Record<string, unknown>;
  created_at: string;
}

export interface EvidenceImage {
  id: number;
  device_id: number;
  path: string;
  image_format: string;
  size_bytes: number;
  md5: string;
  sha256: string;
  verified: boolean;
  created_at: string;
}

export interface ScanOptions {
  use_image: boolean;
  recover_files: boolean;
  run_carving: boolean;
  run_recycle: boolean;
  max_recover_size_mb: number;
}

export interface Scan {
  id: number;
  device_id: number;
  image_id: number | null;
  status: "pending" | "running" | "completed" | "failed" | "cancelled";
  progress: number;
  current_step: string;
  options: Record<string, unknown>;
  error: string;
  started_at: string | null;
  finished_at: string | null;
  created_at: string;
}

export interface Finding {
  id: number;
  scan_id: number;
  finding_type: "deleted_file" | "carved_file" | "recycle_artifact" | "slack_space";
  severity: "info" | "low" | "medium" | "high";
  file_name: string;
  original_path: string;
  inode: string;
  size_bytes: number;
  mime_type: string;
  recovered: boolean;
  recovered_path: string;
  md5: string;
  sha256: string;
  mtime: string | null;
  atime: string | null;
  ctime: string | null;
  crtime: string | null;
  source_tool: string;
  meta: Record<string, unknown>;
  created_at: string;
}

export interface TimelineEvent {
  id: number;
  scan_id: number;
  finding_id: number | null;
  timestamp: string;
  event_type: string;
  description: string;
}

export interface AuditLog {
  id: number;
  case_id: number | null;
  action: string;
  actor: string;
  target: string;
  detail: Record<string, unknown>;
  timestamp: string;
}

export interface HealthInfo {
  status: string;
  version: string;
  platform: string;
  mock_mode: boolean;
  tools: Record<string, boolean>;
  tools_ready: boolean;
}

export interface RealtimeEvent {
  type: string;
  data: Record<string, unknown>;
}
