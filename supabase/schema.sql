-- Prism audit schema for Supabase (Postgres)
-- Run in the SQL editor; then set SUPABASE_URL + SUPABASE_SERVICE_KEY.

create extension if not exists "pgcrypto";

create table if not exists scan_runs (
  id uuid primary key default gen_random_uuid(),
  run_id text unique not null,
  target text,
  status text,
  mode text,
  steps int,
  findings int,
  report_path text,
  base_url text,
  reason text,
  logged_at timestamptz default now(),
  payload jsonb default '{}'::jsonb
);

create table if not exists audit_events (
  id text primary key,
  run_id text not null,
  kind text not null,
  message text not null,
  detail jsonb default '{}'::jsonb,
  timestamp timestamptz,
  created_at timestamptz default now()
);

create index if not exists audit_events_run_id_idx on audit_events (run_id);
create index if not exists audit_events_timestamp_idx on audit_events (timestamp);

create table if not exists findings (
  id uuid primary key default gen_random_uuid(),
  run_id text not null,
  title text,
  severity text,
  category text,
  evidence text,
  remediation text,
  asset text,
  cwe text,
  confidence float,
  logged_at timestamptz default now(),
  payload jsonb default '{}'::jsonb
);

create index if not exists findings_run_id_idx on findings (run_id);
create index if not exists findings_severity_idx on findings (severity);

-- RLS: service role bypasses; enable for anon lockdown
alter table scan_runs enable row level security;
alter table audit_events enable row level security;
alter table findings enable row level security;

-- Optional read policy for authenticated dashboard users
create policy "read_runs_auth" on scan_runs for select to authenticated using (true);
create policy "read_events_auth" on audit_events for select to authenticated using (true);
create policy "read_findings_auth" on findings for select to authenticated using (true);