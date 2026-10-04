-- ScamShield: run once in the Supabase SQL editor.

create table if not exists public.checks (
  id              bigint generated always as identity primary key,
  created_at      timestamptz not null default now(),
  status          text not null check (status in ('ok', 'error')),
  message         text not null,           -- what the user pasted (sanitized)
  result          text,                    -- the answer shown to the user
  raw_result      text,                    -- the model's original answer, before guardrails
  risk_level      text check (risk_level in ('low', 'medium', 'high')),
  red_flags       jsonb not null default '[]'::jsonb,
  model           text,
  error           text,
  upstream_status integer,
  latency_ms      integer,
  prompt_tokens     integer,               -- token usage reported by Gemini
  completion_tokens integer,
  total_tokens      integer
);

-- For tables created before token usage was logged.
alter table public.checks add column if not exists prompt_tokens integer;
alter table public.checks add column if not exists completion_tokens integer;
alter table public.checks add column if not exists total_tokens integer;

-- Keeps the "checks processed" count (status = 'ok') fast as the table grows.
create index if not exists checks_ok_idx on public.checks (id) where status = 'ok';
create index if not exists checks_created_at_idx on public.checks (created_at desc);

-- Messages can contain personal details. With RLS on and no policies, the
-- public anon key can't read or write anything; only the server's secret key can.
alter table public.checks enable row level security;
