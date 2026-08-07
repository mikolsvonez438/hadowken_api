
-- Run once in Supabase SQL Editor before deploying the updated API.
-- Existing columns are preserved; these fields add explicit health tracking.

alter table public.netflix_accounts
  add column if not exists validation_status text not null default 'unknown',
  add column if not exists last_validation_error text,
  add column if not exists consecutive_failures integer not null default 0;

alter table public.netflix_accounts
  drop constraint if exists netflix_accounts_validation_status_check;

alter table public.netflix_accounts
  add constraint netflix_accounts_validation_status_check
  check (validation_status in ('working', 'expired', 'dead', 'unknown'));

create index if not exists netflix_accounts_last_checked_idx
  on public.netflix_accounts (last_checked asc nulls first);

create index if not exists netflix_accounts_health_idx
  on public.netflix_accounts (validation_status, is_active);

comment on column public.netflix_accounts.validation_status is
  'Latest automated result: working, expired, dead, or unknown for temporary failures.';

