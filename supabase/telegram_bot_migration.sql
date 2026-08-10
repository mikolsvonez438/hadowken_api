-- Telegram batch-bot job ledger.
-- Prevents Telegram webhook retries from checking the same ZIP more than once.

create table if not exists public.telegram_bot_jobs (
    update_id bigint primary key,
    telegram_user_id bigint not null,
    chat_id bigint not null,
    filename text,
    status text not null default 'processing'
        check (status in ('processing', 'completed', 'failed')),
    summary jsonb,
    error text,
    created_at timestamptz not null default now(),
    completed_at timestamptz
);

create index if not exists telegram_bot_jobs_created_at_idx
    on public.telegram_bot_jobs (created_at desc);

alter table public.telegram_bot_jobs enable row level security;

-- No anon/authenticated policies are created. The backend service-role key is
-- the only intended reader/writer for this operational table.

