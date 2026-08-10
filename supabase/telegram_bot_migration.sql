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

-- Expiring indirection for Telegram copy buttons. Netflix login URLs can be
-- longer than Telegram's 256-character CopyTextButton limit, so the bot stores
-- the token here and gives Telegram a short, unguessable redirect URL.
create table if not exists public.telegram_short_links (
    code text primary key,
    nftoken text not null,
    created_by uuid,
    created_at timestamptz not null default now(),
    expires_at timestamptz not null
);

create index if not exists telegram_short_links_expires_at_idx
    on public.telegram_short_links (expires_at);

alter table public.telegram_short_links enable row level security;

-- No anon/authenticated policies are created. The backend service-role key is
-- the only intended reader/writer for these operational tables.
