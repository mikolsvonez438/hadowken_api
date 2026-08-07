-- BATCHED SUPABASE DATABASE CRON
-- Replace the placeholder below with the exact CRON_SECRET from backend Vercel.
-- This script is safe to rerun: it updates the Vault entries and replaces the job.

create extension if not exists pg_cron;
create extension if not exists pg_net;
create extension if not exists supabase_vault;

do $$
declare
  existing_id uuid;
begin
  select id into existing_id
  from vault.secrets
  where name = 'account_validation_api_url'
  order by created_at desc
  limit 1;

  if existing_id is null then
    perform vault.create_secret(
      'https://hadowken-api.vercel.app/api/cron/validate-accounts?batch_size=25',
      'account_validation_api_url',
      'Backend endpoint called by the account health cron'
    );
  else
    perform vault.update_secret(
      existing_id,
      'https://hadowken-api.vercel.app/api/cron/validate-accounts?batch_size=25',
      'account_validation_api_url',
      'Backend endpoint called by the account health cron'
    );
  end if;

  select id into existing_id
  from vault.secrets
  where name = 'account_validation_cron_secret'
  order by created_at desc
  limit 1;

  if existing_id is null then
    perform vault.create_secret(
      'REPLACE_WITH_THE_SAME_CRON_SECRET_USED_IN_VERCEL',
      'account_validation_cron_secret',
      'Bearer token used by the account health cron'
    );
  else
    perform vault.update_secret(
      existing_id,
      'REPLACE_WITH_THE_SAME_CRON_SECRET_USED_IN_VERCEL',
      'account_validation_cron_secret',
      'Bearer token used by the account health cron'
    );
  end if;
end
$$;

do $$
begin
  perform cron.unschedule('daily-netflix-account-validation');
exception when others then null;
end
$$;

do $$
begin
  perform cron.unschedule('hourly-netflix-account-validation');
exception when others then null;
end
$$;

do $$
begin
  perform cron.unschedule('netflix-account-validation-batches');
exception when others then null;
end
$$;

-- Every 15 minutes, validate up to 25 records whose last check is at least 24 hours old.
-- Recently checked records are skipped, avoiding unnecessary repeated validation.
select cron.schedule(
  'netflix-account-validation-batches',
  '*/15 * * * *',
  $job$
    select net.http_get(
      url := (
        select decrypted_secret
        from vault.decrypted_secrets
        where name = 'account_validation_api_url'
        order by created_at desc
        limit 1
      ),
      headers := jsonb_build_object(
        'Authorization', 'Bearer ' || (
          select decrypted_secret
          from vault.decrypted_secrets
          where name = 'account_validation_cron_secret'
          order by created_at desc
          limit 1
        )
      ),
      timeout_milliseconds := 240000
    ) as request_id;
  $job$
);

-- Monitor with:
-- select * from cron.job_run_details order by start_time desc limit 20;
-- select * from net._http_response order by created desc limit 20;
