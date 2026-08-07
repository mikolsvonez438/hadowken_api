-- OPTIONAL ALTERNATIVE TO VERCEL CRON
-- Run this only if you prefer Supabase Database Cron. Do not enable both schedulers.
-- Before running, replace REPLACE_WITH_THE_SAME_CRON_SECRET_USED_IN_VERCEL.

create extension if not exists pg_cron;
create extension if not exists pg_net;
create extension if not exists supabase_vault;

select vault.create_secret(
  'https://hadowken-api.vercel.app/api/cron/validate-accounts',
  'account_validation_api_url',
  'Backend endpoint called by the account health cron'
);

select vault.create_secret(
  'REPLACE_WITH_THE_SAME_CRON_SECRET_USED_IN_VERCEL',
  'account_validation_cron_secret',
  'Bearer token used by the account health cron'
);

do $$
begin
  perform cron.unschedule('daily-netflix-account-validation');
exception
  when others then null;
end
$$;

-- 16:00 UTC is midnight in Asia/Manila (UTC+8).
select cron.schedule(
  'daily-netflix-account-validation',
  '0 16 * * *',
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
      timeout_milliseconds := 300000
    ) as request_id;
  $job$
);

-- Monitor with:
-- select * from cron.job_run_details order by start_time desc limit 20;
-- select * from net._http_response order by created desc limit 20;
