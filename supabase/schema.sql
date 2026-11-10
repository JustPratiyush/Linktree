-- Linktree schema (already applied to the Supabase "Linktree" project).
-- Public visitors can only READ active links/profile. All writes go through
-- SECURITY DEFINER functions that first verify the admin password (bcrypt hash
-- stored in the non-exposed `private` schema). 10 failed attempts in 15 min
-- locks login.
--
-- To reset a forgotten password, run in the Supabase SQL editor:
--   update private.admin_secret set password_hash = extensions.crypt('NEW-PASSWORD', extensions.gen_salt('bf', 10)) where id = 1;
-- (full migration below)

create extension if not exists pgcrypto with schema extensions;

create table if not exists public.profile (
  id int primary key default 1 check (id = 1),
  name text not null default '',
  bio text not null default '',
  avatar_url text,
  updated_at timestamptz not null default now()
);

create table if not exists public.links (
  id uuid primary key default gen_random_uuid(),
  kind text not null default 'link' check (kind in ('social','link')),
  section text not null default 'Projects',
  platform text,
  title text not null,
  subtitle text,
  url text not null check (url ~* '^(https?://|mailto:)'),
  icon_url text,
  position int not null default 0,
  is_active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index if not exists links_order_idx on public.links (kind, position);

alter table public.profile enable row level security;
alter table public.links enable row level security;
create policy "public read profile" on public.profile for select to anon, authenticated using (true);
create policy "public read active links" on public.links for select to anon, authenticated using (is_active);

create schema if not exists private;
revoke all on schema private from anon, authenticated, public;
create table if not exists private.admin_secret (id int primary key default 1 check (id = 1), password_hash text not null);
create table if not exists private.login_attempts (at timestamptz not null default now(), ok boolean not null);

create or replace function private.check_admin(p_password text)
returns boolean language plpgsql security definer set search_path = '' as $$
declare v_hash text; v_fails int; v_ok boolean;
begin
  select count(*) into v_fails from private.login_attempts where not ok and at > now() - interval '15 minutes';
  if v_fails >= 10 then return false; end if;
  select password_hash into v_hash from private.admin_secret where id = 1;
  v_ok := v_hash is not null and p_password is not null and extensions.crypt(p_password, v_hash) = v_hash;
  insert into private.login_attempts(ok) values (v_ok);
  delete from private.login_attempts where at < now() - interval '1 day';
  return v_ok;
end $$;

create or replace function public.admin_login(p_password text)
returns jsonb language plpgsql security definer set search_path = '' as $$
begin
  if not private.check_admin(p_password) then return jsonb_build_object('ok', false, 'error', 'Wrong password (or too many attempts, wait 15 min).'); end if;
  return jsonb_build_object('ok', true,
    'links', coalesce((select jsonb_agg(to_jsonb(l) order by l.kind, l.position) from public.links l), '[]'::jsonb));
end $$;

create or replace function public.admin_save_link(p_password text, p_link jsonb)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare v_id uuid; v_row public.links;
begin
  if not private.check_admin(p_password) then return jsonb_build_object('ok', false, 'error', 'Unauthorized'); end if;
  v_id := nullif(p_link->>'id','')::uuid;
  if v_id is null then
    insert into public.links (kind, section, platform, title, subtitle, url, icon_url, position, is_active)
    values (coalesce(p_link->>'kind','link'), coalesce(nullif(p_link->>'section',''),'Projects'), nullif(p_link->>'platform',''),
            p_link->>'title', nullif(p_link->>'subtitle',''), p_link->>'url', nullif(p_link->>'icon_url',''),
            coalesce((p_link->>'position')::int, (select coalesce(max(position),0)+1 from public.links)),
            coalesce((p_link->>'is_active')::boolean, true))
    returning * into v_row;
  else
    update public.links set
      kind = coalesce(p_link->>'kind', kind), section = coalesce(nullif(p_link->>'section',''), section),
      platform = nullif(p_link->>'platform',''), title = coalesce(p_link->>'title', title),
      subtitle = nullif(p_link->>'subtitle',''), url = coalesce(p_link->>'url', url),
      icon_url = nullif(p_link->>'icon_url',''), position = coalesce((p_link->>'position')::int, position),
      is_active = coalesce((p_link->>'is_active')::boolean, is_active), updated_at = now()
    where id = v_id returning * into v_row;
  end if;
  return jsonb_build_object('ok', true, 'link', to_jsonb(v_row));
exception when others then
  return jsonb_build_object('ok', false, 'error', sqlerrm);
end $$;

create or replace function public.admin_delete_link(p_password text, p_id uuid)
returns jsonb language plpgsql security definer set search_path = '' as $$
begin
  if not private.check_admin(p_password) then return jsonb_build_object('ok', false, 'error', 'Unauthorized'); end if;
  delete from public.links where id = p_id;
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.admin_reorder(p_password text, p_ids uuid[])
returns jsonb language plpgsql security definer set search_path = '' as $$
begin
  if not private.check_admin(p_password) then return jsonb_build_object('ok', false, 'error', 'Unauthorized'); end if;
  update public.links l set position = t.ord, updated_at = now()
  from unnest(p_ids) with ordinality as t(id, ord) where l.id = t.id;
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.admin_save_profile(p_password text, p_profile jsonb)
returns jsonb language plpgsql security definer set search_path = '' as $$
begin
  if not private.check_admin(p_password) then return jsonb_build_object('ok', false, 'error', 'Unauthorized'); end if;
  insert into public.profile (id, name, bio, avatar_url) values (1, coalesce(p_profile->>'name',''), coalesce(p_profile->>'bio',''), nullif(p_profile->>'avatar_url',''))
  on conflict (id) do update set name = excluded.name, bio = excluded.bio, avatar_url = excluded.avatar_url, updated_at = now();
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.admin_change_password(p_password text, p_new text)
returns jsonb language plpgsql security definer set search_path = '' as $$
begin
  if not private.check_admin(p_password) then return jsonb_build_object('ok', false, 'error', 'Unauthorized'); end if;
  if length(coalesce(p_new,'')) < 10 then return jsonb_build_object('ok', false, 'error', 'New password must be at least 10 characters.'); end if;
  update private.admin_secret set password_hash = extensions.crypt(p_new, extensions.gen_salt('bf', 10)) where id = 1;
  return jsonb_build_object('ok', true);
end $$;

revoke all on function private.check_admin(text) from public, anon, authenticated;
revoke all on function public.admin_login(text), public.admin_save_link(text, jsonb), public.admin_delete_link(text, uuid),
  public.admin_reorder(text, uuid[]), public.admin_save_profile(text, jsonb), public.admin_change_password(text, text) from public;
grant execute on function public.admin_login(text), public.admin_save_link(text, jsonb), public.admin_delete_link(text, uuid),
  public.admin_reorder(text, uuid[]), public.admin_save_profile(text, jsonb), public.admin_change_password(text, text) to anon, authenticated;
revoke insert, update, delete, truncate on public.links, public.profile from anon, authenticated;
