create extension if not exists pgcrypto;

do $$ begin create type public.member_role as enum ('owner','project_manager','site_manager','purchasing','tradesperson','customer'); exception when duplicate_object then null; end $$;
do $$ begin create type public.request_status as enum ('new','under_review','needs_pricing','awaiting_approval','approved','rejected','completed'); exception when duplicate_object then null; end $$;
do $$ begin create type public.task_status as enum ('todo','scheduled','in_progress','completed'); exception when duplicate_object then null; end $$;
do $$ begin create type public.material_status as enum ('to_order','ordered','delivering','delivered','delayed'); exception when duplicate_object then null; end $$;
do $$ begin create type public.invitation_status as enum ('pending','accepted','cancelled','expired'); exception when duplicate_object then null; end $$;

create table if not exists public.companies(id uuid primary key default gen_random_uuid(), name text not null, created_at timestamptz not null default now());
create table if not exists public.memberships(id uuid primary key default gen_random_uuid(), company_id uuid not null references public.companies(id) on delete cascade, user_id uuid not null references auth.users(id) on delete cascade, role public.member_role not null, full_name text, created_at timestamptz not null default now(), unique(company_id,user_id));
create table if not exists public.invitations(id uuid primary key default gen_random_uuid(), company_id uuid not null references public.companies(id) on delete cascade, email text not null, role public.member_role not null check(role <> 'owner'), invited_by uuid not null references auth.users(id), status public.invitation_status not null default 'pending', expires_at timestamptz not null default (now()+interval '7 days'), created_at timestamptz not null default now(), accepted_at timestamptz);
create unique index if not exists invitations_one_pending_email on public.invitations(company_id,lower(email)) where status='pending';
create table if not exists public.project_members(
 id uuid primary key default gen_random_uuid(),
 company_id uuid not null references public.companies(id) on delete cascade,
 project_id uuid not null references public.projects(id) on delete cascade,
 user_id uuid not null references auth.users(id) on delete cascade,
 role public.member_role not null,
 created_at timestamptz not null default now(),
 unique(project_id,user_id)
);
create index if not exists project_members_user_idx on public.project_members(user_id);
create index if not exists project_members_project_idx on public.project_members(project_id);

create table if not exists public.projects(id uuid primary key default gen_random_uuid(), company_id uuid not null references public.companies(id) on delete cascade, name text not null, address text, customer_id uuid references auth.users(id), progress integer not null default 0 check(progress between 0 and 100), created_at timestamptz not null default now());
create table if not exists public.requests(id uuid primary key default gen_random_uuid(), company_id uuid not null references public.companies(id) on delete cascade, project_id uuid not null references public.projects(id) on delete cascade, customer_id uuid references auth.users(id), title text not null, detail text not null default '', category text, price numeric(12,2) not null default 0, schedule_impact text, status public.request_status not null default 'new', created_at timestamptz not null default now(), updated_at timestamptz not null default now());
create table if not exists public.tasks(id uuid primary key default gen_random_uuid(), company_id uuid not null references public.companies(id) on delete cascade, project_id uuid not null references public.projects(id) on delete cascade, request_id uuid references public.requests(id) on delete set null, title text not null, description text, assignee_id uuid references auth.users(id), assignee_name text, status public.task_status not null default 'todo', created_at timestamptz not null default now());
create table if not exists public.materials(id uuid primary key default gen_random_uuid(), company_id uuid not null references public.companies(id) on delete cascade, project_id uuid not null references public.projects(id) on delete cascade, name text not null, quantity numeric default 1, supplier text, status public.material_status not null default 'to_order', required_date date, created_at timestamptz not null default now());

create or replace function public.my_company_ids() returns setof uuid language sql stable security definer set search_path=public as $$ select company_id from public.memberships where user_id=auth.uid(); $$;
create or replace function public.my_role(cid uuid) returns public.member_role language sql stable security definer set search_path=public as $$ select role from public.memberships where user_id=auth.uid() and company_id=cid limit 1; $$;
create or replace function public.is_company_owner(cid uuid) returns boolean language sql stable security definer set search_path=public as $$ select exists(select 1 from public.memberships where company_id=cid and user_id=auth.uid() and role='owner'); $$;

alter table public.companies enable row level security; alter table public.memberships enable row level security; alter table public.invitations enable row level security; alter table public.projects enable row level security; alter table public.requests enable row level security; alter table public.tasks enable row level security; alter table public.materials enable row level security; alter table public.project_members enable row level security;

-- Remove old policies when re-running the schema.
do $$ declare p record; begin for p in select policyname,tablename from pg_policies where schemaname='public' and tablename in ('companies','memberships','invitations','projects','requests','tasks','materials','project_members') loop execute format('drop policy if exists %I on public.%I',p.policyname,p.tablename); end loop; end $$;

create policy "company members read company" on public.companies for select using (id in (select public.my_company_ids()));
create policy "membership self or owner read" on public.memberships for select using (user_id=auth.uid() or public.is_company_owner(company_id));
create policy "owner inserts memberships" on public.memberships for insert with check (public.is_company_owner(company_id));
create policy "owner updates memberships" on public.memberships for update using (public.is_company_owner(company_id)) with check (public.is_company_owner(company_id));
create policy "owner deletes memberships" on public.memberships for delete using (public.is_company_owner(company_id));

create policy "owner manages invitations" on public.invitations for all using (public.is_company_owner(company_id)) with check (public.is_company_owner(company_id));
create or replace function public.can_access_project(pid uuid) returns boolean language sql stable security definer set search_path=public as $$
 select exists(select 1 from public.projects p where p.id=pid and p.company_id in (select public.my_company_ids()) and (public.my_role(p.company_id)='owner' or exists(select 1 from public.project_members pm where pm.project_id=pid and pm.user_id=auth.uid())));
$$;

create policy "members read assigned projects" on public.projects for select using (public.can_access_project(id));
create policy "owners create projects" on public.projects for insert with check (public.is_company_owner(company_id));
create policy "owners and assigned pm update projects" on public.projects for update using (public.is_company_owner(company_id) or (public.my_role(company_id)='project_manager' and public.can_access_project(id))) with check (public.is_company_owner(company_id) or (public.my_role(company_id)='project_manager' and public.can_access_project(id)));

create policy "owners manage project assignments" on public.project_members for all using (public.is_company_owner(company_id)) with check (public.is_company_owner(company_id));
create policy "members read own project assignments" on public.project_members for select using (company_id in (select public.my_company_ids()) and (user_id=auth.uid() or public.is_company_owner(company_id)));

create policy "members read assigned requests" on public.requests for select using (public.can_access_project(project_id));
create policy "assigned users create requests" on public.requests for insert with check (public.can_access_project(project_id));
create policy "authorized update assigned requests" on public.requests for update using (public.can_access_project(project_id) and public.my_role(company_id) in ('owner','project_manager','site_manager','customer')) with check (public.can_access_project(project_id));
create policy "members read assigned tasks" on public.tasks for select using (public.can_access_project(project_id));
create policy "authorized create assigned tasks" on public.tasks for insert with check (public.can_access_project(project_id) and public.my_role(company_id) in ('owner','project_manager','site_manager'));
create policy "authorized update assigned tasks" on public.tasks for update using (public.can_access_project(project_id) and public.my_role(company_id) in ('owner','project_manager','site_manager','tradesperson')) with check (public.can_access_project(project_id));
create policy "members read assigned materials" on public.materials for select using (public.can_access_project(project_id));
create policy "authorized create assigned materials" on public.materials for insert with check (public.can_access_project(project_id) and public.my_role(company_id) in ('owner','project_manager','purchasing'));
create policy "authorized update assigned materials" on public.materials for update using (public.can_access_project(project_id) and public.my_role(company_id) in ('owner','project_manager','purchasing')) with check (public.can_access_project(project_id));

create or replace function public.set_project_assignment(target_user_id uuid,target_project_id uuid) returns void language plpgsql security definer set search_path=public as $$
declare cid uuid; r public.member_role;
begin
 select company_id into cid from public.projects where id=target_project_id;
 if cid is null or not public.is_company_owner(cid) then raise exception 'Owner access required'; end if;
 select role into r from public.memberships where company_id=cid and user_id=target_user_id;
 if r is null then raise exception 'User is not a member of this company'; end if;
 insert into public.project_members(company_id,project_id,user_id,role) values(cid,target_project_id,target_user_id,r) on conflict(project_id,user_id) do update set role=excluded.role;
end $$;

create or replace function public.remove_project_assignment(target_user_id uuid,target_project_id uuid) returns void language plpgsql security definer set search_path=public as $$
declare cid uuid;
begin
 select company_id into cid from public.projects where id=target_project_id;
 if cid is null or not public.is_company_owner(cid) then raise exception 'Owner access required'; end if;
 delete from public.project_members where project_id=target_project_id and user_id=target_user_id;
end $$;

create or replace function public.sync_project_role() returns trigger language plpgsql security definer set search_path=public as $$
begin update public.project_members set role=new.role where user_id=new.user_id and company_id=new.company_id; return new; end $$;
drop trigger if exists sync_project_member_role on public.memberships;
create trigger sync_project_member_role after update of role on public.memberships for each row execute procedure public.sync_project_role();

-- Owner-only RPCs. These avoid trusting client-side role fields for admin actions.
create or replace function public.change_member_role(target_membership_id uuid,new_role public.member_role) returns void language plpgsql security definer set search_path=public as $$
declare cid uuid; target_role public.member_role; owner_count integer;
begin
 select company_id,role into cid,target_role from public.memberships where id=target_membership_id;
 if cid is null then raise exception 'Membership not found'; end if;
 if not public.is_company_owner(cid) then raise exception 'Owner access required'; end if;
 if new_role='owner' then raise exception 'Owner role cannot be assigned from this screen'; end if;
 if target_role='owner' then raise exception 'The owner role cannot be changed'; end if;
 update public.memberships set role=new_role where id=target_membership_id;
end $$;

create or replace function public.remove_company_member(target_membership_id uuid) returns void language plpgsql security definer set search_path=public as $$
declare cid uuid; target_user uuid; target_role public.member_role;
begin
 select company_id,user_id,role into cid,target_user,target_role from public.memberships where id=target_membership_id;
 if cid is null then raise exception 'Membership not found'; end if;
 if not public.is_company_owner(cid) then raise exception 'Owner access required'; end if;
 if target_role='owner' then raise exception 'The owner cannot be removed'; end if;
 delete from public.memberships where id=target_membership_id;
end $$;

create or replace function public.cancel_invitation(invitation_id uuid) returns void language plpgsql security definer set search_path=public as $$
declare cid uuid;
begin
 select company_id into cid from public.invitations where id=invitation_id;
 if cid is null then raise exception 'Invitation not found'; end if;
 if not public.is_company_owner(cid) then raise exception 'Owner access required'; end if;
 update public.invitations set status='cancelled' where id=invitation_id and status='pending';
end $$;

-- Signup trigger: first owner creates a company; invited signups are attached to the existing company.
create or replace function public.handle_new_user() returns trigger language plpgsql security definer set search_path=public as $$
declare cid uuid; cname text; inv public.invitations%rowtype;
begin
 select * into inv from public.invitations where lower(email)=lower(new.email) and status='pending' and expires_at>now() order by created_at desc limit 1;
 if inv.id is not null then
   insert into public.memberships(company_id,user_id,role,full_name) values(inv.company_id,new.id,inv.role,new.raw_user_meta_data->>'full_name') on conflict (company_id,user_id) do update set role=excluded.role,full_name=excluded.full_name;
   update public.invitations set status='accepted',accepted_at=now() where id=inv.id;
 else
   cname:=coalesce(new.raw_user_meta_data->>'company_name','My Renovation Company');
   insert into public.companies(name) values(cname) returning id into cid;
   insert into public.memberships(company_id,user_id,role,full_name) values(cid,new.id,'owner',new.raw_user_meta_data->>'full_name');
 end if;
 return new;
end; $$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users for each row execute procedure public.handle_new_user();
