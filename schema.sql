-- The South Punjab School – Student Registration System (Stage 1)
-- Run in Supabase: SQL Editor > New query > Run

create extension if not exists pg_trgm;

-- ---------- Roles ----------
create table profiles (
  id uuid primary key references auth.users on delete cascade,
  full_name text,
  role text not null default 'viewer' check (role in ('admin','staff','viewer')),
  created_at timestamptz default now()
);

create function public.role() returns text language sql stable security definer set search_path = public as
$$ select role from profiles where id = auth.uid() $$;

-- first user to sign up becomes admin; everyone else is viewer until an admin changes it
create function public.handle_new_user() returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into profiles(id, full_name, role)
  values (new.id, new.raw_user_meta_data->>'full_name',
          case when (select count(*) from profiles) = 0 then 'admin' else 'viewer' end);
  return new;
end $$;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function handle_new_user();

-- ---------- Settings & counters ----------
create table settings (
  id int primary key default 1 check (id = 1),
  school_name text default 'The South Punjab School Chowk Azam, Layyah',
  adm_prefix text default 'SPS',
  adm_include_year boolean default true,
  academic_session text default '2026-27'
);
insert into settings default values;

create table adm_counter (year int primary key, last_no int not null default 0); -- never decremented => numbers never reused

create table classes (
  id serial primary key, name text unique not null, sort int, active boolean default true
);
insert into classes(name, sort) select n, row_number() over () from unnest(array
  ['Play','Nursery','Prep','Class 1','Class 2','Class 3','Class 4','Class 5','Class 6','Class 7','Class 8','Class 9','Class 10']) n;

-- ---------- Students ----------
create table students (
  id uuid primary key default gen_random_uuid(),
  admission_no text unique,
  full_name text not null,
  father_name text not null,
  dob date check (dob < current_date),
  gender text check (gender in ('Male','Female')),
  admission_date date default current_date,
  class_name text references classes(name) on update cascade,
  section text,
  prev_school text, prev_class text,
  status text not null default 'Active' check (status in ('Active','Inactive','Withdrawn','Graduated')),
  workflow text not null default 'Submitted' check (workflow in ('Draft','Submitted','Under Review','Approved','Rejected')),
  father_phone text check (father_phone ~ '^03[0-9]{9}$'),
  mother_name text, mother_phone text, guardian_name text, guardian_relation text,
  father_cnic text check (father_cnic is null or father_cnic ~ '^[0-9]{5}-?[0-9]{7}-?[0-9]$'),
  address text, city text, emergency_phone text,
  medical_notes text,            -- hidden from viewers via view below
  remarks text,
  photo_path text,               -- private storage bucket path
  archived boolean default false,
  created_by uuid default auth.uid(), created_at timestamptz default now(),
  updated_at timestamptz default now()
);
create index on students using gin (full_name gin_trgm_ops);
create index on students using gin (father_name gin_trgm_ops);
create index on students (class_name, status);
create index on students (father_phone);

-- atomic, race-free admission number
create function public.assign_admission_no() returns trigger language plpgsql security definer set search_path = public as $$
declare s settings; y int := extract(year from coalesce(new.admission_date,current_date)); n int;
begin
  if new.admission_no is not null and new.admission_no <> '' then return new; end if;
  select * into s from settings;
  insert into adm_counter(year,last_no) values (y,1)
    on conflict (year) do update set last_no = adm_counter.last_no + 1 returning last_no into n;
  new.admission_no := s.adm_prefix || '-' || case when s.adm_include_year then y::text || '-' else '' end || lpad(n::text,4,'0');
  return new;
end $$;
create trigger trg_adm before insert on students for each row execute function assign_admission_no();

create function public.touch() returns trigger language plpgsql as $$ begin new.updated_at = now(); return new; end $$;
create trigger trg_touch before update on students for each row execute function touch();

-- viewer-safe view (no medical notes, no CNIC)
create view students_public with (security_invoker = true) as
  select id, admission_no, full_name, father_name, dob, gender, admission_date, class_name, section, status,
         workflow, father_phone, address, city, photo_path, archived, created_at, updated_at from students;

-- ---------- Audit ----------
create table audit_log (
  id bigserial primary key, at timestamptz default now(), user_id uuid default auth.uid(),
  action text, table_name text, record_id text, detail jsonb
);
create function public.audit() returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into audit_log(action, table_name, record_id, detail)
  values (tg_op, tg_table_name, coalesce(new.id::text, old.id::text),
          jsonb_build_object('name', coalesce(new.full_name, old.full_name), 'adm', coalesce(new.admission_no, old.admission_no)));
  return coalesce(new, old);
end $$;
create trigger trg_audit after insert or update or delete on students for each row execute function audit();

-- ---------- Row Level Security (enforced by the database, not the browser) ----------
alter table profiles enable row level security;
alter table settings enable row level security;
alter table classes enable row level security;
alter table students enable row level security;
alter table audit_log enable row level security;
alter table adm_counter enable row level security;

create policy p_self on profiles for select using (id = auth.uid() or public.role() = 'admin');
create policy p_admin_upd on profiles for update using (public.role() = 'admin');
create policy set_read on settings for select using (auth.uid() is not null);
create policy set_admin on settings for update using (public.role() = 'admin');
create policy cls_read on classes for select using (auth.uid() is not null);
create policy cls_admin on classes for all using (public.role() = 'admin');

-- viewers read through students_public only; base table needs staff/admin
create policy st_read on students for select using (public.role() in ('admin','staff'));
create policy st_ins on students for insert with check (public.role() in ('admin','staff'));
create policy st_upd on students for update using (public.role() in ('admin','staff'));
create policy st_del on students for delete using (public.role() = 'admin');
create policy aud_read on audit_log for select using (public.role() = 'admin');
grant select on students_public to authenticated;
-- viewer access to the view: security_invoker would apply st_read, so allow viewers a limited read policy:
create policy st_viewer on students for select using (public.role() = 'viewer');
-- table-level SELECT must be revoked first; column-level revokes have no effect otherwise
revoke select on students from authenticated;
grant select (id, admission_no, full_name, father_name, dob, gender, admission_date, class_name, section, status,
  workflow, father_phone, address, city, photo_path, archived, created_at, updated_at) on students to authenticated;
-- NOTE: staff/admin read these sensitive columns through the RPC below
create function public.student_full(sid uuid) returns students language sql stable security definer set search_path = public as
$$ select * from students where id = sid and public.role() in ('admin','staff') $$;

-- ---------- Private photo bucket ----------
insert into storage.buckets(id, name, public, file_size_limit, allowed_mime_types)
values ('student-photos','student-photos', false, 1048576, array['image/jpeg','image/png','image/webp']);
create policy ph_read on storage.objects for select using (bucket_id='student-photos' and auth.uid() is not null);
create policy ph_write on storage.objects for insert with check (bucket_id='student-photos' and public.role() in ('admin','staff'));
