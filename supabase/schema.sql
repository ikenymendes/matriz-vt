-- =====================================================================
--  MATRIZ VT · Mega Mídia OOH  —  estrutura do banco (Supabase / Postgres)
--  Como usar: Supabase → SQL Editor → New query → cole TUDO → Run.
--  Pode rodar de novo sem problema (é idempotente).
-- =====================================================================

-- 1) PERFIS: quem pode entrar e com qual papel -------------------------
create table if not exists public.perfis (
  id        uuid primary key references auth.users(id) on delete cascade,
  email     text,
  nome      text,
  papel     text not null default 'operador' check (papel in ('admin','operador')),
  ativo     boolean not null default true,
  criado_em timestamptz not null default now()
);

-- 2) REGISTROS: todos os dados do sistema, um registro por linha --------
--    chave  = "tipo:id" (ex.: vt:v1793..., fx:p15, ft:v1793...__p15)
--    tipo   = fx pontos fixos | vr pontos variáveis | vt campanhas/eventos
--             ft fotos | mn manutenções | es estáticos | cf circuitos fixos
--             cfg configurações (base, motoboys, prioridades) | rot rota
--    u      = data/hora da última alteração (ms) — vence o mais recente
--    rev    = contador do servidor (usado na sincronização)
create sequence if not exists public.registros_rev_seq;
create table if not exists public.registros (
  chave          text primary key,
  tipo           text not null check (tipo in ('fx','vr','vt','ft','mn','es','cf','cfg','rot')),
  dados          jsonb,
  u              bigint not null default 0,
  excluido       boolean not null default false,
  rev            bigint not null default nextval('public.registros_rev_seq'),
  atualizado_por uuid,
  atualizado_em  timestamptz not null default now(),
  constraint registros_chave_tipo check (split_part(chave, ':', 1) = tipo)
);
create index if not exists registros_rev_idx on public.registros (rev);

-- 3) FUNÇÕES AUXILIARES --------------------------------------------------
create or replace function public.eh_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.perfis where id = auth.uid() and papel = 'admin' and ativo);
$$;

create or replace function public.eh_ativo() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.perfis where id = auth.uid() and ativo);
$$;

-- Primeiro usuário criado vira ADMIN; os demais entram como OPERADOR.
create or replace function public.novo_usuario() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into public.perfis (id, email, nome, papel)
  values (new.id, new.email,
          coalesce(new.raw_user_meta_data->>'nome', split_part(new.email, '@', 1)),
          case when exists (select 1 from public.perfis) then 'operador' else 'admin' end)
  on conflict (id) do nothing;
  return new;
end $$;
drop trigger if exists ao_criar_usuario on auth.users;
create trigger ao_criar_usuario after insert on auth.users
  for each row execute function public.novo_usuario();

-- Nunca deixar o sistema sem nenhum admin ativo.
create or replace function public.protege_ultimo_admin() returns trigger
language plpgsql as $$
begin
  if (old.papel = 'admin' and old.ativo) and not (new.papel = 'admin' and new.ativo) then
    if not exists (select 1 from public.perfis where papel = 'admin' and ativo and id <> old.id) then
      raise exception 'Precisa existir pelo menos um admin ativo.';
    end if;
  end if;
  return new;
end $$;
drop trigger if exists protege_admin on public.perfis;
create trigger protege_admin before update on public.perfis
  for each row execute function public.protege_ultimo_admin();

-- Carimba cada gravação com o contador do servidor e o autor.
create or replace function public.carimba_registro() returns trigger
language plpgsql as $$
begin
  new.rev := nextval('public.registros_rev_seq');
  new.atualizado_por := auth.uid();
  new.atualizado_em := now();
  return new;
end $$;
drop trigger if exists carimba on public.registros;
create trigger carimba before insert or update on public.registros
  for each row execute function public.carimba_registro();

-- 4) PERMISSÕES (RLS) ----------------------------------------------------
alter table public.perfis    enable row level security;
alter table public.registros enable row level security;

-- Perfis: cada um vê o seu; o admin vê e edita todos.
drop policy if exists perfis_ver on public.perfis;
create policy perfis_ver on public.perfis for select to authenticated
  using (id = auth.uid() or public.eh_admin());
drop policy if exists perfis_editar on public.perfis;
create policy perfis_editar on public.perfis for update to authenticated
  using (public.eh_admin()) with check (public.eh_admin());

-- Registros: todos os usuários ativos leem.
drop policy if exists reg_ver on public.registros;
create policy reg_ver on public.registros for select to authenticated
  using (public.eh_ativo());

-- Criar: qualquer usuário ativo cria tudo, EXCETO pontos fixos (fx) e
-- configurações (cfg), que só o admin cria. (Ponto variável novo = livre.)
drop policy if exists reg_criar on public.registros;
create policy reg_criar on public.registros for insert to authenticated
  with check (public.eh_ativo() and (tipo not in ('fx','cfg') or public.eh_admin()));

-- Alterar/apagar: pontos fixos (fx), pontos variáveis (vr) e configurações
-- (cfg) SÓ o admin. Todo o resto (campanhas, fotos, manutenção...) é livre.
-- Para proteger mais tipos (ex.: 'es' estáticos), acrescente na lista abaixo.
drop policy if exists reg_alterar on public.registros;
create policy reg_alterar on public.registros for update to authenticated
  using (public.eh_ativo() and (tipo not in ('fx','vr','cfg') or public.eh_admin()))
  with check (public.eh_ativo() and (tipo not in ('fx','vr','cfg') or public.eh_admin()));

drop policy if exists reg_apagar on public.registros;
create policy reg_apagar on public.registros for delete to authenticated
  using (public.eh_admin());

-- 5) GRAVAÇÃO EM LOTE (o sistema usa esta função) -------------------------
--    Recebe uma lista de registros e devolve o que foi aceito, o que foi
--    negado por permissão e o que estava desatualizado (alguém gravou depois).
create or replace function public.gravar_registros(p jsonb) returns jsonb
language plpgsql security invoker set search_path = public as $$
declare
  r jsonb; k text; t text; nu bigint; n int; cur bigint;
  ok text[] := '{}'; negado text[] := '{}'; antigo text[] := '{}';
begin
  for r in select * from jsonb_array_elements(p) loop
    k := r->>'chave'; t := r->>'tipo'; nu := coalesce((r->>'u')::bigint, 0);
    update public.registros
       set tipo = t, dados = r->'dados', u = nu, excluido = coalesce((r->>'excluido')::boolean, false)
     where chave = k and u <= nu;
    get diagnostics n = row_count;
    if n > 0 then
      ok := ok || k;
    else
      select u into cur from public.registros where chave = k;
      if found then
        if cur > nu then antigo := antigo || k; else negado := negado || k; end if;
      else
        begin
          insert into public.registros (chave, tipo, dados, u, excluido)
          values (k, t, r->'dados', nu, coalesce((r->>'excluido')::boolean, false));
          ok := ok || k;
        exception when insufficient_privilege or check_violation then
          negado := negado || k;
        end;
      end if;
    end if;
  end loop;
  return jsonb_build_object('ok', to_jsonb(ok), 'negado', to_jsonb(negado), 'antigo', to_jsonb(antigo));
end $$;

-- 6) ACESSOS ----------------------------------------------------------------
revoke all on public.perfis, public.registros from anon;
grant select, update on public.perfis to authenticated;
grant select, insert, update, delete on public.registros to authenticated;
revoke all on function public.gravar_registros(jsonb) from public, anon;
grant execute on function public.gravar_registros(jsonb) to authenticated;
grant usage on sequence public.registros_rev_seq to authenticated;
