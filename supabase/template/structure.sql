--
-- PostgreSQL database dump
--

\restrict aPxfMzRoOk7OTOF61hS1d6jUVsZnBrf9zRW1S3cGJjkFdcgbGcwHcixYDH0XUO9

-- Dumped from database version 17.6
-- Dumped by pg_dump version 17.7 (Ubuntu 17.7-3.pgdg24.04+1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: auth; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA "auth";


--
-- Name: pg_cron; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS "pg_cron" WITH SCHEMA "pg_catalog";


--
-- Name: EXTENSION "pg_cron"; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION "pg_cron" IS 'Job scheduler for PostgreSQL';


--
-- Name: extensions; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA "extensions";


--
-- Name: graphql; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA "graphql";


--
-- Name: graphql_public; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA "graphql_public";


--
-- Name: pg_net; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS "pg_net" WITH SCHEMA "extensions";


--
-- Name: EXTENSION "pg_net"; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION "pg_net" IS 'Async HTTP';


--
-- Name: pgbouncer; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA "pgbouncer";


--
-- Name: SCHEMA "public"; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON SCHEMA "public" IS 'standard public schema';


--
-- Name: realtime; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA "realtime";


--
-- Name: storage; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA "storage";


--
-- Name: supabase_migrations; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA "supabase_migrations";


--
-- Name: vault; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA "vault";


--
-- Name: pg_graphql; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS "pg_graphql" WITH SCHEMA "graphql";


--
-- Name: EXTENSION "pg_graphql"; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION "pg_graphql" IS 'pg_graphql: GraphQL support';


--
-- Name: pg_stat_statements; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS "pg_stat_statements" WITH SCHEMA "extensions";


--
-- Name: EXTENSION "pg_stat_statements"; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION "pg_stat_statements" IS 'track planning and execution statistics of all SQL statements executed';


--
-- Name: pgcrypto; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS "pgcrypto" WITH SCHEMA "extensions";


--
-- Name: EXTENSION "pgcrypto"; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION "pgcrypto" IS 'cryptographic functions';


--
-- Name: supabase_vault; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS "supabase_vault" WITH SCHEMA "vault";


--
-- Name: EXTENSION "supabase_vault"; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION "supabase_vault" IS 'Supabase Vault Extension';


--
-- Name: uuid-ossp; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA "extensions";


--
-- Name: EXTENSION "uuid-ossp"; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION "uuid-ossp" IS 'generate universally unique identifiers (UUIDs)';


--
-- Name: aal_level; Type: TYPE; Schema: auth; Owner: -
--

CREATE TYPE "auth"."aal_level" AS ENUM (
    'aal1',
    'aal2',
    'aal3'
);


--
-- Name: code_challenge_method; Type: TYPE; Schema: auth; Owner: -
--

CREATE TYPE "auth"."code_challenge_method" AS ENUM (
    's256',
    'plain'
);


--
-- Name: factor_status; Type: TYPE; Schema: auth; Owner: -
--

CREATE TYPE "auth"."factor_status" AS ENUM (
    'unverified',
    'verified'
);


--
-- Name: factor_type; Type: TYPE; Schema: auth; Owner: -
--

CREATE TYPE "auth"."factor_type" AS ENUM (
    'totp',
    'webauthn',
    'phone'
);


--
-- Name: oauth_authorization_status; Type: TYPE; Schema: auth; Owner: -
--

CREATE TYPE "auth"."oauth_authorization_status" AS ENUM (
    'pending',
    'approved',
    'denied',
    'expired'
);


--
-- Name: oauth_client_type; Type: TYPE; Schema: auth; Owner: -
--

CREATE TYPE "auth"."oauth_client_type" AS ENUM (
    'public',
    'confidential'
);


--
-- Name: oauth_registration_type; Type: TYPE; Schema: auth; Owner: -
--

CREATE TYPE "auth"."oauth_registration_type" AS ENUM (
    'dynamic',
    'manual'
);


--
-- Name: oauth_response_type; Type: TYPE; Schema: auth; Owner: -
--

CREATE TYPE "auth"."oauth_response_type" AS ENUM (
    'code'
);


--
-- Name: one_time_token_type; Type: TYPE; Schema: auth; Owner: -
--

CREATE TYPE "auth"."one_time_token_type" AS ENUM (
    'confirmation_token',
    'reauthentication_token',
    'recovery_token',
    'email_change_token_new',
    'email_change_token_current',
    'phone_change_token'
);


--
-- Name: booking_status; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE "public"."booking_status" AS ENUM (
    'pending',
    'confirmed',
    'checked_in',
    'checked_out',
    'cancelled',
    'no_show'
);


--
-- Name: data_classification; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE "public"."data_classification" AS ENUM (
    'PUBLIC',
    'RESTRICTED',
    'CONFIDENTIAL'
);


--
-- Name: expense_status; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE "public"."expense_status" AS ENUM (
    'pending',
    'approved',
    'rejected',
    'paid'
);


--
-- Name: payment_status; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE "public"."payment_status" AS ENUM (
    'pending',
    'partial',
    'paid',
    'refunded'
);


--
-- Name: room_status; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE "public"."room_status" AS ENUM (
    'occupied',
    'cleaning',
    'cleaned',
    'maintenance',
    'dirty',
    'available',
    'discontinued'
);


--
-- Name: user_status; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE "public"."user_status" AS ENUM (
    'active',
    'inactive',
    'suspended'
);


--
-- Name: action; Type: TYPE; Schema: realtime; Owner: -
--

CREATE TYPE "realtime"."action" AS ENUM (
    'INSERT',
    'UPDATE',
    'DELETE',
    'TRUNCATE',
    'ERROR'
);


--
-- Name: equality_op; Type: TYPE; Schema: realtime; Owner: -
--

CREATE TYPE "realtime"."equality_op" AS ENUM (
    'eq',
    'neq',
    'lt',
    'lte',
    'gt',
    'gte',
    'in'
);


--
-- Name: user_defined_filter; Type: TYPE; Schema: realtime; Owner: -
--

CREATE TYPE "realtime"."user_defined_filter" AS (
	"column_name" "text",
	"op" "realtime"."equality_op",
	"value" "text"
);


--
-- Name: wal_column; Type: TYPE; Schema: realtime; Owner: -
--

CREATE TYPE "realtime"."wal_column" AS (
	"name" "text",
	"type_name" "text",
	"type_oid" "oid",
	"value" "jsonb",
	"is_pkey" boolean,
	"is_selectable" boolean
);


--
-- Name: wal_rls; Type: TYPE; Schema: realtime; Owner: -
--

CREATE TYPE "realtime"."wal_rls" AS (
	"wal" "jsonb",
	"is_rls_enabled" boolean,
	"subscription_ids" "uuid"[],
	"errors" "text"[]
);


--
-- Name: buckettype; Type: TYPE; Schema: storage; Owner: -
--

CREATE TYPE "storage"."buckettype" AS ENUM (
    'STANDARD',
    'ANALYTICS',
    'VECTOR'
);


--
-- Name: email(); Type: FUNCTION; Schema: auth; Owner: -
--

CREATE FUNCTION "auth"."email"() RETURNS "text"
    LANGUAGE "sql" STABLE
    AS $$
  select 
  coalesce(
    nullif(current_setting('request.jwt.claim.email', true), ''),
    (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'email')
  )::text
$$;


--
-- Name: FUNCTION "email"(); Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON FUNCTION "auth"."email"() IS 'Deprecated. Use auth.jwt() -> ''email'' instead.';


--
-- Name: jwt(); Type: FUNCTION; Schema: auth; Owner: -
--

CREATE FUNCTION "auth"."jwt"() RETURNS "jsonb"
    LANGUAGE "sql" STABLE
    AS $$
  select 
    coalesce(
        nullif(current_setting('request.jwt.claim', true), ''),
        nullif(current_setting('request.jwt.claims', true), '')
    )::jsonb
$$;


--
-- Name: role(); Type: FUNCTION; Schema: auth; Owner: -
--

CREATE FUNCTION "auth"."role"() RETURNS "text"
    LANGUAGE "sql" STABLE
    AS $$
  select 
  coalesce(
    nullif(current_setting('request.jwt.claim.role', true), ''),
    (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'role')
  )::text
$$;


--
-- Name: FUNCTION "role"(); Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON FUNCTION "auth"."role"() IS 'Deprecated. Use auth.jwt() -> ''role'' instead.';


--
-- Name: uid(); Type: FUNCTION; Schema: auth; Owner: -
--

CREATE FUNCTION "auth"."uid"() RETURNS "uuid"
    LANGUAGE "sql" STABLE
    AS $$
  select 
  coalesce(
    nullif(current_setting('request.jwt.claim.sub', true), ''),
    (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'sub')
  )::uuid
$$;


--
-- Name: FUNCTION "uid"(); Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON FUNCTION "auth"."uid"() IS 'Deprecated. Use auth.jwt() -> ''sub'' instead.';


--
-- Name: grant_pg_cron_access(); Type: FUNCTION; Schema: extensions; Owner: -
--

CREATE FUNCTION "extensions"."grant_pg_cron_access"() RETURNS "event_trigger"
    LANGUAGE "plpgsql"
    AS $$
BEGIN
  IF EXISTS (
    SELECT
    FROM pg_event_trigger_ddl_commands() AS ev
    JOIN pg_extension AS ext
    ON ev.objid = ext.oid
    WHERE ext.extname = 'pg_cron'
  )
  THEN
    grant usage on schema cron to postgres with grant option;

    alter default privileges in schema cron grant all on tables to postgres with grant option;
    alter default privileges in schema cron grant all on functions to postgres with grant option;
    alter default privileges in schema cron grant all on sequences to postgres with grant option;

    alter default privileges for user supabase_admin in schema cron grant all
        on sequences to postgres with grant option;
    alter default privileges for user supabase_admin in schema cron grant all
        on tables to postgres with grant option;
    alter default privileges for user supabase_admin in schema cron grant all
        on functions to postgres with grant option;

    grant all privileges on all tables in schema cron to postgres with grant option;
    revoke all on table cron.job from postgres;
    grant select on table cron.job to postgres with grant option;
  END IF;
END;
$$;


--
-- Name: FUNCTION "grant_pg_cron_access"(); Type: COMMENT; Schema: extensions; Owner: -
--

COMMENT ON FUNCTION "extensions"."grant_pg_cron_access"() IS 'Grants access to pg_cron';


--
-- Name: grant_pg_graphql_access(); Type: FUNCTION; Schema: extensions; Owner: -
--

CREATE FUNCTION "extensions"."grant_pg_graphql_access"() RETURNS "event_trigger"
    LANGUAGE "plpgsql"
    AS $_$
DECLARE
    func_is_graphql_resolve bool;
BEGIN
    func_is_graphql_resolve = (
        SELECT n.proname = 'resolve'
        FROM pg_event_trigger_ddl_commands() AS ev
        LEFT JOIN pg_catalog.pg_proc AS n
        ON ev.objid = n.oid
    );

    IF func_is_graphql_resolve
    THEN
        -- Update public wrapper to pass all arguments through to the pg_graphql resolve func
        DROP FUNCTION IF EXISTS graphql_public.graphql;
        create or replace function graphql_public.graphql(
            "operationName" text default null,
            query text default null,
            variables jsonb default null,
            extensions jsonb default null
        )
            returns jsonb
            language sql
        as $$
            select graphql.resolve(
                query := query,
                variables := coalesce(variables, '{}'),
                "operationName" := "operationName",
                extensions := extensions
            );
        $$;

        -- This hook executes when `graphql.resolve` is created. That is not necessarily the last
        -- function in the extension so we need to grant permissions on existing entities AND
        -- update default permissions to any others that are created after `graphql.resolve`
        grant usage on schema graphql to postgres, anon, authenticated, service_role;
        grant select on all tables in schema graphql to postgres, anon, authenticated, service_role;
        grant execute on all functions in schema graphql to postgres, anon, authenticated, service_role;
        grant all on all sequences in schema graphql to postgres, anon, authenticated, service_role;
        alter default privileges in schema graphql grant all on tables to postgres, anon, authenticated, service_role;
        alter default privileges in schema graphql grant all on functions to postgres, anon, authenticated, service_role;
        alter default privileges in schema graphql grant all on sequences to postgres, anon, authenticated, service_role;

        -- Allow postgres role to allow granting usage on graphql and graphql_public schemas to custom roles
        grant usage on schema graphql_public to postgres with grant option;
        grant usage on schema graphql to postgres with grant option;
    END IF;

END;
$_$;


--
-- Name: FUNCTION "grant_pg_graphql_access"(); Type: COMMENT; Schema: extensions; Owner: -
--

COMMENT ON FUNCTION "extensions"."grant_pg_graphql_access"() IS 'Grants access to pg_graphql';


--
-- Name: grant_pg_net_access(); Type: FUNCTION; Schema: extensions; Owner: -
--

CREATE FUNCTION "extensions"."grant_pg_net_access"() RETURNS "event_trigger"
    LANGUAGE "plpgsql"
    AS $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM pg_event_trigger_ddl_commands() AS ev
    JOIN pg_extension AS ext
    ON ev.objid = ext.oid
    WHERE ext.extname = 'pg_net'
  )
  THEN
    IF NOT EXISTS (
      SELECT 1
      FROM pg_roles
      WHERE rolname = 'supabase_functions_admin'
    )
    THEN
      CREATE USER supabase_functions_admin NOINHERIT CREATEROLE LOGIN NOREPLICATION;
    END IF;

    GRANT USAGE ON SCHEMA net TO supabase_functions_admin, postgres, anon, authenticated, service_role;

    IF EXISTS (
      SELECT FROM pg_extension
      WHERE extname = 'pg_net'
      -- all versions in use on existing projects as of 2025-02-20
      -- version 0.12.0 onwards don't need these applied
      AND extversion IN ('0.2', '0.6', '0.7', '0.7.1', '0.8', '0.10.0', '0.11.0')
    ) THEN
      ALTER function net.http_get(url text, params jsonb, headers jsonb, timeout_milliseconds integer) SECURITY DEFINER;
      ALTER function net.http_post(url text, body jsonb, params jsonb, headers jsonb, timeout_milliseconds integer) SECURITY DEFINER;

      ALTER function net.http_get(url text, params jsonb, headers jsonb, timeout_milliseconds integer) SET search_path = net;
      ALTER function net.http_post(url text, body jsonb, params jsonb, headers jsonb, timeout_milliseconds integer) SET search_path = net;

      REVOKE ALL ON FUNCTION net.http_get(url text, params jsonb, headers jsonb, timeout_milliseconds integer) FROM PUBLIC;
      REVOKE ALL ON FUNCTION net.http_post(url text, body jsonb, params jsonb, headers jsonb, timeout_milliseconds integer) FROM PUBLIC;

      GRANT EXECUTE ON FUNCTION net.http_get(url text, params jsonb, headers jsonb, timeout_milliseconds integer) TO supabase_functions_admin, postgres, anon, authenticated, service_role;
      GRANT EXECUTE ON FUNCTION net.http_post(url text, body jsonb, params jsonb, headers jsonb, timeout_milliseconds integer) TO supabase_functions_admin, postgres, anon, authenticated, service_role;
    END IF;
  END IF;
END;
$$;


--
-- Name: FUNCTION "grant_pg_net_access"(); Type: COMMENT; Schema: extensions; Owner: -
--

COMMENT ON FUNCTION "extensions"."grant_pg_net_access"() IS 'Grants access to pg_net';


--
-- Name: pgrst_ddl_watch(); Type: FUNCTION; Schema: extensions; Owner: -
--

CREATE FUNCTION "extensions"."pgrst_ddl_watch"() RETURNS "event_trigger"
    LANGUAGE "plpgsql"
    AS $$
DECLARE
  cmd record;
BEGIN
  FOR cmd IN SELECT * FROM pg_event_trigger_ddl_commands()
  LOOP
    IF cmd.command_tag IN (
      'CREATE SCHEMA', 'ALTER SCHEMA'
    , 'CREATE TABLE', 'CREATE TABLE AS', 'SELECT INTO', 'ALTER TABLE'
    , 'CREATE FOREIGN TABLE', 'ALTER FOREIGN TABLE'
    , 'CREATE VIEW', 'ALTER VIEW'
    , 'CREATE MATERIALIZED VIEW', 'ALTER MATERIALIZED VIEW'
    , 'CREATE FUNCTION', 'ALTER FUNCTION'
    , 'CREATE TRIGGER'
    , 'CREATE TYPE', 'ALTER TYPE'
    , 'CREATE RULE'
    , 'COMMENT'
    )
    -- don't notify in case of CREATE TEMP table or other objects created on pg_temp
    AND cmd.schema_name is distinct from 'pg_temp'
    THEN
      NOTIFY pgrst, 'reload schema';
    END IF;
  END LOOP;
END; $$;


--
-- Name: pgrst_drop_watch(); Type: FUNCTION; Schema: extensions; Owner: -
--

CREATE FUNCTION "extensions"."pgrst_drop_watch"() RETURNS "event_trigger"
    LANGUAGE "plpgsql"
    AS $$
DECLARE
  obj record;
BEGIN
  FOR obj IN SELECT * FROM pg_event_trigger_dropped_objects()
  LOOP
    IF obj.object_type IN (
      'schema'
    , 'table'
    , 'foreign table'
    , 'view'
    , 'materialized view'
    , 'function'
    , 'trigger'
    , 'type'
    , 'rule'
    )
    AND obj.is_temporary IS false -- no pg_temp objects
    THEN
      NOTIFY pgrst, 'reload schema';
    END IF;
  END LOOP;
END; $$;


--
-- Name: set_graphql_placeholder(); Type: FUNCTION; Schema: extensions; Owner: -
--

CREATE FUNCTION "extensions"."set_graphql_placeholder"() RETURNS "event_trigger"
    LANGUAGE "plpgsql"
    AS $_$
    DECLARE
    graphql_is_dropped bool;
    BEGIN
    graphql_is_dropped = (
        SELECT ev.schema_name = 'graphql_public'
        FROM pg_event_trigger_dropped_objects() AS ev
        WHERE ev.schema_name = 'graphql_public'
    );

    IF graphql_is_dropped
    THEN
        create or replace function graphql_public.graphql(
            "operationName" text default null,
            query text default null,
            variables jsonb default null,
            extensions jsonb default null
        )
            returns jsonb
            language plpgsql
        as $$
            DECLARE
                server_version float;
            BEGIN
                server_version = (SELECT (SPLIT_PART((select version()), ' ', 2))::float);

                IF server_version >= 14 THEN
                    RETURN jsonb_build_object(
                        'errors', jsonb_build_array(
                            jsonb_build_object(
                                'message', 'pg_graphql extension is not enabled.'
                            )
                        )
                    );
                ELSE
                    RETURN jsonb_build_object(
                        'errors', jsonb_build_array(
                            jsonb_build_object(
                                'message', 'pg_graphql is only available on projects running Postgres 14 onwards.'
                            )
                        )
                    );
                END IF;
            END;
        $$;
    END IF;

    END;
$_$;


--
-- Name: FUNCTION "set_graphql_placeholder"(); Type: COMMENT; Schema: extensions; Owner: -
--

COMMENT ON FUNCTION "extensions"."set_graphql_placeholder"() IS 'Reintroduces placeholder function for graphql_public.graphql';


--
-- Name: get_auth("text"); Type: FUNCTION; Schema: pgbouncer; Owner: -
--

CREATE FUNCTION "pgbouncer"."get_auth"("p_usename" "text") RETURNS TABLE("username" "text", "password" "text")
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $_$
begin
    raise debug 'PgBouncer auth request: %', p_usename;

    return query
    select 
        rolname::text, 
        case when rolvaliduntil < now() 
            then null 
            else rolpassword::text 
        end 
    from pg_authid 
    where rolname=$1 and rolcanlogin;
end;
$_$;


--
-- Name: audit_trigger(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."audit_trigger"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'pg_temp'
    AS $$
DECLARE
  client_ip text;
BEGIN
  -- Use the secure IP function
  client_ip := get_real_client_ip();
  
  INSERT INTO public.audit_logs (
    user_id,
    action,
    table_name,
    record_id,
    old_values,
    new_values,
    ip_address,
    user_agent
  ) VALUES (
    auth.uid(),
    TG_OP,
    TG_TABLE_NAME,
    COALESCE(NEW.id, OLD.id),
    CASE 
      WHEN TG_OP = 'DELETE' THEN to_jsonb(OLD)
      WHEN TG_OP = 'UPDATE' THEN to_jsonb(OLD)
      ELSE NULL 
    END,
    CASE 
      WHEN TG_OP = 'INSERT' OR TG_OP = 'UPDATE' THEN to_jsonb(NEW) 
      ELSE NULL 
    END,
    client_ip::inet,
    current_setting('request.headers', true)::json->>'user-agent'
  );
  
  RETURN COALESCE(NEW, OLD);
END;
$$;


--
-- Name: can_access_guest_document("text"); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."can_access_guest_document"("file_path" "text") RETURNS boolean
    LANGUAGE "plpgsql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public', 'pg_temp', 'storage'
    AS $$
DECLARE
  guest_record RECORD;
BEGIN
  -- Admin users can access all documents
  IF has_permission(auth.uid(), 'view_sensitive_guest_data') THEN
    RETURN true;
  END IF;
  
  -- Find guest by document URL
  SELECT id INTO guest_record
  FROM public.guests
  WHERE id_document_url LIKE '%' || file_path || '%';
  
  IF guest_record IS NULL THEN
    RETURN false;
  END IF;
  
  -- Check if user has access to this specific guest
  RETURN user_can_access_guest(guest_record.id);
END;
$$;


--
-- Name: check_password_security("text"); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."check_password_security"("password_text" "text") RETURNS "jsonb"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'pg_temp'
    AS $$
DECLARE
  result jsonb := '{"valid": true, "warnings": []}'::jsonb;
  warnings text[] := '{}';
  sanitized_password text;
BEGIN
  -- Input validation
  IF password_text IS NULL THEN
    RETURN jsonb_build_object('valid', false, 'warnings', ARRAY['Password is required'], 'strength_score', 'invalid');
  END IF;
  
  -- Length limits for security
  IF length(password_text) > 128 THEN
    RETURN jsonb_build_object('valid', false, 'warnings', ARRAY['Password is too long (max 128 characters)'], 'strength_score', 'invalid');
  END IF;
  
  -- Basic sanitization - remove null bytes and control characters
  sanitized_password := regexp_replace(password_text, '[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', 'g');
  
  -- Check minimum length
  IF length(sanitized_password) < 12 THEN
    warnings := array_append(warnings, 'Password must be at least 12 characters long');
  END IF;
  
  -- Check for uppercase letters
  IF sanitized_password !~ '[A-Z]' THEN
    warnings := array_append(warnings, 'Password must contain at least one uppercase letter');
  END IF;
  
  -- Check for lowercase letters
  IF sanitized_password !~ '[a-z]' THEN
    warnings := array_append(warnings, 'Password must contain at least one lowercase letter');
  END IF;
  
  -- Check for numbers
  IF sanitized_password !~ '[0-9]' THEN
    warnings := array_append(warnings, 'Password must contain at least one number');
  END IF;
  
  -- Check for special characters
  IF sanitized_password !~ '[^A-Za-z0-9]' THEN
    warnings := array_append(warnings, 'Password must contain at least one special character');
  END IF;
  
  -- Check for common patterns (case insensitive)
  IF sanitized_password ~* '(password|123456|qwerty|admin|user|login|guest|test|welcome|dragon|football|monkey|letmein|master|shadow|michael|superman|tigger|jordan|harley|ranger|hunter|soccer|hockey|andrew|daniel|martin|joseph|thomas|taylor|system|security)' THEN
    warnings := array_append(warnings, 'Password contains common words or patterns');
  END IF;
  
  -- Check for keyboard patterns
  IF sanitized_password ~* '(qwertyuiop|asdfghjkl|zxcvbnm|1234567890|0987654321|abcdefg|password123|admin123|user123)' THEN
    warnings := array_append(warnings, 'Password contains keyboard patterns');
  END IF;
  
  -- Check for repeated characters
  IF sanitized_password ~ '(.)\1{3,}' THEN
    warnings := array_append(warnings, 'Password contains too many repeated characters');
  END IF;
  
  -- Check for sequential patterns
  IF sanitized_password ~* '(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|123|234|345|456|567|678|789)' THEN
    warnings := array_append(warnings, 'Password contains sequential patterns');
  END IF;
  
  -- Build result
  result := jsonb_build_object(
    'valid', array_length(warnings, 1) IS NULL,
    'warnings', warnings,
    'strength_score', CASE 
      WHEN array_length(warnings, 1) IS NULL THEN 'strong'
      WHEN array_length(warnings, 1) <= 2 THEN 'medium'
      ELSE 'weak'
    END
  );
  
  -- Log weak password attempts
  IF array_length(warnings, 1) > 3 THEN
    PERFORM log_security_event(
      'WEAK_PASSWORD_ATTEMPT',
      'medium',
      'Weak password detected during validation',
      get_real_client_ip(),
      auth.uid(),
      jsonb_build_object('warnings_count', array_length(warnings, 1))
    );
  END IF;
  
  RETURN result;
  
EXCEPTION WHEN OTHERS THEN
  PERFORM log_security_event(
    'FUNCTION_ERROR',
    'medium',
    format('check_password_security function error: %s', SQLERRM),
    get_real_client_ip(),
    auth.uid(),
    jsonb_build_object('function', 'check_password_security')
  );
  RETURN jsonb_build_object('valid', false, 'warnings', ARRAY['Password validation failed'], 'strength_score', 'error');
END;
$$;


--
-- Name: check_rate_limit("text", "text", integer, integer); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."check_rate_limit"("identifier" "text", "action_type" "text", "max_requests" integer DEFAULT 100, "window_minutes" integer DEFAULT 60) RETURNS "jsonb"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'pg_temp'
    AS $_$
DECLARE
  current_count integer;
  window_start timestamp with time zone;
  is_blocked boolean := false;
  sanitized_identifier text;
  sanitized_action text;
BEGIN
  -- Input validation
  IF identifier IS NULL OR trim(identifier) = '' THEN
    RETURN jsonb_build_object('allowed', false, 'error', 'Identifier is required');
  END IF;
  
  IF action_type IS NULL OR trim(action_type) = '' THEN
    RETURN jsonb_build_object('allowed', false, 'error', 'Action type is required');
  END IF;
  
  -- Validate and sanitize inputs
  sanitized_identifier := trim(identifier);
  sanitized_action := trim(action_type);
  
  -- Length and format validation
  IF length(sanitized_identifier) > 45 THEN -- IP address max length
    RETURN jsonb_build_object('allowed', false, 'error', 'Invalid identifier');
  END IF;
  
  IF length(sanitized_action) > 50 THEN
    RETURN jsonb_build_object('allowed', false, 'error', 'Invalid action type');
  END IF;
  
  -- Validate action type format
  IF NOT sanitized_action ~ '^[a-zA-Z0-9_]+$' THEN
    RETURN jsonb_build_object('allowed', false, 'error', 'Invalid action type format');
  END IF;
  
  -- Validate numeric parameters
  IF max_requests IS NULL OR max_requests < 1 OR max_requests > 10000 THEN
    max_requests := 100;
  END IF;
  
  IF window_minutes IS NULL OR window_minutes < 1 OR window_minutes > 1440 THEN -- Max 24 hours
    window_minutes := 60;
  END IF;
  
  window_start := now() - (window_minutes || ' minutes')::interval;
  
  -- Count requests in the current window
  SELECT COUNT(*) INTO current_count
  FROM audit_logs
  WHERE action = sanitized_action
  AND ip_address = sanitized_identifier::inet
  AND timestamp > window_start;
  
  -- Check if limit exceeded
  IF current_count >= max_requests THEN
    is_blocked := true;
    
    -- Log rate limit violation
    PERFORM log_security_event(
      'RATE_LIMIT_EXCEEDED',
      'high',
      format('Rate limit exceeded: %s requests in %s minutes for %s', current_count, window_minutes, sanitized_action),
      sanitized_identifier,
      auth.uid(),
      jsonb_build_object(
        'current_count', current_count,
        'max_requests', max_requests,
        'window_minutes', window_minutes,
        'action_type', sanitized_action
      )
    );
  END IF;
  
  RETURN jsonb_build_object(
    'allowed', NOT is_blocked,
    'current_count', current_count,
    'max_requests', max_requests,
    'window_minutes', window_minutes,
    'reset_time', (window_start + (window_minutes || ' minutes')::interval)
  );
  
EXCEPTION WHEN OTHERS THEN
  PERFORM log_security_event(
    'FUNCTION_ERROR',
    'medium',
    format('check_rate_limit function error: %s', SQLERRM),
    get_real_client_ip(),
    auth.uid(),
    jsonb_build_object('function', 'check_rate_limit', 'action', sanitized_action)
  );
  RETURN jsonb_build_object('allowed', false, 'error', 'Rate limit check failed');
END;
$_$;


--
-- Name: cleanup_expired_security_data(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."cleanup_expired_security_data"() RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'pg_temp'
    AS $$
BEGIN
  -- Clean up expired sessions
  UPDATE public.user_sessions
  SET is_active = false
  WHERE expires_at < now() AND is_active = true;
  
  -- Clean up old password reset tokens
  DELETE FROM public.secure_password_reset_tokens
  WHERE expires_at < now() - INTERVAL '24 hours';
  
  -- Clean up old account lockouts
  DELETE FROM public.account_lockouts
  WHERE locked_until < now() - INTERVAL '7 days';
  
  -- Clean up resolved anomalies older than 30 days
  DELETE FROM public.login_anomalies
  WHERE is_resolved = true AND resolved_at < now() - INTERVAL '30 days';
  
END;
$$;


--
-- Name: cleanup_old_audit_logs(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."cleanup_old_audit_logs"() RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
BEGIN
  DELETE FROM public.audit_logs 
  WHERE timestamp < now() - interval '7 days';
END;
$$;


--
-- Name: create_notification("uuid", "text", "text", "text", "text", "uuid"); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."create_notification"("p_user_id" "uuid", "p_title" "text", "p_message" "text", "p_type" "text" DEFAULT 'info'::"text", "p_category" "text" DEFAULT 'system'::"text", "p_related_id" "uuid" DEFAULT NULL::"uuid") RETURNS "uuid"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'pg_temp'
    AS $_$
DECLARE
  notification_id UUID;
  setting_enabled BOOLEAN := true;
  sanitized_title text;
  sanitized_message text;
  sanitized_type text;
  sanitized_category text;
BEGIN
  -- Input validation
  IF p_user_id IS NULL THEN
    RAISE EXCEPTION 'User ID is required';
  END IF;
  
  IF p_title IS NULL OR trim(p_title) = '' THEN
    RAISE EXCEPTION 'Title is required';
  END IF;
  
  IF p_message IS NULL OR trim(p_message) = '' THEN
    RAISE EXCEPTION 'Message is required';
  END IF;
  
  -- Sanitize inputs
  sanitized_title := trim(p_title);
  sanitized_message := trim(p_message);
  sanitized_type := COALESCE(trim(p_type), 'info');
  sanitized_category := COALESCE(trim(p_category), 'system');
  
  -- Validate input lengths
  IF length(sanitized_title) > 200 THEN
    sanitized_title := left(sanitized_title, 200);
  END IF;
  
  IF length(sanitized_message) > 1000 THEN
    sanitized_message := left(sanitized_message, 1000);
  END IF;
  
  -- Validate type
  IF NOT sanitized_type IN ('info', 'warning', 'error', 'success') THEN
    sanitized_type := 'info';
  END IF;
  
  -- Validate category
  IF NOT sanitized_category ~ '^[a-zA-Z0-9_]+$' OR length(sanitized_category) > 50 THEN
    sanitized_category := 'system';
  END IF;
  
  -- Check if user has notifications enabled for this category
  SELECT COALESCE(ns.enabled, true) INTO setting_enabled
  FROM notification_settings ns
  WHERE ns.user_id = p_user_id AND ns.category = sanitized_category
  UNION ALL
  SELECT COALESCE(ns.enabled, true)
  FROM notification_settings ns
  JOIN user_role_assignments ura ON ns.role_id = ura.role_id
  WHERE ura.user_id = p_user_id AND ns.category = sanitized_category
  LIMIT 1;

  -- Only create notification if enabled
  IF setting_enabled THEN
    INSERT INTO public.notifications (
      user_id, title, message, type, category, related_id
    ) VALUES (
      p_user_id, sanitized_title, sanitized_message, sanitized_type, sanitized_category, p_related_id
    ) RETURNING id INTO notification_id;
  END IF;

  RETURN notification_id;
  
EXCEPTION WHEN OTHERS THEN
  -- Log error and return null
  PERFORM log_security_event(
    'FUNCTION_ERROR',
    'medium',
    format('create_notification function error: %s', SQLERRM),
    get_real_client_ip(),
    auth.uid(),
    jsonb_build_object('function', 'create_notification', 'user_id', p_user_id)
  );
  RETURN NULL;
END;
$_$;


--
-- Name: decrypt_audit_field("text", "text"); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."decrypt_audit_field"("encrypted_data" "text", "field_type" "text" DEFAULT 'json'::"text") RETURNS "text"
    LANGUAGE "plpgsql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public', 'pg_temp', 'extensions'
    AS $$
DECLARE
  encryption_key TEXT;
  decrypted_data TEXT;
BEGIN
  IF NOT has_permission(auth.uid(), 'view_audit_logs'::text) THEN
    RETURN 'ACCESS_DENIED';
  END IF;
  
  encryption_key := 'audit_encryption_key_2024';
  
  BEGIN
    decrypted_data := convert_from(decrypt(decode(encrypted_data, 'base64'), encryption_key::bytea, 'aes'::text), 'UTF8');
    RETURN decrypted_data;
  EXCEPTION WHEN OTHERS THEN
    RETURN 'DECRYPTION_ERROR';
  END;
END;
$$;


--
-- Name: delete_booking_documents(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."delete_booking_documents"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    SET "search_path" TO 'public'
    AS $$
BEGIN
  -- Delete associated documents from storage
  IF OLD.document_urls IS NOT NULL THEN
    -- This would need to be handled by the application layer
    -- as we can't directly delete from storage in triggers
  END IF;
  
  RETURN OLD;
END;
$$;


--
-- Name: delete_expense_documents(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."delete_expense_documents"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    SET "search_path" TO 'public', 'pg_temp'
    AS $$
BEGIN
  IF OLD.receipt_urls IS NOT NULL OR OLD.document_urls IS NOT NULL THEN
    -- This would need to be handled by the application layer
    -- as we can't directly delete from storage in triggers
  END IF;
  
  RETURN OLD;
END;
$$;


--
-- Name: detect_login_anomalies("text", "uuid", "inet", "text", "jsonb"); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."detect_login_anomalies"("user_email_param" "text", "user_id_param" "uuid", "current_ip" "inet", "current_user_agent" "text" DEFAULT NULL::"text", "location_data" "jsonb" DEFAULT NULL::"jsonb") RETURNS "jsonb"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'pg_temp'
    AS $$
DECLARE
  anomalies TEXT[] := ARRAY[]::TEXT[];
  risk_score INTEGER := 0;
  last_login_record RECORD;
  device_fingerprint TEXT;
  is_business_hours BOOLEAN;
  current_hour INTEGER;
BEGIN
  -- Input validation
  IF user_email_param IS NULL OR user_id_param IS NULL OR current_ip IS NULL THEN
    RETURN jsonb_build_object('anomalies', ARRAY[]::TEXT[], 'risk_score', 0);
  END IF;
  
  -- Create device fingerprint from user agent
  device_fingerprint := md5(COALESCE(current_user_agent, 'unknown'));
  
  -- Get business hours check (9 AM to 6 PM)
  current_hour := EXTRACT(hour FROM now() AT TIME ZONE 'UTC');
  is_business_hours := current_hour >= 9 AND current_hour <= 18;
  
  -- Get last successful login
  SELECT 
    ip_address::text as last_ip,
    user_agent,
    location_country,
    location_region,
    timestamp as last_login_time
  INTO last_login_record
  FROM public.audit_logs
  WHERE action = 'SECURITY_AUTH_LOGIN'
  AND new_values->>'success' = 'true'
  AND new_values->>'email' LIKE '%' || split_part(trim(lower(user_email_param)), '@', 1) || '%'
  AND timestamp < now()
  ORDER BY timestamp DESC
  LIMIT 1;
  
  -- Check for new device (different user agent fingerprint)
  IF last_login_record.user_agent IS NOT NULL THEN
    IF md5(last_login_record.user_agent) != device_fingerprint THEN
      anomalies := array_append(anomalies, 'new_device');
      risk_score := risk_score + 40;
      
      -- Log new device anomaly
      INSERT INTO public.login_anomalies (
        user_id, user_email, anomaly_type, severity, ip_address, user_agent, metadata
      ) VALUES (
        user_id_param, user_email_param, 'new_device', 'medium', current_ip, current_user_agent,
        jsonb_build_object(
          'previous_user_agent_hash', md5(last_login_record.user_agent),
          'current_user_agent_hash', device_fingerprint,
          'last_login', last_login_record.last_login_time
        )
      );
    END IF;
  END IF;
  
  -- Check for unusual location (different country or region)
  IF last_login_record.last_ip IS NOT NULL AND location_data IS NOT NULL THEN
    IF (location_data->>'country' != last_login_record.location_country OR
        location_data->>'region' != last_login_record.location_region) THEN
      anomalies := array_append(anomalies, 'unusual_location');
      risk_score := risk_score + 35;
      
      -- Log location anomaly
      INSERT INTO public.login_anomalies (
        user_id, user_email, anomaly_type, severity, ip_address,
        location_country, location_region, location_city, metadata
      ) VALUES (
        user_id_param, user_email_param, 'unusual_location', 'high', current_ip,
        location_data->>'country', location_data->>'region', location_data->>'city',
        jsonb_build_object(
          'previous_country', last_login_record.location_country,
          'previous_region', last_login_record.location_region,
          'current_country', location_data->>'country',
          'current_region', location_data->>'region'
        )
      );
    END IF;
  END IF;
  
  -- Check for outside business hours
  IF NOT is_business_hours THEN
    anomalies := array_append(anomalies, 'outside_hours');
    risk_score := risk_score + 15;
    
    -- Log outside hours anomaly
    INSERT INTO public.login_anomalies (
      user_id, user_email, anomaly_type, severity, ip_address, metadata
    ) VALUES (
      user_id_param, user_email_param, 'outside_hours', 'low', current_ip,
      jsonb_build_object(
        'login_hour', current_hour,
        'is_weekend', EXTRACT(dow FROM now()) IN (0, 6)
      )
    );
  END IF;
  
  -- Check for rapid successive logins (within 1 minute of last login)
  IF last_login_record.last_login_time > now() - INTERVAL '1 minute' THEN
    anomalies := array_append(anomalies, 'rapid_login');
    risk_score := risk_score + 25;
  END IF;
  
  RETURN jsonb_build_object(
    'anomalies', anomalies,
    'risk_score', risk_score,
    'risk_level', CASE 
      WHEN risk_score >= 60 THEN 'critical'
      WHEN risk_score >= 40 THEN 'high'
      WHEN risk_score >= 20 THEN 'medium'
      ELSE 'low'
    END,
    'requires_additional_verification', risk_score >= 40
  );
  
EXCEPTION WHEN OTHERS THEN
  PERFORM log_security_event(
    'FUNCTION_ERROR',
    'medium',
    format('detect_login_anomalies function error: %s', SQLERRM),
    current_ip::text,
    user_id_param,
    jsonb_build_object('function', 'detect_login_anomalies', 'email', user_email_param)
  );
  RETURN jsonb_build_object('anomalies', ARRAY[]::TEXT[], 'risk_score', 0, 'error', 'Anomaly detection failed');
END;
$$;


--
-- Name: enable_security_settings(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."enable_security_settings"() RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'pg_temp'
    AS $$
BEGIN
  RAISE NOTICE 'Enable MFA and enforce password policy manually (free plan).';
END;
$$;


--
-- Name: encrypt_audit_data(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."encrypt_audit_data"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'pg_temp', 'extensions'
    AS $$
DECLARE
  encryption_key TEXT;
BEGIN
  encryption_key := 'audit_encryption_key_2024';
  
  IF NEW.old_values IS NOT NULL AND (
    NEW.old_values ? 'email' OR 
    NEW.old_values ? 'phone' OR 
    NEW.old_values ? 'passport_number' OR
    NEW.old_values ? 'address'
  ) THEN
    NEW.old_values_encrypted := encode(encrypt(NEW.old_values::text::bytea, encryption_key::bytea, 'aes'::text), 'base64');
  END IF;
  
  IF NEW.new_values IS NOT NULL AND (
    NEW.new_values ? 'email' OR 
    NEW.new_values ? 'phone' OR 
    NEW.new_values ? 'passport_number' OR
    NEW.new_values ? 'address'
  ) THEN
    NEW.new_values_encrypted := encode(encrypt(NEW.new_values::text::bytea, encryption_key::bytea, 'aes'::text), 'base64');
  END IF;
  
  IF NEW.user_agent IS NOT NULL THEN
    NEW.user_agent_encrypted := encode(encrypt(NEW.user_agent::bytea, encryption_key::bytea, 'aes'::text), 'base64');
  END IF;
  
  RETURN NEW;
END;
$$;


--
-- Name: enforce_admin_2fa(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."enforce_admin_2fa"() RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'pg_temp'
    AS $$
DECLARE
  admin_user RECORD;
BEGIN
  -- Find all users with admin roles who don't have 2FA enforcement records
  FOR admin_user IN
    SELECT DISTINCT p.id, p.email, ura.created_at as role_assigned_at
    FROM public.profiles p
    JOIN public.user_role_assignments ura ON p.id = ura.user_id
    JOIN public.user_roles ur ON ura.role_id = ur.id
    WHERE ur.name = 'admin'
    AND p.id NOT IN (SELECT user_id FROM public.admin_2fa_enforcement)
  LOOP
    -- Create 2FA enforcement record
    INSERT INTO public.admin_2fa_enforcement (
      user_id,
      user_email,
      admin_role_assigned_at,
      enforcement_deadline
    ) VALUES (
      admin_user.id,
      admin_user.email,
      admin_user.role_assigned_at,
      admin_user.role_assigned_at + INTERVAL '24 hours'
    );
    
    -- Create notification for the user
    INSERT INTO public.notifications (
      user_id,
      title,
      message,
      category,
      type
    ) VALUES (
      admin_user.id,
      '🔐 2FA Required for Admin Access',
      'As an administrator, you must enable Two-Factor Authentication within 24 hours. Please visit Security Settings to set up 2FA.',
      'security',
      'warning'
    );
    
    -- Log security event
    PERFORM log_security_event(
      'ADMIN_2FA_ENFORCEMENT_CREATED',
      'high',
      format('2FA enforcement initiated for admin user: %s', admin_user.email),
      get_real_client_ip(),
      admin_user.id,
      jsonb_build_object(
        'enforcement_deadline', admin_user.role_assigned_at + INTERVAL '24 hours',
        'role_assigned_at', admin_user.role_assigned_at
      )
    );
  END LOOP;
  
  -- Update 2FA status for users who have enabled it
  UPDATE public.admin_2fa_enforcement
  SET 
    is_2fa_enabled = true,
    updated_at = now()
  WHERE user_id IN (
    SELECT user_id 
    FROM public.user_2fa_tokens 
    WHERE is_verified = true
  )
  AND is_2fa_enabled = false;
  
EXCEPTION WHEN OTHERS THEN
  PERFORM log_security_event(
    'FUNCTION_ERROR',
    'medium',
    format('enforce_admin_2fa function error: %s', SQLERRM),
    get_real_client_ip(),
    NULL,
    jsonb_build_object('function', 'enforce_admin_2fa')
  );
END;
$$;


--
-- Name: ensure_single_default_pdf_template(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."ensure_single_default_pdf_template"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    AS $$
BEGIN
  IF NEW.is_default = TRUE THEN
    UPDATE pdf_contract_templates
    SET is_default = FALSE
    WHERE is_default = TRUE
      AND id != NEW.id;
  END IF;
  RETURN NEW;
END;
$$;


--
-- Name: generate_secure_password_reset_token("text", "inet", "text"); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."generate_secure_password_reset_token"("user_email_param" "text", "client_ip" "inet" DEFAULT NULL::"inet", "user_agent_param" "text" DEFAULT NULL::"text") RETURNS "jsonb"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'pg_temp'
    AS $_$
DECLARE
  user_record RECORD;
  reset_token TEXT;
  token_hash TEXT;
  result JSONB;
BEGIN
  -- Input validation
  IF user_email_param IS NULL OR trim(user_email_param) = '' THEN
    RETURN jsonb_build_object('success', false, 'error', 'Email is required');
  END IF;
  
  -- Validate email format
  IF NOT trim(lower(user_email_param)) ~ '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$' THEN
    RETURN jsonb_build_object('success', false, 'error', 'Invalid email format');
  END IF;
  
  -- Check if user exists
  SELECT id, email, name INTO user_record
  FROM public.profiles
  WHERE email = trim(lower(user_email_param));
  
  IF user_record IS NULL THEN
    -- Don't reveal that user doesn't exist
    RETURN jsonb_build_object('success', true, 'message', 'If the email exists, a reset link will be sent');
  END IF;
  
  -- Check rate limiting for password reset requests (max 3 per hour)
  IF (SELECT COUNT(*) 
      FROM public.secure_password_reset_tokens 
      WHERE user_email = trim(lower(user_email_param))
      AND created_at > now() - INTERVAL '1 hour') >= 3 THEN
    
    PERFORM log_security_event(
      'PASSWORD_RESET_RATE_LIMIT',
      'medium',
      format('Password reset rate limit exceeded for: %s', user_email_param),
      client_ip::text,
      user_record.id,
      jsonb_build_object('attempts_in_hour', 3)
    );
    
    RETURN jsonb_build_object('success', false, 'error', 'Too many reset requests. Please wait before trying again.');
  END IF;
  
  -- Generate secure random token (32 bytes = 256 bits)
  reset_token := encode(gen_random_bytes(32), 'base64');
  reset_token := replace(replace(replace(reset_token, '/', '_'), '+', '-'), '=', '');
  
  -- Create hash of the token for database storage
  token_hash := encode(digest(reset_token, 'sha256'), 'hex');
  
  -- Invalidate any existing tokens for this user
  UPDATE public.secure_password_reset_tokens
  SET is_used = true, used_at = now()
  WHERE user_email = trim(lower(user_email_param))
  AND is_used = false
  AND expires_at > now();
  
  -- Store the token hash in database
  INSERT INTO public.secure_password_reset_tokens (
    user_id,
    user_email,
    token_hash,
    expires_at,
    ip_address,
    user_agent
  ) VALUES (
    user_record.id,
    trim(lower(user_email_param)),
    token_hash,
    now() + INTERVAL '1 hour',
    client_ip,
    user_agent_param
  );
  
  -- Log security event
  PERFORM log_security_event(
    'PASSWORD_RESET_TOKEN_GENERATED',
    'medium',
    format('Password reset token generated for: %s', user_email_param),
    client_ip::text,
    user_record.id,
    jsonb_build_object(
      'token_expires_at', now() + INTERVAL '1 hour',
      'user_agent', user_agent_param
    )
  );
  
  RETURN jsonb_build_object(
    'success', true,
    'token', reset_token,
    'expires_at', now() + INTERVAL '1 hour',
    'user_id', user_record.id,
    'user_name', user_record.name
  );
  
EXCEPTION WHEN OTHERS THEN
  PERFORM log_security_event(
    'FUNCTION_ERROR',
    'medium',
    format('generate_secure_password_reset_token function error: %s', SQLERRM),
    client_ip::text,
    NULL,
    jsonb_build_object('function', 'generate_secure_password_reset_token', 'email', user_email_param)
  );
  RETURN jsonb_build_object('success', false, 'error', 'Token generation failed');
END;
$_$;


--
-- Name: get_auto_check_settings(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."get_auto_check_settings"() RETURNS TABLE("auto_checkin_enabled" boolean, "auto_checkout_enabled" boolean, "default_checkin_time" time without time zone, "default_checkout_time" time without time zone, "timezone" "text")
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'pg_temp'
    AS $$
BEGIN
  RETURN QUERY
  SELECT 
    s.auto_checkin_enabled,
    s.auto_checkout_enabled,
    s.default_checkin_time,
    s.default_checkout_time,
    s.timezone
  FROM public.general_settings s
  ORDER BY s.created_at DESC
  LIMIT 1;
END;
$$;


--
-- Name: get_guest_secure("uuid", "text"); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."get_guest_secure"("guest_id" "uuid", "access_reason" "text" DEFAULT 'view'::"text") RETURNS TABLE("id" "uuid", "first_name" "text", "last_name" "text", "email" "text", "phone" "text", "address" "text", "city" "text", "state" "text", "country" "text", "zip_code" "text", "nationality" "text", "passport_number" "text", "id_document_url" "text", "notes" "text", "consent_data_processing" boolean, "consent_marketing" boolean, "consent_third_party_sharing" boolean, "consent_timestamp" timestamp with time zone, "privacy_level" "text", "created_at" timestamp with time zone, "updated_at" timestamp with time zone)
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'pg_temp'
    AS $$
DECLARE
  guest_record RECORD;
  user_perms TEXT[];
BEGIN
  -- Check if user has permission to view guests
  IF NOT has_permission(auth.uid(), 'view_guests') THEN
    RAISE EXCEPTION 'Access denied: insufficient permissions';
  END IF;
  
  -- Get user permissions
  user_perms := ARRAY['view_guests'];
  IF has_permission(auth.uid(), 'view_sensitive_guest_data') THEN
    user_perms := user_perms || 'view_sensitive_guest_data';
  END IF;
  
  -- Fetch guest record
  SELECT g.* INTO guest_record
  FROM public.guests g
  WHERE g.id = guest_id;
  
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Guest not found';
  END IF;
  
  -- Log access
  PERFORM log_guest_data_access(
    guest_id,
    ARRAY['all_fields'], 
    access_reason,
    jsonb_build_object('permissions', user_perms)
  );
  
  -- Return masked data
  RETURN QUERY SELECT
    guest_record.id,
    mask_guest_field(guest_record.first_name, 'first_name', user_perms),
    mask_guest_field(guest_record.last_name, 'last_name', user_perms),
    mask_guest_field(guest_record.email, 'email', user_perms),
    mask_guest_field(guest_record.phone, 'phone', user_perms),
    mask_guest_field(guest_record.address, 'address', user_perms),
    mask_guest_field(guest_record.city, 'city', user_perms),
    mask_guest_field(guest_record.state, 'state', user_perms),
    mask_guest_field(guest_record.country, 'country', user_perms),
    mask_guest_field(guest_record.zip_code, 'zip_code', user_perms),
    mask_guest_field(guest_record.nationality, 'nationality', user_perms),
    mask_guest_field(guest_record.passport_number, 'passport_number', user_perms),
    mask_guest_field(guest_record.id_document_url, 'id_document_url', user_perms),
    mask_guest_field(guest_record.notes, 'notes', user_perms),
    guest_record.consent_data_processing,
    guest_record.consent_marketing,
    guest_record.consent_third_party_sharing,
    guest_record.consent_timestamp,
    guest_record.privacy_level,
    guest_record.created_at,
    guest_record.updated_at;
END;
$$;


--
-- Name: get_ip_location("text"); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."get_ip_location"("ip_address" "text") RETURNS "jsonb"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE
  result jsonb;
BEGIN
  -- This is a placeholder function. In a real implementation,
  -- you would call an external API service like ipapi.co or ip-api.com
  -- For now, we'll return a mock structure
  result := jsonb_build_object(
    'country', 'Unknown',
    'region', 'Unknown', 
    'city', 'Unknown'
  );
  
  RETURN result;
END;
$$;


--
-- Name: get_owner_bookings("uuid"); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."get_owner_bookings"("p_user_uuid" "uuid") RETURNS TABLE("id" "uuid", "guest_name" "text", "guest_email" "text", "guest_phone" "text", "room_number" "text", "room_type" "text", "property_name" "text", "check_in" "date", "check_out" "date", "status" "text", "total_amount" numeric)
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'pg_temp'
    AS $$
DECLARE
  v_owner_id UUID;
BEGIN
  SELECT o.id INTO v_owner_id FROM owners o WHERE o.auth_user_id = p_user_uuid LIMIT 1;
  
  IF v_owner_id IS NULL THEN
    RETURN;
  END IF;

  RETURN QUERY
  SELECT 
    b.id,
    COALESCE(g.first_name || ' ' || g.last_name, 'Unknown Guest') as guest_name,
    g.email as guest_email,
    g.phone as guest_phone,
    r.number as room_number,
    rt.name as room_type,
    p.name as property_name,
    b.check_in_date as check_in,
    b.check_out_date as check_out,
    b.status::TEXT as status,
    b.total_amount
  FROM bookings b
  INNER JOIN room_ownership ro ON b.room_id = ro.room_id
  INNER JOIN rooms r ON b.room_id = r.id
  LEFT JOIN room_types rt ON r.room_type_id = rt.id
  LEFT JOIN properties p ON r.property_id = p.id
  LEFT JOIN guests g ON b.guest_id = g.id
  WHERE ro.owner_id = v_owner_id 
    AND ro.active = true
  ORDER BY b.check_in_date DESC;
END;
$$;


--
-- Name: get_owner_bookings_simple("uuid"); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."get_owner_bookings_simple"("p_user_uuid" "uuid") RETURNS TABLE("id" "uuid", "guest_name" "text", "room_number" "text", "check_in_date" timestamp with time zone, "check_out_date" timestamp with time zone, "status" "text")
    LANGUAGE "plpgsql"
    SET "search_path" TO 'public', 'pg_temp'
    AS $$
BEGIN
  RETURN QUERY
  SELECT
    b.id,
    g.first_name || ' ' || g.last_name AS guest_name,
    r.number AS room_number,
    b.check_in_date,
    b.check_out_date,
    b.status
  FROM bookings b
  JOIN rooms r ON b.room_id = r.id
  JOIN guests g ON b.guest_id = g.id
  WHERE b.room_id IN (SELECT room_id FROM get_owner_rooms(p_user_uuid))
  ORDER BY b.check_in_date DESC
  LIMIT 10;
END;
$$;


--
-- Name: get_owner_cleaning_tasks("uuid"); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."get_owner_cleaning_tasks"("p_user_uuid" "uuid") RETURNS TABLE("id" "uuid", "room_number" "text", "property_name" "text", "status" "text", "assigned_to" "text", "priority" "text", "estimated_duration" integer, "notes" "text", "created_at" timestamp with time zone, "completed_at" timestamp with time zone)
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'pg_temp'
    AS $$
DECLARE
  v_owner_id UUID;
BEGIN
  SELECT o.id INTO v_owner_id FROM owners o WHERE o.auth_user_id = p_user_uuid LIMIT 1;
  
  IF v_owner_id IS NULL THEN
    RETURN;
  END IF;

  RETURN QUERY
  SELECT 
    ct.id,
    r.number as room_number,
    p.name as property_name,
    ct.status,
    pr.name as assigned_to,
    'medium'::TEXT as priority,
    30 as estimated_duration,
    ct.notes,
    ct.created_at,
    ct.completed_date as completed_at
  FROM cleaning_tasks ct
  INNER JOIN rooms r ON ct.room_id = r.id
  INNER JOIN room_ownership ro ON r.id = ro.room_id
  LEFT JOIN properties p ON r.property_id = p.id
  LEFT JOIN profiles pr ON ct.assigned_to = pr.id
  WHERE ro.owner_id = v_owner_id 
    AND ro.active = true
  ORDER BY ct.created_at DESC;
END;
$$;


--
-- Name: get_owner_dashboard_stats("uuid"); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."get_owner_dashboard_stats"("p_user_uuid" "uuid") RETURNS TABLE("available_rooms" bigint, "total_rooms" bigint, "check_ins" bigint, "check_outs" bigint, "occupancy_rate" numeric, "monthly_revenue" numeric, "occupied_rooms" bigint, "maintenance_rooms" bigint)
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'pg_temp'
    AS $$
DECLARE
  v_owner_id UUID;
BEGIN
  SELECT id INTO v_owner_id FROM owners WHERE auth_user_id = p_user_uuid LIMIT 1;
  
  IF v_owner_id IS NULL THEN
    RETURN QUERY SELECT 0::BIGINT, 0::BIGINT, 0::BIGINT, 0::BIGINT, 0::NUMERIC, 0::NUMERIC, 0::BIGINT, 0::BIGINT;
    RETURN;
  END IF;

  RETURN QUERY
  WITH owner_rooms AS (
    SELECT r.id, r.status
    FROM rooms r
    INNER JOIN room_ownership ro ON r.id = ro.room_id
    WHERE ro.owner_id = v_owner_id AND ro.active = true
  )
  SELECT
    COUNT(*) FILTER (WHERE status = 'available')::BIGINT as available_rooms,
    COUNT(*)::BIGINT as total_rooms,
    (SELECT COUNT(*)::BIGINT FROM bookings b 
     WHERE b.room_id IN (SELECT id FROM owner_rooms) 
     AND b.check_in_date = CURRENT_DATE 
     AND b.status IN ('confirmed', 'checked_in')) as check_ins,
    (SELECT COUNT(*)::BIGINT FROM bookings b 
     WHERE b.room_id IN (SELECT id FROM owner_rooms) 
     AND b.check_out_date = CURRENT_DATE 
     AND b.status = 'checked_in') as check_outs,
    CASE WHEN COUNT(*) > 0 
      THEN ROUND((COUNT(*) FILTER (WHERE status = 'occupied')::NUMERIC / COUNT(*)::NUMERIC) * 100, 2)
      ELSE 0 
    END as occupancy_rate,
    COALESCE((SELECT SUM(total_amount) FROM bookings b 
     WHERE b.room_id IN (SELECT id FROM owner_rooms) 
     AND EXTRACT(MONTH FROM b.created_at) = EXTRACT(MONTH FROM CURRENT_DATE)
     AND EXTRACT(YEAR FROM b.created_at) = EXTRACT(YEAR FROM CURRENT_DATE)
     AND b.status IN ('confirmed', 'checked_in', 'checked_out')), 0) as monthly_revenue,
    COUNT(*) FILTER (WHERE status = 'occupied')::BIGINT as occupied_rooms,
    COUNT(*) FILTER (WHERE status = 'maintenance')::BIGINT as maintenance_rooms
  FROM owner_rooms;
END;
$$;


--
-- Name: get_owner_properties("uuid"); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."get_owner_properties"("user_uuid" "uuid") RETURNS "uuid"[]
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  SELECT ARRAY_AGG(po.property_id)
  FROM public.owners o
  JOIN public.property_ownership po ON o.id = po.owner_id
  WHERE o.auth_user_id = user_uuid AND o.active = true AND po.active = true;
$$;


--
-- Name: get_owner_reports_data("uuid"); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."get_owner_reports_data"("p_user_uuid" "uuid") RETURNS TABLE("total_revenue" numeric, "total_bookings" bigint, "average_booking_value" numeric, "occupancy_rate" double precision)
    LANGUAGE "plpgsql"
    SET "search_path" TO 'public', 'pg_temp'
    AS $$
DECLARE
  owner_room_ids UUID[];
BEGIN
  -- Get owner's room IDs
  SELECT ARRAY_AGG(room_id) INTO owner_room_ids
  FROM get_owner_rooms(p_user_uuid);

  IF owner_room_ids IS NULL THEN
    RETURN QUERY SELECT 0, 0, 0, 0.0;
    RETURN;
  END IF;

  -- Calculate stats
  SELECT
    COALESCE(SUM(b.total_amount), 0),
    COUNT(b.id),
    COALESCE(AVG(b.total_amount), 0),
    (CASE WHEN COUNT(r.id) > 0 THEN (COUNT(b.id) * 100.0 / COUNT(r.id)) ELSE 0.0 END)
  INTO
    total_revenue,
    total_bookings,
    average_booking_value,
    occupancy_rate
  FROM rooms r
  LEFT JOIN bookings b ON r.id = b.room_id AND b.status IN ('confirmed', 'checked_in', 'checked_out')
  WHERE r.id = ANY(owner_room_ids);

  RETURN QUERY SELECT
    total_revenue,
    total_bookings,
    average_booking_value,
    occupancy_rate;
END;
$$;


--
-- Name: get_owner_rooms("uuid"); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."get_owner_rooms"("user_uuid" "uuid") RETURNS TABLE("room_id" "uuid")
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
BEGIN
  RETURN QUERY
  -- Get rooms from direct room ownership
  SELECT ro.room_id
  FROM public.room_ownership ro
  JOIN public.owners o ON ro.owner_id = o.id
  WHERE o.auth_user_id = user_uuid 
    AND ro.active = TRUE
  
  UNION
  
  -- Get rooms from property ownership
  SELECT r.id as room_id
  FROM public.rooms r
  JOIN public.properties p ON r.property_id = p.id
  JOIN public.property_ownership po ON p.id = po.property_id
  JOIN public.owners o ON po.owner_id = o.id
  WHERE o.auth_user_id = user_uuid 
    AND po.active = TRUE;
END;
$$;


--
-- Name: get_real_client_ip(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."get_real_client_ip"() RETURNS "text"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'pg_temp'
    AS $$
DECLARE
  headers json;
  forwarded_ip text;
  real_ip text;
BEGIN
  -- Try to get headers safely
  BEGIN
    headers := current_setting('request.headers', true)::json;
  EXCEPTION WHEN OTHERS THEN
    headers := null;
  END;
  
  -- Extract real client IP from various headers
  IF headers IS NOT NULL THEN
    -- Check X-Forwarded-For header (most common)
    forwarded_ip := headers->>'x-forwarded-for';
    IF forwarded_ip IS NULL THEN
      forwarded_ip := headers->>'x-real-ip';
    END IF;
    IF forwarded_ip IS NULL THEN
      forwarded_ip := headers->>'cf-connecting-ip'; -- Cloudflare
    END IF;
    IF forwarded_ip IS NULL THEN
      forwarded_ip := headers->>'x-client-ip';
    END IF;
    IF forwarded_ip IS NULL THEN
      forwarded_ip := headers->>'remote-addr';
    END IF;
    
    -- Clean up the forwarded IP (take first IP if comma-separated)
    IF forwarded_ip IS NOT NULL THEN
      real_ip := trim(split_part(forwarded_ip, ',', 1));
      -- Filter out private/local IPs and return only public IPs
      IF real_ip !~ '^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|::1|fc00:|fe80:)' THEN
        RETURN real_ip;
      END IF;
    END IF;
  END IF;
  
  -- Fallback to inet_client_addr if no public IP found
  RETURN inet_client_addr()::text;
END;
$$;


--
-- Name: FUNCTION "get_real_client_ip"(); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION "public"."get_real_client_ip"() IS 'Extracts real client IP from various proxy headers';


--
-- Name: get_room_status("uuid"); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."get_room_status"("room_id" "uuid") RETURNS "jsonb"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'pg_temp'
    AS $$
DECLARE
  room_data jsonb;
BEGIN
  -- Input validation
  IF room_id IS NULL THEN
    RETURN jsonb_build_object('error', 'Room ID is required');
  END IF;
  
  -- Get room status
  SELECT jsonb_build_object(
    'id', r.id,
    'number', r.number,
    'status', r.status,
    'updated_at', r.updated_at
  ) INTO room_data
  FROM rooms r
  WHERE r.id = room_id;
  
  IF room_data IS NULL THEN
    RETURN jsonb_build_object('error', 'Room not found');
  END IF;
  
  RETURN room_data;
  
EXCEPTION WHEN OTHERS THEN
  RETURN jsonb_build_object('error', 'Failed to get room status');
END;
$$;


--
-- Name: get_system_time_in_timezone(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."get_system_time_in_timezone"() RETURNS timestamp without time zone
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'pg_temp'
    AS $$
DECLARE
    system_timezone text;
BEGIN
    -- Get configured timezone from settings
    SELECT timezone INTO system_timezone
    FROM general_settings
    ORDER BY created_at DESC
    LIMIT 1;
    
    -- Return current time in configured timezone
    RETURN now() AT TIME ZONE COALESCE(system_timezone, 'UTC');
    
EXCEPTION WHEN OTHERS THEN
    -- Fallback to UTC if anything goes wrong
    RETURN now() AT TIME ZONE 'UTC';
END;
$$;


--
-- Name: get_unread_notification_count("uuid"); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."get_unread_notification_count"("p_user_id" "uuid") RETURNS integer
    LANGUAGE "sql" SECURITY DEFINER
    SET "search_path" TO 'public', 'pg_temp'
    AS $$
  SELECT CASE 
    WHEN p_user_id IS NULL THEN 0
    ELSE (
      SELECT COUNT(*)::INTEGER
      FROM public.notifications
      WHERE user_id = p_user_id AND read = false
    )
  END;
$$;


--
-- Name: get_user_permissions("uuid"); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."get_user_permissions"("user_uuid" "uuid") RETURNS "jsonb"
    LANGUAGE "plpgsql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public', 'pg_temp'
    AS $_$
DECLARE
  result jsonb := '{}'::jsonb;
  role_perms record;
  key text;
  value jsonb;
BEGIN
  -- Input validation
  IF user_uuid IS NULL THEN
    RETURN '{}'::jsonb;
  END IF;
  
  -- Get all permissions from user's roles and merge them
  FOR role_perms IN
    SELECT ur.permissions
    FROM public.user_role_assignments ura
    JOIN public.user_roles ur ON ura.role_id = ur.id
    WHERE ura.user_id = user_uuid
  LOOP
    -- Simple merge - iterate through each permission in the role
    FOR key, value IN SELECT * FROM jsonb_each(COALESCE(role_perms.permissions, '{}'::jsonb))
    LOOP
      -- Validate key format
      IF key ~ '^[a-zA-Z0-9_.]+$' AND length(key) <= 100 THEN
        -- If the key doesn't exist in result, add it
        -- If it exists and both are objects, merge them
        -- Otherwise, override with the new value
        IF result ? key THEN
          IF jsonb_typeof(result->key) = 'object' AND jsonb_typeof(value) = 'object' THEN
            result := jsonb_set(result, ARRAY[key], (result->key) || value);
          ELSE
            result := jsonb_set(result, ARRAY[key], value);
          END IF;
        ELSE
          result := jsonb_set(result, ARRAY[key], value);
        END IF;
      END IF;
    END LOOP;
  END LOOP;
  
  RETURN result;
  
EXCEPTION WHEN OTHERS THEN
  -- Log error and return empty permissions
  PERFORM log_security_event(
    'FUNCTION_ERROR',
    'medium',
    format('get_user_permissions function error: %s', SQLERRM),
    get_real_client_ip(),
    user_uuid,
    jsonb_build_object('function', 'get_user_permissions')
  );
  RETURN '{}'::jsonb;
END;
$_$;


--
-- Name: get_user_role("uuid"); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."get_user_role"("user_uuid" "uuid") RETURNS "text"
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  SELECT ur.name
  FROM public.user_role_assignments ura
  JOIN public.user_roles ur ON ura.role_id = ur.id
  WHERE ura.user_id = user_uuid
  LIMIT 1;
$$;


--
-- Name: handle_new_user(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."handle_new_user"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
BEGIN
  INSERT INTO public.profiles (id, name, email, status)
  VALUES (NEW.id, COALESCE(NEW.raw_user_meta_data->>'name', NEW.email), NEW.email, 'active');
  RETURN NEW;
END;
$$;


--
-- Name: handle_progressive_lockout("text", "inet"); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."handle_progressive_lockout"("user_email_param" "text", "client_ip" "inet" DEFAULT NULL::"inet") RETURNS "jsonb"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'pg_temp'
    AS $$
DECLARE
  lockout_record RECORD;
  new_level INTEGER;
  lockout_duration INTERVAL;
  result JSONB;
BEGIN
  -- Input validation
  IF user_email_param IS NULL OR trim(user_email_param) = '' THEN
    RETURN jsonb_build_object('locked', false, 'error', 'Invalid email');
  END IF;
  
  -- Get current lockout status
  SELECT * INTO lockout_record
  FROM public.account_lockouts
  WHERE user_email = trim(lower(user_email_param))
  AND locked_until > now()
  ORDER BY created_at DESC
  LIMIT 1;
  
  -- If no active lockout, start fresh
  IF lockout_record IS NULL THEN
    -- Check recent failed attempts in the last hour
    SELECT COUNT(*) INTO new_level
    FROM public.audit_logs
    WHERE action = 'SECURITY_AUTH_LOGIN'
    AND new_values->>'success' = 'false'
    AND new_values->>'email' LIKE '%' || split_part(trim(lower(user_email_param)), '@', 1) || '%'
    AND timestamp > now() - INTERVAL '1 hour';
    
    -- Determine lockout level and duration
    IF new_level >= 10 THEN
      new_level := 3; -- 24 hour lockout
      lockout_duration := INTERVAL '24 hours';
    ELSIF new_level >= 5 THEN
      new_level := 2; -- 1 hour lockout
      lockout_duration := INTERVAL '1 hour';
    ELSIF new_level >= 3 THEN
      new_level := 1; -- 15 minute lockout
      lockout_duration := INTERVAL '15 minutes';
    ELSE
      -- No lockout needed
      RETURN jsonb_build_object(
        'locked', false,
        'attempts', new_level,
        'next_lockout_at', 3
      );
    END IF;
    
    -- Create new lockout record
    INSERT INTO public.account_lockouts (
      user_email,
      lockout_level,
      attempts_count,
      locked_until,
      ip_address
    ) VALUES (
      trim(lower(user_email_param)),
      new_level,
      new_level,
      now() + lockout_duration,
      client_ip
    );
    
    -- Log security event
    PERFORM log_security_event(
      'PROGRESSIVE_LOCKOUT_APPLIED',
      'high',
      format('Progressive lockout level %s applied to %s', new_level, user_email_param),
      client_ip::text,
      NULL,
      jsonb_build_object(
        'lockout_level', new_level,
        'duration_minutes', EXTRACT(epoch FROM lockout_duration) / 60,
        'attempts_count', new_level
      )
    );
    
    RETURN jsonb_build_object(
      'locked', true,
      'level', new_level,
      'locked_until', now() + lockout_duration,
      'attempts', new_level
    );
  ELSE
    -- Account is currently locked
    RETURN jsonb_build_object(
      'locked', true,
      'level', lockout_record.lockout_level,
      'locked_until', lockout_record.locked_until,
      'attempts', lockout_record.attempts_count
    );
  END IF;
  
EXCEPTION WHEN OTHERS THEN
  PERFORM log_security_event(
    'FUNCTION_ERROR',
    'medium',
    format('handle_progressive_lockout function error: %s', SQLERRM),
    client_ip::text,
    NULL,
    jsonb_build_object('function', 'handle_progressive_lockout', 'email', user_email_param)
  );
  RETURN jsonb_build_object('locked', false, 'error', 'Lockout check failed');
END;
$$;


--
-- Name: has_permission("uuid", "text"); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."has_permission"("user_uuid" "uuid", "permission_name" "text") RETURNS boolean
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'pg_temp'
    AS $_$
DECLARE
    user_role_name TEXT;
    role_record RECORD;
    permission_parts TEXT[];
    nested_key TEXT;
    nested_value JSONB;
    flat_permission_exists BOOLEAN := FALSE;
BEGIN
    -- Input validation
    IF user_uuid IS NULL OR permission_name IS NULL OR trim(permission_name) = '' THEN
        RETURN FALSE;
    END IF;
    
    -- Sanitize permission name
    permission_name := trim(permission_name);
    
    -- Validate permission name format (alphanumeric, underscore, dot only)
    IF NOT permission_name ~ '^[a-zA-Z0-9_.]+$' THEN
        RETURN FALSE;
    END IF;
    
    -- Length check
    IF length(permission_name) > 100 THEN
        RETURN FALSE;
    END IF;
    
    -- Get user role
    SELECT name INTO user_role_name
    FROM user_roles ur
    JOIN user_role_assignments ura ON ur.id = ura.role_id
    WHERE ura.user_id = user_uuid
    LIMIT 1;
    
    -- Admin has all permissions
    IF user_role_name = 'admin' THEN
        RETURN TRUE;
    END IF;
    
    -- Check for flat permission first (e.g., 'view_bookings')
    FOR role_record IN 
        SELECT ur.permissions
        FROM user_roles ur
        JOIN user_role_assignments ura ON ur.id = ura.role_id
        WHERE ura.user_id = user_uuid
    LOOP
        IF role_record.permissions ? permission_name THEN
            flat_permission_exists := TRUE;
            EXIT;
        END IF;
    END LOOP;
    
    IF flat_permission_exists THEN
        RETURN TRUE;
    END IF;
    
    -- Map flat permission names to nested structure
    nested_key := CASE permission_name
        WHEN 'view_bookings' THEN 'bookings.view'
        WHEN 'create_bookings' THEN 'bookings.create'
        WHEN 'update_bookings' THEN 'bookings.update'
        WHEN 'delete_bookings' THEN 'bookings.delete'
        WHEN 'view_rooms' THEN 'rooms.view'
        WHEN 'create_rooms' THEN 'rooms.create'
        WHEN 'update_rooms' THEN 'rooms.update'
        WHEN 'delete_rooms' THEN 'rooms.delete'
        WHEN 'view_guests' THEN 'guests.view'
        WHEN 'create_guests' THEN 'guests.create'
        WHEN 'update_guests' THEN 'guests.update'
        WHEN 'delete_guests' THEN 'guests.delete'
        WHEN 'view_owners' THEN 'owners.view'
        WHEN 'create_owners' THEN 'owners.create'
        WHEN 'update_owners' THEN 'owners.update'
        WHEN 'delete_owners' THEN 'owners.delete'
        WHEN 'view_users' THEN 'users.view'
        WHEN 'create_users' THEN 'users.create'
        WHEN 'update_users' THEN 'users.update'
        WHEN 'delete_users' THEN 'users.delete'
        WHEN 'manage_users' THEN 'users.create'
        WHEN 'view_reports' THEN 'reports.view'
        WHEN 'create_reports' THEN 'reports.create'
        WHEN 'view_cleaning' THEN 'cleaning.view'
        WHEN 'create_cleaning' THEN 'cleaning.create'
        WHEN 'update_cleaning' THEN 'cleaning.update'
        WHEN 'delete_cleaning' THEN 'cleaning.delete'
        WHEN 'view_expenses' THEN 'expenses.view'
        WHEN 'create_expenses' THEN 'expenses.create'
        WHEN 'update_expenses' THEN 'expenses.update'
        WHEN 'delete_expenses' THEN 'expenses.delete'
        WHEN 'view_settings' THEN 'settings.view'
        WHEN 'update_settings' THEN 'settings.update'
        WHEN 'view_audit_logs' THEN 'auditLogs.view'
        WHEN 'view_sensitive_guest_data' THEN 'guests.sensitive'
        ELSE permission_name
    END;
    
    -- Check nested permissions
    IF nested_key LIKE '%.%' THEN
        permission_parts := string_to_array(nested_key, '.');
        
        FOR role_record IN 
            SELECT ur.permissions
            FROM user_roles ur
            JOIN user_role_assignments ura ON ur.id = ura.role_id
            WHERE ura.user_id = user_uuid
        LOOP
            nested_value := role_record.permissions;
            
            -- Navigate through nested structure
            FOR i IN 1..array_length(permission_parts, 1) LOOP
                IF nested_value ? permission_parts[i] THEN
                    IF i = array_length(permission_parts, 1) THEN
                        -- Final level - check boolean value
                        IF (nested_value ->> permission_parts[i])::boolean THEN
                            RETURN TRUE;
                        END IF;
                    ELSE
                        -- Intermediate level - navigate deeper
                        nested_value := nested_value -> permission_parts[i];
                    END IF;
                ELSE
                    -- Permission path doesn't exist
                    EXIT;
                END IF;
            END LOOP;
        END LOOP;
    END IF;
    
    RETURN FALSE;
    
EXCEPTION WHEN OTHERS THEN
    -- Log security event on function error
    PERFORM log_security_event(
        'FUNCTION_ERROR',
        'medium',
        format('has_permission function error: %s', SQLERRM),
        get_real_client_ip(),
        user_uuid,
        jsonb_build_object('function', 'has_permission', 'permission', permission_name)
    );
    RETURN FALSE;
END;
$_$;


--
-- Name: FUNCTION "has_permission"("user_uuid" "uuid", "permission_name" "text"); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION "public"."has_permission"("user_uuid" "uuid", "permission_name" "text") IS 'Checks if user has specific permission based on assigned roles';


--
-- Name: is_owner("uuid"); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."is_owner"("user_uuid" "uuid") RETURNS boolean
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public', 'pg_temp'
    AS $$
  SELECT CASE 
    WHEN user_uuid IS NULL THEN false
    ELSE EXISTS (
      SELECT 1 FROM public.owners 
      WHERE auth_user_id = user_uuid AND active = true
    )
  END;
$$;


--
-- Name: log_audit_access("text", integer, "jsonb"); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."log_audit_access"("access_type" "text", "record_count" integer DEFAULT 0, "filters_applied" "jsonb" DEFAULT '{}'::"jsonb") RETURNS "uuid"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'pg_temp'
    AS $$
DECLARE
  access_log_id UUID;
  client_ip TEXT;
  user_agent TEXT;
BEGIN
  -- Get client IP
  client_ip := get_real_client_ip();
  
  -- Get user agent from headers
  BEGIN
    user_agent := current_setting('request.headers', true)::json->>'user-agent';
  EXCEPTION WHEN OTHERS THEN
    user_agent := NULL;
  END;
  
  -- Insert audit access log
  INSERT INTO public.audit_access_log (
    user_id,
    access_type,
    record_count,
    filters_applied,
    ip_address,
    user_agent,
    session_id
  ) VALUES (
    auth.uid(),
    access_type,
    record_count,
    filters_applied,
    client_ip::inet,
    user_agent,
    (SELECT session_id FROM audit_logs WHERE user_id = auth.uid() ORDER BY timestamp DESC LIMIT 1)
  ) RETURNING id INTO access_log_id;
  
  RETURN access_log_id;
END;
$$;


--
-- Name: log_audit_action(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."log_audit_action"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'pg_temp'
    AS $$
DECLARE
  v_action text;
  v_old jsonb;
  v_new jsonb;
  v_record_id uuid;
BEGIN
  IF (TG_OP = 'INSERT') THEN
    v_action := TG_TABLE_NAME || ' INSERT';
    v_new := row_to_json(NEW)::jsonb;
    v_record_id := COALESCE(NEW.id, NULL);
  ELSIF (TG_OP = 'UPDATE') THEN
    v_action := TG_TABLE_NAME || ' UPDATE';
    v_old := row_to_json(OLD)::jsonb;
    v_new := row_to_json(NEW)::jsonb;
    v_record_id := COALESCE(NEW.id, OLD.id);
  ELSIF (TG_OP = 'DELETE') THEN
    v_action := TG_TABLE_NAME || ' DELETE';
    v_old := row_to_json(OLD)::jsonb;
    v_record_id := COALESCE(OLD.id, NULL);
  END IF;

  INSERT INTO public.audit_logs (
    action,
    table_name,
    record_id,
    old_values,
    new_values,
    user_id,
    timestamp
  )
  VALUES (
    v_action,
    TG_TABLE_NAME,
    v_record_id,
    v_old,
    v_new,
    auth.uid(),
    now()
  );

  IF (TG_OP = 'DELETE') THEN
    RETURN OLD;
  ELSE
    RETURN NEW;
  END IF;
END;
$$;


--
-- Name: log_audit_with_location("text", "text", "uuid", "jsonb", "jsonb", "text"); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."log_audit_with_location"("p_action" "text", "p_table_name" "text", "p_record_id" "uuid" DEFAULT NULL::"uuid", "p_old_values" "jsonb" DEFAULT NULL::"jsonb", "p_new_values" "jsonb" DEFAULT NULL::"jsonb", "p_real_ip" "text" DEFAULT NULL::"text") RETURNS "uuid"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE
  audit_id uuid;
  final_ip text;
  location_data jsonb;
BEGIN
  -- Use provided IP or try to get real IP
  IF p_real_ip IS NOT NULL THEN
    final_ip := p_real_ip;
  ELSE
    final_ip := get_real_client_ip();
  END IF;
  
  -- Get location data (placeholder for now)
  location_data := get_ip_location(final_ip);
  
  INSERT INTO public.audit_logs (
    user_id,
    action,
    table_name,
    record_id,
    old_values,
    new_values,
    ip_address,
    user_agent,
    location_country,
    location_region,
    location_city
  ) VALUES (
    auth.uid(),
    p_action,
    p_table_name,
    p_record_id,
    p_old_values,
    p_new_values,
    final_ip::inet,
    current_setting('request.headers', true)::json->>'user-agent',
    location_data->>'country',
    location_data->>'region',
    location_data->>'city'
  ) RETURNING id INTO audit_id;
  
  RETURN audit_id;
END;
$$;


--
-- Name: log_audit_with_real_ip("text", "text", "uuid", "jsonb", "jsonb", "text"); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."log_audit_with_real_ip"("p_action" "text", "p_table_name" "text", "p_record_id" "uuid" DEFAULT NULL::"uuid", "p_old_values" "jsonb" DEFAULT NULL::"jsonb", "p_new_values" "jsonb" DEFAULT NULL::"jsonb", "p_real_ip" "text" DEFAULT NULL::"text") RETURNS "uuid"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE
  audit_id uuid;
  final_ip text;
BEGIN
  -- Use provided IP or try to get real IP
  IF p_real_ip IS NOT NULL THEN
    final_ip := p_real_ip;
  ELSE
    final_ip := get_real_client_ip();
  END IF;
  
  INSERT INTO public.audit_logs (
    user_id,
    action,
    table_name,
    record_id,
    old_values,
    new_values,
    ip_address,
    user_agent
  ) VALUES (
    auth.uid(),
    p_action,
    p_table_name,
    p_record_id,
    p_old_values,
    p_new_values,
    final_ip::inet,
    current_setting('request.headers', true)::json->>'user-agent'
  ) RETURNING id INTO audit_id;
  
  RETURN audit_id;
END;
$$;


--
-- Name: log_authentication_event("text", "text", boolean, "text", "jsonb"); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."log_authentication_event"("event_type" "text", "user_email" "text" DEFAULT NULL::"text", "success" boolean DEFAULT true, "failure_reason" "text" DEFAULT NULL::"text", "metadata" "jsonb" DEFAULT '{}'::"jsonb") RETURNS "uuid"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'pg_temp'
    AS $_$
DECLARE
  event_id uuid;
  severity text;
  client_ip text;
  sanitized_event_type text;
  sanitized_email text;
  sanitized_failure_reason text;
BEGIN
  -- Input validation
  IF event_type IS NULL OR trim(event_type) = '' THEN
    RAISE EXCEPTION 'Event type is required';
  END IF;
  
  -- Sanitize and validate inputs
  sanitized_event_type := trim(event_type);
  
  -- Validate event type format
  IF NOT sanitized_event_type ~ '^[a-zA-Z0-9_]+$' THEN
    RAISE EXCEPTION 'Invalid event type format';
  END IF;
  
  IF length(sanitized_event_type) > 50 THEN
    RAISE EXCEPTION 'Event type too long';
  END IF;
  
  -- Validate allowed event types
  IF NOT sanitized_event_type IN ('login', 'logout', 'register', 'password_reset', 'email_change', '2fa_setup', '2fa_verify', 'account_lock', 'account_unlock', 'password_change') THEN
    RAISE EXCEPTION 'Unknown event type: %', sanitized_event_type;
  END IF;
  
  -- Sanitize email if provided
  IF user_email IS NOT NULL THEN
    sanitized_email := trim(lower(user_email));
    IF length(sanitized_email) > 254 THEN
      RAISE EXCEPTION 'Email too long';
    END IF;
    -- Basic email format validation
    IF NOT sanitized_email ~ '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$' THEN
      RAISE EXCEPTION 'Invalid email format';
    END IF;
  END IF;
  
  -- Sanitize failure reason if provided
  IF failure_reason IS NOT NULL THEN
    sanitized_failure_reason := trim(failure_reason);
    IF length(sanitized_failure_reason) > 500 THEN
      sanitized_failure_reason := left(sanitized_failure_reason, 500);
    END IF;
    -- Remove potential injection attempts
    sanitized_failure_reason := regexp_replace(sanitized_failure_reason, '[<>"\''\\]', '', 'g');
  END IF;
  
  -- Validate metadata
  IF metadata IS NOT NULL THEN
    -- Ensure metadata is not too large
    IF length(metadata::text) > 10000 THEN
      metadata := '{"error": "metadata_too_large"}'::jsonb;
    END IF;
  ELSE
    metadata := '{}'::jsonb;
  END IF;
  
  client_ip := get_real_client_ip();
  
  -- Determine severity based on event
  severity := CASE 
    WHEN NOT success THEN 'high'
    WHEN sanitized_event_type IN ('login', 'logout') THEN 'low'
    WHEN sanitized_event_type IN ('password_reset', 'email_change', 'password_change') THEN 'medium'
    WHEN sanitized_event_type IN ('2fa_setup', '2fa_verify') THEN 'medium'
    WHEN sanitized_event_type IN ('account_lock', 'account_unlock') THEN 'high'
    ELSE 'low'
  END;
  
  -- Enhanced metadata with validation
  metadata := metadata || jsonb_build_object(
    'user_email', sanitized_email,
    'success', success,
    'failure_reason', sanitized_failure_reason,
    'ip_address', client_ip,
    'timestamp', now(),
    'user_agent', current_setting('request.headers', true)::json->>'user-agent'
  );
  
  -- Log to audit system
  event_id := log_security_event(
    'AUTH_' || upper(sanitized_event_type),
    severity,
    CASE 
      WHEN success THEN format('Authentication %s successful', sanitized_event_type)
      ELSE format('Authentication %s failed: %s', sanitized_event_type, COALESCE(sanitized_failure_reason, 'Unknown reason'))
    END,
    client_ip,
    auth.uid(),
    metadata
  );
  
  -- Check for brute force attempts on failed logins
  IF NOT success AND sanitized_event_type = 'login' THEN
    DECLARE
      recent_failures integer;
    BEGIN
      SELECT COUNT(*) INTO recent_failures
      FROM audit_logs
      WHERE action = 'SECURITY_EVENT'
      AND new_values->>'event_type' = 'AUTH_LOGIN'
      AND new_values->>'success' = 'false'
      AND ip_address = client_ip::inet
      AND timestamp > now() - interval '15 minutes';
      
      IF recent_failures >= 5 THEN
        PERFORM log_security_event(
          'BRUTE_FORCE_DETECTED',
          'critical',
          format('Brute force attack detected: %s failed login attempts from %s', recent_failures, client_ip),
          client_ip,
          NULL,
          jsonb_build_object(
            'failed_attempts', recent_failures,
            'target_email', sanitized_email,
            'time_window', '15 minutes'
          )
        );
      END IF;
    END;
  END IF;
  
  RETURN event_id;
  
EXCEPTION WHEN OTHERS THEN
  -- Log the error but don't expose sensitive details
  PERFORM log_security_event(
    'FUNCTION_ERROR',
    'high',
    format('log_authentication_event function error: %s', SQLERRM),
    get_real_client_ip(),
    auth.uid(),
    jsonb_build_object('function', 'log_authentication_event', 'event_type', event_type)
  );
  RAISE;
END;
$_$;


--
-- Name: log_guest_data_access("uuid", "text"[], "text", "jsonb"); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."log_guest_data_access"("guest_id" "uuid", "accessed_fields" "text"[], "access_reason" "text" DEFAULT 'view'::"text", "additional_metadata" "jsonb" DEFAULT '{}'::"jsonb") RETURNS "uuid"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'pg_temp'
    AS $$
DECLARE
  access_log_id UUID;
  client_ip TEXT;
BEGIN
  -- Get client IP
  client_ip := get_real_client_ip();
  
  -- Log the access
  INSERT INTO public.audit_logs (
    user_id,
    action,
    table_name,
    record_id,
    new_values,
    ip_address,
    user_agent
  ) VALUES (
    auth.uid(),
    'GUEST_DATA_ACCESS',
    'guests',
    guest_id,
    jsonb_build_object(
      'accessed_fields', accessed_fields,
      'access_reason', access_reason,
      'metadata', additional_metadata,
      'timestamp', now()
    ),
    client_ip::inet,
    current_setting('request.headers', true)::json->>'user-agent'
  ) RETURNING id INTO access_log_id;
  
  -- Update guest's last access timestamp
  UPDATE public.guests 
  SET 
    last_data_access = now(),
    access_log_id = access_log_id
  WHERE id = guest_id;
  
  RETURN access_log_id;
END;
$$;


--
-- Name: log_html_content_access("text", "uuid", "text"); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."log_html_content_access"("content_type" "text", "content_id" "uuid", "access_type" "text" DEFAULT 'view'::"text") RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'pg_temp'
    AS $$
DECLARE
  current_user_id uuid;
  client_ip text;
BEGIN
  current_user_id := auth.uid();
  client_ip := 'unknown';
  
  INSERT INTO audit_logs (
    user_id,
    action,
    table_name,
    record_id,
    ip_address,
    user_agent,
    created_at
  ) VALUES (
    current_user_id,
    format('html_content_%s_%s', content_type, access_type),
    'html_content_access',
    content_id,
    client_ip,
    'system',
    now()
  );
END;
$$;


--
-- Name: log_security_event("uuid", "text", "jsonb"); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."log_security_event"("p_user_id" "uuid", "p_event" "text", "p_meta" "jsonb" DEFAULT '{}'::"jsonb") RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'pg_temp'
    AS $$
BEGIN
  INSERT INTO public.security_events(user_id, event_type, meta, created_at)
  VALUES (p_user_id, p_event, coalesce(p_meta, '{}'::jsonb), now());
END;
$$;


--
-- Name: log_security_event("text", "text", "text", "text", "uuid", "jsonb"); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."log_security_event"("event_type" "text", "severity" "text" DEFAULT 'medium'::"text", "description" "text" DEFAULT NULL::"text", "ip_address" "text" DEFAULT NULL::"text", "user_id" "uuid" DEFAULT NULL::"uuid", "metadata" "jsonb" DEFAULT '{}'::"jsonb") RETURNS "uuid"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'pg_temp'
    AS $_$
DECLARE
  event_id uuid;
  real_ip text;
  sanitized_event_type text;
  sanitized_severity text;
  sanitized_description text;
BEGIN
  -- Input validation and sanitization
  IF event_type IS NULL OR trim(event_type) = '' THEN
    RAISE EXCEPTION 'Event type is required';
  END IF;
  
  sanitized_event_type := trim(event_type);
  
  -- Validate event type format and length
  IF NOT sanitized_event_type ~ '^[A-Z0-9_]+$' THEN
    RAISE EXCEPTION 'Invalid event type format';
  END IF;
  
  IF length(sanitized_event_type) > 100 THEN
    RAISE EXCEPTION 'Event type too long';
  END IF;
  
  -- Validate and sanitize severity
  sanitized_severity := COALESCE(trim(lower(severity)), 'medium');
  IF NOT sanitized_severity IN ('low', 'medium', 'high', 'critical') THEN
    sanitized_severity := 'medium';
  END IF;
  
  -- Sanitize description
  IF description IS NOT NULL THEN
    sanitized_description := trim(description);
    IF length(sanitized_description) > 1000 THEN
      sanitized_description := left(sanitized_description, 1000);
    END IF;
    -- Remove potential injection attempts
    sanitized_description := regexp_replace(sanitized_description, '[<>"\''\\]', '', 'g');
  END IF;
  
  -- Validate metadata size
  IF metadata IS NOT NULL AND length(metadata::text) > 50000 THEN
    metadata := '{"error": "metadata_too_large"}'::jsonb;
  END IF;

  -- Get real IP if not provided
  IF ip_address IS NULL THEN
    real_ip := get_real_client_ip();
  ELSE
    real_ip := trim(ip_address);
    -- Validate IP format
    IF length(real_ip) > 45 THEN -- IPv6 max length
      real_ip := 'invalid_ip';
    END IF;
  END IF;

  -- Log security event to audit logs
  INSERT INTO audit_logs (
    user_id,
    action,
    table_name,
    old_values,
    new_values,
    ip_address,
    user_agent
  ) VALUES (
    COALESCE(user_id, auth.uid()),
    'SECURITY_EVENT',
    'security_events',
    NULL,
    jsonb_build_object(
      'event_type', sanitized_event_type,
      'severity', sanitized_severity,
      'description', sanitized_description,
      'metadata', COALESCE(metadata, '{}'::jsonb),
      'timestamp', now()
    ),
    real_ip::inet,
    current_setting('request.headers', true)::json->>'user-agent'
  ) RETURNING id INTO event_id;

  -- Auto-block IPs with repeated critical security events
  IF sanitized_severity = 'critical' THEN
    -- Check if this IP has had multiple critical events recently
    IF (
      SELECT COUNT(*) 
      FROM audit_logs 
      WHERE action = 'SECURITY_EVENT' 
      AND ip_address = real_ip::inet
      AND new_values->>'severity' = 'critical'
      AND timestamp > now() - interval '1 hour'
    ) >= 3 THEN
      -- Auto-block the IP
      INSERT INTO ip_access_rules (
        ip_address,
        rule_type,
        reason,
        description,
        created_by
      ) VALUES (
        real_ip::inet,
        'block',
        'Automated block due to repeated critical security events',
        format('IP %s blocked automatically after %s critical security events in 1 hour', real_ip, 3),
        NULL -- System action
      ) ON CONFLICT (ip_address) DO UPDATE SET
        rule_type = 'block',
        reason = EXCLUDED.reason,
        description = EXCLUDED.description,
        is_active = true,
        created_at = now();
    END IF;
  END IF;

  RETURN event_id;
  
EXCEPTION WHEN OTHERS THEN
  -- Final fallback - try to log to audit_logs without validation
  BEGIN
    INSERT INTO audit_logs (user_id, action, table_name, new_values, ip_address)
    VALUES (auth.uid(), 'FUNCTION_ERROR', 'log_security_event', 
            jsonb_build_object('error', SQLERRM, 'event_type', event_type), 
            get_real_client_ip()::inet)
    RETURNING id INTO event_id;
    RETURN event_id;
  EXCEPTION WHEN OTHERS THEN
    -- If even that fails, generate a UUID and return it
    RETURN gen_random_uuid();
  END;
END;
$_$;


--
-- Name: mask_guest_field("text", "text", "text"[], "public"."data_classification"); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."mask_guest_field"("field_value" "text", "field_name" "text", "user_permissions" "text"[] DEFAULT '{}'::"text"[], "classification_override" "public"."data_classification" DEFAULT NULL::"public"."data_classification") RETURNS "text"
    LANGUAGE "plpgsql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public', 'pg_temp'
    AS $_$
DECLARE
  field_classification data_classification;
  required_perm TEXT;
  masking_rule TEXT;
  has_permission_check BOOLEAN := false;
BEGIN
  -- Return null if no value
  IF field_value IS NULL OR field_value = '' THEN
    RETURN field_value;
  END IF;
  
  -- Get field classification
  SELECT classification, required_permission, masking_rule 
  INTO field_classification, required_perm, masking_rule
  FROM guest_data_classification 
  WHERE field_name = mask_guest_field.field_name;
  
  -- Use override if provided
  IF classification_override IS NOT NULL THEN
    field_classification := classification_override;
  END IF;
  
  -- Default to CONFIDENTIAL if not found
  IF field_classification IS NULL THEN
    field_classification := 'CONFIDENTIAL';
    required_perm := 'view_sensitive_guest_data';
    masking_rule := 'full_mask';
  END IF;
  
  -- Check if user has required permission
  IF required_perm = ANY(user_permissions) OR 
     has_permission(auth.uid(), required_perm) THEN
    has_permission_check := true;
  END IF;
  
  -- Apply masking based on classification and permissions
  CASE field_classification
    WHEN 'PUBLIC' THEN
      RETURN field_value; -- Always visible
    
    WHEN 'RESTRICTED' THEN
      IF has_permission_check THEN
        RETURN field_value;
      ELSE
        -- Apply partial masking based on field type
        CASE masking_rule
          WHEN 'email_partial' THEN
            IF field_value ~ '^[^@]+@[^@]+\.[^@]+$' THEN
              RETURN substring(field_value from 1 for 1) || '***@' || split_part(field_value, '@', 2);
            ELSE
              RETURN '***';
            END IF;
          WHEN 'phone_partial' THEN
            IF length(regexp_replace(field_value, '[^\d]', '', 'g')) >= 4 THEN
              RETURN '***-***-' || right(regexp_replace(field_value, '[^\d]', '', 'g'), 4);
            ELSE
              RETURN '***-***-****';
            END IF;
          WHEN 'partial' THEN
            IF length(field_value) > 4 THEN
              RETURN left(field_value, 2) || '***' || right(field_value, 1);
            ELSE
              RETURN '***';
            END IF;
          ELSE
            RETURN '***';
        END CASE;
      END IF;
    
    WHEN 'CONFIDENTIAL' THEN
      IF has_permission_check THEN
        RETURN field_value;
      ELSE
        -- Full masking for confidential data
        CASE masking_rule
          WHEN 'passport_masked' THEN
            RETURN '***-***-***';
          WHEN 'address_partial' THEN
            -- Show only city and country if available
            RETURN 'CONFIDENTIAL - Contact admin for access';
          WHEN 'access_restricted' THEN
            RETURN 'ACCESS_RESTRICTED';
          WHEN 'summary_only' THEN
            RETURN 'NOTES_RESTRICTED';
          ELSE
            RETURN 'CONFIDENTIAL';
        END CASE;
      END IF;
    
    ELSE
      RETURN 'UNKNOWN_CLASSIFICATION';
  END CASE;
END;
$_$;


--
-- Name: mask_sensitive_audit_data("text", "text", "text"); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."mask_sensitive_audit_data"("data_value" "text", "field_name" "text" DEFAULT NULL::"text", "user_role" "text" DEFAULT NULL::"text") RETURNS "text"
    LANGUAGE "plpgsql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public', 'pg_temp'
    AS $_$
BEGIN
  -- Only show full data to system admins
  IF user_role = 'admin' OR has_permission(auth.uid(), 'view_audit_logs'::text) THEN
    -- Admins see full data but with controlled exposure
    IF field_name IN ('email', 'user_email') THEN
      -- Mask emails: show first 2 chars + domain
      IF data_value ~ '^[^@]+@[^@]+\.[^@]+$' THEN
        RETURN substring(data_value from 1 for 2) || '***@' || split_part(data_value, '@', 2);
      END IF;
    ELSIF field_name IN ('ip_address', 'client_ip') THEN
      -- Mask IP: show first 2 octets
      IF data_value ~ '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' THEN
        RETURN split_part(data_value, '.', 1) || '.' || split_part(data_value, '.', 2) || '.***.**';
      END IF;
    ELSIF field_name IN ('phone', 'phone_number') THEN
      -- Mask phone: show last 4 digits
      IF length(regexp_replace(data_value, '[^\d]', '', 'g')) >= 4 THEN
        RETURN '***-***-' || right(regexp_replace(data_value, '[^\d]', '', 'g'), 4);
      END IF;
    END IF;
    RETURN data_value;
  ELSE
    -- Non-admins get heavily masked data
    IF field_name IN ('email', 'user_email') AND data_value ~ '^[^@]+@[^@]+\.[^@]+$' THEN
      RETURN '***@' || split_part(data_value, '@', 2);
    ELSIF field_name IN ('ip_address', 'client_ip') THEN
      RETURN '***.***.***.**';
    ELSIF field_name IN ('phone', 'phone_number') THEN
      RETURN '***-***-****';
    ELSE
      RETURN '***';
    END IF;
  END IF;
END;
$_$;


--
-- Name: mask_sensitive_data("text", "text"); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."mask_sensitive_data"("data_value" "text", "user_role" "text" DEFAULT NULL::"text") RETURNS "text"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $_$
BEGIN
  -- Only show full data to admins, mask for others
  IF user_role = 'admin' OR has_permission(auth.uid(), 'view_audit_logs'::text) THEN
    RETURN data_value;
  ELSE
    -- Mask email: show first 2 chars + domain
    IF data_value ~ '^[^@]+@[^@]+\.[^@]+$' THEN
      RETURN substring(data_value from 1 for 2) || '***@' || split_part(data_value, '@', 2);
    -- Mask phone: show last 4 digits
    ELSIF data_value ~ '^[\+\d\s\-\(\)]+$' AND length(regexp_replace(data_value, '[^\d]', '', 'g')) >= 4 THEN
      RETURN '***-***-' || right(regexp_replace(data_value, '[^\d]', '', 'g'), 4);
    -- Generic masking for other sensitive data
    ELSE
      RETURN left(data_value, 2) || repeat('*', greatest(length(data_value) - 4, 0)) || right(data_value, 2);
    END IF;
  END IF;
END;
$_$;


--
-- Name: process_auto_check_operations(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."process_auto_check_operations"() RETURNS TABLE("checkin_count" integer, "checkout_count" integer, "checkin_booking_ids" "uuid"[], "checkout_booking_ids" "uuid"[], "checkin_errors" "text"[], "checkout_errors" "text"[])
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'pg_temp'
    AS $$
DECLARE
  ci_count integer := 0;
  co_count integer := 0;
  ci_ids uuid[] := '{}';
  co_ids uuid[] := '{}';
  ci_errs text[] := '{}';
  co_errs text[] := '{}';
BEGIN
  -- Process check-ins
  SELECT processed_count, booking_ids, errors
  INTO ci_count, ci_ids, ci_errs
  FROM public.process_auto_checkins();

  -- Process check-outs
  SELECT processed_count, booking_ids, errors
  INTO co_count, co_ids, co_errs
  FROM public.process_auto_checkouts();

  RETURN QUERY SELECT ci_count, co_count, ci_ids, co_ids, ci_errs, co_errs;
END;
$$;


--
-- Name: process_auto_checkins(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."process_auto_checkins"() RETURNS TABLE("processed_count" integer, "booking_ids" "uuid"[], "errors" "text"[])
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'pg_temp'
    AS $$
DECLARE
    settings_record RECORD;
    current_time_in_tz timestamp;
    booking_record RECORD;
    processed_bookings uuid[] := '{}';
    error_messages text[] := '{}';
    process_count integer := 0;
BEGIN
    -- Get system settings
    SELECT 
        timezone,
        default_checkin_time,
        auto_checkin_enabled
    INTO settings_record
    FROM general_settings
    ORDER BY created_at DESC
    LIMIT 1;
    
    -- Check if auto check-in is enabled
    IF NOT COALESCE(settings_record.auto_checkin_enabled, false) THEN
        RETURN QUERY SELECT 0, '{}'::uuid[], ARRAY['Auto check-in is disabled']::text[];
        RETURN;
    END IF;
    
    -- Get current time in configured timezone
    current_time_in_tz := now() AT TIME ZONE COALESCE(settings_record.timezone, 'UTC');
    
    -- Process bookings that are ready for check-in
    FOR booking_record IN
        SELECT 
            b.id,
            b.reference,
            b.check_in_date,
            b.status,
            r.number as room_number,
            g.first_name || ' ' || g.last_name as guest_name
        FROM bookings b
        LEFT JOIN rooms r ON b.room_id = r.id
        LEFT JOIN guests g ON b.guest_id = g.id
        WHERE b.status = 'confirmed'
        AND b.check_in_date = current_time_in_tz::date
        AND (current_time_in_tz::time >= COALESCE(settings_record.default_checkin_time, '15:00:00'::time))
    LOOP
        BEGIN
            -- Update booking status to checked_in
            UPDATE bookings 
            SET 
                status = 'checked_in',
                updated_at = now()
            WHERE id = booking_record.id;
            
            -- Update room status to occupied
            UPDATE rooms 
            SET 
                status = 'occupied',
                updated_at = now()
            WHERE id = (SELECT room_id FROM bookings WHERE id = booking_record.id);
            
            -- Add to processed list
            processed_bookings := array_append(processed_bookings, booking_record.id);
            process_count := process_count + 1;
            
            -- Log the action
            INSERT INTO audit_logs (
                user_id,
                action,
                table_name,
                record_id,
                new_values,
                ip_address
            ) VALUES (
                NULL, -- System action
                'AUTO_CHECKIN',
                'bookings',
                booking_record.id,
                jsonb_build_object(
                    'reference', booking_record.reference,
                    'room_number', booking_record.room_number,
                    'guest_name', booking_record.guest_name,
                    'check_in_date', booking_record.check_in_date,
                    'processed_at', current_time_in_tz
                ),
                '127.0.0.1'::inet
            );
            
        EXCEPTION WHEN OTHERS THEN
            error_messages := array_append(error_messages, 
                'Error processing booking ' || booking_record.reference || ': ' || SQLERRM);
        END;
    END LOOP;
    
    RETURN QUERY SELECT process_count, processed_bookings, error_messages;
END;
$$;


--
-- Name: FUNCTION "process_auto_checkins"(); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION "public"."process_auto_checkins"() IS 'Automatically processes eligible bookings for check-in';


--
-- Name: process_auto_checkouts(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."process_auto_checkouts"() RETURNS TABLE("processed_count" integer, "booking_ids" "uuid"[], "errors" "text"[])
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'pg_temp'
    AS $$
DECLARE
    settings_record RECORD;
    current_time_in_tz timestamp;
    booking_record RECORD;
    processed_bookings uuid[] := '{}';
    error_messages text[] := '{}';
    process_count integer := 0;
BEGIN
    -- Get system settings
    SELECT 
        timezone,
        default_checkout_time,
        auto_checkout_enabled
    INTO settings_record
    FROM public.general_settings
    ORDER BY created_at DESC
    LIMIT 1;

    -- Check if auto check-out is enabled
    IF NOT COALESCE(settings_record.auto_checkout_enabled, false) THEN
        RETURN QUERY SELECT 0, '{}'::uuid[], ARRAY['Auto check-out is disabled']::text[];
        RETURN;
    END IF;

    -- Get current time in configured timezone
    current_time_in_tz := now() AT TIME ZONE COALESCE(settings_record.timezone, 'UTC');

    -- Process bookings that are ready for check-out
    FOR booking_record IN
        SELECT 
            b.id,
            b.reference,
            b.check_out_date,
            b.status,
            r.number as room_number,
            g.first_name || ' ' || g.last_name as guest_name
        FROM public.bookings b
        LEFT JOIN public.rooms r ON b.room_id = r.id
        LEFT JOIN public.guests g ON b.guest_id = g.id
        WHERE b.status = 'checked_in'
          AND b.check_out_date = current_time_in_tz::date
          AND (current_time_in_tz::time >= COALESCE(settings_record.default_checkout_time, '11:00:00'::time))
    LOOP
        BEGIN
            -- Update booking status to checked_out
            UPDATE public.bookings 
            SET 
                status = 'checked_out',
                updated_at = now()
            WHERE id = booking_record.id;

            -- Update room status to available
            UPDATE public.rooms 
            SET 
                status = 'available',
                updated_at = now()
            WHERE id = (SELECT room_id FROM public.bookings WHERE id = booking_record.id);

            -- Add to processed list
            processed_bookings := array_append(processed_bookings, booking_record.id);
            process_count := process_count + 1;

            -- Log the action
            INSERT INTO public.audit_logs (
                user_id,
                action,
                table_name,
                record_id,
                new_values,
                ip_address
            ) VALUES (
                NULL, -- System action
                'AUTO_CHECKOUT',
                'bookings',
                booking_record.id,
                jsonb_build_object(
                    'reference', booking_record.reference,
                    'room_number', booking_record.room_number,
                    'guest_name', booking_record.guest_name,
                    'check_out_date', booking_record.check_out_date,
                    'processed_at', current_time_in_tz
                ),
                '127.0.0.1'::inet
            );

        EXCEPTION WHEN OTHERS THEN
            error_messages := array_append(error_messages, 
                'Error processing booking ' || booking_record.reference || ': ' || SQLERRM);
        END;
    END LOOP;

    RETURN QUERY SELECT process_count, processed_bookings, error_messages;
END;
$$;


--
-- Name: FUNCTION "process_auto_checkouts"(); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION "public"."process_auto_checkouts"() IS 'Automatically processes eligible bookings for check-out';


--
-- Name: safe_delete_owner("uuid"); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."safe_delete_owner"("owner_id_param" "uuid") RETURNS "jsonb"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE
  result jsonb := '{"success": true}'::jsonb;
  affected_tables text[] := '{}';
BEGIN
  -- Check if owner exists
  IF NOT EXISTS (SELECT 1 FROM owners WHERE id = owner_id_param) THEN
    RETURN jsonb_build_object('success', false, 'error', 'Owner not found');
  END IF;

  -- Update room_ownership to set owner_id to null
  UPDATE room_ownership 
  SET owner_id = null, active = false, updated_at = now()
  WHERE owner_id = owner_id_param;
  
  IF FOUND THEN
    affected_tables := array_append(affected_tables, 'room_ownership');
  END IF;

  -- Update property_ownership to set owner_id to null  
  UPDATE property_ownership
  SET owner_id = null, active = false, updated_at = now()
  WHERE owner_id = owner_id_param;
  
  IF FOUND THEN
    affected_tables := array_append(affected_tables, 'property_ownership');
  END IF;

  -- Update expenses to set owner_id to null (but keep the expense records)
  UPDATE expenses
  SET owner_id = null, updated_at = now()
  WHERE owner_id = owner_id_param;
  
  IF FOUND THEN
    affected_tables := array_append(affected_tables, 'expenses');
  END IF;

  -- Log the deletion action before deleting
  INSERT INTO audit_logs (
    user_id,
    action,
    table_name,
    record_id,
    old_values,
    new_values,
    ip_address
  ) VALUES (
    auth.uid(),
    'SAFE_DELETE_OWNER',
    'owners',
    owner_id_param,
    (SELECT to_jsonb(owners.*) FROM owners WHERE id = owner_id_param),
    jsonb_build_object('affected_tables', affected_tables),
    get_real_client_ip()::inet
  );

  -- Now safely delete the owner
  DELETE FROM owners WHERE id = owner_id_param;

  -- Return success with info about what was updated
  RETURN jsonb_build_object(
    'success', true,
    'affected_tables', affected_tables,
    'message', 'Owner deleted successfully. Related records were updated to remove owner references.'
  );

EXCEPTION WHEN OTHERS THEN
  -- If anything fails, return error
  RETURN jsonb_build_object(
    'success', false,
    'error', SQLERRM,
    'sqlstate', SQLSTATE
  );
END;
$$;


--
-- Name: safe_delete_room("uuid"); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."safe_delete_room"("room_id_param" "uuid") RETURNS "jsonb"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'pg_temp'
    AS $$
DECLARE
  result jsonb := '{"success": true}'::jsonb;
  affected_tables text[] := '{}';
  room_exists boolean;
  active_bookings_count integer;
BEGIN
  -- Input validation
  IF room_id_param IS NULL THEN
    RETURN jsonb_build_object('success', false, 'error', 'Room ID is required');
  END IF;

  -- Check if room exists
  SELECT EXISTS (SELECT 1 FROM rooms WHERE id = room_id_param) INTO room_exists;
  IF NOT room_exists THEN
    RETURN jsonb_build_object('success', false, 'error', 'Room not found');
  END IF;

  -- Check for active bookings
  SELECT COUNT(*) INTO active_bookings_count
  FROM bookings 
  WHERE room_id = room_id_param 
  AND status IN ('confirmed', 'checked_in');
  
  IF active_bookings_count > 0 THEN
    RETURN jsonb_build_object(
      'success', false, 
      'error', format('Cannot delete room with %s active bookings. Please cancel or complete all bookings first.', active_bookings_count)
    );
  END IF;

  -- Update room_ownership to set room_id to null and deactivate
  UPDATE room_ownership 
  SET room_id = null, active = false, updated_at = now()
  WHERE room_id = room_id_param;
  
  IF FOUND THEN
    affected_tables := array_append(affected_tables, 'room_ownership');
  END IF;

  -- Update cleaning_tasks to set room_id to null
  UPDATE cleaning_tasks
  SET room_id = null, updated_at = now()
  WHERE room_id = room_id_param;
  
  IF FOUND THEN
    affected_tables := array_append(affected_tables, 'cleaning_tasks');
  END IF;

  -- Update expenses to set room_id to null (but keep the expense records)
  UPDATE expenses
  SET room_id = null, updated_at = now()
  WHERE room_id = room_id_param;
  
  IF FOUND THEN
    affected_tables := array_append(affected_tables, 'expenses');
  END IF;

  -- Update old bookings to set room_id to null (keep historical data)
  UPDATE bookings
  SET room_id = null, updated_at = now()
  WHERE room_id = room_id_param
  AND status NOT IN ('confirmed', 'checked_in');
  
  IF FOUND THEN
    affected_tables := array_append(affected_tables, 'bookings');
  END IF;

  -- Log the deletion action before deleting
  INSERT INTO audit_logs (
    user_id,
    action,
    table_name,
    record_id,
    old_values,
    new_values,
    ip_address
  ) VALUES (
    auth.uid(),
    'SAFE_DELETE_ROOM',
    'rooms',
    room_id_param,
    (SELECT to_jsonb(rooms.*) FROM rooms WHERE id = room_id_param),
    jsonb_build_object('affected_tables', affected_tables),
    get_real_client_ip()::inet
  );

  -- Now safely delete the room
  DELETE FROM rooms WHERE id = room_id_param;

  -- Return success with info about what was updated
  RETURN jsonb_build_object(
    'success', true,
    'affected_tables', affected_tables,
    'message', 'Room deleted successfully. Related records were updated to remove room references.'
  );

EXCEPTION WHEN OTHERS THEN
  -- If anything fails, return error
  RETURN jsonb_build_object(
    'success', false,
    'error', SQLERRM,
    'sqlstate', SQLSTATE
  );
END;
$$;


--
-- Name: sanitize_contract_template_content(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."sanitize_contract_template_content"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    SET "search_path" TO 'public', 'pg_temp'
    AS $$
BEGIN
  IF NOT validate_html_content(NEW.template_content) THEN
    RAISE EXCEPTION 'Invalid HTML content detected';
  END IF;
  
  NEW.template_content := sanitize_html_content(NEW.template_content);
  
  RETURN NEW;
END;
$$;


--
-- Name: sanitize_html_content("text"); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."sanitize_html_content"("input_html" "text") RETURNS "text"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'pg_temp'
    AS $$
DECLARE
  sanitized_html text;
BEGIN
  sanitized_html := input_html;
  
  -- Remove script tags and their content
  sanitized_html := regexp_replace(sanitized_html, '<script[^>]*>.*?</script>', '', 'gi');
  
  -- Remove dangerous attributes
  sanitized_html := regexp_replace(sanitized_html, '\s(on\w+|javascript:|data:)\s*=\s*[''"][^''"]*[''"]', '', 'gi');
  
  -- Remove iframe, object, embed tags
  sanitized_html := regexp_replace(sanitized_html, '<(iframe|object|embed|link|meta)[^>]*>', '', 'gi');
  
  -- Remove style attributes with javascript
  sanitized_html := regexp_replace(sanitized_html, 'style\s*=\s*[''"][^''"]*expression\s*\([^''"]', '', 'gi');
  sanitized_html := regexp_replace(sanitized_html, 'style\s*=\s*[''"][^''"]*javascript:[^''"]*[''"]', '', 'gi');
  
  RETURN sanitized_html;
END;
$$;


--
-- Name: set_pdf_contract_templates_user(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."set_pdf_contract_templates_user"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    NEW.created_by = COALESCE(NEW.created_by, auth.uid());
  END IF;
  NEW.updated_by = auth.uid();
  NEW.updated_at = TIMEZONE('utc'::text, NOW());
  RETURN NEW;
END;
$$;


--
-- Name: trigger_admin_2fa_enforcement(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."trigger_admin_2fa_enforcement"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'pg_temp'
    AS $$
BEGIN
  -- Check if the assigned role is admin
  IF EXISTS (
    SELECT 1 FROM public.user_roles 
    WHERE id = NEW.role_id AND name = 'admin'
  ) THEN
    -- Schedule 2FA enforcement check
    PERFORM enforce_admin_2fa();
  END IF;
  
  RETURN NEW;
END;
$$;


--
-- Name: update_guest_consent("uuid", boolean, boolean, boolean, "jsonb"); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."update_guest_consent"("guest_id" "uuid", "data_processing" boolean DEFAULT NULL::boolean, "marketing" boolean DEFAULT NULL::boolean, "third_party_sharing" boolean DEFAULT NULL::boolean, "consent_metadata" "jsonb" DEFAULT '{}'::"jsonb") RETURNS boolean
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'pg_temp'
    AS $$
DECLARE
  client_ip TEXT;
BEGIN
  -- Check permissions
  IF NOT has_permission(auth.uid(), 'update_bookings') THEN
    RAISE EXCEPTION 'Access denied: insufficient permissions to update consent';
  END IF;
  
  client_ip := get_real_client_ip();
  
  -- Update consent fields
  UPDATE public.guests SET
    consent_data_processing = COALESCE(data_processing, consent_data_processing),
    consent_marketing = COALESCE(marketing, consent_marketing),
    consent_third_party_sharing = COALESCE(third_party_sharing, consent_third_party_sharing),
    consent_timestamp = now(),
    consent_ip_address = client_ip::inet,
    updated_at = now()
  WHERE id = guest_id;
  
  -- Log consent update
  PERFORM log_audit_access(
    'consent_update',
    1,
    jsonb_build_object(
      'guest_id', guest_id,
      'data_processing', data_processing,
      'marketing', marketing,
      'third_party_sharing', third_party_sharing,
      'metadata', consent_metadata
    )
  );
  
  RETURN FOUND;
END;
$$;


--
-- Name: update_notification_timestamps(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."update_notification_timestamps"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    SET "search_path" TO 'public', 'pg_temp'
    AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$;


--
-- Name: update_room_status("uuid", "public"."room_status", "uuid"); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."update_room_status"("room_uuid" "uuid", "new_status" "public"."room_status", "user_uuid" "uuid" DEFAULT "auth"."uid"()) RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'pg_temp'
    AS $$
DECLARE
  room_exists boolean;
  valid_status boolean;
BEGIN
  -- Input validation
  IF room_uuid IS NULL THEN
    RAISE EXCEPTION 'Room ID is required';
  END IF;
  
  IF new_status IS NULL THEN
    RAISE EXCEPTION 'Status is required';
  END IF;
  
  -- Check if room exists
  SELECT EXISTS (SELECT 1 FROM rooms WHERE id = room_uuid) INTO room_exists;
  IF NOT room_exists THEN
    RAISE EXCEPTION 'Room not found';
  END IF;
  
  -- Validate status transition (implement business logic)
  SELECT new_status IN ('available', 'occupied', 'cleaning', 'maintenance', 'out_of_order') INTO valid_status;
  IF NOT valid_status THEN
    RAISE EXCEPTION 'Invalid room status';
  END IF;
  
  -- Update room status
  UPDATE public.rooms 
  SET 
    status = new_status,
    updated_by = COALESCE(user_uuid, auth.uid()),
    updated_at = now(),
    last_cleaned = CASE 
      WHEN new_status = 'cleaned' THEN now() 
      ELSE last_cleaned 
    END
  WHERE id = room_uuid;
  
  -- Create cleaning task if status is 'cleaning'
  IF new_status = 'cleaning' THEN
    INSERT INTO public.cleaning_tasks (room_id, status, created_by)
    VALUES (room_uuid, 'in_progress', COALESCE(user_uuid, auth.uid()));
  END IF;
  
  -- Complete cleaning task if status is 'cleaned'
  IF new_status = 'cleaned' THEN
    UPDATE public.cleaning_tasks 
    SET status = 'completed', completed_date = now()
    WHERE room_id = room_uuid AND status = 'in_progress';
  END IF;
  
EXCEPTION WHEN OTHERS THEN
  -- Log error
  PERFORM log_security_event(
    'FUNCTION_ERROR',
    'medium',
    format('update_room_status function error: %s', SQLERRM),
    get_real_client_ip(),
    user_uuid,
    jsonb_build_object('function', 'update_room_status', 'room_id', room_uuid, 'status', new_status)
  );
  RAISE;
END;
$$;


--
-- Name: update_updated_at_column(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."update_updated_at_column"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    SET "search_path" TO 'public'
    AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$;


--
-- Name: user_can_access_guest("uuid"); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."user_can_access_guest"("guest_id" "uuid") RETURNS boolean
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE
  user_role_name TEXT;
  user_id UUID := auth.uid();
  is_admin_user BOOLEAN;
  is_staff_user BOOLEAN;
  is_owner_user BOOLEAN;
BEGIN
  -- Get user role name from user_role_assignments
  SELECT ur.name INTO user_role_name 
  FROM public.user_role_assignments ura
  JOIN public.user_roles ur ON ura.role_id = ur.id
  WHERE ura.user_id = auth.uid()
  LIMIT 1;
  
  is_admin_user := (user_role_name = 'admin');
  is_staff_user := (user_role_name IN ('staff', 'admin'));
  is_owner_user := is_owner(user_id);

  -- Admins with 'view_sensitive_guest_data' permission can see all guests
  IF is_admin_user AND has_permission(auth.uid(), 'view_sensitive_guest_data') THEN
    RETURN TRUE;
  END IF;

  -- Staff with 'view_guests' permission can see guests from their bookings
  IF is_staff_user AND has_permission(auth.uid(), 'view_guests') THEN
    IF EXISTS (
      SELECT 1
      FROM public.bookings b
      WHERE b.guest_id = user_can_access_guest.guest_id
    ) THEN
      RETURN TRUE;
    END IF;
  END IF;

  -- Owners can see guests from their rooms' bookings
  IF is_owner_user THEN
    IF EXISTS (
      SELECT 1
      FROM public.bookings b
      WHERE b.guest_id = user_can_access_guest.guest_id 
        AND b.room_id IN (SELECT room_id FROM get_owner_rooms(user_id))
    ) THEN
      RETURN TRUE;
    END IF;
  END IF;

  RETURN FALSE;
END;
$$;


--
-- Name: user_has_mfa("uuid"); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."user_has_mfa"("uid" "uuid") RETURNS boolean
    LANGUAGE "sql" SECURITY DEFINER
    SET "search_path" TO 'public', 'pg_temp'
    AS $$
  SELECT EXISTS(SELECT 1 FROM auth.mfa_factors WHERE user_id = uid);
$$;


--
-- Name: validate_document_access("text", "text", "uuid"); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."validate_document_access"("bucket_name" "text", "file_path" "text", "user_id" "uuid" DEFAULT "auth"."uid"()) RETURNS boolean
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE
  is_user_owner boolean := false;
  access_granted boolean := false;
BEGIN
  -- Check if user exists and is authenticated
  IF user_id IS NULL THEN
    RETURN false;
  END IF;
  
  -- Check if user is owner
  is_user_owner := is_owner(user_id);
  
  -- Admin users have access to all documents
  IF has_permission(user_id, 'view_audit_logs'::text) THEN
    RETURN true;
  END IF;
  
  -- Check bucket-specific access
  CASE bucket_name
    WHEN 'guest-documents' THEN
      IF NOT has_permission(user_id, 'view_bookings'::text) THEN
        RETURN false;
      END IF;
      
      IF is_user_owner THEN
        -- Owners can only access documents from their bookings
        SELECT EXISTS (
          SELECT 1 FROM bookings b 
          WHERE b.document_urls @> ARRAY[file_path]
          AND b.room_id = ANY (get_owner_rooms(user_id))
        ) INTO access_granted;
      ELSE
        -- Staff can access all guest documents
        access_granted := true;
      END IF;
    
    WHEN 'booking-documents' THEN
      IF NOT has_permission(user_id, 'view_bookings'::text) THEN
        RETURN false;
      END IF;
      
      IF is_user_owner THEN
        -- Owners can only access documents from their bookings
        SELECT EXISTS (
          SELECT 1 FROM bookings b 
          WHERE b.document_urls @> ARRAY[file_path]
          AND b.room_id = ANY (get_owner_rooms(user_id))
        ) INTO access_granted;
      ELSE
        -- Staff can access all booking documents
        access_granted := true;
      END IF;
    
    WHEN 'expense-receipts' THEN
      IF NOT has_permission(user_id, 'view_expenses'::text) THEN
        RETURN false;
      END IF;
      
      IF is_user_owner THEN
        -- Owners can only access receipts from their properties/expenses
        SELECT EXISTS (
          SELECT 1 FROM expenses e 
          WHERE (e.receipt_urls @> ARRAY[file_path] OR e.document_urls @> ARRAY[file_path])
          AND (
            e.property_id = ANY (get_owner_properties(user_id)) OR
            e.room_id = ANY (get_owner_rooms(user_id)) OR
            e.owner_id IN (SELECT id FROM owners WHERE auth_user_id = user_id)
          )
        ) INTO access_granted;
      ELSE
        -- Staff can access all expense receipts
        access_granted := true;
      END IF;
    
    WHEN 'room-images', 'avatars' THEN
      -- Public buckets - always accessible for viewing
      access_granted := true;
    
    ELSE
      -- Unknown bucket
      access_granted := false;
  END CASE;
  
  RETURN access_granted;
  
EXCEPTION WHEN OTHERS THEN
  -- In case of any error, deny access
  RETURN false;
END;
$$;


--
-- Name: validate_email("text"); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."validate_email"("email_input" "text") RETURNS "jsonb"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'pg_temp'
    AS $_$
DECLARE
  result jsonb;
  sanitized_email text;
BEGIN
  -- Input validation
  IF email_input IS NULL THEN
    RETURN jsonb_build_object('valid', false, 'error', 'Email is required');
  END IF;
  
  -- Length check before processing
  IF length(email_input) > 320 THEN -- RFC 5321 limit
    RETURN jsonb_build_object('valid', false, 'error', 'Email is too long');
  END IF;
  
  -- Sanitize input - remove dangerous characters
  sanitized_email := regexp_replace(trim(lower(email_input)), '[<>"\''\\]', '', 'g');
  
  -- Basic format validation
  IF sanitized_email = '' THEN
    RETURN jsonb_build_object('valid', false, 'error', 'Email is required');
  END IF;
  
  IF length(sanitized_email) > 254 THEN
    RETURN jsonb_build_object('valid', false, 'error', 'Email is too long');
  END IF;
  
  -- RFC 5322 compliant regex (simplified)
  IF NOT sanitized_email ~ '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$' THEN
    RETURN jsonb_build_object('valid', false, 'error', 'Invalid email format');
  END IF;
  
  -- Check for suspicious patterns
  IF sanitized_email ~ '(\.{2,}|@{2,}|\+{2,}|_{3,}|%{2,})' THEN
    RETURN jsonb_build_object('valid', false, 'error', 'Email contains invalid patterns');
  END IF;
  
  -- Additional security checks
  IF sanitized_email ~ '(script|javascript|vbscript|onload|onerror)' THEN
    RETURN jsonb_build_object('valid', false, 'error', 'Email contains prohibited content');
  END IF;
  
  RETURN jsonb_build_object('valid', true, 'sanitized', sanitized_email);
  
EXCEPTION WHEN OTHERS THEN
  PERFORM log_security_event(
    'FUNCTION_ERROR',
    'medium',
    format('validate_email function error: %s', SQLERRM),
    get_real_client_ip(),
    auth.uid(),
    jsonb_build_object('function', 'validate_email', 'input_length', length(email_input))
  );
  RETURN jsonb_build_object('valid', false, 'error', 'Email validation failed');
END;
$_$;


--
-- Name: validate_file_upload("text", bigint, "text", "text"); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."validate_file_upload"("file_name" "text", "file_size" bigint, "content_type" "text", "bucket_name" "text") RETURNS "jsonb"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'pg_temp'
    AS $_$
DECLARE
  result jsonb;
  allowed_types text[];
  max_size bigint;
  file_extension text;
  sanitized_name text;
BEGIN
  -- Input validation
  IF file_name IS NULL OR trim(file_name) = '' THEN
    RETURN jsonb_build_object('valid', false, 'error', 'File name is required');
  END IF;
  
  IF file_size IS NULL OR file_size < 0 THEN
    RETURN jsonb_build_object('valid', false, 'error', 'Invalid file size');
  END IF;
  
  IF content_type IS NULL OR trim(content_type) = '' THEN
    RETURN jsonb_build_object('valid', false, 'error', 'Content type is required');
  END IF;
  
  IF bucket_name IS NULL OR trim(bucket_name) = '' THEN
    RETURN jsonb_build_object('valid', false, 'error', 'Bucket name is required');
  END IF;
  
  -- Sanitize file name
  sanitized_name := regexp_replace(trim(file_name), '[^\w\-_.]', '_', 'g');
  
  -- Get file extension safely
  file_extension := lower(substring(sanitized_name from '\.([^.]*)$'));
  
  -- Validate file name length
  IF length(sanitized_name) > 255 THEN
    RETURN jsonb_build_object('valid', false, 'error', 'File name too long (max 255 characters)');
  END IF;
  
  -- Check for dangerous file patterns
  IF sanitized_name ~* '\.(php|jsp|asp|aspx|cgi|pl|sh|bat|cmd|exe|scr|vbs|js|jar|war)$' THEN
    RETURN jsonb_build_object('valid', false, 'error', 'File type not allowed for security reasons');
  END IF;
  
  -- Validate file name security
  IF sanitized_name ~ '\.\.|/|\\|<|>|\||:|\*|\?|"|[\x00-\x1f]' THEN
    RETURN jsonb_build_object('valid', false, 'error', 'File name contains invalid characters');
  END IF;
  
  -- Prevent null byte injection
  IF position(E'\\000' in file_name) > 0 THEN
    RETURN jsonb_build_object('valid', false, 'error', 'File name contains invalid characters');
  END IF;
  
  -- Define allowed types and sizes per bucket with validation
  CASE bucket_name
    WHEN 'avatars' THEN
      allowed_types := ARRAY['image/jpeg', 'image/png', 'image/webp', 'image/gif'];
      max_size := 5 * 1024 * 1024; -- 5MB
    WHEN 'room-images' THEN
      allowed_types := ARRAY['image/jpeg', 'image/png', 'image/webp', 'image/gif'];
      max_size := 10 * 1024 * 1024; -- 10MB
    WHEN 'guest-documents', 'booking-documents' THEN
      allowed_types := ARRAY['application/pdf', 'image/jpeg', 'image/png', 'image/tiff'];
      max_size := 20 * 1024 * 1024; -- 20MB
    WHEN 'expense-receipts' THEN
      allowed_types := ARRAY['application/pdf', 'image/jpeg', 'image/png', 'image/tiff'];
      max_size := 15 * 1024 * 1024; -- 15MB
    ELSE
      RETURN jsonb_build_object('valid', false, 'error', 'Unknown bucket type');
  END CASE;
  
  -- Validate file size
  IF file_size > max_size THEN
    RETURN jsonb_build_object('valid', false, 'error', format('File size exceeds %s MB limit', max_size / (1024 * 1024)));
  END IF;
  
  -- Minimum file size check (prevent empty files)
  IF file_size < 1 THEN
    RETURN jsonb_build_object('valid', false, 'error', 'File cannot be empty');
  END IF;
  
  -- Validate content type
  IF NOT content_type = ANY(allowed_types) THEN
    RETURN jsonb_build_object('valid', false, 'error', 'File type not allowed for this bucket');
  END IF;
  
  -- Cross-validate content type with file extension
  IF NOT (
    (content_type = 'image/jpeg' AND file_extension IN ('jpg', 'jpeg')) OR
    (content_type = 'image/png' AND file_extension = 'png') OR
    (content_type = 'image/webp' AND file_extension = 'webp') OR
    (content_type = 'image/gif' AND file_extension = 'gif') OR
    (content_type = 'image/tiff' AND file_extension IN ('tif', 'tiff')) OR
    (content_type = 'application/pdf' AND file_extension = 'pdf')
  ) THEN
    RETURN jsonb_build_object('valid', false, 'error', 'File extension does not match content type');
  END IF;
  
  RETURN jsonb_build_object('valid', true, 'sanitized_name', sanitized_name);
  
EXCEPTION WHEN OTHERS THEN
  PERFORM log_security_event(
    'FUNCTION_ERROR',
    'medium',
    format('validate_file_upload function error: %s', SQLERRM),
    get_real_client_ip(),
    auth.uid(),
    jsonb_build_object(
      'function', 'validate_file_upload',
      'bucket', bucket_name,
      'file_size', file_size
    )
  );
  RETURN jsonb_build_object('valid', false, 'error', 'File validation failed');
END;
$_$;


--
-- Name: validate_guest_document_access("uuid", "text", "text"); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."validate_guest_document_access"("guest_id" "uuid", "document_type" "text", "document_path" "text") RETURNS boolean
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'pg_temp'
    AS $$
DECLARE
  guest_exists BOOLEAN;
  has_sensitive_access BOOLEAN;
BEGIN
  -- Check if guest exists and user has access
  SELECT EXISTS (
    SELECT 1 FROM public.guests 
    WHERE id = guest_id
  ) INTO guest_exists;
  
  IF NOT guest_exists THEN
    RETURN false;
  END IF;
  
  -- Check basic guest viewing permission
  IF NOT has_permission(auth.uid(), 'view_guests') THEN
    RETURN false;
  END IF;
  
  -- Check sensitive data access for document types
  has_sensitive_access := has_permission(auth.uid(), 'view_sensitive_guest_data');
  
  IF document_type IN ('id_document', 'passport', 'visa', 'identification') THEN
    IF NOT has_sensitive_access THEN
      -- Log unauthorized access attempt
      PERFORM log_security_event(
        'UNAUTHORIZED_DOCUMENT_ACCESS',
        'high',
        format('Attempted access to guest document: %s for guest %s', document_type, guest_id),
        get_real_client_ip(),
        auth.uid(),
        jsonb_build_object(
          'guest_id', guest_id,
          'document_type', document_type,
          'document_path', document_path
        )
      );
      RETURN false;
    END IF;
  END IF;
  
  -- Log legitimate access
  PERFORM log_guest_data_access(
    guest_id,
    ARRAY[document_type],
    'document_access',
    jsonb_build_object(
      'document_type', document_type,
      'document_path', document_path
    )
  );
  
  RETURN true;
END;
$$;


--
-- Name: validate_html_content("text", integer); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."validate_html_content"("input_html" "text", "max_length" integer DEFAULT 50000) RETURNS boolean
    LANGUAGE "plpgsql"
    SET "search_path" TO 'public', 'pg_temp'
    AS $$
BEGIN
  IF length(input_html) > max_length THEN
    RETURN false;
  END IF;
  
  IF input_html ~* '<script[^>]*>' THEN
    RETURN false;
  END IF;
  
  IF input_html ~* 'javascript:' THEN
    RETURN false;
  END IF;
  
  IF input_html ~* 'on\w+\s*=' THEN
    RETURN false;
  END IF;
  
  IF input_html ~* 'data:text/html' THEN
    RETURN false;
  END IF;
  
  RETURN true;
END;
$$;


--
-- Name: validate_phone("text"); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."validate_phone"("phone_input" "text") RETURNS "jsonb"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'pg_temp'
    AS $$
DECLARE
  result jsonb;
  sanitized_phone text;
  digits_only text;
BEGIN
  -- Handle null input
  IF phone_input IS NULL OR trim(phone_input) = '' THEN
    RETURN jsonb_build_object('valid', true, 'sanitized', NULL); -- Phone is optional
  END IF;
  
  -- Length check before processing
  IF length(phone_input) > 50 THEN
    RETURN jsonb_build_object('valid', false, 'error', 'Phone number too long');
  END IF;
  
  -- Sanitize input - remove all non-digits except + at start and common separators
  sanitized_phone := regexp_replace(trim(phone_input), '[^\d\+\-\s\(\)]', '', 'g');
  digits_only := regexp_replace(sanitized_phone, '[^\d]', '', 'g');
  
  -- Check for script injection attempts
  IF phone_input ~ '(script|javascript|<|>|[\x00-\x1f])' THEN
    RETURN jsonb_build_object('valid', false, 'error', 'Phone contains invalid characters');
  END IF;
  
  -- Validate phone length
  IF length(digits_only) < 7 OR length(digits_only) > 15 THEN
    RETURN jsonb_build_object('valid', false, 'error', 'Phone number must be 7-15 digits');
  END IF;
  
  -- Check for suspicious patterns (all same digits, sequential numbers)
  IF digits_only ~ '^(0{7,}|1{7,}|2{7,}|3{7,}|4{7,}|5{7,}|6{7,}|7{7,}|8{7,}|9{7,}|123456789|987654321)' THEN
    RETURN jsonb_build_object('valid', false, 'error', 'Phone number contains invalid patterns');
  END IF;
  
  -- Ensure + is only at the beginning if present
  IF sanitized_phone ~ '\+' AND NOT sanitized_phone ~ '^\+' THEN
    RETURN jsonb_build_object('valid', false, 'error', 'Invalid phone format');
  END IF;
  
  RETURN jsonb_build_object('valid', true, 'sanitized', sanitized_phone);
  
EXCEPTION WHEN OTHERS THEN
  PERFORM log_security_event(
    'FUNCTION_ERROR',
    'medium',
    format('validate_phone function error: %s', SQLERRM),
    get_real_client_ip(),
    auth.uid(),
    jsonb_build_object('function', 'validate_phone', 'input_length', length(phone_input))
  );
  RETURN jsonb_build_object('valid', false, 'error', 'Phone validation failed');
END;
$$;


--
-- Name: validate_session_security("jsonb"); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."validate_session_security"("session_data" "jsonb" DEFAULT NULL::"jsonb") RETURNS "jsonb"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'pg_temp'
    AS $$
DECLARE
  result jsonb := '{"valid": true}'::jsonb;
  warnings text[] := '{}';
  client_ip text;
  user_agent text;
  session_age interval;
BEGIN
  client_ip := get_real_client_ip();
  
  -- Get user agent from headers safely
  BEGIN
    user_agent := current_setting('request.headers', true)::json->>'user-agent';
  EXCEPTION WHEN OTHERS THEN
    user_agent := NULL;
  END;
  
  -- Validate session_data if provided
  IF session_data IS NOT NULL THEN
    -- Validate session data structure
    IF NOT (session_data ? 'created_at' OR session_data ? 'last_ip' OR session_data ? 'user_agent') THEN
      -- Accept any valid JSON structure
    END IF;
    
    -- Check if IP changed dramatically (different country)
    IF session_data ? 'last_ip' AND session_data->>'last_ip' != client_ip THEN
      warnings := array_append(warnings, 'IP address changed during session');
    END IF;
    
    -- Check if user agent changed
    IF session_data ? 'user_agent' AND session_data->>'user_agent' != user_agent THEN
      warnings := array_append(warnings, 'User agent changed during session');
    END IF;
    
    -- Check session age
    IF session_data ? 'created_at' THEN
      BEGIN
        session_age := now() - (session_data->>'created_at')::timestamp with time zone;
        IF session_age > interval '24 hours' THEN
          warnings := array_append(warnings, 'Session is older than 24 hours');
        END IF;
        IF session_age > interval '7 days' THEN
          warnings := array_append(warnings, 'Session is critically old');
        END IF;
      EXCEPTION WHEN OTHERS THEN
        warnings := array_append(warnings, 'Invalid session timestamp');
      END;
    END IF;
    
    -- Check for session fixation attempts
    IF session_data ? 'session_id' THEN
      DECLARE
        session_id_str text;
      BEGIN
        session_id_str := session_data->>'session_id';
        -- Validate session ID format (should be random string)
        IF length(session_id_str) < 16 OR session_id_str ~ '^(0+|1+|a+|test|admin|session)' THEN
          warnings := array_append(warnings, 'Suspicious session ID detected');
        END IF;
      EXCEPTION WHEN OTHERS THEN
        warnings := array_append(warnings, 'Invalid session ID format');
      END;
    END IF;
  END IF;
  
  -- Check for suspicious patterns in user agent
  IF user_agent IS NOT NULL THEN
    -- Check length
    IF length(user_agent) > 1000 THEN
      warnings := array_append(warnings, 'Suspicious user agent length');
    END IF;
    
    -- Check for malicious user agents
    IF user_agent ~* '(bot|crawler|spider|scanner)' AND NOT user_agent ~* '(googlebot|bingbot|facebookexternalhit|twitterbot)' THEN
      warnings := array_append(warnings, 'Suspicious user agent detected');
    END IF;
    
    -- Check for script injection in user agent
    IF user_agent ~* '(<script|javascript:|data:|vbscript:|onload|onerror)' THEN
      warnings := array_append(warnings, 'Malicious user agent detected');
    END IF;
    
    -- Check for null bytes or control characters
    IF user_agent ~ '[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]' THEN
      warnings := array_append(warnings, 'User agent contains control characters');
    END IF;
  END IF;
  
  -- Check client IP for suspicious patterns
  IF client_ip IS NOT NULL AND client_ip != 'unknown' THEN
    -- Check for local/private IP addresses that shouldn't be external
    IF client_ip ~ '^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)' THEN
      warnings := array_append(warnings, 'Client using private IP address');
    END IF;
  END IF;
  
  -- Log security events if warnings found
  IF array_length(warnings, 1) > 0 THEN
    PERFORM log_security_event(
      'SESSION_SECURITY_WARNING',
      CASE 
        WHEN array_length(warnings, 1) > 3 THEN 'high'
        WHEN array_length(warnings, 1) > 1 THEN 'medium'
        ELSE 'low'
      END,
      'Session security validation found potential issues',
      client_ip,
      auth.uid(),
      jsonb_build_object(
        'warnings', warnings,
        'user_agent', user_agent,
        'session_data', session_data
      )
    );
  END IF;
  
  RETURN jsonb_build_object(
    'valid', array_length(warnings, 1) IS NULL OR array_length(warnings, 1) <= 2,
    'warnings', COALESCE(warnings, ARRAY[]::text[]),
    'current_ip', client_ip,
    'current_user_agent', user_agent,
    'risk_level', CASE 
      WHEN array_length(warnings, 1) IS NULL THEN 'low'
      WHEN array_length(warnings, 1) <= 1 THEN 'medium'
      ELSE 'high'
    END
  );
  
EXCEPTION WHEN OTHERS THEN
  PERFORM log_security_event(
    'FUNCTION_ERROR',
    'medium',
    format('validate_session_security function error: %s', SQLERRM),
    get_real_client_ip(),
    auth.uid(),
    jsonb_build_object('function', 'validate_session_security')
  );
  RETURN jsonb_build_object('valid', false, 'error', 'Session validation failed');
END;
$$;


--
-- Name: validate_user_session("text", "inet", "text"); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."validate_user_session"("session_token_param" "text", "current_ip" "inet" DEFAULT NULL::"inet", "current_user_agent" "text" DEFAULT NULL::"text") RETURNS "jsonb"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'pg_temp'
    AS $$
DECLARE
  session_record RECORD;
  anomalies TEXT[] := ARRAY[]::TEXT[];
  risk_score INTEGER := 0;
  result JSONB;
BEGIN
  -- Input validation
  IF session_token_param IS NULL OR trim(session_token_param) = '' THEN
    RETURN jsonb_build_object('valid', false, 'error', 'Invalid session token');
  END IF;
  
  -- Get session record
  SELECT * INTO session_record
  FROM public.user_sessions
  WHERE session_token = session_token_param
  AND is_active = true
  AND expires_at > now();
  
  IF session_record IS NULL THEN
    RETURN jsonb_build_object('valid', false, 'reason', 'Session not found or expired');
  END IF;
  
  -- Check for IP address changes
  IF current_ip IS NOT NULL AND session_record.ip_address IS NOT NULL 
     AND session_record.ip_address != current_ip THEN
    anomalies := array_append(anomalies, 'ip_change');
    risk_score := risk_score + 30;
    
    -- Log anomaly
    INSERT INTO public.login_anomalies (
      user_id, user_email, anomaly_type, severity, ip_address,
      metadata
    ) VALUES (
      session_record.user_id,
      (SELECT email FROM public.profiles WHERE id = session_record.user_id),
      'ip_change',
      'medium',
      current_ip,
      jsonb_build_object(
        'previous_ip', session_record.ip_address,
        'current_ip', current_ip,
        'session_age_minutes', EXTRACT(epoch FROM now() - session_record.created_at) / 60
      )
    );
  END IF;
  
  -- Check for user agent changes
  IF current_user_agent IS NOT NULL AND session_record.user_agent IS NOT NULL 
     AND session_record.user_agent != current_user_agent THEN
    anomalies := array_append(anomalies, 'user_agent_change');
    risk_score := risk_score + 20;
  END IF;
  
  -- Check session age (flag if older than 24 hours)
  IF session_record.created_at < now() - INTERVAL '24 hours' THEN
    anomalies := array_append(anomalies, 'old_session');
    risk_score := risk_score + 10;
  END IF;
  
  -- Check for concurrent sessions
  IF (SELECT COUNT(*) FROM public.user_sessions 
      WHERE user_id = session_record.user_id 
      AND is_active = true 
      AND expires_at > now()) > 3 THEN
    anomalies := array_append(anomalies, 'concurrent_sessions');
    risk_score := risk_score + 25;
  END IF;
  
  -- Update session activity
  UPDATE public.user_sessions
  SET 
    last_activity = now(),
    expires_at = now() + INTERVAL '30 minutes',
    ip_address = COALESCE(current_ip, ip_address),
    user_agent = COALESCE(current_user_agent, user_agent)
  WHERE session_token = session_token_param;
  
  RETURN jsonb_build_object(
    'valid', true,
    'user_id', session_record.user_id,
    'anomalies', anomalies,
    'risk_score', risk_score,
    'risk_level', CASE 
      WHEN risk_score >= 50 THEN 'high'
      WHEN risk_score >= 25 THEN 'medium'
      ELSE 'low'
    END,
    'session_age_hours', EXTRACT(epoch FROM now() - session_record.created_at) / 3600
  );
  
EXCEPTION WHEN OTHERS THEN
  PERFORM log_security_event(
    'FUNCTION_ERROR',
    'medium',
    format('validate_user_session function error: %s', SQLERRM),
    current_ip::text,
    session_record.user_id,
    jsonb_build_object('function', 'validate_user_session')
  );
  RETURN jsonb_build_object('valid', false, 'error', 'Session validation failed');
END;
$$;


--
-- Name: apply_rls("jsonb", integer); Type: FUNCTION; Schema: realtime; Owner: -
--

CREATE FUNCTION "realtime"."apply_rls"("wal" "jsonb", "max_record_bytes" integer DEFAULT (1024 * 1024)) RETURNS SETOF "realtime"."wal_rls"
    LANGUAGE "plpgsql"
    AS $$
declare
-- Regclass of the table e.g. public.notes
entity_ regclass = (quote_ident(wal ->> 'schema') || '.' || quote_ident(wal ->> 'table'))::regclass;

-- I, U, D, T: insert, update ...
action realtime.action = (
    case wal ->> 'action'
        when 'I' then 'INSERT'
        when 'U' then 'UPDATE'
        when 'D' then 'DELETE'
        else 'ERROR'
    end
);

-- Is row level security enabled for the table
is_rls_enabled bool = relrowsecurity from pg_class where oid = entity_;

subscriptions realtime.subscription[] = array_agg(subs)
    from
        realtime.subscription subs
    where
        subs.entity = entity_;

-- Subscription vars
roles regrole[] = array_agg(distinct us.claims_role::text)
    from
        unnest(subscriptions) us;

working_role regrole;
claimed_role regrole;
claims jsonb;

subscription_id uuid;
subscription_has_access bool;
visible_to_subscription_ids uuid[] = '{}';

-- structured info for wal's columns
columns realtime.wal_column[];
-- previous identity values for update/delete
old_columns realtime.wal_column[];

error_record_exceeds_max_size boolean = octet_length(wal::text) > max_record_bytes;

-- Primary jsonb output for record
output jsonb;

begin
perform set_config('role', null, true);

columns =
    array_agg(
        (
            x->>'name',
            x->>'type',
            x->>'typeoid',
            realtime.cast(
                (x->'value') #>> '{}',
                coalesce(
                    (x->>'typeoid')::regtype, -- null when wal2json version <= 2.4
                    (x->>'type')::regtype
                )
            ),
            (pks ->> 'name') is not null,
            true
        )::realtime.wal_column
    )
    from
        jsonb_array_elements(wal -> 'columns') x
        left join jsonb_array_elements(wal -> 'pk') pks
            on (x ->> 'name') = (pks ->> 'name');

old_columns =
    array_agg(
        (
            x->>'name',
            x->>'type',
            x->>'typeoid',
            realtime.cast(
                (x->'value') #>> '{}',
                coalesce(
                    (x->>'typeoid')::regtype, -- null when wal2json version <= 2.4
                    (x->>'type')::regtype
                )
            ),
            (pks ->> 'name') is not null,
            true
        )::realtime.wal_column
    )
    from
        jsonb_array_elements(wal -> 'identity') x
        left join jsonb_array_elements(wal -> 'pk') pks
            on (x ->> 'name') = (pks ->> 'name');

for working_role in select * from unnest(roles) loop

    -- Update `is_selectable` for columns and old_columns
    columns =
        array_agg(
            (
                c.name,
                c.type_name,
                c.type_oid,
                c.value,
                c.is_pkey,
                pg_catalog.has_column_privilege(working_role, entity_, c.name, 'SELECT')
            )::realtime.wal_column
        )
        from
            unnest(columns) c;

    old_columns =
            array_agg(
                (
                    c.name,
                    c.type_name,
                    c.type_oid,
                    c.value,
                    c.is_pkey,
                    pg_catalog.has_column_privilege(working_role, entity_, c.name, 'SELECT')
                )::realtime.wal_column
            )
            from
                unnest(old_columns) c;

    if action <> 'DELETE' and count(1) = 0 from unnest(columns) c where c.is_pkey then
        return next (
            jsonb_build_object(
                'schema', wal ->> 'schema',
                'table', wal ->> 'table',
                'type', action
            ),
            is_rls_enabled,
            -- subscriptions is already filtered by entity
            (select array_agg(s.subscription_id) from unnest(subscriptions) as s where claims_role = working_role),
            array['Error 400: Bad Request, no primary key']
        )::realtime.wal_rls;

    -- The claims role does not have SELECT permission to the primary key of entity
    elsif action <> 'DELETE' and sum(c.is_selectable::int) <> count(1) from unnest(columns) c where c.is_pkey then
        return next (
            jsonb_build_object(
                'schema', wal ->> 'schema',
                'table', wal ->> 'table',
                'type', action
            ),
            is_rls_enabled,
            (select array_agg(s.subscription_id) from unnest(subscriptions) as s where claims_role = working_role),
            array['Error 401: Unauthorized']
        )::realtime.wal_rls;

    else
        output = jsonb_build_object(
            'schema', wal ->> 'schema',
            'table', wal ->> 'table',
            'type', action,
            'commit_timestamp', to_char(
                ((wal ->> 'timestamp')::timestamptz at time zone 'utc'),
                'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
            ),
            'columns', (
                select
                    jsonb_agg(
                        jsonb_build_object(
                            'name', pa.attname,
                            'type', pt.typname
                        )
                        order by pa.attnum asc
                    )
                from
                    pg_attribute pa
                    join pg_type pt
                        on pa.atttypid = pt.oid
                where
                    attrelid = entity_
                    and attnum > 0
                    and pg_catalog.has_column_privilege(working_role, entity_, pa.attname, 'SELECT')
            )
        )
        -- Add "record" key for insert and update
        || case
            when action in ('INSERT', 'UPDATE') then
                jsonb_build_object(
                    'record',
                    (
                        select
                            jsonb_object_agg(
                                -- if unchanged toast, get column name and value from old record
                                coalesce((c).name, (oc).name),
                                case
                                    when (c).name is null then (oc).value
                                    else (c).value
                                end
                            )
                        from
                            unnest(columns) c
                            full outer join unnest(old_columns) oc
                                on (c).name = (oc).name
                        where
                            coalesce((c).is_selectable, (oc).is_selectable)
                            and ( not error_record_exceeds_max_size or (octet_length((c).value::text) <= 64))
                    )
                )
            else '{}'::jsonb
        end
        -- Add "old_record" key for update and delete
        || case
            when action = 'UPDATE' then
                jsonb_build_object(
                        'old_record',
                        (
                            select jsonb_object_agg((c).name, (c).value)
                            from unnest(old_columns) c
                            where
                                (c).is_selectable
                                and ( not error_record_exceeds_max_size or (octet_length((c).value::text) <= 64))
                        )
                    )
            when action = 'DELETE' then
                jsonb_build_object(
                    'old_record',
                    (
                        select jsonb_object_agg((c).name, (c).value)
                        from unnest(old_columns) c
                        where
                            (c).is_selectable
                            and ( not error_record_exceeds_max_size or (octet_length((c).value::text) <= 64))
                            and ( not is_rls_enabled or (c).is_pkey ) -- if RLS enabled, we can't secure deletes so filter to pkey
                    )
                )
            else '{}'::jsonb
        end;

        -- Create the prepared statement
        if is_rls_enabled and action <> 'DELETE' then
            if (select 1 from pg_prepared_statements where name = 'walrus_rls_stmt' limit 1) > 0 then
                deallocate walrus_rls_stmt;
            end if;
            execute realtime.build_prepared_statement_sql('walrus_rls_stmt', entity_, columns);
        end if;

        visible_to_subscription_ids = '{}';

        for subscription_id, claims in (
                select
                    subs.subscription_id,
                    subs.claims
                from
                    unnest(subscriptions) subs
                where
                    subs.entity = entity_
                    and subs.claims_role = working_role
                    and (
                        realtime.is_visible_through_filters(columns, subs.filters)
                        or (
                          action = 'DELETE'
                          and realtime.is_visible_through_filters(old_columns, subs.filters)
                        )
                    )
        ) loop

            if not is_rls_enabled or action = 'DELETE' then
                visible_to_subscription_ids = visible_to_subscription_ids || subscription_id;
            else
                -- Check if RLS allows the role to see the record
                perform
                    -- Trim leading and trailing quotes from working_role because set_config
                    -- doesn't recognize the role as valid if they are included
                    set_config('role', trim(both '"' from working_role::text), true),
                    set_config('request.jwt.claims', claims::text, true);

                execute 'execute walrus_rls_stmt' into subscription_has_access;

                if subscription_has_access then
                    visible_to_subscription_ids = visible_to_subscription_ids || subscription_id;
                end if;
            end if;
        end loop;

        perform set_config('role', null, true);

        return next (
            output,
            is_rls_enabled,
            visible_to_subscription_ids,
            case
                when error_record_exceeds_max_size then array['Error 413: Payload Too Large']
                else '{}'
            end
        )::realtime.wal_rls;

    end if;
end loop;

perform set_config('role', null, true);
end;
$$;


--
-- Name: broadcast_changes("text", "text", "text", "text", "text", "record", "record", "text"); Type: FUNCTION; Schema: realtime; Owner: -
--

CREATE FUNCTION "realtime"."broadcast_changes"("topic_name" "text", "event_name" "text", "operation" "text", "table_name" "text", "table_schema" "text", "new" "record", "old" "record", "level" "text" DEFAULT 'ROW'::"text") RETURNS "void"
    LANGUAGE "plpgsql"
    AS $$
DECLARE
    -- Declare a variable to hold the JSONB representation of the row
    row_data jsonb := '{}'::jsonb;
BEGIN
    IF level = 'STATEMENT' THEN
        RAISE EXCEPTION 'function can only be triggered for each row, not for each statement';
    END IF;
    -- Check the operation type and handle accordingly
    IF operation = 'INSERT' OR operation = 'UPDATE' OR operation = 'DELETE' THEN
        row_data := jsonb_build_object('old_record', OLD, 'record', NEW, 'operation', operation, 'table', table_name, 'schema', table_schema);
        PERFORM realtime.send (row_data, event_name, topic_name);
    ELSE
        RAISE EXCEPTION 'Unexpected operation type: %', operation;
    END IF;
EXCEPTION
    WHEN OTHERS THEN
        RAISE EXCEPTION 'Failed to process the row: %', SQLERRM;
END;

$$;


--
-- Name: build_prepared_statement_sql("text", "regclass", "realtime"."wal_column"[]); Type: FUNCTION; Schema: realtime; Owner: -
--

CREATE FUNCTION "realtime"."build_prepared_statement_sql"("prepared_statement_name" "text", "entity" "regclass", "columns" "realtime"."wal_column"[]) RETURNS "text"
    LANGUAGE "sql"
    AS $$
      /*
      Builds a sql string that, if executed, creates a prepared statement to
      tests retrive a row from *entity* by its primary key columns.
      Example
          select realtime.build_prepared_statement_sql('public.notes', '{"id"}'::text[], '{"bigint"}'::text[])
      */
          select
      'prepare ' || prepared_statement_name || ' as
          select
              exists(
                  select
                      1
                  from
                      ' || entity || '
                  where
                      ' || string_agg(quote_ident(pkc.name) || '=' || quote_nullable(pkc.value #>> '{}') , ' and ') || '
              )'
          from
              unnest(columns) pkc
          where
              pkc.is_pkey
          group by
              entity
      $$;


--
-- Name: cast("text", "regtype"); Type: FUNCTION; Schema: realtime; Owner: -
--

CREATE FUNCTION "realtime"."cast"("val" "text", "type_" "regtype") RETURNS "jsonb"
    LANGUAGE "plpgsql" IMMUTABLE
    AS $$
    declare
      res jsonb;
    begin
      execute format('select to_jsonb(%L::'|| type_::text || ')', val)  into res;
      return res;
    end
    $$;


--
-- Name: check_equality_op("realtime"."equality_op", "regtype", "text", "text"); Type: FUNCTION; Schema: realtime; Owner: -
--

CREATE FUNCTION "realtime"."check_equality_op"("op" "realtime"."equality_op", "type_" "regtype", "val_1" "text", "val_2" "text") RETURNS boolean
    LANGUAGE "plpgsql" IMMUTABLE
    AS $$
      /*
      Casts *val_1* and *val_2* as type *type_* and check the *op* condition for truthiness
      */
      declare
          op_symbol text = (
              case
                  when op = 'eq' then '='
                  when op = 'neq' then '!='
                  when op = 'lt' then '<'
                  when op = 'lte' then '<='
                  when op = 'gt' then '>'
                  when op = 'gte' then '>='
                  when op = 'in' then '= any'
                  else 'UNKNOWN OP'
              end
          );
          res boolean;
      begin
          execute format(
              'select %L::'|| type_::text || ' ' || op_symbol
              || ' ( %L::'
              || (
                  case
                      when op = 'in' then type_::text || '[]'
                      else type_::text end
              )
              || ')', val_1, val_2) into res;
          return res;
      end;
      $$;


--
-- Name: is_visible_through_filters("realtime"."wal_column"[], "realtime"."user_defined_filter"[]); Type: FUNCTION; Schema: realtime; Owner: -
--

CREATE FUNCTION "realtime"."is_visible_through_filters"("columns" "realtime"."wal_column"[], "filters" "realtime"."user_defined_filter"[]) RETURNS boolean
    LANGUAGE "sql" IMMUTABLE
    AS $_$
    /*
    Should the record be visible (true) or filtered out (false) after *filters* are applied
    */
        select
            -- Default to allowed when no filters present
            $2 is null -- no filters. this should not happen because subscriptions has a default
            or array_length($2, 1) is null -- array length of an empty array is null
            or bool_and(
                coalesce(
                    realtime.check_equality_op(
                        op:=f.op,
                        type_:=coalesce(
                            col.type_oid::regtype, -- null when wal2json version <= 2.4
                            col.type_name::regtype
                        ),
                        -- cast jsonb to text
                        val_1:=col.value #>> '{}',
                        val_2:=f.value
                    ),
                    false -- if null, filter does not match
                )
            )
        from
            unnest(filters) f
            join unnest(columns) col
                on f.column_name = col.name;
    $_$;


--
-- Name: list_changes("name", "name", integer, integer); Type: FUNCTION; Schema: realtime; Owner: -
--

CREATE FUNCTION "realtime"."list_changes"("publication" "name", "slot_name" "name", "max_changes" integer, "max_record_bytes" integer) RETURNS SETOF "realtime"."wal_rls"
    LANGUAGE "sql"
    SET "log_min_messages" TO 'fatal'
    AS $$
      with pub as (
        select
          concat_ws(
            ',',
            case when bool_or(pubinsert) then 'insert' else null end,
            case when bool_or(pubupdate) then 'update' else null end,
            case when bool_or(pubdelete) then 'delete' else null end
          ) as w2j_actions,
          coalesce(
            string_agg(
              realtime.quote_wal2json(format('%I.%I', schemaname, tablename)::regclass),
              ','
            ) filter (where ppt.tablename is not null and ppt.tablename not like '% %'),
            ''
          ) w2j_add_tables
        from
          pg_publication pp
          left join pg_publication_tables ppt
            on pp.pubname = ppt.pubname
        where
          pp.pubname = publication
        group by
          pp.pubname
        limit 1
      ),
      w2j as (
        select
          x.*, pub.w2j_add_tables
        from
          pub,
          pg_logical_slot_get_changes(
            slot_name, null, max_changes,
            'include-pk', 'true',
            'include-transaction', 'false',
            'include-timestamp', 'true',
            'include-type-oids', 'true',
            'format-version', '2',
            'actions', pub.w2j_actions,
            'add-tables', pub.w2j_add_tables
          ) x
      )
      select
        xyz.wal,
        xyz.is_rls_enabled,
        xyz.subscription_ids,
        xyz.errors
      from
        w2j,
        realtime.apply_rls(
          wal := w2j.data::jsonb,
          max_record_bytes := max_record_bytes
        ) xyz(wal, is_rls_enabled, subscription_ids, errors)
      where
        w2j.w2j_add_tables <> ''
        and xyz.subscription_ids[1] is not null
    $$;


--
-- Name: quote_wal2json("regclass"); Type: FUNCTION; Schema: realtime; Owner: -
--

CREATE FUNCTION "realtime"."quote_wal2json"("entity" "regclass") RETURNS "text"
    LANGUAGE "sql" IMMUTABLE STRICT
    AS $$
      select
        (
          select string_agg('' || ch,'')
          from unnest(string_to_array(nsp.nspname::text, null)) with ordinality x(ch, idx)
          where
            not (x.idx = 1 and x.ch = '"')
            and not (
              x.idx = array_length(string_to_array(nsp.nspname::text, null), 1)
              and x.ch = '"'
            )
        )
        || '.'
        || (
          select string_agg('' || ch,'')
          from unnest(string_to_array(pc.relname::text, null)) with ordinality x(ch, idx)
          where
            not (x.idx = 1 and x.ch = '"')
            and not (
              x.idx = array_length(string_to_array(nsp.nspname::text, null), 1)
              and x.ch = '"'
            )
          )
      from
        pg_class pc
        join pg_namespace nsp
          on pc.relnamespace = nsp.oid
      where
        pc.oid = entity
    $$;


--
-- Name: send("jsonb", "text", "text", boolean); Type: FUNCTION; Schema: realtime; Owner: -
--

CREATE FUNCTION "realtime"."send"("payload" "jsonb", "event" "text", "topic" "text", "private" boolean DEFAULT true) RETURNS "void"
    LANGUAGE "plpgsql"
    AS $$
DECLARE
  generated_id uuid;
  final_payload jsonb;
BEGIN
  BEGIN
    -- Generate a new UUID for the id
    generated_id := gen_random_uuid();

    -- Check if payload has an 'id' key, if not, add the generated UUID
    IF payload ? 'id' THEN
      final_payload := payload;
    ELSE
      final_payload := jsonb_set(payload, '{id}', to_jsonb(generated_id));
    END IF;

    -- Set the topic configuration
    EXECUTE format('SET LOCAL realtime.topic TO %L', topic);

    -- Attempt to insert the message
    INSERT INTO realtime.messages (id, payload, event, topic, private, extension)
    VALUES (generated_id, final_payload, event, topic, private, 'broadcast');
  EXCEPTION
    WHEN OTHERS THEN
      -- Capture and notify the error
      RAISE WARNING 'ErrorSendingBroadcastMessage: %', SQLERRM;
  END;
END;
$$;


--
-- Name: subscription_check_filters(); Type: FUNCTION; Schema: realtime; Owner: -
--

CREATE FUNCTION "realtime"."subscription_check_filters"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    AS $$
    /*
    Validates that the user defined filters for a subscription:
    - refer to valid columns that the claimed role may access
    - values are coercable to the correct column type
    */
    declare
        col_names text[] = coalesce(
                array_agg(c.column_name order by c.ordinal_position),
                '{}'::text[]
            )
            from
                information_schema.columns c
            where
                format('%I.%I', c.table_schema, c.table_name)::regclass = new.entity
                and pg_catalog.has_column_privilege(
                    (new.claims ->> 'role'),
                    format('%I.%I', c.table_schema, c.table_name)::regclass,
                    c.column_name,
                    'SELECT'
                );
        filter realtime.user_defined_filter;
        col_type regtype;

        in_val jsonb;
    begin
        for filter in select * from unnest(new.filters) loop
            -- Filtered column is valid
            if not filter.column_name = any(col_names) then
                raise exception 'invalid column for filter %', filter.column_name;
            end if;

            -- Type is sanitized and safe for string interpolation
            col_type = (
                select atttypid::regtype
                from pg_catalog.pg_attribute
                where attrelid = new.entity
                      and attname = filter.column_name
            );
            if col_type is null then
                raise exception 'failed to lookup type for column %', filter.column_name;
            end if;

            -- Set maximum number of entries for in filter
            if filter.op = 'in'::realtime.equality_op then
                in_val = realtime.cast(filter.value, (col_type::text || '[]')::regtype);
                if coalesce(jsonb_array_length(in_val), 0) > 100 then
                    raise exception 'too many values for `in` filter. Maximum 100';
                end if;
            else
                -- raises an exception if value is not coercable to type
                perform realtime.cast(filter.value, col_type);
            end if;

        end loop;

        -- Apply consistent order to filters so the unique constraint on
        -- (subscription_id, entity, filters) can't be tricked by a different filter order
        new.filters = coalesce(
            array_agg(f order by f.column_name, f.op, f.value),
            '{}'
        ) from unnest(new.filters) f;

        return new;
    end;
    $$;


--
-- Name: to_regrole("text"); Type: FUNCTION; Schema: realtime; Owner: -
--

CREATE FUNCTION "realtime"."to_regrole"("role_name" "text") RETURNS "regrole"
    LANGUAGE "sql" IMMUTABLE
    AS $$ select role_name::regrole $$;


--
-- Name: topic(); Type: FUNCTION; Schema: realtime; Owner: -
--

CREATE FUNCTION "realtime"."topic"() RETURNS "text"
    LANGUAGE "sql" STABLE
    AS $$
select nullif(current_setting('realtime.topic', true), '')::text;
$$;


--
-- Name: add_prefixes("text", "text"); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION "storage"."add_prefixes"("_bucket_id" "text", "_name" "text") RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
DECLARE
    prefixes text[];
BEGIN
    prefixes := "storage"."get_prefixes"("_name");

    IF array_length(prefixes, 1) > 0 THEN
        INSERT INTO storage.prefixes (name, bucket_id)
        SELECT UNNEST(prefixes) as name, "_bucket_id" ON CONFLICT DO NOTHING;
    END IF;
END;
$$;


--
-- Name: can_insert_object("text", "text", "uuid", "jsonb"); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION "storage"."can_insert_object"("bucketid" "text", "name" "text", "owner" "uuid", "metadata" "jsonb") RETURNS "void"
    LANGUAGE "plpgsql"
    AS $$
BEGIN
  INSERT INTO "storage"."objects" ("bucket_id", "name", "owner", "metadata") VALUES (bucketid, name, owner, metadata);
  -- hack to rollback the successful insert
  RAISE sqlstate 'PT200' using
  message = 'ROLLBACK',
  detail = 'rollback successful insert';
END
$$;


--
-- Name: delete_leaf_prefixes("text"[], "text"[]); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION "storage"."delete_leaf_prefixes"("bucket_ids" "text"[], "names" "text"[]) RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
DECLARE
    v_rows_deleted integer;
BEGIN
    LOOP
        WITH candidates AS (
            SELECT DISTINCT
                t.bucket_id,
                unnest(storage.get_prefixes(t.name)) AS name
            FROM unnest(bucket_ids, names) AS t(bucket_id, name)
        ),
        uniq AS (
             SELECT
                 bucket_id,
                 name,
                 storage.get_level(name) AS level
             FROM candidates
             WHERE name <> ''
             GROUP BY bucket_id, name
        ),
        leaf AS (
             SELECT
                 p.bucket_id,
                 p.name,
                 p.level
             FROM storage.prefixes AS p
                  JOIN uniq AS u
                       ON u.bucket_id = p.bucket_id
                           AND u.name = p.name
                           AND u.level = p.level
             WHERE NOT EXISTS (
                 SELECT 1
                 FROM storage.objects AS o
                 WHERE o.bucket_id = p.bucket_id
                   AND o.level = p.level + 1
                   AND o.name COLLATE "C" LIKE p.name || '/%'
             )
             AND NOT EXISTS (
                 SELECT 1
                 FROM storage.prefixes AS c
                 WHERE c.bucket_id = p.bucket_id
                   AND c.level = p.level + 1
                   AND c.name COLLATE "C" LIKE p.name || '/%'
             )
        )
        DELETE
        FROM storage.prefixes AS p
            USING leaf AS l
        WHERE p.bucket_id = l.bucket_id
          AND p.name = l.name
          AND p.level = l.level;

        GET DIAGNOSTICS v_rows_deleted = ROW_COUNT;
        EXIT WHEN v_rows_deleted = 0;
    END LOOP;
END;
$$;


--
-- Name: delete_prefix("text", "text"); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION "storage"."delete_prefix"("_bucket_id" "text", "_name" "text") RETURNS boolean
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
BEGIN
    -- Check if we can delete the prefix
    IF EXISTS(
        SELECT FROM "storage"."prefixes"
        WHERE "prefixes"."bucket_id" = "_bucket_id"
          AND level = "storage"."get_level"("_name") + 1
          AND "prefixes"."name" COLLATE "C" LIKE "_name" || '/%'
        LIMIT 1
    )
    OR EXISTS(
        SELECT FROM "storage"."objects"
        WHERE "objects"."bucket_id" = "_bucket_id"
          AND "storage"."get_level"("objects"."name") = "storage"."get_level"("_name") + 1
          AND "objects"."name" COLLATE "C" LIKE "_name" || '/%'
        LIMIT 1
    ) THEN
    -- There are sub-objects, skip deletion
    RETURN false;
    ELSE
        DELETE FROM "storage"."prefixes"
        WHERE "prefixes"."bucket_id" = "_bucket_id"
          AND level = "storage"."get_level"("_name")
          AND "prefixes"."name" = "_name";
        RETURN true;
    END IF;
END;
$$;


--
-- Name: delete_prefix_hierarchy_trigger(); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION "storage"."delete_prefix_hierarchy_trigger"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    AS $$
DECLARE
    prefix text;
BEGIN
    prefix := "storage"."get_prefix"(OLD."name");

    IF coalesce(prefix, '') != '' THEN
        PERFORM "storage"."delete_prefix"(OLD."bucket_id", prefix);
    END IF;

    RETURN OLD;
END;
$$;


--
-- Name: enforce_bucket_name_length(); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION "storage"."enforce_bucket_name_length"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    AS $$
begin
    if length(new.name) > 100 then
        raise exception 'bucket name "%" is too long (% characters). Max is 100.', new.name, length(new.name);
    end if;
    return new;
end;
$$;


--
-- Name: extension("text"); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION "storage"."extension"("name" "text") RETURNS "text"
    LANGUAGE "plpgsql" IMMUTABLE
    AS $$
DECLARE
    _parts text[];
    _filename text;
BEGIN
    SELECT string_to_array(name, '/') INTO _parts;
    SELECT _parts[array_length(_parts,1)] INTO _filename;
    RETURN reverse(split_part(reverse(_filename), '.', 1));
END
$$;


--
-- Name: filename("text"); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION "storage"."filename"("name" "text") RETURNS "text"
    LANGUAGE "plpgsql"
    AS $$
DECLARE
_parts text[];
BEGIN
	select string_to_array(name, '/') into _parts;
	return _parts[array_length(_parts,1)];
END
$$;


--
-- Name: foldername("text"); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION "storage"."foldername"("name" "text") RETURNS "text"[]
    LANGUAGE "plpgsql" IMMUTABLE
    AS $$
DECLARE
    _parts text[];
BEGIN
    -- Split on "/" to get path segments
    SELECT string_to_array(name, '/') INTO _parts;
    -- Return everything except the last segment
    RETURN _parts[1 : array_length(_parts,1) - 1];
END
$$;


--
-- Name: get_level("text"); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION "storage"."get_level"("name" "text") RETURNS integer
    LANGUAGE "sql" IMMUTABLE STRICT
    AS $$
SELECT array_length(string_to_array("name", '/'), 1);
$$;


--
-- Name: get_prefix("text"); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION "storage"."get_prefix"("name" "text") RETURNS "text"
    LANGUAGE "sql" IMMUTABLE STRICT
    AS $_$
SELECT
    CASE WHEN strpos("name", '/') > 0 THEN
             regexp_replace("name", '[\/]{1}[^\/]+\/?$', '')
         ELSE
             ''
        END;
$_$;


--
-- Name: get_prefixes("text"); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION "storage"."get_prefixes"("name" "text") RETURNS "text"[]
    LANGUAGE "plpgsql" IMMUTABLE STRICT
    AS $$
DECLARE
    parts text[];
    prefixes text[];
    prefix text;
BEGIN
    -- Split the name into parts by '/'
    parts := string_to_array("name", '/');
    prefixes := '{}';

    -- Construct the prefixes, stopping one level below the last part
    FOR i IN 1..array_length(parts, 1) - 1 LOOP
            prefix := array_to_string(parts[1:i], '/');
            prefixes := array_append(prefixes, prefix);
    END LOOP;

    RETURN prefixes;
END;
$$;


--
-- Name: get_size_by_bucket(); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION "storage"."get_size_by_bucket"() RETURNS TABLE("size" bigint, "bucket_id" "text")
    LANGUAGE "plpgsql" STABLE
    AS $$
BEGIN
    return query
        select sum((metadata->>'size')::bigint) as size, obj.bucket_id
        from "storage".objects as obj
        group by obj.bucket_id;
END
$$;


--
-- Name: list_multipart_uploads_with_delimiter("text", "text", "text", integer, "text", "text"); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION "storage"."list_multipart_uploads_with_delimiter"("bucket_id" "text", "prefix_param" "text", "delimiter_param" "text", "max_keys" integer DEFAULT 100, "next_key_token" "text" DEFAULT ''::"text", "next_upload_token" "text" DEFAULT ''::"text") RETURNS TABLE("key" "text", "id" "text", "created_at" timestamp with time zone)
    LANGUAGE "plpgsql"
    AS $_$
BEGIN
    RETURN QUERY EXECUTE
        'SELECT DISTINCT ON(key COLLATE "C") * from (
            SELECT
                CASE
                    WHEN position($2 IN substring(key from length($1) + 1)) > 0 THEN
                        substring(key from 1 for length($1) + position($2 IN substring(key from length($1) + 1)))
                    ELSE
                        key
                END AS key, id, created_at
            FROM
                storage.s3_multipart_uploads
            WHERE
                bucket_id = $5 AND
                key ILIKE $1 || ''%'' AND
                CASE
                    WHEN $4 != '''' AND $6 = '''' THEN
                        CASE
                            WHEN position($2 IN substring(key from length($1) + 1)) > 0 THEN
                                substring(key from 1 for length($1) + position($2 IN substring(key from length($1) + 1))) COLLATE "C" > $4
                            ELSE
                                key COLLATE "C" > $4
                            END
                    ELSE
                        true
                END AND
                CASE
                    WHEN $6 != '''' THEN
                        id COLLATE "C" > $6
                    ELSE
                        true
                    END
            ORDER BY
                key COLLATE "C" ASC, created_at ASC) as e order by key COLLATE "C" LIMIT $3'
        USING prefix_param, delimiter_param, max_keys, next_key_token, bucket_id, next_upload_token;
END;
$_$;


--
-- Name: list_objects_with_delimiter("text", "text", "text", integer, "text", "text"); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION "storage"."list_objects_with_delimiter"("bucket_id" "text", "prefix_param" "text", "delimiter_param" "text", "max_keys" integer DEFAULT 100, "start_after" "text" DEFAULT ''::"text", "next_token" "text" DEFAULT ''::"text") RETURNS TABLE("name" "text", "id" "uuid", "metadata" "jsonb", "updated_at" timestamp with time zone)
    LANGUAGE "plpgsql"
    AS $_$
BEGIN
    RETURN QUERY EXECUTE
        'SELECT DISTINCT ON(name COLLATE "C") * from (
            SELECT
                CASE
                    WHEN position($2 IN substring(name from length($1) + 1)) > 0 THEN
                        substring(name from 1 for length($1) + position($2 IN substring(name from length($1) + 1)))
                    ELSE
                        name
                END AS name, id, metadata, updated_at
            FROM
                storage.objects
            WHERE
                bucket_id = $5 AND
                name ILIKE $1 || ''%'' AND
                CASE
                    WHEN $6 != '''' THEN
                    name COLLATE "C" > $6
                ELSE true END
                AND CASE
                    WHEN $4 != '''' THEN
                        CASE
                            WHEN position($2 IN substring(name from length($1) + 1)) > 0 THEN
                                substring(name from 1 for length($1) + position($2 IN substring(name from length($1) + 1))) COLLATE "C" > $4
                            ELSE
                                name COLLATE "C" > $4
                            END
                    ELSE
                        true
                END
            ORDER BY
                name COLLATE "C" ASC) as e order by name COLLATE "C" LIMIT $3'
        USING prefix_param, delimiter_param, max_keys, next_token, bucket_id, start_after;
END;
$_$;


--
-- Name: lock_top_prefixes("text"[], "text"[]); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION "storage"."lock_top_prefixes"("bucket_ids" "text"[], "names" "text"[]) RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
DECLARE
    v_bucket text;
    v_top text;
BEGIN
    FOR v_bucket, v_top IN
        SELECT DISTINCT t.bucket_id,
            split_part(t.name, '/', 1) AS top
        FROM unnest(bucket_ids, names) AS t(bucket_id, name)
        WHERE t.name <> ''
        ORDER BY 1, 2
        LOOP
            PERFORM pg_advisory_xact_lock(hashtextextended(v_bucket || '/' || v_top, 0));
        END LOOP;
END;
$$;


--
-- Name: objects_delete_cleanup(); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION "storage"."objects_delete_cleanup"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
DECLARE
    v_bucket_ids text[];
    v_names      text[];
BEGIN
    IF current_setting('storage.gc.prefixes', true) = '1' THEN
        RETURN NULL;
    END IF;

    PERFORM set_config('storage.gc.prefixes', '1', true);

    SELECT COALESCE(array_agg(d.bucket_id), '{}'),
           COALESCE(array_agg(d.name), '{}')
    INTO v_bucket_ids, v_names
    FROM deleted AS d
    WHERE d.name <> '';

    PERFORM storage.lock_top_prefixes(v_bucket_ids, v_names);
    PERFORM storage.delete_leaf_prefixes(v_bucket_ids, v_names);

    RETURN NULL;
END;
$$;


--
-- Name: objects_insert_prefix_trigger(); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION "storage"."objects_insert_prefix_trigger"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    AS $$
BEGIN
    PERFORM "storage"."add_prefixes"(NEW."bucket_id", NEW."name");
    NEW.level := "storage"."get_level"(NEW."name");

    RETURN NEW;
END;
$$;


--
-- Name: objects_update_cleanup(); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION "storage"."objects_update_cleanup"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
DECLARE
    -- NEW - OLD (destinations to create prefixes for)
    v_add_bucket_ids text[];
    v_add_names      text[];

    -- OLD - NEW (sources to prune)
    v_src_bucket_ids text[];
    v_src_names      text[];
BEGIN
    IF TG_OP <> 'UPDATE' THEN
        RETURN NULL;
    END IF;

    -- 1) Compute NEW−OLD (added paths) and OLD−NEW (moved-away paths)
    WITH added AS (
        SELECT n.bucket_id, n.name
        FROM new_rows n
        WHERE n.name <> '' AND position('/' in n.name) > 0
        EXCEPT
        SELECT o.bucket_id, o.name FROM old_rows o WHERE o.name <> ''
    ),
    moved AS (
         SELECT o.bucket_id, o.name
         FROM old_rows o
         WHERE o.name <> ''
         EXCEPT
         SELECT n.bucket_id, n.name FROM new_rows n WHERE n.name <> ''
    )
    SELECT
        -- arrays for ADDED (dest) in stable order
        COALESCE( (SELECT array_agg(a.bucket_id ORDER BY a.bucket_id, a.name) FROM added a), '{}' ),
        COALESCE( (SELECT array_agg(a.name      ORDER BY a.bucket_id, a.name) FROM added a), '{}' ),
        -- arrays for MOVED (src) in stable order
        COALESCE( (SELECT array_agg(m.bucket_id ORDER BY m.bucket_id, m.name) FROM moved m), '{}' ),
        COALESCE( (SELECT array_agg(m.name      ORDER BY m.bucket_id, m.name) FROM moved m), '{}' )
    INTO v_add_bucket_ids, v_add_names, v_src_bucket_ids, v_src_names;

    -- Nothing to do?
    IF (array_length(v_add_bucket_ids, 1) IS NULL) AND (array_length(v_src_bucket_ids, 1) IS NULL) THEN
        RETURN NULL;
    END IF;

    -- 2) Take per-(bucket, top) locks: ALL prefixes in consistent global order to prevent deadlocks
    DECLARE
        v_all_bucket_ids text[];
        v_all_names text[];
    BEGIN
        -- Combine source and destination arrays for consistent lock ordering
        v_all_bucket_ids := COALESCE(v_src_bucket_ids, '{}') || COALESCE(v_add_bucket_ids, '{}');
        v_all_names := COALESCE(v_src_names, '{}') || COALESCE(v_add_names, '{}');

        -- Single lock call ensures consistent global ordering across all transactions
        IF array_length(v_all_bucket_ids, 1) IS NOT NULL THEN
            PERFORM storage.lock_top_prefixes(v_all_bucket_ids, v_all_names);
        END IF;
    END;

    -- 3) Create destination prefixes (NEW−OLD) BEFORE pruning sources
    IF array_length(v_add_bucket_ids, 1) IS NOT NULL THEN
        WITH candidates AS (
            SELECT DISTINCT t.bucket_id, unnest(storage.get_prefixes(t.name)) AS name
            FROM unnest(v_add_bucket_ids, v_add_names) AS t(bucket_id, name)
            WHERE name <> ''
        )
        INSERT INTO storage.prefixes (bucket_id, name)
        SELECT c.bucket_id, c.name
        FROM candidates c
        ON CONFLICT DO NOTHING;
    END IF;

    -- 4) Prune source prefixes bottom-up for OLD−NEW
    IF array_length(v_src_bucket_ids, 1) IS NOT NULL THEN
        -- re-entrancy guard so DELETE on prefixes won't recurse
        IF current_setting('storage.gc.prefixes', true) <> '1' THEN
            PERFORM set_config('storage.gc.prefixes', '1', true);
        END IF;

        PERFORM storage.delete_leaf_prefixes(v_src_bucket_ids, v_src_names);
    END IF;

    RETURN NULL;
END;
$$;


--
-- Name: objects_update_level_trigger(); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION "storage"."objects_update_level_trigger"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    AS $$
BEGIN
    -- Ensure this is an update operation and the name has changed
    IF TG_OP = 'UPDATE' AND (NEW."name" <> OLD."name" OR NEW."bucket_id" <> OLD."bucket_id") THEN
        -- Set the new level
        NEW."level" := "storage"."get_level"(NEW."name");
    END IF;
    RETURN NEW;
END;
$$;


--
-- Name: objects_update_prefix_trigger(); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION "storage"."objects_update_prefix_trigger"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    AS $$
DECLARE
    old_prefixes TEXT[];
BEGIN
    -- Ensure this is an update operation and the name has changed
    IF TG_OP = 'UPDATE' AND (NEW."name" <> OLD."name" OR NEW."bucket_id" <> OLD."bucket_id") THEN
        -- Retrieve old prefixes
        old_prefixes := "storage"."get_prefixes"(OLD."name");

        -- Remove old prefixes that are only used by this object
        WITH all_prefixes as (
            SELECT unnest(old_prefixes) as prefix
        ),
        can_delete_prefixes as (
             SELECT prefix
             FROM all_prefixes
             WHERE NOT EXISTS (
                 SELECT 1 FROM "storage"."objects"
                 WHERE "bucket_id" = OLD."bucket_id"
                   AND "name" <> OLD."name"
                   AND "name" LIKE (prefix || '%')
             )
         )
        DELETE FROM "storage"."prefixes" WHERE name IN (SELECT prefix FROM can_delete_prefixes);

        -- Add new prefixes
        PERFORM "storage"."add_prefixes"(NEW."bucket_id", NEW."name");
    END IF;
    -- Set the new level
    NEW."level" := "storage"."get_level"(NEW."name");

    RETURN NEW;
END;
$$;


--
-- Name: operation(); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION "storage"."operation"() RETURNS "text"
    LANGUAGE "plpgsql" STABLE
    AS $$
BEGIN
    RETURN current_setting('storage.operation', true);
END;
$$;


--
-- Name: prefixes_delete_cleanup(); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION "storage"."prefixes_delete_cleanup"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
DECLARE
    v_bucket_ids text[];
    v_names      text[];
BEGIN
    IF current_setting('storage.gc.prefixes', true) = '1' THEN
        RETURN NULL;
    END IF;

    PERFORM set_config('storage.gc.prefixes', '1', true);

    SELECT COALESCE(array_agg(d.bucket_id), '{}'),
           COALESCE(array_agg(d.name), '{}')
    INTO v_bucket_ids, v_names
    FROM deleted AS d
    WHERE d.name <> '';

    PERFORM storage.lock_top_prefixes(v_bucket_ids, v_names);
    PERFORM storage.delete_leaf_prefixes(v_bucket_ids, v_names);

    RETURN NULL;
END;
$$;


--
-- Name: prefixes_insert_trigger(); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION "storage"."prefixes_insert_trigger"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    AS $$
BEGIN
    PERFORM "storage"."add_prefixes"(NEW."bucket_id", NEW."name");
    RETURN NEW;
END;
$$;


--
-- Name: search("text", "text", integer, integer, integer, "text", "text", "text"); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION "storage"."search"("prefix" "text", "bucketname" "text", "limits" integer DEFAULT 100, "levels" integer DEFAULT 1, "offsets" integer DEFAULT 0, "search" "text" DEFAULT ''::"text", "sortcolumn" "text" DEFAULT 'name'::"text", "sortorder" "text" DEFAULT 'asc'::"text") RETURNS TABLE("name" "text", "id" "uuid", "updated_at" timestamp with time zone, "created_at" timestamp with time zone, "last_accessed_at" timestamp with time zone, "metadata" "jsonb")
    LANGUAGE "plpgsql"
    AS $$
declare
    can_bypass_rls BOOLEAN;
begin
    SELECT rolbypassrls
    INTO can_bypass_rls
    FROM pg_roles
    WHERE rolname = coalesce(nullif(current_setting('role', true), 'none'), current_user);

    IF can_bypass_rls THEN
        RETURN QUERY SELECT * FROM storage.search_v1_optimised(prefix, bucketname, limits, levels, offsets, search, sortcolumn, sortorder);
    ELSE
        RETURN QUERY SELECT * FROM storage.search_legacy_v1(prefix, bucketname, limits, levels, offsets, search, sortcolumn, sortorder);
    END IF;
end;
$$;


--
-- Name: search_legacy_v1("text", "text", integer, integer, integer, "text", "text", "text"); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION "storage"."search_legacy_v1"("prefix" "text", "bucketname" "text", "limits" integer DEFAULT 100, "levels" integer DEFAULT 1, "offsets" integer DEFAULT 0, "search" "text" DEFAULT ''::"text", "sortcolumn" "text" DEFAULT 'name'::"text", "sortorder" "text" DEFAULT 'asc'::"text") RETURNS TABLE("name" "text", "id" "uuid", "updated_at" timestamp with time zone, "created_at" timestamp with time zone, "last_accessed_at" timestamp with time zone, "metadata" "jsonb")
    LANGUAGE "plpgsql" STABLE
    AS $_$
declare
    v_order_by text;
    v_sort_order text;
begin
    case
        when sortcolumn = 'name' then
            v_order_by = 'name';
        when sortcolumn = 'updated_at' then
            v_order_by = 'updated_at';
        when sortcolumn = 'created_at' then
            v_order_by = 'created_at';
        when sortcolumn = 'last_accessed_at' then
            v_order_by = 'last_accessed_at';
        else
            v_order_by = 'name';
        end case;

    case
        when sortorder = 'asc' then
            v_sort_order = 'asc';
        when sortorder = 'desc' then
            v_sort_order = 'desc';
        else
            v_sort_order = 'asc';
        end case;

    v_order_by = v_order_by || ' ' || v_sort_order;

    return query execute
        'with folders as (
           select path_tokens[$1] as folder
           from storage.objects
             where objects.name ilike $2 || $3 || ''%''
               and bucket_id = $4
               and array_length(objects.path_tokens, 1) <> $1
           group by folder
           order by folder ' || v_sort_order || '
     )
     (select folder as "name",
            null as id,
            null as updated_at,
            null as created_at,
            null as last_accessed_at,
            null as metadata from folders)
     union all
     (select path_tokens[$1] as "name",
            id,
            updated_at,
            created_at,
            last_accessed_at,
            metadata
     from storage.objects
     where objects.name ilike $2 || $3 || ''%''
       and bucket_id = $4
       and array_length(objects.path_tokens, 1) = $1
     order by ' || v_order_by || ')
     limit $5
     offset $6' using levels, prefix, search, bucketname, limits, offsets;
end;
$_$;


--
-- Name: search_v1_optimised("text", "text", integer, integer, integer, "text", "text", "text"); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION "storage"."search_v1_optimised"("prefix" "text", "bucketname" "text", "limits" integer DEFAULT 100, "levels" integer DEFAULT 1, "offsets" integer DEFAULT 0, "search" "text" DEFAULT ''::"text", "sortcolumn" "text" DEFAULT 'name'::"text", "sortorder" "text" DEFAULT 'asc'::"text") RETURNS TABLE("name" "text", "id" "uuid", "updated_at" timestamp with time zone, "created_at" timestamp with time zone, "last_accessed_at" timestamp with time zone, "metadata" "jsonb")
    LANGUAGE "plpgsql" STABLE
    AS $_$
declare
    v_order_by text;
    v_sort_order text;
begin
    case
        when sortcolumn = 'name' then
            v_order_by = 'name';
        when sortcolumn = 'updated_at' then
            v_order_by = 'updated_at';
        when sortcolumn = 'created_at' then
            v_order_by = 'created_at';
        when sortcolumn = 'last_accessed_at' then
            v_order_by = 'last_accessed_at';
        else
            v_order_by = 'name';
        end case;

    case
        when sortorder = 'asc' then
            v_sort_order = 'asc';
        when sortorder = 'desc' then
            v_sort_order = 'desc';
        else
            v_sort_order = 'asc';
        end case;

    v_order_by = v_order_by || ' ' || v_sort_order;

    return query execute
        'with folders as (
           select (string_to_array(name, ''/''))[level] as name
           from storage.prefixes
             where lower(prefixes.name) like lower($2 || $3) || ''%''
               and bucket_id = $4
               and level = $1
           order by name ' || v_sort_order || '
     )
     (select name,
            null as id,
            null as updated_at,
            null as created_at,
            null as last_accessed_at,
            null as metadata from folders)
     union all
     (select path_tokens[level] as "name",
            id,
            updated_at,
            created_at,
            last_accessed_at,
            metadata
     from storage.objects
     where lower(objects.name) like lower($2 || $3) || ''%''
       and bucket_id = $4
       and level = $1
     order by ' || v_order_by || ')
     limit $5
     offset $6' using levels, prefix, search, bucketname, limits, offsets;
end;
$_$;


--
-- Name: search_v2("text", "text", integer, integer, "text", "text", "text", "text"); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION "storage"."search_v2"("prefix" "text", "bucket_name" "text", "limits" integer DEFAULT 100, "levels" integer DEFAULT 1, "start_after" "text" DEFAULT ''::"text", "sort_order" "text" DEFAULT 'asc'::"text", "sort_column" "text" DEFAULT 'name'::"text", "sort_column_after" "text" DEFAULT ''::"text") RETURNS TABLE("key" "text", "name" "text", "id" "uuid", "updated_at" timestamp with time zone, "created_at" timestamp with time zone, "last_accessed_at" timestamp with time zone, "metadata" "jsonb")
    LANGUAGE "plpgsql" STABLE
    AS $_$
DECLARE
    sort_col text;
    sort_ord text;
    cursor_op text;
    cursor_expr text;
    sort_expr text;
BEGIN
    -- Validate sort_order
    sort_ord := lower(sort_order);
    IF sort_ord NOT IN ('asc', 'desc') THEN
        sort_ord := 'asc';
    END IF;

    -- Determine cursor comparison operator
    IF sort_ord = 'asc' THEN
        cursor_op := '>';
    ELSE
        cursor_op := '<';
    END IF;
    
    sort_col := lower(sort_column);
    -- Validate sort column  
    IF sort_col IN ('updated_at', 'created_at') THEN
        cursor_expr := format(
            '($5 = '''' OR ROW(date_trunc(''milliseconds'', %I), name COLLATE "C") %s ROW(COALESCE(NULLIF($6, '''')::timestamptz, ''epoch''::timestamptz), $5))',
            sort_col, cursor_op
        );
        sort_expr := format(
            'COALESCE(date_trunc(''milliseconds'', %I), ''epoch''::timestamptz) %s, name COLLATE "C" %s',
            sort_col, sort_ord, sort_ord
        );
    ELSE
        cursor_expr := format('($5 = '''' OR name COLLATE "C" %s $5)', cursor_op);
        sort_expr := format('name COLLATE "C" %s', sort_ord);
    END IF;

    RETURN QUERY EXECUTE format(
        $sql$
        SELECT * FROM (
            (
                SELECT
                    split_part(name, '/', $4) AS key,
                    name,
                    NULL::uuid AS id,
                    updated_at,
                    created_at,
                    NULL::timestamptz AS last_accessed_at,
                    NULL::jsonb AS metadata
                FROM storage.prefixes
                WHERE name COLLATE "C" LIKE $1 || '%%'
                    AND bucket_id = $2
                    AND level = $4
                    AND %s
                ORDER BY %s
                LIMIT $3
            )
            UNION ALL
            (
                SELECT
                    split_part(name, '/', $4) AS key,
                    name,
                    id,
                    updated_at,
                    created_at,
                    last_accessed_at,
                    metadata
                FROM storage.objects
                WHERE name COLLATE "C" LIKE $1 || '%%'
                    AND bucket_id = $2
                    AND level = $4
                    AND %s
                ORDER BY %s
                LIMIT $3
            )
        ) obj
        ORDER BY %s
        LIMIT $3
        $sql$,
        cursor_expr,    -- prefixes WHERE
        sort_expr,      -- prefixes ORDER BY
        cursor_expr,    -- objects WHERE
        sort_expr,      -- objects ORDER BY
        sort_expr       -- final ORDER BY
    )
    USING prefix, bucket_name, limits, levels, start_after, sort_column_after;
END;
$_$;


--
-- Name: update_updated_at_column(); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION "storage"."update_updated_at_column"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW; 
END;
$$;


SET default_tablespace = '';

SET default_table_access_method = "heap";

--
-- Name: audit_log_entries; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE "auth"."audit_log_entries" (
    "instance_id" "uuid",
    "id" "uuid" NOT NULL,
    "payload" json,
    "created_at" timestamp with time zone,
    "ip_address" character varying(64) DEFAULT ''::character varying NOT NULL
);


--
-- Name: TABLE "audit_log_entries"; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE "auth"."audit_log_entries" IS 'Auth: Audit trail for user actions.';


--
-- Name: flow_state; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE "auth"."flow_state" (
    "id" "uuid" NOT NULL,
    "user_id" "uuid",
    "auth_code" "text" NOT NULL,
    "code_challenge_method" "auth"."code_challenge_method" NOT NULL,
    "code_challenge" "text" NOT NULL,
    "provider_type" "text" NOT NULL,
    "provider_access_token" "text",
    "provider_refresh_token" "text",
    "created_at" timestamp with time zone,
    "updated_at" timestamp with time zone,
    "authentication_method" "text" NOT NULL,
    "auth_code_issued_at" timestamp with time zone
);


--
-- Name: TABLE "flow_state"; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE "auth"."flow_state" IS 'stores metadata for pkce logins';


--
-- Name: identities; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE "auth"."identities" (
    "provider_id" "text" NOT NULL,
    "user_id" "uuid" NOT NULL,
    "identity_data" "jsonb" NOT NULL,
    "provider" "text" NOT NULL,
    "last_sign_in_at" timestamp with time zone,
    "created_at" timestamp with time zone,
    "updated_at" timestamp with time zone,
    "email" "text" GENERATED ALWAYS AS ("lower"(("identity_data" ->> 'email'::"text"))) STORED,
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL
);


--
-- Name: TABLE "identities"; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE "auth"."identities" IS 'Auth: Stores identities associated to a user.';


--
-- Name: COLUMN "identities"."email"; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON COLUMN "auth"."identities"."email" IS 'Auth: Email is a generated column that references the optional email property in the identity_data';


--
-- Name: instances; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE "auth"."instances" (
    "id" "uuid" NOT NULL,
    "uuid" "uuid",
    "raw_base_config" "text",
    "created_at" timestamp with time zone,
    "updated_at" timestamp with time zone
);


--
-- Name: TABLE "instances"; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE "auth"."instances" IS 'Auth: Manages users across multiple sites.';


--
-- Name: mfa_amr_claims; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE "auth"."mfa_amr_claims" (
    "session_id" "uuid" NOT NULL,
    "created_at" timestamp with time zone NOT NULL,
    "updated_at" timestamp with time zone NOT NULL,
    "authentication_method" "text" NOT NULL,
    "id" "uuid" NOT NULL
);


--
-- Name: TABLE "mfa_amr_claims"; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE "auth"."mfa_amr_claims" IS 'auth: stores authenticator method reference claims for multi factor authentication';


--
-- Name: mfa_challenges; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE "auth"."mfa_challenges" (
    "id" "uuid" NOT NULL,
    "factor_id" "uuid" NOT NULL,
    "created_at" timestamp with time zone NOT NULL,
    "verified_at" timestamp with time zone,
    "ip_address" "inet" NOT NULL,
    "otp_code" "text",
    "web_authn_session_data" "jsonb"
);


--
-- Name: TABLE "mfa_challenges"; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE "auth"."mfa_challenges" IS 'auth: stores metadata about challenge requests made';


--
-- Name: mfa_factors; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE "auth"."mfa_factors" (
    "id" "uuid" NOT NULL,
    "user_id" "uuid" NOT NULL,
    "friendly_name" "text",
    "factor_type" "auth"."factor_type" NOT NULL,
    "status" "auth"."factor_status" NOT NULL,
    "created_at" timestamp with time zone NOT NULL,
    "updated_at" timestamp with time zone NOT NULL,
    "secret" "text",
    "phone" "text",
    "last_challenged_at" timestamp with time zone,
    "web_authn_credential" "jsonb",
    "web_authn_aaguid" "uuid",
    "last_webauthn_challenge_data" "jsonb"
);


--
-- Name: TABLE "mfa_factors"; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE "auth"."mfa_factors" IS 'auth: stores metadata about factors';


--
-- Name: COLUMN "mfa_factors"."last_webauthn_challenge_data"; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON COLUMN "auth"."mfa_factors"."last_webauthn_challenge_data" IS 'Stores the latest WebAuthn challenge data including attestation/assertion for customer verification';


--
-- Name: oauth_authorizations; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE "auth"."oauth_authorizations" (
    "id" "uuid" NOT NULL,
    "authorization_id" "text" NOT NULL,
    "client_id" "uuid" NOT NULL,
    "user_id" "uuid",
    "redirect_uri" "text" NOT NULL,
    "scope" "text" NOT NULL,
    "state" "text",
    "resource" "text",
    "code_challenge" "text",
    "code_challenge_method" "auth"."code_challenge_method",
    "response_type" "auth"."oauth_response_type" DEFAULT 'code'::"auth"."oauth_response_type" NOT NULL,
    "status" "auth"."oauth_authorization_status" DEFAULT 'pending'::"auth"."oauth_authorization_status" NOT NULL,
    "authorization_code" "text",
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "expires_at" timestamp with time zone DEFAULT ("now"() + '00:03:00'::interval) NOT NULL,
    "approved_at" timestamp with time zone,
    CONSTRAINT "oauth_authorizations_authorization_code_length" CHECK (("char_length"("authorization_code") <= 255)),
    CONSTRAINT "oauth_authorizations_code_challenge_length" CHECK (("char_length"("code_challenge") <= 128)),
    CONSTRAINT "oauth_authorizations_expires_at_future" CHECK (("expires_at" > "created_at")),
    CONSTRAINT "oauth_authorizations_redirect_uri_length" CHECK (("char_length"("redirect_uri") <= 2048)),
    CONSTRAINT "oauth_authorizations_resource_length" CHECK (("char_length"("resource") <= 2048)),
    CONSTRAINT "oauth_authorizations_scope_length" CHECK (("char_length"("scope") <= 4096)),
    CONSTRAINT "oauth_authorizations_state_length" CHECK (("char_length"("state") <= 4096))
);


--
-- Name: oauth_clients; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE "auth"."oauth_clients" (
    "id" "uuid" NOT NULL,
    "client_secret_hash" "text",
    "registration_type" "auth"."oauth_registration_type" NOT NULL,
    "redirect_uris" "text" NOT NULL,
    "grant_types" "text" NOT NULL,
    "client_name" "text",
    "client_uri" "text",
    "logo_uri" "text",
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "deleted_at" timestamp with time zone,
    "client_type" "auth"."oauth_client_type" DEFAULT 'confidential'::"auth"."oauth_client_type" NOT NULL,
    CONSTRAINT "oauth_clients_client_name_length" CHECK (("char_length"("client_name") <= 1024)),
    CONSTRAINT "oauth_clients_client_uri_length" CHECK (("char_length"("client_uri") <= 2048)),
    CONSTRAINT "oauth_clients_logo_uri_length" CHECK (("char_length"("logo_uri") <= 2048))
);


--
-- Name: oauth_consents; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE "auth"."oauth_consents" (
    "id" "uuid" NOT NULL,
    "user_id" "uuid" NOT NULL,
    "client_id" "uuid" NOT NULL,
    "scopes" "text" NOT NULL,
    "granted_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "revoked_at" timestamp with time zone,
    CONSTRAINT "oauth_consents_revoked_after_granted" CHECK ((("revoked_at" IS NULL) OR ("revoked_at" >= "granted_at"))),
    CONSTRAINT "oauth_consents_scopes_length" CHECK (("char_length"("scopes") <= 2048)),
    CONSTRAINT "oauth_consents_scopes_not_empty" CHECK (("char_length"(TRIM(BOTH FROM "scopes")) > 0))
);


--
-- Name: one_time_tokens; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE "auth"."one_time_tokens" (
    "id" "uuid" NOT NULL,
    "user_id" "uuid" NOT NULL,
    "token_type" "auth"."one_time_token_type" NOT NULL,
    "token_hash" "text" NOT NULL,
    "relates_to" "text" NOT NULL,
    "created_at" timestamp without time zone DEFAULT "now"() NOT NULL,
    "updated_at" timestamp without time zone DEFAULT "now"() NOT NULL,
    CONSTRAINT "one_time_tokens_token_hash_check" CHECK (("char_length"("token_hash") > 0))
);


--
-- Name: refresh_tokens; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE "auth"."refresh_tokens" (
    "instance_id" "uuid",
    "id" bigint NOT NULL,
    "token" character varying(255),
    "user_id" character varying(255),
    "revoked" boolean,
    "created_at" timestamp with time zone,
    "updated_at" timestamp with time zone,
    "parent" character varying(255),
    "session_id" "uuid"
);


--
-- Name: TABLE "refresh_tokens"; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE "auth"."refresh_tokens" IS 'Auth: Store of tokens used to refresh JWT tokens once they expire.';


--
-- Name: refresh_tokens_id_seq; Type: SEQUENCE; Schema: auth; Owner: -
--

CREATE SEQUENCE "auth"."refresh_tokens_id_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: refresh_tokens_id_seq; Type: SEQUENCE OWNED BY; Schema: auth; Owner: -
--

ALTER SEQUENCE "auth"."refresh_tokens_id_seq" OWNED BY "auth"."refresh_tokens"."id";


--
-- Name: saml_providers; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE "auth"."saml_providers" (
    "id" "uuid" NOT NULL,
    "sso_provider_id" "uuid" NOT NULL,
    "entity_id" "text" NOT NULL,
    "metadata_xml" "text" NOT NULL,
    "metadata_url" "text",
    "attribute_mapping" "jsonb",
    "created_at" timestamp with time zone,
    "updated_at" timestamp with time zone,
    "name_id_format" "text",
    CONSTRAINT "entity_id not empty" CHECK (("char_length"("entity_id") > 0)),
    CONSTRAINT "metadata_url not empty" CHECK ((("metadata_url" = NULL::"text") OR ("char_length"("metadata_url") > 0))),
    CONSTRAINT "metadata_xml not empty" CHECK (("char_length"("metadata_xml") > 0))
);


--
-- Name: TABLE "saml_providers"; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE "auth"."saml_providers" IS 'Auth: Manages SAML Identity Provider connections.';


--
-- Name: saml_relay_states; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE "auth"."saml_relay_states" (
    "id" "uuid" NOT NULL,
    "sso_provider_id" "uuid" NOT NULL,
    "request_id" "text" NOT NULL,
    "for_email" "text",
    "redirect_to" "text",
    "created_at" timestamp with time zone,
    "updated_at" timestamp with time zone,
    "flow_state_id" "uuid",
    CONSTRAINT "request_id not empty" CHECK (("char_length"("request_id") > 0))
);


--
-- Name: TABLE "saml_relay_states"; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE "auth"."saml_relay_states" IS 'Auth: Contains SAML Relay State information for each Service Provider initiated login.';


--
-- Name: schema_migrations; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE "auth"."schema_migrations" (
    "version" character varying(255) NOT NULL
);


--
-- Name: TABLE "schema_migrations"; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE "auth"."schema_migrations" IS 'Auth: Manages updates to the auth system.';


--
-- Name: sessions; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE "auth"."sessions" (
    "id" "uuid" NOT NULL,
    "user_id" "uuid" NOT NULL,
    "created_at" timestamp with time zone,
    "updated_at" timestamp with time zone,
    "factor_id" "uuid",
    "aal" "auth"."aal_level",
    "not_after" timestamp with time zone,
    "refreshed_at" timestamp without time zone,
    "user_agent" "text",
    "ip" "inet",
    "tag" "text",
    "oauth_client_id" "uuid",
    "refresh_token_hmac_key" "text",
    "refresh_token_counter" bigint
);


--
-- Name: TABLE "sessions"; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE "auth"."sessions" IS 'Auth: Stores session data associated to a user.';


--
-- Name: COLUMN "sessions"."not_after"; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON COLUMN "auth"."sessions"."not_after" IS 'Auth: Not after is a nullable column that contains a timestamp after which the session should be regarded as expired.';


--
-- Name: COLUMN "sessions"."refresh_token_hmac_key"; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON COLUMN "auth"."sessions"."refresh_token_hmac_key" IS 'Holds a HMAC-SHA256 key used to sign refresh tokens for this session.';


--
-- Name: COLUMN "sessions"."refresh_token_counter"; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON COLUMN "auth"."sessions"."refresh_token_counter" IS 'Holds the ID (counter) of the last issued refresh token.';


--
-- Name: sso_domains; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE "auth"."sso_domains" (
    "id" "uuid" NOT NULL,
    "sso_provider_id" "uuid" NOT NULL,
    "domain" "text" NOT NULL,
    "created_at" timestamp with time zone,
    "updated_at" timestamp with time zone,
    CONSTRAINT "domain not empty" CHECK (("char_length"("domain") > 0))
);


--
-- Name: TABLE "sso_domains"; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE "auth"."sso_domains" IS 'Auth: Manages SSO email address domain mapping to an SSO Identity Provider.';


--
-- Name: sso_providers; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE "auth"."sso_providers" (
    "id" "uuid" NOT NULL,
    "resource_id" "text",
    "created_at" timestamp with time zone,
    "updated_at" timestamp with time zone,
    "disabled" boolean,
    CONSTRAINT "resource_id not empty" CHECK ((("resource_id" = NULL::"text") OR ("char_length"("resource_id") > 0)))
);


--
-- Name: TABLE "sso_providers"; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE "auth"."sso_providers" IS 'Auth: Manages SSO identity provider information; see saml_providers for SAML.';


--
-- Name: COLUMN "sso_providers"."resource_id"; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON COLUMN "auth"."sso_providers"."resource_id" IS 'Auth: Uniquely identifies a SSO provider according to a user-chosen resource ID (case insensitive), useful in infrastructure as code.';


--
-- Name: users; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE "auth"."users" (
    "instance_id" "uuid",
    "id" "uuid" NOT NULL,
    "aud" character varying(255),
    "role" character varying(255),
    "email" character varying(255),
    "encrypted_password" character varying(255),
    "email_confirmed_at" timestamp with time zone,
    "invited_at" timestamp with time zone,
    "confirmation_token" character varying(255),
    "confirmation_sent_at" timestamp with time zone,
    "recovery_token" character varying(255),
    "recovery_sent_at" timestamp with time zone,
    "email_change_token_new" character varying(255),
    "email_change" character varying(255),
    "email_change_sent_at" timestamp with time zone,
    "last_sign_in_at" timestamp with time zone,
    "raw_app_meta_data" "jsonb",
    "raw_user_meta_data" "jsonb",
    "is_super_admin" boolean,
    "created_at" timestamp with time zone,
    "updated_at" timestamp with time zone,
    "phone" "text" DEFAULT NULL::character varying,
    "phone_confirmed_at" timestamp with time zone,
    "phone_change" "text" DEFAULT ''::character varying,
    "phone_change_token" character varying(255) DEFAULT ''::character varying,
    "phone_change_sent_at" timestamp with time zone,
    "confirmed_at" timestamp with time zone GENERATED ALWAYS AS (LEAST("email_confirmed_at", "phone_confirmed_at")) STORED,
    "email_change_token_current" character varying(255) DEFAULT ''::character varying,
    "email_change_confirm_status" smallint DEFAULT 0,
    "banned_until" timestamp with time zone,
    "reauthentication_token" character varying(255) DEFAULT ''::character varying,
    "reauthentication_sent_at" timestamp with time zone,
    "is_sso_user" boolean DEFAULT false NOT NULL,
    "deleted_at" timestamp with time zone,
    "is_anonymous" boolean DEFAULT false NOT NULL,
    CONSTRAINT "users_email_change_confirm_status_check" CHECK ((("email_change_confirm_status" >= 0) AND ("email_change_confirm_status" <= 2)))
);


--
-- Name: TABLE "users"; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE "auth"."users" IS 'Auth: Stores user login data within a secure schema.';


--
-- Name: COLUMN "users"."is_sso_user"; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON COLUMN "auth"."users"."is_sso_user" IS 'Auth: Set this column to true when the account comes from SSO. These accounts can have duplicate emails.';


--
-- Name: account_lockouts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE "public"."account_lockouts" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "user_email" "text" NOT NULL,
    "lockout_level" integer DEFAULT 1 NOT NULL,
    "attempts_count" integer DEFAULT 0 NOT NULL,
    "locked_until" timestamp with time zone NOT NULL,
    "ip_address" "inet",
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"()
);


--
-- Name: admin_2fa_enforcement; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE "public"."admin_2fa_enforcement" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "user_id" "uuid" NOT NULL,
    "user_email" "text" NOT NULL,
    "admin_role_assigned_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "enforcement_deadline" timestamp with time zone DEFAULT ("now"() + '24:00:00'::interval) NOT NULL,
    "is_2fa_enabled" boolean DEFAULT false,
    "reminder_sent_count" integer DEFAULT 0,
    "last_reminder_sent" timestamp with time zone,
    "is_enforced" boolean DEFAULT false,
    "enforced_at" timestamp with time zone,
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"()
);


--
-- Name: audit_access_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE "public"."audit_access_log" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "user_id" "uuid",
    "accessed_at" timestamp with time zone DEFAULT "now"(),
    "access_type" "text" NOT NULL,
    "record_count" integer DEFAULT 0,
    "filters_applied" "jsonb" DEFAULT '{}'::"jsonb",
    "ip_address" "inet",
    "user_agent" "text",
    "session_id" "text"
);


--
-- Name: audit_logs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE "public"."audit_logs" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "user_id" "uuid",
    "action" "text" NOT NULL,
    "table_name" "text",
    "record_id" "uuid",
    "old_values" "jsonb",
    "new_values" "jsonb",
    "ip_address" "inet",
    "user_agent" "text",
    "session_id" "text",
    "timestamp" timestamp with time zone DEFAULT "now"(),
    "location_country" "text",
    "location_region" "text",
    "location_city" "text",
    "old_values_encrypted" "text",
    "new_values_encrypted" "text",
    "user_agent_encrypted" "text"
);


--
-- Name: TABLE "audit_logs"; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE "public"."audit_logs" IS 'Complete audit trail of system changes';


--
-- Name: profiles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE "public"."profiles" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "name" "text" NOT NULL,
    "email" "text" NOT NULL,
    "phone" "text",
    "avatar_url" "text",
    "status" "public"."user_status" DEFAULT 'active'::"public"."user_status",
    "last_active" timestamp with time zone DEFAULT "now"(),
    "onboarding_step" integer DEFAULT 0,
    "tutorial_completed" boolean DEFAULT false,
    "tutorial_completed_at" timestamp with time zone,
    "tutorial_skipped" boolean DEFAULT false,
    "tutorial_skipped_at" timestamp with time zone,
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"()
);


--
-- Name: TABLE "profiles"; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE "public"."profiles" IS 'Extended user profile information beyond auth.users';


--
-- Name: audit_logs_with_entities; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW "public"."audit_logs_with_entities" WITH ("security_invoker"='true') AS
 SELECT "al"."id",
    "al"."timestamp",
    "al"."user_id",
    "al"."action",
    "al"."table_name",
    "al"."record_id",
    "al"."old_values",
    "al"."new_values",
    "al"."ip_address",
    "al"."user_agent",
    "al"."session_id",
    "al"."location_country",
    "al"."location_region",
    "al"."location_city",
    "p"."name" AS "user_name",
    "p"."email" AS "user_email"
   FROM ("public"."audit_logs" "al"
     LEFT JOIN "public"."profiles" "p" ON (("al"."user_id" = "p"."id")));


--
-- Name: booking_agents; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE "public"."booking_agents" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "name" "text" NOT NULL,
    "email" "text",
    "phone" "text",
    "commission_rate" numeric DEFAULT 0,
    "active" boolean DEFAULT true,
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"(),
    "created_by" "uuid",
    "updated_by" "uuid"
);


--
-- Name: booking_sources; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE "public"."booking_sources" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "name" "text" NOT NULL,
    "description" "text",
    "commission_rate" numeric DEFAULT 0,
    "active" boolean DEFAULT true,
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"(),
    "created_by" "uuid",
    "updated_by" "uuid"
);


--
-- Name: bookings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE "public"."bookings" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "reference" "text" NOT NULL,
    "room_id" "uuid",
    "guest_id" "uuid",
    "source_id" "uuid",
    "agent_id" "uuid",
    "check_in_date" "date" NOT NULL,
    "check_out_date" "date" NOT NULL,
    "adults" integer DEFAULT 1,
    "children" integer DEFAULT 0,
    "base_rate" numeric NOT NULL,
    "total_amount" numeric NOT NULL,
    "security_deposit" numeric DEFAULT 0,
    "commission" numeric DEFAULT 0,
    "tourism_fee" numeric DEFAULT 0,
    "vat" numeric DEFAULT 0,
    "net_to_owner" numeric,
    "status" "public"."booking_status" DEFAULT 'pending'::"public"."booking_status",
    "payment_status" "public"."payment_status" DEFAULT 'pending'::"public"."payment_status",
    "amount_paid" numeric DEFAULT 0,
    "pending_amount" numeric,
    "special_requests" "text",
    "internal_notes" "text",
    "document_urls" "text"[],
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"(),
    "created_by" "uuid",
    "updated_by" "uuid",
    "actual_check_in" timestamp with time zone,
    "actual_check_out" timestamp with time zone,
    CONSTRAINT "bookings_check_dates_valid" CHECK (("check_out_date" > "check_in_date"))
);


--
-- Name: TABLE "bookings"; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE "public"."bookings" IS 'Main reservation/booking records';


--
-- Name: COLUMN "bookings"."reference"; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN "public"."bookings"."reference" IS 'Unique booking reference number for customer communication';


--
-- Name: COLUMN "bookings"."net_to_owner"; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN "public"."bookings"."net_to_owner" IS 'Amount payable to property owner after deductions';


--
-- Name: cleaning_tasks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE "public"."cleaning_tasks" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "room_id" "uuid",
    "status" "text" DEFAULT 'pending'::"text",
    "assigned_to" "uuid",
    "scheduled_date" timestamp with time zone,
    "completed_date" timestamp with time zone,
    "notes" "text",
    "checklist" "jsonb" DEFAULT '[]'::"jsonb",
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"(),
    "created_by" "uuid",
    "updated_by" "uuid"
);


--
-- Name: TABLE "cleaning_tasks"; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE "public"."cleaning_tasks" IS 'Room cleaning schedules and tracking';


--
-- Name: COLUMN "cleaning_tasks"."checklist"; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN "public"."cleaning_tasks"."checklist" IS 'JSON array of cleaning tasks and completion status';


--
-- Name: contract_templates; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE "public"."contract_templates" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "name" "text" NOT NULL,
    "description" "text",
    "file_url" "text" NOT NULL,
    "created_by" "uuid",
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "is_active" boolean DEFAULT true NOT NULL
);


--
-- Name: TABLE "contract_templates"; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE "public"."contract_templates" IS 'Stores uploaded PDF contract templates with visual field mapping';


--
-- Name: expense_categories; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE "public"."expense_categories" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "name" "text" NOT NULL,
    "description" "text",
    "active" boolean DEFAULT true,
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"(),
    "created_by" "uuid",
    "updated_by" "uuid"
);


--
-- Name: expenses; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE "public"."expenses" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "property_id" "uuid",
    "room_id" "uuid",
    "owner_id" "uuid",
    "category_id" "uuid",
    "payment_method_id" "uuid",
    "date" "date" NOT NULL,
    "amount" numeric NOT NULL,
    "description" "text" NOT NULL,
    "vendor" "text",
    "notes" "text",
    "receipt_urls" "text"[],
    "document_urls" "text"[],
    "status" "public"."expense_status" DEFAULT 'pending'::"public"."expense_status",
    "approved_by" "uuid",
    "approved_at" timestamp with time zone,
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"(),
    "created_by" "uuid",
    "updated_by" "uuid"
);


--
-- Name: TABLE "expenses"; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE "public"."expenses" IS 'Property-related expenses and receipts';


--
-- Name: general_settings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE "public"."general_settings" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "company_name" "text" DEFAULT 'Hotel Management System'::"text" NOT NULL,
    "currency_code" "text" DEFAULT 'USD'::"text" NOT NULL,
    "currency_symbol" "text" DEFAULT '$'::"text" NOT NULL,
    "default_checkin_time" time without time zone DEFAULT '15:00:00'::time without time zone NOT NULL,
    "default_checkout_time" time without time zone DEFAULT '11:00:00'::time without time zone NOT NULL,
    "default_tax_rate" numeric DEFAULT 0,
    "auto_checkin_enabled" boolean DEFAULT true,
    "auto_checkout_enabled" boolean DEFAULT false,
    "notifications_enabled" boolean DEFAULT true,
    "reminder_days" integer DEFAULT 1,
    "data_retention_days" integer DEFAULT 365,
    "timezone" "text" DEFAULT 'Asia/Dubai'::"text" NOT NULL,
    "date_format" "text" DEFAULT 'MM/dd/yyyy'::"text" NOT NULL,
    "backup_frequency" "text" DEFAULT 'daily'::"text",
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "created_by" "uuid",
    "updated_by" "uuid"
);


--
-- Name: TABLE "general_settings"; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE "public"."general_settings" IS 'System-wide configuration settings';


--
-- Name: guest_data_classification; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE "public"."guest_data_classification" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "field_name" "text" NOT NULL,
    "classification" "public"."data_classification" NOT NULL,
    "required_permission" "text" NOT NULL,
    "masking_rule" "text",
    "description" "text",
    "created_at" timestamp with time zone DEFAULT "now"()
);


--
-- Name: guests; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE "public"."guests" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "first_name" "text" NOT NULL,
    "last_name" "text" NOT NULL,
    "email" "text",
    "phone" "text",
    "address" "text",
    "city" "text",
    "state" "text",
    "zip_code" "text",
    "country" "text",
    "nationality" "text",
    "passport_number" "text",
    "id_document_url" "text",
    "notes" "text",
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"(),
    "created_by" "uuid",
    "updated_by" "uuid",
    "consent_data_processing" boolean DEFAULT false,
    "consent_marketing" boolean DEFAULT false,
    "consent_third_party_sharing" boolean DEFAULT false,
    "consent_timestamp" timestamp with time zone,
    "consent_ip_address" "inet",
    "data_retention_expiry" "date",
    "privacy_level" "text" DEFAULT 'standard'::"text",
    "last_data_access" timestamp with time zone,
    "access_log_id" "uuid"
);


--
-- Name: TABLE "guests"; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE "public"."guests" IS 'Guest information and contact details';


--
-- Name: ip_access_rules; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE "public"."ip_access_rules" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "ip_address" "inet" NOT NULL,
    "rule_type" "text" NOT NULL,
    "description" "text",
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "created_by" "uuid",
    "expires_at" timestamp with time zone,
    "is_active" boolean DEFAULT true NOT NULL,
    "reason" "text",
    "failed_attempts" integer DEFAULT 0,
    CONSTRAINT "ip_access_rules_rule_type_check" CHECK (("rule_type" = ANY (ARRAY['allow'::"text", 'block'::"text"])))
);


--
-- Name: login_anomalies; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE "public"."login_anomalies" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "user_id" "uuid",
    "user_email" "text" NOT NULL,
    "anomaly_type" "text" NOT NULL,
    "severity" "text" DEFAULT 'medium'::"text" NOT NULL,
    "ip_address" "inet",
    "user_agent" "text",
    "location_country" "text",
    "location_region" "text",
    "location_city" "text",
    "metadata" "jsonb" DEFAULT '{}'::"jsonb",
    "is_resolved" boolean DEFAULT false,
    "resolved_by" "uuid",
    "resolved_at" timestamp with time zone,
    "created_at" timestamp with time zone DEFAULT "now"()
);


--
-- Name: notification_settings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE "public"."notification_settings" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "user_id" "uuid",
    "role_id" "uuid",
    "category" "text" NOT NULL,
    "enabled" boolean DEFAULT true NOT NULL,
    "email_enabled" boolean DEFAULT true NOT NULL,
    "browser_enabled" boolean DEFAULT true NOT NULL,
    "mobile_enabled" boolean DEFAULT false NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"() NOT NULL
);


--
-- Name: notifications; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE "public"."notifications" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "user_id" "uuid",
    "title" "text" NOT NULL,
    "message" "text" NOT NULL,
    "type" "text" DEFAULT 'info'::"text" NOT NULL,
    "category" "text" NOT NULL,
    "related_id" "uuid",
    "read" boolean DEFAULT false NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"() NOT NULL
);


--
-- Name: owners; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE "public"."owners" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "auth_user_id" "uuid",
    "name" "text" NOT NULL,
    "email" "text" NOT NULL,
    "phone" "text",
    "address" "text",
    "city" "text",
    "state" "text",
    "zip_code" "text",
    "country" "text",
    "payment_info" "jsonb" DEFAULT '{}'::"jsonb",
    "active" boolean DEFAULT true,
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"(),
    "created_by" "uuid",
    "updated_by" "uuid"
);


--
-- Name: TABLE "owners"; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE "public"."owners" IS 'Property owners and their payment information';


--
-- Name: COLUMN "owners"."payment_info"; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN "public"."owners"."payment_info" IS 'JSON object containing payment preferences and banking details';


--
-- Name: payment_methods; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE "public"."payment_methods" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "name" "text" NOT NULL,
    "description" "text",
    "active" boolean DEFAULT true,
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"(),
    "created_by" "uuid",
    "updated_by" "uuid"
);


--
-- Name: pdf_field_mappings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE "public"."pdf_field_mappings" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "template_id" "uuid" NOT NULL,
    "field_name" "text" NOT NULL,
    "page_number" integer DEFAULT 1 NOT NULL,
    "x_position" numeric NOT NULL,
    "y_position" numeric NOT NULL,
    "font_size" integer DEFAULT 12 NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    CONSTRAINT "pdf_field_mappings_font_size_check" CHECK ((("font_size" > 0) AND ("font_size" <= 72))),
    CONSTRAINT "pdf_field_mappings_x_position_check" CHECK ((("x_position" >= (0)::numeric) AND ("x_position" <= (1)::numeric))),
    CONSTRAINT "pdf_field_mappings_y_position_check" CHECK ((("y_position" >= (0)::numeric) AND ("y_position" <= (1)::numeric)))
);


--
-- Name: TABLE "pdf_field_mappings"; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE "public"."pdf_field_mappings" IS 'Stores field positions for PDF contract generation (normalized 0-1 coordinates)';


--
-- Name: COLUMN "pdf_field_mappings"."page_number"; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN "public"."pdf_field_mappings"."page_number" IS 'Page number where field should be placed (1-indexed)';


--
-- Name: COLUMN "pdf_field_mappings"."x_position"; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN "public"."pdf_field_mappings"."x_position" IS 'Normalized X position (0-1) from left edge of page';


--
-- Name: COLUMN "pdf_field_mappings"."y_position"; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN "public"."pdf_field_mappings"."y_position" IS 'Normalized Y position (0-1) from top edge of page';


--
-- Name: properties; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE "public"."properties" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "name" "text" NOT NULL,
    "description" "text",
    "address" "text" NOT NULL,
    "city" "text",
    "state" "text",
    "zip_code" "text",
    "country" "text",
    "phone" "text",
    "email" "text",
    "active" boolean DEFAULT true,
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"(),
    "created_by" "uuid",
    "updated_by" "uuid"
);


--
-- Name: TABLE "properties"; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE "public"."properties" IS 'Physical properties/buildings being managed';


--
-- Name: property_ownership; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE "public"."property_ownership" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "owner_id" "uuid",
    "property_id" "uuid",
    "commission_rate" numeric DEFAULT 0,
    "contract_start_date" "date",
    "contract_end_date" "date",
    "active" boolean DEFAULT true,
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"(),
    "created_by" "uuid",
    "updated_by" "uuid"
);


--
-- Name: room_ownership; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE "public"."room_ownership" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "owner_id" "uuid",
    "room_id" "uuid",
    "commission_rate" numeric DEFAULT 0,
    "contract_start_date" "date",
    "contract_end_date" "date",
    "active" boolean DEFAULT true,
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"(),
    "created_by" "uuid",
    "updated_by" "uuid"
);


--
-- Name: room_types; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE "public"."room_types" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "name" "text" NOT NULL,
    "description" "text",
    "max_adults" integer DEFAULT 2,
    "max_children" integer DEFAULT 0,
    "base_rate" numeric DEFAULT 0,
    "amenities" "jsonb" DEFAULT '[]'::"jsonb",
    "active" boolean DEFAULT true,
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"(),
    "created_by" "uuid",
    "updated_by" "uuid"
);


--
-- Name: TABLE "room_types"; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE "public"."room_types" IS 'Standardized room configurations and pricing';


--
-- Name: rooms; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE "public"."rooms" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "property_id" "uuid",
    "room_type_id" "uuid",
    "number" "text" NOT NULL,
    "name" "text",
    "description" "text",
    "floor" "text",
    "size" numeric,
    "max_adults" integer DEFAULT 2,
    "max_children" integer DEFAULT 0,
    "base_rate" numeric NOT NULL,
    "amenities" "jsonb" DEFAULT '[]'::"jsonb",
    "image_urls" "text"[],
    "status" "public"."room_status" DEFAULT 'available'::"public"."room_status",
    "notes" "text",
    "last_cleaned" timestamp with time zone,
    "next_maintenance" timestamp with time zone,
    "active" boolean DEFAULT true,
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"(),
    "created_by" "uuid",
    "updated_by" "uuid"
);


--
-- Name: TABLE "rooms"; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE "public"."rooms" IS 'Individual rooms/units within properties';


--
-- Name: COLUMN "rooms"."amenities"; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN "public"."rooms"."amenities" IS 'JSON array of room amenities and features';


--
-- Name: secure_password_reset_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE "public"."secure_password_reset_tokens" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "user_id" "uuid" NOT NULL,
    "user_email" "text" NOT NULL,
    "token_hash" "text" NOT NULL,
    "expires_at" timestamp with time zone DEFAULT ("now"() + '01:00:00'::interval) NOT NULL,
    "is_used" boolean DEFAULT false,
    "used_at" timestamp with time zone,
    "ip_address" "inet",
    "user_agent" "text",
    "created_at" timestamp with time zone DEFAULT "now"()
);


--
-- Name: security_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE "public"."security_events" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "user_id" "uuid" NOT NULL,
    "event_type" "text" NOT NULL,
    "meta" "jsonb" DEFAULT '{}'::"jsonb" NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL
);

ALTER TABLE ONLY "public"."security_events" FORCE ROW LEVEL SECURITY;


--
-- Name: security_incidents; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE "public"."security_incidents" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "incident_type" "text" NOT NULL,
    "severity" "text" NOT NULL,
    "description" "text" NOT NULL,
    "ip_address" "inet",
    "user_id" "uuid",
    "user_agent" "text",
    "request_details" "jsonb" DEFAULT '{}'::"jsonb",
    "response_details" "jsonb" DEFAULT '{}'::"jsonb",
    "is_resolved" boolean DEFAULT false,
    "resolved_by" "uuid",
    "resolved_at" timestamp with time zone,
    "resolution_notes" "text",
    "created_at" timestamp with time zone DEFAULT "now"(),
    CONSTRAINT "security_incidents_severity_check" CHECK (("severity" = ANY (ARRAY['low'::"text", 'medium'::"text", 'high'::"text", 'critical'::"text"])))
);


--
-- Name: user_2fa_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE "public"."user_2fa_tokens" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "user_id" "uuid" NOT NULL,
    "token_type" "text" NOT NULL,
    "secret_encrypted" "text" NOT NULL,
    "is_verified" boolean DEFAULT false,
    "backup_codes_encrypted" "text"[],
    "created_at" timestamp with time zone DEFAULT "now"(),
    "last_used_at" timestamp with time zone,
    "expires_at" timestamp with time zone,
    CONSTRAINT "user_2fa_tokens_token_type_check" CHECK (("token_type" = ANY (ARRAY['totp'::"text", 'backup'::"text"])))
);


--
-- Name: user_role_assignments; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE "public"."user_role_assignments" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "user_id" "uuid",
    "role_id" "uuid",
    "assigned_by" "uuid",
    "created_at" timestamp with time zone DEFAULT "now"()
);


--
-- Name: TABLE "user_role_assignments"; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE "public"."user_role_assignments" IS 'Many-to-many relationship between users and roles';


--
-- Name: user_roles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE "public"."user_roles" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "name" "text" NOT NULL,
    "description" "text",
    "permissions" "jsonb" DEFAULT '{}'::"jsonb",
    "is_system" boolean DEFAULT false,
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"()
);


--
-- Name: TABLE "user_roles"; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE "public"."user_roles" IS 'System roles with granular permissions';


--
-- Name: COLUMN "user_roles"."permissions"; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN "public"."user_roles"."permissions" IS 'JSON object with hierarchical permission structure';


--
-- Name: user_sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE "public"."user_sessions" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "user_id" "uuid" NOT NULL,
    "session_token" "text" NOT NULL,
    "ip_address" "inet",
    "user_agent" "text",
    "location_country" "text",
    "location_region" "text",
    "location_city" "text",
    "is_active" boolean DEFAULT true,
    "created_at" timestamp with time zone DEFAULT "now"(),
    "last_activity" timestamp with time zone DEFAULT "now"(),
    "expires_at" timestamp with time zone DEFAULT ("now"() + '00:30:00'::interval)
);


--
-- Name: messages; Type: TABLE; Schema: realtime; Owner: -
--

CREATE TABLE "realtime"."messages" (
    "topic" "text" NOT NULL,
    "extension" "text" NOT NULL,
    "payload" "jsonb",
    "event" "text",
    "private" boolean DEFAULT false,
    "updated_at" timestamp without time zone DEFAULT "now"() NOT NULL,
    "inserted_at" timestamp without time zone DEFAULT "now"() NOT NULL,
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL
)
PARTITION BY RANGE ("inserted_at");


--
-- Name: messages_2025_11_09; Type: TABLE; Schema: realtime; Owner: -
--

CREATE TABLE "realtime"."messages_2025_11_09" (
    "topic" "text" NOT NULL,
    "extension" "text" NOT NULL,
    "payload" "jsonb",
    "event" "text",
    "private" boolean DEFAULT false,
    "updated_at" timestamp without time zone DEFAULT "now"() NOT NULL,
    "inserted_at" timestamp without time zone DEFAULT "now"() NOT NULL,
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL
);


--
-- Name: messages_2025_11_10; Type: TABLE; Schema: realtime; Owner: -
--

CREATE TABLE "realtime"."messages_2025_11_10" (
    "topic" "text" NOT NULL,
    "extension" "text" NOT NULL,
    "payload" "jsonb",
    "event" "text",
    "private" boolean DEFAULT false,
    "updated_at" timestamp without time zone DEFAULT "now"() NOT NULL,
    "inserted_at" timestamp without time zone DEFAULT "now"() NOT NULL,
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL
);


--
-- Name: messages_2025_11_11; Type: TABLE; Schema: realtime; Owner: -
--

CREATE TABLE "realtime"."messages_2025_11_11" (
    "topic" "text" NOT NULL,
    "extension" "text" NOT NULL,
    "payload" "jsonb",
    "event" "text",
    "private" boolean DEFAULT false,
    "updated_at" timestamp without time zone DEFAULT "now"() NOT NULL,
    "inserted_at" timestamp without time zone DEFAULT "now"() NOT NULL,
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL
);


--
-- Name: messages_2025_11_12; Type: TABLE; Schema: realtime; Owner: -
--

CREATE TABLE "realtime"."messages_2025_11_12" (
    "topic" "text" NOT NULL,
    "extension" "text" NOT NULL,
    "payload" "jsonb",
    "event" "text",
    "private" boolean DEFAULT false,
    "updated_at" timestamp without time zone DEFAULT "now"() NOT NULL,
    "inserted_at" timestamp without time zone DEFAULT "now"() NOT NULL,
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL
);


--
-- Name: messages_2025_11_13; Type: TABLE; Schema: realtime; Owner: -
--

CREATE TABLE "realtime"."messages_2025_11_13" (
    "topic" "text" NOT NULL,
    "extension" "text" NOT NULL,
    "payload" "jsonb",
    "event" "text",
    "private" boolean DEFAULT false,
    "updated_at" timestamp without time zone DEFAULT "now"() NOT NULL,
    "inserted_at" timestamp without time zone DEFAULT "now"() NOT NULL,
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL
);


--
-- Name: messages_2025_11_14; Type: TABLE; Schema: realtime; Owner: -
--

CREATE TABLE "realtime"."messages_2025_11_14" (
    "topic" "text" NOT NULL,
    "extension" "text" NOT NULL,
    "payload" "jsonb",
    "event" "text",
    "private" boolean DEFAULT false,
    "updated_at" timestamp without time zone DEFAULT "now"() NOT NULL,
    "inserted_at" timestamp without time zone DEFAULT "now"() NOT NULL,
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL
);


--
-- Name: messages_2025_11_15; Type: TABLE; Schema: realtime; Owner: -
--

CREATE TABLE "realtime"."messages_2025_11_15" (
    "topic" "text" NOT NULL,
    "extension" "text" NOT NULL,
    "payload" "jsonb",
    "event" "text",
    "private" boolean DEFAULT false,
    "updated_at" timestamp without time zone DEFAULT "now"() NOT NULL,
    "inserted_at" timestamp without time zone DEFAULT "now"() NOT NULL,
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL
);


--
-- Name: schema_migrations; Type: TABLE; Schema: realtime; Owner: -
--

CREATE TABLE "realtime"."schema_migrations" (
    "version" bigint NOT NULL,
    "inserted_at" timestamp(0) without time zone
);


--
-- Name: subscription; Type: TABLE; Schema: realtime; Owner: -
--

CREATE TABLE "realtime"."subscription" (
    "id" bigint NOT NULL,
    "subscription_id" "uuid" NOT NULL,
    "entity" "regclass" NOT NULL,
    "filters" "realtime"."user_defined_filter"[] DEFAULT '{}'::"realtime"."user_defined_filter"[] NOT NULL,
    "claims" "jsonb" NOT NULL,
    "claims_role" "regrole" GENERATED ALWAYS AS ("realtime"."to_regrole"(("claims" ->> 'role'::"text"))) STORED NOT NULL,
    "created_at" timestamp without time zone DEFAULT "timezone"('utc'::"text", "now"()) NOT NULL
);


--
-- Name: subscription_id_seq; Type: SEQUENCE; Schema: realtime; Owner: -
--

ALTER TABLE "realtime"."subscription" ALTER COLUMN "id" ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME "realtime"."subscription_id_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: buckets; Type: TABLE; Schema: storage; Owner: -
--

CREATE TABLE "storage"."buckets" (
    "id" "text" NOT NULL,
    "name" "text" NOT NULL,
    "owner" "uuid",
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"(),
    "public" boolean DEFAULT false,
    "avif_autodetection" boolean DEFAULT false,
    "file_size_limit" bigint,
    "allowed_mime_types" "text"[],
    "owner_id" "text",
    "type" "storage"."buckettype" DEFAULT 'STANDARD'::"storage"."buckettype" NOT NULL
);


--
-- Name: COLUMN "buckets"."owner"; Type: COMMENT; Schema: storage; Owner: -
--

COMMENT ON COLUMN "storage"."buckets"."owner" IS 'Field is deprecated, use owner_id instead';


--
-- Name: buckets_analytics; Type: TABLE; Schema: storage; Owner: -
--

CREATE TABLE "storage"."buckets_analytics" (
    "name" "text" NOT NULL,
    "type" "storage"."buckettype" DEFAULT 'ANALYTICS'::"storage"."buckettype" NOT NULL,
    "format" "text" DEFAULT 'ICEBERG'::"text" NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "deleted_at" timestamp with time zone
);


--
-- Name: buckets_vectors; Type: TABLE; Schema: storage; Owner: -
--

CREATE TABLE "storage"."buckets_vectors" (
    "id" "text" NOT NULL,
    "type" "storage"."buckettype" DEFAULT 'VECTOR'::"storage"."buckettype" NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"() NOT NULL
);


--
-- Name: migrations; Type: TABLE; Schema: storage; Owner: -
--

CREATE TABLE "storage"."migrations" (
    "id" integer NOT NULL,
    "name" character varying(100) NOT NULL,
    "hash" character varying(40) NOT NULL,
    "executed_at" timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: objects; Type: TABLE; Schema: storage; Owner: -
--

CREATE TABLE "storage"."objects" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "bucket_id" "text",
    "name" "text",
    "owner" "uuid",
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"(),
    "last_accessed_at" timestamp with time zone DEFAULT "now"(),
    "metadata" "jsonb",
    "path_tokens" "text"[] GENERATED ALWAYS AS ("string_to_array"("name", '/'::"text")) STORED,
    "version" "text",
    "owner_id" "text",
    "user_metadata" "jsonb",
    "level" integer
);


--
-- Name: COLUMN "objects"."owner"; Type: COMMENT; Schema: storage; Owner: -
--

COMMENT ON COLUMN "storage"."objects"."owner" IS 'Field is deprecated, use owner_id instead';


--
-- Name: prefixes; Type: TABLE; Schema: storage; Owner: -
--

CREATE TABLE "storage"."prefixes" (
    "bucket_id" "text" NOT NULL,
    "name" "text" NOT NULL COLLATE "pg_catalog"."C",
    "level" integer GENERATED ALWAYS AS ("storage"."get_level"("name")) STORED NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"()
);


--
-- Name: s3_multipart_uploads; Type: TABLE; Schema: storage; Owner: -
--

CREATE TABLE "storage"."s3_multipart_uploads" (
    "id" "text" NOT NULL,
    "in_progress_size" bigint DEFAULT 0 NOT NULL,
    "upload_signature" "text" NOT NULL,
    "bucket_id" "text" NOT NULL,
    "key" "text" NOT NULL COLLATE "pg_catalog"."C",
    "version" "text" NOT NULL,
    "owner_id" "text",
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "user_metadata" "jsonb"
);


--
-- Name: s3_multipart_uploads_parts; Type: TABLE; Schema: storage; Owner: -
--

CREATE TABLE "storage"."s3_multipart_uploads_parts" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "upload_id" "text" NOT NULL,
    "size" bigint DEFAULT 0 NOT NULL,
    "part_number" integer NOT NULL,
    "bucket_id" "text" NOT NULL,
    "key" "text" NOT NULL COLLATE "pg_catalog"."C",
    "etag" "text" NOT NULL,
    "owner_id" "text",
    "version" "text" NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL
);


--
-- Name: vector_indexes; Type: TABLE; Schema: storage; Owner: -
--

CREATE TABLE "storage"."vector_indexes" (
    "id" "text" DEFAULT "gen_random_uuid"() NOT NULL,
    "name" "text" NOT NULL COLLATE "pg_catalog"."C",
    "bucket_id" "text" NOT NULL,
    "data_type" "text" NOT NULL,
    "dimension" integer NOT NULL,
    "distance_metric" "text" NOT NULL,
    "metadata_configuration" "jsonb",
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"() NOT NULL
);


--
-- Name: schema_migrations; Type: TABLE; Schema: supabase_migrations; Owner: -
--

CREATE TABLE "supabase_migrations"."schema_migrations" (
    "version" "text" NOT NULL,
    "statements" "text"[],
    "name" "text",
    "created_by" "text",
    "idempotency_key" "text",
    "rollback" "text"[]
);


--
-- Name: messages_2025_11_09; Type: TABLE ATTACH; Schema: realtime; Owner: -
--

ALTER TABLE ONLY "realtime"."messages" ATTACH PARTITION "realtime"."messages_2025_11_09" FOR VALUES FROM ('2025-11-09 00:00:00') TO ('2025-11-10 00:00:00');


--
-- Name: messages_2025_11_10; Type: TABLE ATTACH; Schema: realtime; Owner: -
--

ALTER TABLE ONLY "realtime"."messages" ATTACH PARTITION "realtime"."messages_2025_11_10" FOR VALUES FROM ('2025-11-10 00:00:00') TO ('2025-11-11 00:00:00');


--
-- Name: messages_2025_11_11; Type: TABLE ATTACH; Schema: realtime; Owner: -
--

ALTER TABLE ONLY "realtime"."messages" ATTACH PARTITION "realtime"."messages_2025_11_11" FOR VALUES FROM ('2025-11-11 00:00:00') TO ('2025-11-12 00:00:00');


--
-- Name: messages_2025_11_12; Type: TABLE ATTACH; Schema: realtime; Owner: -
--

ALTER TABLE ONLY "realtime"."messages" ATTACH PARTITION "realtime"."messages_2025_11_12" FOR VALUES FROM ('2025-11-12 00:00:00') TO ('2025-11-13 00:00:00');


--
-- Name: messages_2025_11_13; Type: TABLE ATTACH; Schema: realtime; Owner: -
--

ALTER TABLE ONLY "realtime"."messages" ATTACH PARTITION "realtime"."messages_2025_11_13" FOR VALUES FROM ('2025-11-13 00:00:00') TO ('2025-11-14 00:00:00');


--
-- Name: messages_2025_11_14; Type: TABLE ATTACH; Schema: realtime; Owner: -
--

ALTER TABLE ONLY "realtime"."messages" ATTACH PARTITION "realtime"."messages_2025_11_14" FOR VALUES FROM ('2025-11-14 00:00:00') TO ('2025-11-15 00:00:00');


--
-- Name: messages_2025_11_15; Type: TABLE ATTACH; Schema: realtime; Owner: -
--

ALTER TABLE ONLY "realtime"."messages" ATTACH PARTITION "realtime"."messages_2025_11_15" FOR VALUES FROM ('2025-11-15 00:00:00') TO ('2025-11-16 00:00:00');


--
-- Name: refresh_tokens id; Type: DEFAULT; Schema: auth; Owner: -
--

ALTER TABLE ONLY "auth"."refresh_tokens" ALTER COLUMN "id" SET DEFAULT "nextval"('"auth"."refresh_tokens_id_seq"'::"regclass");


--
-- Name: mfa_amr_claims amr_id_pk; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY "auth"."mfa_amr_claims"
    ADD CONSTRAINT "amr_id_pk" PRIMARY KEY ("id");


--
-- Name: audit_log_entries audit_log_entries_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY "auth"."audit_log_entries"
    ADD CONSTRAINT "audit_log_entries_pkey" PRIMARY KEY ("id");


--
-- Name: flow_state flow_state_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY "auth"."flow_state"
    ADD CONSTRAINT "flow_state_pkey" PRIMARY KEY ("id");


--
-- Name: identities identities_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY "auth"."identities"
    ADD CONSTRAINT "identities_pkey" PRIMARY KEY ("id");


--
-- Name: identities identities_provider_id_provider_unique; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY "auth"."identities"
    ADD CONSTRAINT "identities_provider_id_provider_unique" UNIQUE ("provider_id", "provider");


--
-- Name: instances instances_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY "auth"."instances"
    ADD CONSTRAINT "instances_pkey" PRIMARY KEY ("id");


--
-- Name: mfa_amr_claims mfa_amr_claims_session_id_authentication_method_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY "auth"."mfa_amr_claims"
    ADD CONSTRAINT "mfa_amr_claims_session_id_authentication_method_pkey" UNIQUE ("session_id", "authentication_method");


--
-- Name: mfa_challenges mfa_challenges_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY "auth"."mfa_challenges"
    ADD CONSTRAINT "mfa_challenges_pkey" PRIMARY KEY ("id");


--
-- Name: mfa_factors mfa_factors_last_challenged_at_key; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY "auth"."mfa_factors"
    ADD CONSTRAINT "mfa_factors_last_challenged_at_key" UNIQUE ("last_challenged_at");


--
-- Name: mfa_factors mfa_factors_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY "auth"."mfa_factors"
    ADD CONSTRAINT "mfa_factors_pkey" PRIMARY KEY ("id");


--
-- Name: oauth_authorizations oauth_authorizations_authorization_code_key; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY "auth"."oauth_authorizations"
    ADD CONSTRAINT "oauth_authorizations_authorization_code_key" UNIQUE ("authorization_code");


--
-- Name: oauth_authorizations oauth_authorizations_authorization_id_key; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY "auth"."oauth_authorizations"
    ADD CONSTRAINT "oauth_authorizations_authorization_id_key" UNIQUE ("authorization_id");


--
-- Name: oauth_authorizations oauth_authorizations_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY "auth"."oauth_authorizations"
    ADD CONSTRAINT "oauth_authorizations_pkey" PRIMARY KEY ("id");


--
-- Name: oauth_clients oauth_clients_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY "auth"."oauth_clients"
    ADD CONSTRAINT "oauth_clients_pkey" PRIMARY KEY ("id");


--
-- Name: oauth_consents oauth_consents_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY "auth"."oauth_consents"
    ADD CONSTRAINT "oauth_consents_pkey" PRIMARY KEY ("id");


--
-- Name: oauth_consents oauth_consents_user_client_unique; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY "auth"."oauth_consents"
    ADD CONSTRAINT "oauth_consents_user_client_unique" UNIQUE ("user_id", "client_id");


--
-- Name: one_time_tokens one_time_tokens_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY "auth"."one_time_tokens"
    ADD CONSTRAINT "one_time_tokens_pkey" PRIMARY KEY ("id");


--
-- Name: refresh_tokens refresh_tokens_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY "auth"."refresh_tokens"
    ADD CONSTRAINT "refresh_tokens_pkey" PRIMARY KEY ("id");


--
-- Name: refresh_tokens refresh_tokens_token_unique; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY "auth"."refresh_tokens"
    ADD CONSTRAINT "refresh_tokens_token_unique" UNIQUE ("token");


--
-- Name: saml_providers saml_providers_entity_id_key; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY "auth"."saml_providers"
    ADD CONSTRAINT "saml_providers_entity_id_key" UNIQUE ("entity_id");


--
-- Name: saml_providers saml_providers_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY "auth"."saml_providers"
    ADD CONSTRAINT "saml_providers_pkey" PRIMARY KEY ("id");


--
-- Name: saml_relay_states saml_relay_states_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY "auth"."saml_relay_states"
    ADD CONSTRAINT "saml_relay_states_pkey" PRIMARY KEY ("id");


--
-- Name: schema_migrations schema_migrations_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY "auth"."schema_migrations"
    ADD CONSTRAINT "schema_migrations_pkey" PRIMARY KEY ("version");


--
-- Name: sessions sessions_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY "auth"."sessions"
    ADD CONSTRAINT "sessions_pkey" PRIMARY KEY ("id");


--
-- Name: sso_domains sso_domains_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY "auth"."sso_domains"
    ADD CONSTRAINT "sso_domains_pkey" PRIMARY KEY ("id");


--
-- Name: sso_providers sso_providers_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY "auth"."sso_providers"
    ADD CONSTRAINT "sso_providers_pkey" PRIMARY KEY ("id");


--
-- Name: users users_phone_key; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY "auth"."users"
    ADD CONSTRAINT "users_phone_key" UNIQUE ("phone");


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY "auth"."users"
    ADD CONSTRAINT "users_pkey" PRIMARY KEY ("id");


--
-- Name: account_lockouts account_lockouts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."account_lockouts"
    ADD CONSTRAINT "account_lockouts_pkey" PRIMARY KEY ("id");


--
-- Name: admin_2fa_enforcement admin_2fa_enforcement_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."admin_2fa_enforcement"
    ADD CONSTRAINT "admin_2fa_enforcement_pkey" PRIMARY KEY ("id");


--
-- Name: admin_2fa_enforcement admin_2fa_enforcement_user_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."admin_2fa_enforcement"
    ADD CONSTRAINT "admin_2fa_enforcement_user_id_key" UNIQUE ("user_id");


--
-- Name: audit_access_log audit_access_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."audit_access_log"
    ADD CONSTRAINT "audit_access_log_pkey" PRIMARY KEY ("id");


--
-- Name: audit_logs audit_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."audit_logs"
    ADD CONSTRAINT "audit_logs_pkey" PRIMARY KEY ("id");


--
-- Name: booking_agents booking_agents_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."booking_agents"
    ADD CONSTRAINT "booking_agents_pkey" PRIMARY KEY ("id");


--
-- Name: booking_sources booking_sources_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."booking_sources"
    ADD CONSTRAINT "booking_sources_pkey" PRIMARY KEY ("id");


--
-- Name: bookings bookings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."bookings"
    ADD CONSTRAINT "bookings_pkey" PRIMARY KEY ("id");


--
-- Name: bookings bookings_reference_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."bookings"
    ADD CONSTRAINT "bookings_reference_key" UNIQUE ("reference");


--
-- Name: cleaning_tasks cleaning_tasks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."cleaning_tasks"
    ADD CONSTRAINT "cleaning_tasks_pkey" PRIMARY KEY ("id");


--
-- Name: contract_templates contract_templates_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."contract_templates"
    ADD CONSTRAINT "contract_templates_name_key" UNIQUE ("name");


--
-- Name: contract_templates contract_templates_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."contract_templates"
    ADD CONSTRAINT "contract_templates_pkey" PRIMARY KEY ("id");


--
-- Name: expense_categories expense_categories_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."expense_categories"
    ADD CONSTRAINT "expense_categories_pkey" PRIMARY KEY ("id");


--
-- Name: expenses expenses_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."expenses"
    ADD CONSTRAINT "expenses_pkey" PRIMARY KEY ("id");


--
-- Name: general_settings general_settings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."general_settings"
    ADD CONSTRAINT "general_settings_pkey" PRIMARY KEY ("id");


--
-- Name: guest_data_classification guest_data_classification_field_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."guest_data_classification"
    ADD CONSTRAINT "guest_data_classification_field_name_key" UNIQUE ("field_name");


--
-- Name: guest_data_classification guest_data_classification_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."guest_data_classification"
    ADD CONSTRAINT "guest_data_classification_pkey" PRIMARY KEY ("id");


--
-- Name: guests guests_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."guests"
    ADD CONSTRAINT "guests_pkey" PRIMARY KEY ("id");


--
-- Name: ip_access_rules ip_access_rules_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."ip_access_rules"
    ADD CONSTRAINT "ip_access_rules_pkey" PRIMARY KEY ("id");


--
-- Name: login_anomalies login_anomalies_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."login_anomalies"
    ADD CONSTRAINT "login_anomalies_pkey" PRIMARY KEY ("id");


--
-- Name: notification_settings notification_settings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."notification_settings"
    ADD CONSTRAINT "notification_settings_pkey" PRIMARY KEY ("id");


--
-- Name: notification_settings notification_settings_role_id_category_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."notification_settings"
    ADD CONSTRAINT "notification_settings_role_id_category_key" UNIQUE ("role_id", "category");


--
-- Name: notification_settings notification_settings_user_id_category_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."notification_settings"
    ADD CONSTRAINT "notification_settings_user_id_category_key" UNIQUE ("user_id", "category");


--
-- Name: notifications notifications_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."notifications"
    ADD CONSTRAINT "notifications_pkey" PRIMARY KEY ("id");


--
-- Name: owners owners_email_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."owners"
    ADD CONSTRAINT "owners_email_key" UNIQUE ("email");


--
-- Name: owners owners_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."owners"
    ADD CONSTRAINT "owners_pkey" PRIMARY KEY ("id");


--
-- Name: payment_methods payment_methods_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."payment_methods"
    ADD CONSTRAINT "payment_methods_pkey" PRIMARY KEY ("id");


--
-- Name: pdf_field_mappings pdf_field_mappings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."pdf_field_mappings"
    ADD CONSTRAINT "pdf_field_mappings_pkey" PRIMARY KEY ("id");


--
-- Name: pdf_field_mappings pdf_field_mappings_unique_field; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."pdf_field_mappings"
    ADD CONSTRAINT "pdf_field_mappings_unique_field" UNIQUE ("template_id", "field_name", "page_number");


--
-- Name: profiles profiles_email_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."profiles"
    ADD CONSTRAINT "profiles_email_key" UNIQUE ("email");


--
-- Name: profiles profiles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."profiles"
    ADD CONSTRAINT "profiles_pkey" PRIMARY KEY ("id");


--
-- Name: properties properties_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."properties"
    ADD CONSTRAINT "properties_pkey" PRIMARY KEY ("id");


--
-- Name: property_ownership property_ownership_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."property_ownership"
    ADD CONSTRAINT "property_ownership_pkey" PRIMARY KEY ("id");


--
-- Name: room_ownership room_ownership_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."room_ownership"
    ADD CONSTRAINT "room_ownership_pkey" PRIMARY KEY ("id");


--
-- Name: room_types room_types_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."room_types"
    ADD CONSTRAINT "room_types_pkey" PRIMARY KEY ("id");


--
-- Name: rooms rooms_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."rooms"
    ADD CONSTRAINT "rooms_pkey" PRIMARY KEY ("id");


--
-- Name: rooms rooms_property_number_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."rooms"
    ADD CONSTRAINT "rooms_property_number_unique" UNIQUE ("property_id", "number");


--
-- Name: secure_password_reset_tokens secure_password_reset_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."secure_password_reset_tokens"
    ADD CONSTRAINT "secure_password_reset_tokens_pkey" PRIMARY KEY ("id");


--
-- Name: secure_password_reset_tokens secure_password_reset_tokens_token_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."secure_password_reset_tokens"
    ADD CONSTRAINT "secure_password_reset_tokens_token_hash_key" UNIQUE ("token_hash");


--
-- Name: security_events security_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."security_events"
    ADD CONSTRAINT "security_events_pkey" PRIMARY KEY ("id");


--
-- Name: security_incidents security_incidents_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."security_incidents"
    ADD CONSTRAINT "security_incidents_pkey" PRIMARY KEY ("id");


--
-- Name: user_2fa_tokens user_2fa_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."user_2fa_tokens"
    ADD CONSTRAINT "user_2fa_tokens_pkey" PRIMARY KEY ("id");


--
-- Name: user_role_assignments user_role_assignments_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."user_role_assignments"
    ADD CONSTRAINT "user_role_assignments_pkey" PRIMARY KEY ("id");


--
-- Name: user_role_assignments user_role_assignments_user_role_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."user_role_assignments"
    ADD CONSTRAINT "user_role_assignments_user_role_unique" UNIQUE ("user_id", "role_id");


--
-- Name: user_roles user_roles_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."user_roles"
    ADD CONSTRAINT "user_roles_name_key" UNIQUE ("name");


--
-- Name: user_roles user_roles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."user_roles"
    ADD CONSTRAINT "user_roles_pkey" PRIMARY KEY ("id");


--
-- Name: user_sessions user_sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."user_sessions"
    ADD CONSTRAINT "user_sessions_pkey" PRIMARY KEY ("id");


--
-- Name: user_sessions user_sessions_session_token_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."user_sessions"
    ADD CONSTRAINT "user_sessions_session_token_key" UNIQUE ("session_token");


--
-- Name: messages messages_pkey; Type: CONSTRAINT; Schema: realtime; Owner: -
--

ALTER TABLE ONLY "realtime"."messages"
    ADD CONSTRAINT "messages_pkey" PRIMARY KEY ("id", "inserted_at");


--
-- Name: messages_2025_11_09 messages_2025_11_09_pkey; Type: CONSTRAINT; Schema: realtime; Owner: -
--

ALTER TABLE ONLY "realtime"."messages_2025_11_09"
    ADD CONSTRAINT "messages_2025_11_09_pkey" PRIMARY KEY ("id", "inserted_at");


--
-- Name: messages_2025_11_10 messages_2025_11_10_pkey; Type: CONSTRAINT; Schema: realtime; Owner: -
--

ALTER TABLE ONLY "realtime"."messages_2025_11_10"
    ADD CONSTRAINT "messages_2025_11_10_pkey" PRIMARY KEY ("id", "inserted_at");


--
-- Name: messages_2025_11_11 messages_2025_11_11_pkey; Type: CONSTRAINT; Schema: realtime; Owner: -
--

ALTER TABLE ONLY "realtime"."messages_2025_11_11"
    ADD CONSTRAINT "messages_2025_11_11_pkey" PRIMARY KEY ("id", "inserted_at");


--
-- Name: messages_2025_11_12 messages_2025_11_12_pkey; Type: CONSTRAINT; Schema: realtime; Owner: -
--

ALTER TABLE ONLY "realtime"."messages_2025_11_12"
    ADD CONSTRAINT "messages_2025_11_12_pkey" PRIMARY KEY ("id", "inserted_at");


--
-- Name: messages_2025_11_13 messages_2025_11_13_pkey; Type: CONSTRAINT; Schema: realtime; Owner: -
--

ALTER TABLE ONLY "realtime"."messages_2025_11_13"
    ADD CONSTRAINT "messages_2025_11_13_pkey" PRIMARY KEY ("id", "inserted_at");


--
-- Name: messages_2025_11_14 messages_2025_11_14_pkey; Type: CONSTRAINT; Schema: realtime; Owner: -
--

ALTER TABLE ONLY "realtime"."messages_2025_11_14"
    ADD CONSTRAINT "messages_2025_11_14_pkey" PRIMARY KEY ("id", "inserted_at");


--
-- Name: messages_2025_11_15 messages_2025_11_15_pkey; Type: CONSTRAINT; Schema: realtime; Owner: -
--

ALTER TABLE ONLY "realtime"."messages_2025_11_15"
    ADD CONSTRAINT "messages_2025_11_15_pkey" PRIMARY KEY ("id", "inserted_at");


--
-- Name: subscription pk_subscription; Type: CONSTRAINT; Schema: realtime; Owner: -
--

ALTER TABLE ONLY "realtime"."subscription"
    ADD CONSTRAINT "pk_subscription" PRIMARY KEY ("id");


--
-- Name: schema_migrations schema_migrations_pkey; Type: CONSTRAINT; Schema: realtime; Owner: -
--

ALTER TABLE ONLY "realtime"."schema_migrations"
    ADD CONSTRAINT "schema_migrations_pkey" PRIMARY KEY ("version");


--
-- Name: buckets_analytics buckets_analytics_pkey; Type: CONSTRAINT; Schema: storage; Owner: -
--

ALTER TABLE ONLY "storage"."buckets_analytics"
    ADD CONSTRAINT "buckets_analytics_pkey" PRIMARY KEY ("id");


--
-- Name: buckets buckets_pkey; Type: CONSTRAINT; Schema: storage; Owner: -
--

ALTER TABLE ONLY "storage"."buckets"
    ADD CONSTRAINT "buckets_pkey" PRIMARY KEY ("id");


--
-- Name: buckets_vectors buckets_vectors_pkey; Type: CONSTRAINT; Schema: storage; Owner: -
--

ALTER TABLE ONLY "storage"."buckets_vectors"
    ADD CONSTRAINT "buckets_vectors_pkey" PRIMARY KEY ("id");


--
-- Name: migrations migrations_name_key; Type: CONSTRAINT; Schema: storage; Owner: -
--

ALTER TABLE ONLY "storage"."migrations"
    ADD CONSTRAINT "migrations_name_key" UNIQUE ("name");


--
-- Name: migrations migrations_pkey; Type: CONSTRAINT; Schema: storage; Owner: -
--

ALTER TABLE ONLY "storage"."migrations"
    ADD CONSTRAINT "migrations_pkey" PRIMARY KEY ("id");


--
-- Name: objects objects_pkey; Type: CONSTRAINT; Schema: storage; Owner: -
--

ALTER TABLE ONLY "storage"."objects"
    ADD CONSTRAINT "objects_pkey" PRIMARY KEY ("id");


--
-- Name: prefixes prefixes_pkey; Type: CONSTRAINT; Schema: storage; Owner: -
--

ALTER TABLE ONLY "storage"."prefixes"
    ADD CONSTRAINT "prefixes_pkey" PRIMARY KEY ("bucket_id", "level", "name");


--
-- Name: s3_multipart_uploads_parts s3_multipart_uploads_parts_pkey; Type: CONSTRAINT; Schema: storage; Owner: -
--

ALTER TABLE ONLY "storage"."s3_multipart_uploads_parts"
    ADD CONSTRAINT "s3_multipart_uploads_parts_pkey" PRIMARY KEY ("id");


--
-- Name: s3_multipart_uploads s3_multipart_uploads_pkey; Type: CONSTRAINT; Schema: storage; Owner: -
--

ALTER TABLE ONLY "storage"."s3_multipart_uploads"
    ADD CONSTRAINT "s3_multipart_uploads_pkey" PRIMARY KEY ("id");


--
-- Name: vector_indexes vector_indexes_pkey; Type: CONSTRAINT; Schema: storage; Owner: -
--

ALTER TABLE ONLY "storage"."vector_indexes"
    ADD CONSTRAINT "vector_indexes_pkey" PRIMARY KEY ("id");


--
-- Name: schema_migrations schema_migrations_idempotency_key_key; Type: CONSTRAINT; Schema: supabase_migrations; Owner: -
--

ALTER TABLE ONLY "supabase_migrations"."schema_migrations"
    ADD CONSTRAINT "schema_migrations_idempotency_key_key" UNIQUE ("idempotency_key");


--
-- Name: schema_migrations schema_migrations_pkey; Type: CONSTRAINT; Schema: supabase_migrations; Owner: -
--

ALTER TABLE ONLY "supabase_migrations"."schema_migrations"
    ADD CONSTRAINT "schema_migrations_pkey" PRIMARY KEY ("version");


--
-- Name: audit_logs_instance_id_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX "audit_logs_instance_id_idx" ON "auth"."audit_log_entries" USING "btree" ("instance_id");


--
-- Name: confirmation_token_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE UNIQUE INDEX "confirmation_token_idx" ON "auth"."users" USING "btree" ("confirmation_token") WHERE (("confirmation_token")::"text" !~ '^[0-9 ]*$'::"text");


--
-- Name: email_change_token_current_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE UNIQUE INDEX "email_change_token_current_idx" ON "auth"."users" USING "btree" ("email_change_token_current") WHERE (("email_change_token_current")::"text" !~ '^[0-9 ]*$'::"text");


--
-- Name: email_change_token_new_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE UNIQUE INDEX "email_change_token_new_idx" ON "auth"."users" USING "btree" ("email_change_token_new") WHERE (("email_change_token_new")::"text" !~ '^[0-9 ]*$'::"text");


--
-- Name: factor_id_created_at_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX "factor_id_created_at_idx" ON "auth"."mfa_factors" USING "btree" ("user_id", "created_at");


--
-- Name: flow_state_created_at_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX "flow_state_created_at_idx" ON "auth"."flow_state" USING "btree" ("created_at" DESC);


--
-- Name: identities_email_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX "identities_email_idx" ON "auth"."identities" USING "btree" ("email" "text_pattern_ops");


--
-- Name: INDEX "identities_email_idx"; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON INDEX "auth"."identities_email_idx" IS 'Auth: Ensures indexed queries on the email column';


--
-- Name: identities_user_id_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX "identities_user_id_idx" ON "auth"."identities" USING "btree" ("user_id");


--
-- Name: idx_auth_code; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX "idx_auth_code" ON "auth"."flow_state" USING "btree" ("auth_code");


--
-- Name: idx_user_id_auth_method; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX "idx_user_id_auth_method" ON "auth"."flow_state" USING "btree" ("user_id", "authentication_method");


--
-- Name: mfa_challenge_created_at_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX "mfa_challenge_created_at_idx" ON "auth"."mfa_challenges" USING "btree" ("created_at" DESC);


--
-- Name: mfa_factors_user_friendly_name_unique; Type: INDEX; Schema: auth; Owner: -
--

CREATE UNIQUE INDEX "mfa_factors_user_friendly_name_unique" ON "auth"."mfa_factors" USING "btree" ("friendly_name", "user_id") WHERE (TRIM(BOTH FROM "friendly_name") <> ''::"text");


--
-- Name: mfa_factors_user_id_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX "mfa_factors_user_id_idx" ON "auth"."mfa_factors" USING "btree" ("user_id");


--
-- Name: oauth_auth_pending_exp_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX "oauth_auth_pending_exp_idx" ON "auth"."oauth_authorizations" USING "btree" ("expires_at") WHERE ("status" = 'pending'::"auth"."oauth_authorization_status");


--
-- Name: oauth_clients_deleted_at_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX "oauth_clients_deleted_at_idx" ON "auth"."oauth_clients" USING "btree" ("deleted_at");


--
-- Name: oauth_consents_active_client_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX "oauth_consents_active_client_idx" ON "auth"."oauth_consents" USING "btree" ("client_id") WHERE ("revoked_at" IS NULL);


--
-- Name: oauth_consents_active_user_client_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX "oauth_consents_active_user_client_idx" ON "auth"."oauth_consents" USING "btree" ("user_id", "client_id") WHERE ("revoked_at" IS NULL);


--
-- Name: oauth_consents_user_order_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX "oauth_consents_user_order_idx" ON "auth"."oauth_consents" USING "btree" ("user_id", "granted_at" DESC);


--
-- Name: one_time_tokens_relates_to_hash_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX "one_time_tokens_relates_to_hash_idx" ON "auth"."one_time_tokens" USING "hash" ("relates_to");


--
-- Name: one_time_tokens_token_hash_hash_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX "one_time_tokens_token_hash_hash_idx" ON "auth"."one_time_tokens" USING "hash" ("token_hash");


--
-- Name: one_time_tokens_user_id_token_type_key; Type: INDEX; Schema: auth; Owner: -
--

CREATE UNIQUE INDEX "one_time_tokens_user_id_token_type_key" ON "auth"."one_time_tokens" USING "btree" ("user_id", "token_type");


--
-- Name: reauthentication_token_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE UNIQUE INDEX "reauthentication_token_idx" ON "auth"."users" USING "btree" ("reauthentication_token") WHERE (("reauthentication_token")::"text" !~ '^[0-9 ]*$'::"text");


--
-- Name: recovery_token_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE UNIQUE INDEX "recovery_token_idx" ON "auth"."users" USING "btree" ("recovery_token") WHERE (("recovery_token")::"text" !~ '^[0-9 ]*$'::"text");


--
-- Name: refresh_tokens_instance_id_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX "refresh_tokens_instance_id_idx" ON "auth"."refresh_tokens" USING "btree" ("instance_id");


--
-- Name: refresh_tokens_instance_id_user_id_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX "refresh_tokens_instance_id_user_id_idx" ON "auth"."refresh_tokens" USING "btree" ("instance_id", "user_id");


--
-- Name: refresh_tokens_parent_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX "refresh_tokens_parent_idx" ON "auth"."refresh_tokens" USING "btree" ("parent");


--
-- Name: refresh_tokens_session_id_revoked_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX "refresh_tokens_session_id_revoked_idx" ON "auth"."refresh_tokens" USING "btree" ("session_id", "revoked");


--
-- Name: refresh_tokens_updated_at_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX "refresh_tokens_updated_at_idx" ON "auth"."refresh_tokens" USING "btree" ("updated_at" DESC);


--
-- Name: saml_providers_sso_provider_id_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX "saml_providers_sso_provider_id_idx" ON "auth"."saml_providers" USING "btree" ("sso_provider_id");


--
-- Name: saml_relay_states_created_at_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX "saml_relay_states_created_at_idx" ON "auth"."saml_relay_states" USING "btree" ("created_at" DESC);


--
-- Name: saml_relay_states_for_email_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX "saml_relay_states_for_email_idx" ON "auth"."saml_relay_states" USING "btree" ("for_email");


--
-- Name: saml_relay_states_sso_provider_id_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX "saml_relay_states_sso_provider_id_idx" ON "auth"."saml_relay_states" USING "btree" ("sso_provider_id");


--
-- Name: sessions_not_after_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX "sessions_not_after_idx" ON "auth"."sessions" USING "btree" ("not_after" DESC);


--
-- Name: sessions_oauth_client_id_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX "sessions_oauth_client_id_idx" ON "auth"."sessions" USING "btree" ("oauth_client_id");


--
-- Name: sessions_user_id_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX "sessions_user_id_idx" ON "auth"."sessions" USING "btree" ("user_id");


--
-- Name: sso_domains_domain_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE UNIQUE INDEX "sso_domains_domain_idx" ON "auth"."sso_domains" USING "btree" ("lower"("domain"));


--
-- Name: sso_domains_sso_provider_id_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX "sso_domains_sso_provider_id_idx" ON "auth"."sso_domains" USING "btree" ("sso_provider_id");


--
-- Name: sso_providers_resource_id_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE UNIQUE INDEX "sso_providers_resource_id_idx" ON "auth"."sso_providers" USING "btree" ("lower"("resource_id"));


--
-- Name: sso_providers_resource_id_pattern_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX "sso_providers_resource_id_pattern_idx" ON "auth"."sso_providers" USING "btree" ("resource_id" "text_pattern_ops");


--
-- Name: unique_phone_factor_per_user; Type: INDEX; Schema: auth; Owner: -
--

CREATE UNIQUE INDEX "unique_phone_factor_per_user" ON "auth"."mfa_factors" USING "btree" ("user_id", "phone");


--
-- Name: user_id_created_at_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX "user_id_created_at_idx" ON "auth"."sessions" USING "btree" ("user_id", "created_at");


--
-- Name: users_email_partial_key; Type: INDEX; Schema: auth; Owner: -
--

CREATE UNIQUE INDEX "users_email_partial_key" ON "auth"."users" USING "btree" ("email") WHERE ("is_sso_user" = false);


--
-- Name: INDEX "users_email_partial_key"; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON INDEX "auth"."users_email_partial_key" IS 'Auth: A partial unique index that applies only when is_sso_user is false';


--
-- Name: users_instance_id_email_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX "users_instance_id_email_idx" ON "auth"."users" USING "btree" ("instance_id", "lower"(("email")::"text"));


--
-- Name: users_instance_id_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX "users_instance_id_idx" ON "auth"."users" USING "btree" ("instance_id");


--
-- Name: users_is_anonymous_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX "users_is_anonymous_idx" ON "auth"."users" USING "btree" ("is_anonymous");


--
-- Name: idx_account_lockouts_email_locked_until; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX "idx_account_lockouts_email_locked_until" ON "public"."account_lockouts" USING "btree" ("user_email", "locked_until");


--
-- Name: idx_admin_2fa_enforcement_deadline; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX "idx_admin_2fa_enforcement_deadline" ON "public"."admin_2fa_enforcement" USING "btree" ("enforcement_deadline", "is_2fa_enabled");


--
-- Name: idx_admin_2fa_enforcement_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX "idx_admin_2fa_enforcement_user_id" ON "public"."admin_2fa_enforcement" USING "btree" ("user_id");


--
-- Name: idx_audit_logs_table_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX "idx_audit_logs_table_name" ON "public"."audit_logs" USING "btree" ("table_name");


--
-- Name: idx_audit_logs_timestamp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX "idx_audit_logs_timestamp" ON "public"."audit_logs" USING "btree" ("timestamp");


--
-- Name: idx_audit_logs_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX "idx_audit_logs_user_id" ON "public"."audit_logs" USING "btree" ("user_id");


--
-- Name: idx_bookings_auto_checkin; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX "idx_bookings_auto_checkin" ON "public"."bookings" USING "btree" ("status", "check_in_date") WHERE ("status" = 'confirmed'::"public"."booking_status");


--
-- Name: idx_bookings_auto_checkout; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX "idx_bookings_auto_checkout" ON "public"."bookings" USING "btree" ("status", "check_out_date") WHERE ("status" = 'checked_in'::"public"."booking_status");


--
-- Name: idx_bookings_dates; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX "idx_bookings_dates" ON "public"."bookings" USING "btree" ("check_in_date", "check_out_date");


--
-- Name: idx_bookings_guest_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX "idx_bookings_guest_id" ON "public"."bookings" USING "btree" ("guest_id");


--
-- Name: idx_bookings_room_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX "idx_bookings_room_id" ON "public"."bookings" USING "btree" ("room_id");


--
-- Name: idx_cleaning_tasks_room_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX "idx_cleaning_tasks_room_id" ON "public"."cleaning_tasks" USING "btree" ("room_id");


--
-- Name: idx_cleaning_tasks_scheduled_date; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX "idx_cleaning_tasks_scheduled_date" ON "public"."cleaning_tasks" USING "btree" ("scheduled_date");


--
-- Name: idx_cleaning_tasks_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX "idx_cleaning_tasks_status" ON "public"."cleaning_tasks" USING "btree" ("status");


--
-- Name: idx_contract_templates_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX "idx_contract_templates_active" ON "public"."contract_templates" USING "btree" ("is_active");


--
-- Name: idx_contract_templates_created_by; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX "idx_contract_templates_created_by" ON "public"."contract_templates" USING "btree" ("created_by");


--
-- Name: idx_expenses_date; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX "idx_expenses_date" ON "public"."expenses" USING "btree" ("date");


--
-- Name: idx_expenses_owner_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX "idx_expenses_owner_id" ON "public"."expenses" USING "btree" ("owner_id");


--
-- Name: idx_expenses_property_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX "idx_expenses_property_id" ON "public"."expenses" USING "btree" ("property_id");


--
-- Name: idx_general_settings_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX "idx_general_settings_created_at" ON "public"."general_settings" USING "btree" ("created_at" DESC);


--
-- Name: idx_ip_access_rules_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX "idx_ip_access_rules_active" ON "public"."ip_access_rules" USING "btree" ("is_active") WHERE ("is_active" = true);


--
-- Name: idx_ip_access_rules_ip_address; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX "idx_ip_access_rules_ip_address" ON "public"."ip_access_rules" USING "btree" ("ip_address");


--
-- Name: idx_login_anomalies_severity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX "idx_login_anomalies_severity" ON "public"."login_anomalies" USING "btree" ("severity");


--
-- Name: idx_login_anomalies_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX "idx_login_anomalies_type" ON "public"."login_anomalies" USING "btree" ("anomaly_type");


--
-- Name: idx_login_anomalies_unresolved; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX "idx_login_anomalies_unresolved" ON "public"."login_anomalies" USING "btree" ("is_resolved", "created_at");


--
-- Name: idx_login_anomalies_user_email; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX "idx_login_anomalies_user_email" ON "public"."login_anomalies" USING "btree" ("user_email");


--
-- Name: idx_notification_settings_role_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX "idx_notification_settings_role_id" ON "public"."notification_settings" USING "btree" ("role_id");


--
-- Name: idx_notification_settings_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX "idx_notification_settings_user_id" ON "public"."notification_settings" USING "btree" ("user_id");


--
-- Name: idx_notifications_category; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX "idx_notifications_category" ON "public"."notifications" USING "btree" ("category");


--
-- Name: idx_notifications_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX "idx_notifications_created_at" ON "public"."notifications" USING "btree" ("created_at");


--
-- Name: idx_notifications_read; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX "idx_notifications_read" ON "public"."notifications" USING "btree" ("read");


--
-- Name: idx_notifications_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX "idx_notifications_user_id" ON "public"."notifications" USING "btree" ("user_id");


--
-- Name: idx_password_reset_tokens_email; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX "idx_password_reset_tokens_email" ON "public"."secure_password_reset_tokens" USING "btree" ("user_email");


--
-- Name: idx_password_reset_tokens_expires; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX "idx_password_reset_tokens_expires" ON "public"."secure_password_reset_tokens" USING "btree" ("expires_at", "is_used");


--
-- Name: idx_password_reset_tokens_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX "idx_password_reset_tokens_hash" ON "public"."secure_password_reset_tokens" USING "btree" ("token_hash");


--
-- Name: idx_pdf_field_mappings_template; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX "idx_pdf_field_mappings_template" ON "public"."pdf_field_mappings" USING "btree" ("template_id");


--
-- Name: idx_rooms_property_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX "idx_rooms_property_id" ON "public"."rooms" USING "btree" ("property_id");


--
-- Name: idx_rooms_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX "idx_rooms_status" ON "public"."rooms" USING "btree" ("status");


--
-- Name: idx_user_sessions_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX "idx_user_sessions_active" ON "public"."user_sessions" USING "btree" ("is_active", "expires_at");


--
-- Name: idx_user_sessions_token; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX "idx_user_sessions_token" ON "public"."user_sessions" USING "btree" ("session_token");


--
-- Name: idx_user_sessions_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX "idx_user_sessions_user_id" ON "public"."user_sessions" USING "btree" ("user_id");


--
-- Name: ix_realtime_subscription_entity; Type: INDEX; Schema: realtime; Owner: -
--

CREATE INDEX "ix_realtime_subscription_entity" ON "realtime"."subscription" USING "btree" ("entity");


--
-- Name: messages_inserted_at_topic_index; Type: INDEX; Schema: realtime; Owner: -
--

CREATE INDEX "messages_inserted_at_topic_index" ON ONLY "realtime"."messages" USING "btree" ("inserted_at" DESC, "topic") WHERE (("extension" = 'broadcast'::"text") AND ("private" IS TRUE));


--
-- Name: messages_2025_11_09_inserted_at_topic_idx; Type: INDEX; Schema: realtime; Owner: -
--

CREATE INDEX "messages_2025_11_09_inserted_at_topic_idx" ON "realtime"."messages_2025_11_09" USING "btree" ("inserted_at" DESC, "topic") WHERE (("extension" = 'broadcast'::"text") AND ("private" IS TRUE));


--
-- Name: messages_2025_11_10_inserted_at_topic_idx; Type: INDEX; Schema: realtime; Owner: -
--

CREATE INDEX "messages_2025_11_10_inserted_at_topic_idx" ON "realtime"."messages_2025_11_10" USING "btree" ("inserted_at" DESC, "topic") WHERE (("extension" = 'broadcast'::"text") AND ("private" IS TRUE));


--
-- Name: messages_2025_11_11_inserted_at_topic_idx; Type: INDEX; Schema: realtime; Owner: -
--

CREATE INDEX "messages_2025_11_11_inserted_at_topic_idx" ON "realtime"."messages_2025_11_11" USING "btree" ("inserted_at" DESC, "topic") WHERE (("extension" = 'broadcast'::"text") AND ("private" IS TRUE));


--
-- Name: messages_2025_11_12_inserted_at_topic_idx; Type: INDEX; Schema: realtime; Owner: -
--

CREATE INDEX "messages_2025_11_12_inserted_at_topic_idx" ON "realtime"."messages_2025_11_12" USING "btree" ("inserted_at" DESC, "topic") WHERE (("extension" = 'broadcast'::"text") AND ("private" IS TRUE));


--
-- Name: messages_2025_11_13_inserted_at_topic_idx; Type: INDEX; Schema: realtime; Owner: -
--

CREATE INDEX "messages_2025_11_13_inserted_at_topic_idx" ON "realtime"."messages_2025_11_13" USING "btree" ("inserted_at" DESC, "topic") WHERE (("extension" = 'broadcast'::"text") AND ("private" IS TRUE));


--
-- Name: messages_2025_11_14_inserted_at_topic_idx; Type: INDEX; Schema: realtime; Owner: -
--

CREATE INDEX "messages_2025_11_14_inserted_at_topic_idx" ON "realtime"."messages_2025_11_14" USING "btree" ("inserted_at" DESC, "topic") WHERE (("extension" = 'broadcast'::"text") AND ("private" IS TRUE));


--
-- Name: messages_2025_11_15_inserted_at_topic_idx; Type: INDEX; Schema: realtime; Owner: -
--

CREATE INDEX "messages_2025_11_15_inserted_at_topic_idx" ON "realtime"."messages_2025_11_15" USING "btree" ("inserted_at" DESC, "topic") WHERE (("extension" = 'broadcast'::"text") AND ("private" IS TRUE));


--
-- Name: subscription_subscription_id_entity_filters_key; Type: INDEX; Schema: realtime; Owner: -
--

CREATE UNIQUE INDEX "subscription_subscription_id_entity_filters_key" ON "realtime"."subscription" USING "btree" ("subscription_id", "entity", "filters");


--
-- Name: bname; Type: INDEX; Schema: storage; Owner: -
--

CREATE UNIQUE INDEX "bname" ON "storage"."buckets" USING "btree" ("name");


--
-- Name: bucketid_objname; Type: INDEX; Schema: storage; Owner: -
--

CREATE UNIQUE INDEX "bucketid_objname" ON "storage"."objects" USING "btree" ("bucket_id", "name");


--
-- Name: buckets_analytics_unique_name_idx; Type: INDEX; Schema: storage; Owner: -
--

CREATE UNIQUE INDEX "buckets_analytics_unique_name_idx" ON "storage"."buckets_analytics" USING "btree" ("name") WHERE ("deleted_at" IS NULL);


--
-- Name: idx_multipart_uploads_list; Type: INDEX; Schema: storage; Owner: -
--

CREATE INDEX "idx_multipart_uploads_list" ON "storage"."s3_multipart_uploads" USING "btree" ("bucket_id", "key", "created_at");


--
-- Name: idx_name_bucket_level_unique; Type: INDEX; Schema: storage; Owner: -
--

CREATE UNIQUE INDEX "idx_name_bucket_level_unique" ON "storage"."objects" USING "btree" ("name" COLLATE "C", "bucket_id", "level");


--
-- Name: idx_objects_bucket_id_name; Type: INDEX; Schema: storage; Owner: -
--

CREATE INDEX "idx_objects_bucket_id_name" ON "storage"."objects" USING "btree" ("bucket_id", "name" COLLATE "C");


--
-- Name: idx_objects_lower_name; Type: INDEX; Schema: storage; Owner: -
--

CREATE INDEX "idx_objects_lower_name" ON "storage"."objects" USING "btree" (("path_tokens"["level"]), "lower"("name") "text_pattern_ops", "bucket_id", "level");


--
-- Name: idx_prefixes_lower_name; Type: INDEX; Schema: storage; Owner: -
--

CREATE INDEX "idx_prefixes_lower_name" ON "storage"."prefixes" USING "btree" ("bucket_id", "level", (("string_to_array"("name", '/'::"text"))["level"]), "lower"("name") "text_pattern_ops");


--
-- Name: name_prefix_search; Type: INDEX; Schema: storage; Owner: -
--

CREATE INDEX "name_prefix_search" ON "storage"."objects" USING "btree" ("name" "text_pattern_ops");


--
-- Name: objects_bucket_id_level_idx; Type: INDEX; Schema: storage; Owner: -
--

CREATE UNIQUE INDEX "objects_bucket_id_level_idx" ON "storage"."objects" USING "btree" ("bucket_id", "level", "name" COLLATE "C");


--
-- Name: vector_indexes_name_bucket_id_idx; Type: INDEX; Schema: storage; Owner: -
--

CREATE UNIQUE INDEX "vector_indexes_name_bucket_id_idx" ON "storage"."vector_indexes" USING "btree" ("name", "bucket_id");


--
-- Name: messages_2025_11_09_inserted_at_topic_idx; Type: INDEX ATTACH; Schema: realtime; Owner: -
--

ALTER INDEX "realtime"."messages_inserted_at_topic_index" ATTACH PARTITION "realtime"."messages_2025_11_09_inserted_at_topic_idx";


--
-- Name: messages_2025_11_09_pkey; Type: INDEX ATTACH; Schema: realtime; Owner: -
--

ALTER INDEX "realtime"."messages_pkey" ATTACH PARTITION "realtime"."messages_2025_11_09_pkey";


--
-- Name: messages_2025_11_10_inserted_at_topic_idx; Type: INDEX ATTACH; Schema: realtime; Owner: -
--

ALTER INDEX "realtime"."messages_inserted_at_topic_index" ATTACH PARTITION "realtime"."messages_2025_11_10_inserted_at_topic_idx";


--
-- Name: messages_2025_11_10_pkey; Type: INDEX ATTACH; Schema: realtime; Owner: -
--

ALTER INDEX "realtime"."messages_pkey" ATTACH PARTITION "realtime"."messages_2025_11_10_pkey";


--
-- Name: messages_2025_11_11_inserted_at_topic_idx; Type: INDEX ATTACH; Schema: realtime; Owner: -
--

ALTER INDEX "realtime"."messages_inserted_at_topic_index" ATTACH PARTITION "realtime"."messages_2025_11_11_inserted_at_topic_idx";


--
-- Name: messages_2025_11_11_pkey; Type: INDEX ATTACH; Schema: realtime; Owner: -
--

ALTER INDEX "realtime"."messages_pkey" ATTACH PARTITION "realtime"."messages_2025_11_11_pkey";


--
-- Name: messages_2025_11_12_inserted_at_topic_idx; Type: INDEX ATTACH; Schema: realtime; Owner: -
--

ALTER INDEX "realtime"."messages_inserted_at_topic_index" ATTACH PARTITION "realtime"."messages_2025_11_12_inserted_at_topic_idx";


--
-- Name: messages_2025_11_12_pkey; Type: INDEX ATTACH; Schema: realtime; Owner: -
--

ALTER INDEX "realtime"."messages_pkey" ATTACH PARTITION "realtime"."messages_2025_11_12_pkey";


--
-- Name: messages_2025_11_13_inserted_at_topic_idx; Type: INDEX ATTACH; Schema: realtime; Owner: -
--

ALTER INDEX "realtime"."messages_inserted_at_topic_index" ATTACH PARTITION "realtime"."messages_2025_11_13_inserted_at_topic_idx";


--
-- Name: messages_2025_11_13_pkey; Type: INDEX ATTACH; Schema: realtime; Owner: -
--

ALTER INDEX "realtime"."messages_pkey" ATTACH PARTITION "realtime"."messages_2025_11_13_pkey";


--
-- Name: messages_2025_11_14_inserted_at_topic_idx; Type: INDEX ATTACH; Schema: realtime; Owner: -
--

ALTER INDEX "realtime"."messages_inserted_at_topic_index" ATTACH PARTITION "realtime"."messages_2025_11_14_inserted_at_topic_idx";


--
-- Name: messages_2025_11_14_pkey; Type: INDEX ATTACH; Schema: realtime; Owner: -
--

ALTER INDEX "realtime"."messages_pkey" ATTACH PARTITION "realtime"."messages_2025_11_14_pkey";


--
-- Name: messages_2025_11_15_inserted_at_topic_idx; Type: INDEX ATTACH; Schema: realtime; Owner: -
--

ALTER INDEX "realtime"."messages_inserted_at_topic_index" ATTACH PARTITION "realtime"."messages_2025_11_15_inserted_at_topic_idx";


--
-- Name: messages_2025_11_15_pkey; Type: INDEX ATTACH; Schema: realtime; Owner: -
--

ALTER INDEX "realtime"."messages_pkey" ATTACH PARTITION "realtime"."messages_2025_11_15_pkey";


--
-- Name: users on_auth_user_created; Type: TRIGGER; Schema: auth; Owner: -
--

CREATE TRIGGER "on_auth_user_created" AFTER INSERT ON "auth"."users" FOR EACH ROW EXECUTE FUNCTION "public"."handle_new_user"();


--
-- Name: bookings audit_bookings_trigger; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER "audit_bookings_trigger" AFTER INSERT OR DELETE OR UPDATE ON "public"."bookings" FOR EACH ROW EXECUTE FUNCTION "public"."audit_trigger"();


--
-- Name: cleaning_tasks audit_cleaning_tasks_trigger; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER "audit_cleaning_tasks_trigger" AFTER INSERT OR DELETE OR UPDATE ON "public"."cleaning_tasks" FOR EACH ROW EXECUTE FUNCTION "public"."audit_trigger"();


--
-- Name: expenses audit_expenses_trigger; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER "audit_expenses_trigger" AFTER INSERT OR DELETE OR UPDATE ON "public"."expenses" FOR EACH ROW EXECUTE FUNCTION "public"."audit_trigger"();


--
-- Name: guests audit_guests_trigger; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER "audit_guests_trigger" AFTER INSERT OR DELETE OR UPDATE ON "public"."guests" FOR EACH ROW EXECUTE FUNCTION "public"."audit_trigger"();


--
-- Name: owners audit_owners_trigger; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER "audit_owners_trigger" AFTER INSERT OR DELETE OR UPDATE ON "public"."owners" FOR EACH ROW EXECUTE FUNCTION "public"."audit_trigger"();


--
-- Name: properties audit_properties_trigger; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER "audit_properties_trigger" AFTER INSERT OR DELETE OR UPDATE ON "public"."properties" FOR EACH ROW EXECUTE FUNCTION "public"."audit_trigger"();


--
-- Name: property_ownership audit_property_ownership_trigger; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER "audit_property_ownership_trigger" AFTER INSERT OR DELETE OR UPDATE ON "public"."property_ownership" FOR EACH ROW EXECUTE FUNCTION "public"."audit_trigger"();


--
-- Name: room_ownership audit_room_ownership_trigger; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER "audit_room_ownership_trigger" AFTER INSERT OR DELETE OR UPDATE ON "public"."room_ownership" FOR EACH ROW EXECUTE FUNCTION "public"."audit_trigger"();


--
-- Name: room_types audit_room_types_trigger; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER "audit_room_types_trigger" AFTER INSERT OR DELETE OR UPDATE ON "public"."room_types" FOR EACH ROW EXECUTE FUNCTION "public"."audit_trigger"();


--
-- Name: rooms audit_rooms_trigger; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER "audit_rooms_trigger" AFTER INSERT OR DELETE OR UPDATE ON "public"."rooms" FOR EACH ROW EXECUTE FUNCTION "public"."audit_trigger"();


--
-- Name: user_role_assignments audit_user_role_assignments_trigger; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER "audit_user_role_assignments_trigger" AFTER INSERT OR DELETE OR UPDATE ON "public"."user_role_assignments" FOR EACH ROW EXECUTE FUNCTION "public"."log_audit_action"();


--
-- Name: user_roles audit_user_roles_trigger; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER "audit_user_roles_trigger" AFTER INSERT OR DELETE OR UPDATE ON "public"."user_roles" FOR EACH ROW EXECUTE FUNCTION "public"."log_audit_action"();


--
-- Name: bookings delete_booking_documents_trigger; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER "delete_booking_documents_trigger" BEFORE DELETE ON "public"."bookings" FOR EACH ROW EXECUTE FUNCTION "public"."delete_booking_documents"();


--
-- Name: expenses delete_expense_documents_trigger; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER "delete_expense_documents_trigger" BEFORE DELETE ON "public"."expenses" FOR EACH ROW EXECUTE FUNCTION "public"."delete_expense_documents"();


--
-- Name: audit_logs encrypt_audit_data_trigger; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER "encrypt_audit_data_trigger" BEFORE INSERT OR UPDATE ON "public"."audit_logs" FOR EACH ROW EXECUTE FUNCTION "public"."encrypt_audit_data"();


--
-- Name: user_role_assignments trigger_admin_2fa_enforcement_on_role_assignment; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER "trigger_admin_2fa_enforcement_on_role_assignment" AFTER INSERT ON "public"."user_role_assignments" FOR EACH ROW EXECUTE FUNCTION "public"."trigger_admin_2fa_enforcement"();


--
-- Name: booking_agents update_booking_agents_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER "update_booking_agents_updated_at" BEFORE UPDATE ON "public"."booking_agents" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at_column"();


--
-- Name: booking_sources update_booking_sources_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER "update_booking_sources_updated_at" BEFORE UPDATE ON "public"."booking_sources" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at_column"();


--
-- Name: bookings update_bookings_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER "update_bookings_updated_at" BEFORE UPDATE ON "public"."bookings" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at_column"();


--
-- Name: cleaning_tasks update_cleaning_tasks_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER "update_cleaning_tasks_updated_at" BEFORE UPDATE ON "public"."cleaning_tasks" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at_column"();


--
-- Name: contract_templates update_contract_templates_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER "update_contract_templates_updated_at" BEFORE UPDATE ON "public"."contract_templates" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at_column"();


--
-- Name: expense_categories update_expense_categories_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER "update_expense_categories_updated_at" BEFORE UPDATE ON "public"."expense_categories" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at_column"();


--
-- Name: expenses update_expenses_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER "update_expenses_updated_at" BEFORE UPDATE ON "public"."expenses" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at_column"();


--
-- Name: general_settings update_general_settings_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER "update_general_settings_updated_at" BEFORE UPDATE ON "public"."general_settings" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at_column"();


--
-- Name: guests update_guests_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER "update_guests_updated_at" BEFORE UPDATE ON "public"."guests" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at_column"();


--
-- Name: notification_settings update_notification_settings_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER "update_notification_settings_updated_at" BEFORE UPDATE ON "public"."notification_settings" FOR EACH ROW EXECUTE FUNCTION "public"."update_notification_timestamps"();


--
-- Name: notifications update_notifications_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER "update_notifications_updated_at" BEFORE UPDATE ON "public"."notifications" FOR EACH ROW EXECUTE FUNCTION "public"."update_notification_timestamps"();


--
-- Name: owners update_owners_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER "update_owners_updated_at" BEFORE UPDATE ON "public"."owners" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at_column"();


--
-- Name: payment_methods update_payment_methods_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER "update_payment_methods_updated_at" BEFORE UPDATE ON "public"."payment_methods" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at_column"();


--
-- Name: pdf_field_mappings update_pdf_field_mappings_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER "update_pdf_field_mappings_updated_at" BEFORE UPDATE ON "public"."pdf_field_mappings" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at_column"();


--
-- Name: profiles update_profiles_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER "update_profiles_updated_at" BEFORE UPDATE ON "public"."profiles" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at_column"();


--
-- Name: properties update_properties_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER "update_properties_updated_at" BEFORE UPDATE ON "public"."properties" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at_column"();


--
-- Name: property_ownership update_property_ownership_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER "update_property_ownership_updated_at" BEFORE UPDATE ON "public"."property_ownership" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at_column"();


--
-- Name: room_ownership update_room_ownership_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER "update_room_ownership_updated_at" BEFORE UPDATE ON "public"."room_ownership" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at_column"();


--
-- Name: room_types update_room_types_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER "update_room_types_updated_at" BEFORE UPDATE ON "public"."room_types" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at_column"();


--
-- Name: rooms update_rooms_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER "update_rooms_updated_at" BEFORE UPDATE ON "public"."rooms" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at_column"();


--
-- Name: user_roles update_user_roles_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER "update_user_roles_updated_at" BEFORE UPDATE ON "public"."user_roles" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at_column"();


--
-- Name: subscription tr_check_filters; Type: TRIGGER; Schema: realtime; Owner: -
--

CREATE TRIGGER "tr_check_filters" BEFORE INSERT OR UPDATE ON "realtime"."subscription" FOR EACH ROW EXECUTE FUNCTION "realtime"."subscription_check_filters"();


--
-- Name: buckets enforce_bucket_name_length_trigger; Type: TRIGGER; Schema: storage; Owner: -
--

CREATE TRIGGER "enforce_bucket_name_length_trigger" BEFORE INSERT OR UPDATE OF "name" ON "storage"."buckets" FOR EACH ROW EXECUTE FUNCTION "storage"."enforce_bucket_name_length"();


--
-- Name: objects objects_delete_delete_prefix; Type: TRIGGER; Schema: storage; Owner: -
--

CREATE TRIGGER "objects_delete_delete_prefix" AFTER DELETE ON "storage"."objects" FOR EACH ROW EXECUTE FUNCTION "storage"."delete_prefix_hierarchy_trigger"();


--
-- Name: objects objects_insert_create_prefix; Type: TRIGGER; Schema: storage; Owner: -
--

CREATE TRIGGER "objects_insert_create_prefix" BEFORE INSERT ON "storage"."objects" FOR EACH ROW EXECUTE FUNCTION "storage"."objects_insert_prefix_trigger"();


--
-- Name: objects objects_update_create_prefix; Type: TRIGGER; Schema: storage; Owner: -
--

CREATE TRIGGER "objects_update_create_prefix" BEFORE UPDATE ON "storage"."objects" FOR EACH ROW WHEN ((("new"."name" <> "old"."name") OR ("new"."bucket_id" <> "old"."bucket_id"))) EXECUTE FUNCTION "storage"."objects_update_prefix_trigger"();


--
-- Name: prefixes prefixes_create_hierarchy; Type: TRIGGER; Schema: storage; Owner: -
--

CREATE TRIGGER "prefixes_create_hierarchy" BEFORE INSERT ON "storage"."prefixes" FOR EACH ROW WHEN (("pg_trigger_depth"() < 1)) EXECUTE FUNCTION "storage"."prefixes_insert_trigger"();


--
-- Name: prefixes prefixes_delete_hierarchy; Type: TRIGGER; Schema: storage; Owner: -
--

CREATE TRIGGER "prefixes_delete_hierarchy" AFTER DELETE ON "storage"."prefixes" FOR EACH ROW EXECUTE FUNCTION "storage"."delete_prefix_hierarchy_trigger"();


--
-- Name: objects update_objects_updated_at; Type: TRIGGER; Schema: storage; Owner: -
--

CREATE TRIGGER "update_objects_updated_at" BEFORE UPDATE ON "storage"."objects" FOR EACH ROW EXECUTE FUNCTION "storage"."update_updated_at_column"();


--
-- Name: identities identities_user_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY "auth"."identities"
    ADD CONSTRAINT "identities_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id") ON DELETE CASCADE;


--
-- Name: mfa_amr_claims mfa_amr_claims_session_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY "auth"."mfa_amr_claims"
    ADD CONSTRAINT "mfa_amr_claims_session_id_fkey" FOREIGN KEY ("session_id") REFERENCES "auth"."sessions"("id") ON DELETE CASCADE;


--
-- Name: mfa_challenges mfa_challenges_auth_factor_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY "auth"."mfa_challenges"
    ADD CONSTRAINT "mfa_challenges_auth_factor_id_fkey" FOREIGN KEY ("factor_id") REFERENCES "auth"."mfa_factors"("id") ON DELETE CASCADE;


--
-- Name: mfa_factors mfa_factors_user_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY "auth"."mfa_factors"
    ADD CONSTRAINT "mfa_factors_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id") ON DELETE CASCADE;


--
-- Name: oauth_authorizations oauth_authorizations_client_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY "auth"."oauth_authorizations"
    ADD CONSTRAINT "oauth_authorizations_client_id_fkey" FOREIGN KEY ("client_id") REFERENCES "auth"."oauth_clients"("id") ON DELETE CASCADE;


--
-- Name: oauth_authorizations oauth_authorizations_user_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY "auth"."oauth_authorizations"
    ADD CONSTRAINT "oauth_authorizations_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id") ON DELETE CASCADE;


--
-- Name: oauth_consents oauth_consents_client_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY "auth"."oauth_consents"
    ADD CONSTRAINT "oauth_consents_client_id_fkey" FOREIGN KEY ("client_id") REFERENCES "auth"."oauth_clients"("id") ON DELETE CASCADE;


--
-- Name: oauth_consents oauth_consents_user_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY "auth"."oauth_consents"
    ADD CONSTRAINT "oauth_consents_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id") ON DELETE CASCADE;


--
-- Name: one_time_tokens one_time_tokens_user_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY "auth"."one_time_tokens"
    ADD CONSTRAINT "one_time_tokens_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id") ON DELETE CASCADE;


--
-- Name: refresh_tokens refresh_tokens_session_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY "auth"."refresh_tokens"
    ADD CONSTRAINT "refresh_tokens_session_id_fkey" FOREIGN KEY ("session_id") REFERENCES "auth"."sessions"("id") ON DELETE CASCADE;


--
-- Name: saml_providers saml_providers_sso_provider_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY "auth"."saml_providers"
    ADD CONSTRAINT "saml_providers_sso_provider_id_fkey" FOREIGN KEY ("sso_provider_id") REFERENCES "auth"."sso_providers"("id") ON DELETE CASCADE;


--
-- Name: saml_relay_states saml_relay_states_flow_state_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY "auth"."saml_relay_states"
    ADD CONSTRAINT "saml_relay_states_flow_state_id_fkey" FOREIGN KEY ("flow_state_id") REFERENCES "auth"."flow_state"("id") ON DELETE CASCADE;


--
-- Name: saml_relay_states saml_relay_states_sso_provider_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY "auth"."saml_relay_states"
    ADD CONSTRAINT "saml_relay_states_sso_provider_id_fkey" FOREIGN KEY ("sso_provider_id") REFERENCES "auth"."sso_providers"("id") ON DELETE CASCADE;


--
-- Name: sessions sessions_oauth_client_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY "auth"."sessions"
    ADD CONSTRAINT "sessions_oauth_client_id_fkey" FOREIGN KEY ("oauth_client_id") REFERENCES "auth"."oauth_clients"("id") ON DELETE CASCADE;


--
-- Name: sessions sessions_user_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY "auth"."sessions"
    ADD CONSTRAINT "sessions_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id") ON DELETE CASCADE;


--
-- Name: sso_domains sso_domains_sso_provider_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY "auth"."sso_domains"
    ADD CONSTRAINT "sso_domains_sso_provider_id_fkey" FOREIGN KEY ("sso_provider_id") REFERENCES "auth"."sso_providers"("id") ON DELETE CASCADE;


--
-- Name: audit_access_log audit_access_log_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."audit_access_log"
    ADD CONSTRAINT "audit_access_log_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id");


--
-- Name: bookings bookings_guest_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."bookings"
    ADD CONSTRAINT "bookings_guest_id_fkey" FOREIGN KEY ("guest_id") REFERENCES "public"."guests"("id") ON DELETE CASCADE;


--
-- Name: bookings bookings_room_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."bookings"
    ADD CONSTRAINT "bookings_room_id_fkey" FOREIGN KEY ("room_id") REFERENCES "public"."rooms"("id") ON DELETE CASCADE;


--
-- Name: cleaning_tasks cleaning_tasks_room_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."cleaning_tasks"
    ADD CONSTRAINT "cleaning_tasks_room_id_fkey" FOREIGN KEY ("room_id") REFERENCES "public"."rooms"("id") ON DELETE CASCADE;


--
-- Name: contract_templates contract_templates_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."contract_templates"
    ADD CONSTRAINT "contract_templates_created_by_fkey" FOREIGN KEY ("created_by") REFERENCES "auth"."users"("id") ON DELETE SET NULL;


--
-- Name: expenses expenses_category_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."expenses"
    ADD CONSTRAINT "expenses_category_id_fkey" FOREIGN KEY ("category_id") REFERENCES "public"."expense_categories"("id");


--
-- Name: expenses expenses_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."expenses"
    ADD CONSTRAINT "expenses_created_by_fkey" FOREIGN KEY ("created_by") REFERENCES "public"."profiles"("id");


--
-- Name: expenses expenses_owner_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."expenses"
    ADD CONSTRAINT "expenses_owner_id_fkey" FOREIGN KEY ("owner_id") REFERENCES "public"."owners"("id");


--
-- Name: expenses expenses_payment_method_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."expenses"
    ADD CONSTRAINT "expenses_payment_method_id_fkey" FOREIGN KEY ("payment_method_id") REFERENCES "public"."payment_methods"("id");


--
-- Name: expenses expenses_property_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."expenses"
    ADD CONSTRAINT "expenses_property_id_fkey" FOREIGN KEY ("property_id") REFERENCES "public"."properties"("id");


--
-- Name: expenses expenses_updated_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."expenses"
    ADD CONSTRAINT "expenses_updated_by_fkey" FOREIGN KEY ("updated_by") REFERENCES "public"."profiles"("id");


--
-- Name: room_ownership fk_room_ownership_owner; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."room_ownership"
    ADD CONSTRAINT "fk_room_ownership_owner" FOREIGN KEY ("owner_id") REFERENCES "public"."owners"("id");


--
-- Name: room_ownership fk_room_ownership_room; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."room_ownership"
    ADD CONSTRAINT "fk_room_ownership_room" FOREIGN KEY ("room_id") REFERENCES "public"."rooms"("id");


--
-- Name: user_role_assignments fk_user_role_assignments_role_id; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."user_role_assignments"
    ADD CONSTRAINT "fk_user_role_assignments_role_id" FOREIGN KEY ("role_id") REFERENCES "public"."user_roles"("id");


--
-- Name: ip_access_rules ip_access_rules_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."ip_access_rules"
    ADD CONSTRAINT "ip_access_rules_created_by_fkey" FOREIGN KEY ("created_by") REFERENCES "auth"."users"("id");


--
-- Name: notification_settings notification_settings_role_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."notification_settings"
    ADD CONSTRAINT "notification_settings_role_id_fkey" FOREIGN KEY ("role_id") REFERENCES "public"."user_roles"("id") ON DELETE CASCADE;


--
-- Name: notification_settings notification_settings_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."notification_settings"
    ADD CONSTRAINT "notification_settings_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id") ON DELETE CASCADE;


--
-- Name: notifications notifications_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."notifications"
    ADD CONSTRAINT "notifications_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id") ON DELETE CASCADE;


--
-- Name: pdf_field_mappings pdf_field_mappings_template_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."pdf_field_mappings"
    ADD CONSTRAINT "pdf_field_mappings_template_id_fkey" FOREIGN KEY ("template_id") REFERENCES "public"."contract_templates"("id") ON DELETE CASCADE;


--
-- Name: property_ownership property_ownership_owner_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."property_ownership"
    ADD CONSTRAINT "property_ownership_owner_id_fkey" FOREIGN KEY ("owner_id") REFERENCES "public"."owners"("id") ON DELETE CASCADE;


--
-- Name: property_ownership property_ownership_property_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."property_ownership"
    ADD CONSTRAINT "property_ownership_property_id_fkey" FOREIGN KEY ("property_id") REFERENCES "public"."properties"("id") ON DELETE CASCADE;


--
-- Name: room_ownership room_ownership_owner_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."room_ownership"
    ADD CONSTRAINT "room_ownership_owner_id_fkey" FOREIGN KEY ("owner_id") REFERENCES "public"."owners"("id") ON DELETE CASCADE;


--
-- Name: room_ownership room_ownership_room_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."room_ownership"
    ADD CONSTRAINT "room_ownership_room_id_fkey" FOREIGN KEY ("room_id") REFERENCES "public"."rooms"("id") ON DELETE CASCADE;


--
-- Name: rooms rooms_property_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."rooms"
    ADD CONSTRAINT "rooms_property_id_fkey" FOREIGN KEY ("property_id") REFERENCES "public"."properties"("id") ON DELETE CASCADE;


--
-- Name: rooms rooms_room_type_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."rooms"
    ADD CONSTRAINT "rooms_room_type_id_fkey" FOREIGN KEY ("room_type_id") REFERENCES "public"."room_types"("id") ON DELETE SET NULL;


--
-- Name: user_role_assignments user_role_assignments_role_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."user_role_assignments"
    ADD CONSTRAINT "user_role_assignments_role_id_fkey" FOREIGN KEY ("role_id") REFERENCES "public"."user_roles"("id") ON DELETE CASCADE;


--
-- Name: objects objects_bucketId_fkey; Type: FK CONSTRAINT; Schema: storage; Owner: -
--

ALTER TABLE ONLY "storage"."objects"
    ADD CONSTRAINT "objects_bucketId_fkey" FOREIGN KEY ("bucket_id") REFERENCES "storage"."buckets"("id");


--
-- Name: prefixes prefixes_bucketId_fkey; Type: FK CONSTRAINT; Schema: storage; Owner: -
--

ALTER TABLE ONLY "storage"."prefixes"
    ADD CONSTRAINT "prefixes_bucketId_fkey" FOREIGN KEY ("bucket_id") REFERENCES "storage"."buckets"("id");


--
-- Name: s3_multipart_uploads s3_multipart_uploads_bucket_id_fkey; Type: FK CONSTRAINT; Schema: storage; Owner: -
--

ALTER TABLE ONLY "storage"."s3_multipart_uploads"
    ADD CONSTRAINT "s3_multipart_uploads_bucket_id_fkey" FOREIGN KEY ("bucket_id") REFERENCES "storage"."buckets"("id");


--
-- Name: s3_multipart_uploads_parts s3_multipart_uploads_parts_bucket_id_fkey; Type: FK CONSTRAINT; Schema: storage; Owner: -
--

ALTER TABLE ONLY "storage"."s3_multipart_uploads_parts"
    ADD CONSTRAINT "s3_multipart_uploads_parts_bucket_id_fkey" FOREIGN KEY ("bucket_id") REFERENCES "storage"."buckets"("id");


--
-- Name: s3_multipart_uploads_parts s3_multipart_uploads_parts_upload_id_fkey; Type: FK CONSTRAINT; Schema: storage; Owner: -
--

ALTER TABLE ONLY "storage"."s3_multipart_uploads_parts"
    ADD CONSTRAINT "s3_multipart_uploads_parts_upload_id_fkey" FOREIGN KEY ("upload_id") REFERENCES "storage"."s3_multipart_uploads"("id") ON DELETE CASCADE;


--
-- Name: vector_indexes vector_indexes_bucket_id_fkey; Type: FK CONSTRAINT; Schema: storage; Owner: -
--

ALTER TABLE ONLY "storage"."vector_indexes"
    ADD CONSTRAINT "vector_indexes_bucket_id_fkey" FOREIGN KEY ("bucket_id") REFERENCES "storage"."buckets_vectors"("id");


--
-- Name: audit_log_entries; Type: ROW SECURITY; Schema: auth; Owner: -
--

ALTER TABLE "auth"."audit_log_entries" ENABLE ROW LEVEL SECURITY;

--
-- Name: flow_state; Type: ROW SECURITY; Schema: auth; Owner: -
--

ALTER TABLE "auth"."flow_state" ENABLE ROW LEVEL SECURITY;

--
-- Name: identities; Type: ROW SECURITY; Schema: auth; Owner: -
--

ALTER TABLE "auth"."identities" ENABLE ROW LEVEL SECURITY;

--
-- Name: instances; Type: ROW SECURITY; Schema: auth; Owner: -
--

ALTER TABLE "auth"."instances" ENABLE ROW LEVEL SECURITY;

--
-- Name: mfa_amr_claims; Type: ROW SECURITY; Schema: auth; Owner: -
--

ALTER TABLE "auth"."mfa_amr_claims" ENABLE ROW LEVEL SECURITY;

--
-- Name: mfa_challenges; Type: ROW SECURITY; Schema: auth; Owner: -
--

ALTER TABLE "auth"."mfa_challenges" ENABLE ROW LEVEL SECURITY;

--
-- Name: mfa_factors; Type: ROW SECURITY; Schema: auth; Owner: -
--

ALTER TABLE "auth"."mfa_factors" ENABLE ROW LEVEL SECURITY;

--
-- Name: one_time_tokens; Type: ROW SECURITY; Schema: auth; Owner: -
--

ALTER TABLE "auth"."one_time_tokens" ENABLE ROW LEVEL SECURITY;

--
-- Name: refresh_tokens; Type: ROW SECURITY; Schema: auth; Owner: -
--

ALTER TABLE "auth"."refresh_tokens" ENABLE ROW LEVEL SECURITY;

--
-- Name: saml_providers; Type: ROW SECURITY; Schema: auth; Owner: -
--

ALTER TABLE "auth"."saml_providers" ENABLE ROW LEVEL SECURITY;

--
-- Name: saml_relay_states; Type: ROW SECURITY; Schema: auth; Owner: -
--

ALTER TABLE "auth"."saml_relay_states" ENABLE ROW LEVEL SECURITY;

--
-- Name: schema_migrations; Type: ROW SECURITY; Schema: auth; Owner: -
--

ALTER TABLE "auth"."schema_migrations" ENABLE ROW LEVEL SECURITY;

--
-- Name: sessions; Type: ROW SECURITY; Schema: auth; Owner: -
--

ALTER TABLE "auth"."sessions" ENABLE ROW LEVEL SECURITY;

--
-- Name: sso_domains; Type: ROW SECURITY; Schema: auth; Owner: -
--

ALTER TABLE "auth"."sso_domains" ENABLE ROW LEVEL SECURITY;

--
-- Name: sso_providers; Type: ROW SECURITY; Schema: auth; Owner: -
--

ALTER TABLE "auth"."sso_providers" ENABLE ROW LEVEL SECURITY;

--
-- Name: users; Type: ROW SECURITY; Schema: auth; Owner: -
--

ALTER TABLE "auth"."users" ENABLE ROW LEVEL SECURITY;

--
-- Name: contract_templates Admins can delete contract templates; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Admins can delete contract templates" ON "public"."contract_templates" FOR DELETE TO "authenticated" USING ((EXISTS ( SELECT 1
   FROM ("public"."user_role_assignments" "ura"
     JOIN "public"."user_roles" "ur" ON (("ura"."role_id" = "ur"."id")))
  WHERE (("ura"."user_id" = "auth"."uid"()) AND ("ur"."name" = ANY (ARRAY['admin'::"text", 'manager'::"text"]))))));


--
-- Name: pdf_field_mappings Admins can delete pdf field mappings; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Admins can delete pdf field mappings" ON "public"."pdf_field_mappings" FOR DELETE TO "authenticated" USING ((EXISTS ( SELECT 1
   FROM ("public"."user_role_assignments" "ura"
     JOIN "public"."user_roles" "ur" ON (("ura"."role_id" = "ur"."id")))
  WHERE (("ura"."user_id" = "auth"."uid"()) AND ("ur"."name" = ANY (ARRAY['admin'::"text", 'manager'::"text"]))))));


--
-- Name: contract_templates Admins can insert contract templates; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Admins can insert contract templates" ON "public"."contract_templates" FOR INSERT TO "authenticated" WITH CHECK ((EXISTS ( SELECT 1
   FROM ("public"."user_role_assignments" "ura"
     JOIN "public"."user_roles" "ur" ON (("ura"."role_id" = "ur"."id")))
  WHERE (("ura"."user_id" = "auth"."uid"()) AND ("ur"."name" = ANY (ARRAY['admin'::"text", 'manager'::"text"]))))));


--
-- Name: pdf_field_mappings Admins can insert pdf field mappings; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Admins can insert pdf field mappings" ON "public"."pdf_field_mappings" FOR INSERT TO "authenticated" WITH CHECK ((EXISTS ( SELECT 1
   FROM ("public"."user_role_assignments" "ura"
     JOIN "public"."user_roles" "ur" ON (("ura"."role_id" = "ur"."id")))
  WHERE (("ura"."user_id" = "auth"."uid"()) AND ("ur"."name" = ANY (ARRAY['admin'::"text", 'manager'::"text"]))))));


--
-- Name: ip_access_rules Admins can manage IP access rules; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Admins can manage IP access rules" ON "public"."ip_access_rules" USING ("public"."has_permission"("auth"."uid"(), 'view_audit_logs'::"text"));


--
-- Name: guest_data_classification Admins can manage data classification; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Admins can manage data classification" ON "public"."guest_data_classification" USING ("public"."has_permission"("auth"."uid"(), 'view_audit_logs'::"text"));


--
-- Name: notification_settings Admins can manage notification settings; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Admins can manage notification settings" ON "public"."notification_settings" USING ("public"."has_permission"("auth"."uid"(), 'manage_users'::"text"));


--
-- Name: user_role_assignments Admins can manage role assignments; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Admins can manage role assignments" ON "public"."user_role_assignments" USING ("public"."has_permission"("auth"."uid"(), 'manage_users'::"text"));


--
-- Name: user_roles Admins can manage user roles; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Admins can manage user roles" ON "public"."user_roles" USING ("public"."has_permission"("auth"."uid"(), 'manage_users'::"text"));


--
-- Name: login_anomalies Admins can resolve anomalies; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Admins can resolve anomalies" ON "public"."login_anomalies" FOR UPDATE USING ("public"."has_permission"("auth"."uid"(), 'view_audit_logs'::"text"));


--
-- Name: contract_templates Admins can update contract templates; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Admins can update contract templates" ON "public"."contract_templates" FOR UPDATE TO "authenticated" USING ((EXISTS ( SELECT 1
   FROM ("public"."user_role_assignments" "ura"
     JOIN "public"."user_roles" "ur" ON (("ura"."role_id" = "ur"."id")))
  WHERE (("ura"."user_id" = "auth"."uid"()) AND ("ur"."name" = ANY (ARRAY['admin'::"text", 'manager'::"text"])))))) WITH CHECK ((EXISTS ( SELECT 1
   FROM ("public"."user_role_assignments" "ura"
     JOIN "public"."user_roles" "ur" ON (("ura"."role_id" = "ur"."id")))
  WHERE (("ura"."user_id" = "auth"."uid"()) AND ("ur"."name" = ANY (ARRAY['admin'::"text", 'manager'::"text"]))))));


--
-- Name: pdf_field_mappings Admins can update pdf field mappings; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Admins can update pdf field mappings" ON "public"."pdf_field_mappings" FOR UPDATE TO "authenticated" USING ((EXISTS ( SELECT 1
   FROM ("public"."user_role_assignments" "ura"
     JOIN "public"."user_roles" "ur" ON (("ura"."role_id" = "ur"."id")))
  WHERE (("ura"."user_id" = "auth"."uid"()) AND ("ur"."name" = ANY (ARRAY['admin'::"text", 'manager'::"text"])))))) WITH CHECK ((EXISTS ( SELECT 1
   FROM ("public"."user_role_assignments" "ura"
     JOIN "public"."user_roles" "ur" ON (("ura"."role_id" = "ur"."id")))
  WHERE (("ura"."user_id" = "auth"."uid"()) AND ("ur"."name" = ANY (ARRAY['admin'::"text", 'manager'::"text"]))))));


--
-- Name: admin_2fa_enforcement Admins can view 2FA enforcement; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Admins can view 2FA enforcement" ON "public"."admin_2fa_enforcement" FOR SELECT USING ("public"."has_permission"("auth"."uid"(), 'manage_users'::"text"));


--
-- Name: user_2fa_tokens Admins can view 2FA tokens for security; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Admins can view 2FA tokens for security" ON "public"."user_2fa_tokens" FOR SELECT TO "authenticated" USING ("public"."has_permission"("auth"."uid"(), 'manage_users'::"text"));


--
-- Name: login_anomalies Admins can view all anomalies; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Admins can view all anomalies" ON "public"."login_anomalies" FOR SELECT USING ("public"."has_permission"("auth"."uid"(), 'view_audit_logs'::"text"));


--
-- Name: audit_access_log Admins can view audit access logs; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Admins can view audit access logs" ON "public"."audit_access_log" FOR SELECT USING ("public"."has_permission"("auth"."uid"(), 'view_audit_logs'::"text"));


--
-- Name: audit_logs Admins with audit permission can view logs; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Admins with audit permission can view logs" ON "public"."audit_logs" FOR SELECT USING (("public"."has_permission"("auth"."uid"(), 'view_audit_logs'::"text") AND (EXISTS ( SELECT 1
   FROM ("public"."user_roles" "ur"
     JOIN "public"."user_role_assignments" "ura" ON (("ur"."id" = "ura"."role_id")))
  WHERE (("ura"."user_id" = "auth"."uid"()) AND ("ur"."name" = 'admin'::"text"))))));


--
-- Name: contract_templates Anyone can view contract templates; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Anyone can view contract templates" ON "public"."contract_templates" FOR SELECT TO "authenticated" USING (true);


--
-- Name: pdf_field_mappings Anyone can view pdf field mappings; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Anyone can view pdf field mappings" ON "public"."pdf_field_mappings" FOR SELECT TO "authenticated" USING (true);


--
-- Name: security_events Authorized admins can view security events; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Authorized admins can view security events" ON "public"."security_events" FOR SELECT USING ("public"."has_permission"("auth"."uid"(), 'view_security_events'::"text"));


--
-- Name: security_events Disable delete on security_events; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Disable delete on security_events" ON "public"."security_events" FOR DELETE USING (false);


--
-- Name: security_events Disable direct insert into security_events; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Disable direct insert into security_events" ON "public"."security_events" FOR INSERT TO "authenticated" WITH CHECK (false);


--
-- Name: security_events Disable update on security_events; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Disable update on security_events" ON "public"."security_events" FOR UPDATE USING (false) WITH CHECK (false);


--
-- Name: security_incidents Only security admins can manage incidents; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Only security admins can manage incidents" ON "public"."security_incidents" TO "authenticated" USING ("public"."has_permission"("auth"."uid"(), 'view_audit_logs'::"text"));


--
-- Name: audit_logs Only system functions can create audit logs; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Only system functions can create audit logs" ON "public"."audit_logs" FOR INSERT WITH CHECK ((("current_setting"('role'::"text", true) = 'service_role'::"text") OR (CURRENT_USER = 'postgres'::"name")));


--
-- Name: owners Owners can update their own data; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Owners can update their own data" ON "public"."owners" FOR UPDATE USING (("auth"."uid"() = "auth_user_id"));


--
-- Name: owners Owners can view their own data; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Owners can view their own data" ON "public"."owners" FOR SELECT USING (("auth"."uid"() = "auth_user_id"));


--
-- Name: room_ownership Owners can view their own room ownerships; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Owners can view their own room ownerships" ON "public"."room_ownership" FOR SELECT USING (("auth"."uid"() = "owner_id"));


--
-- Name: properties Owners can view their properties; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Owners can view their properties" ON "public"."properties" FOR SELECT USING (("public"."is_owner"("auth"."uid"()) AND ("id" = ANY ("public"."get_owner_properties"("auth"."uid"())))));


--
-- Name: expenses Owners can view their property expenses; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Owners can view their property expenses" ON "public"."expenses" FOR SELECT USING (("public"."is_owner"("auth"."uid"()) AND ("property_id" IN ( SELECT "r"."property_id"
   FROM "public"."rooms" "r"
  WHERE ("r"."id" IN ( SELECT "get_owner_rooms"."room_id"
           FROM "public"."get_owner_rooms"("auth"."uid"()) "get_owner_rooms"("room_id")))))));


--
-- Name: property_ownership Owners can view their property ownership; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Owners can view their property ownership" ON "public"."property_ownership" FOR SELECT USING (("public"."is_owner"("auth"."uid"()) AND ("owner_id" IN ( SELECT "owners"."id"
   FROM "public"."owners"
  WHERE ("owners"."auth_user_id" = "auth"."uid"())))));


--
-- Name: bookings Owners can view their room bookings; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Owners can view their room bookings" ON "public"."bookings" FOR SELECT USING (("public"."is_owner"("auth"."uid"()) AND ("room_id" IN ( SELECT "get_owner_rooms"."room_id"
   FROM "public"."get_owner_rooms"("auth"."uid"()) "get_owner_rooms"("room_id")))));


--
-- Name: rooms Owners can view their rooms; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Owners can view their rooms" ON "public"."rooms" FOR SELECT USING (("public"."is_owner"("auth"."uid"()) AND ("id" IN ( SELECT "get_owner_rooms"."room_id"
   FROM "public"."get_owner_rooms"("auth"."uid"()) "get_owner_rooms"("room_id")))));


--
-- Name: booking_sources Require authentication for booking_sources; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Require authentication for booking_sources" ON "public"."booking_sources" TO "authenticated" USING (("auth"."uid"() IS NOT NULL));


--
-- Name: bookings Require authentication for bookings; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Require authentication for bookings" ON "public"."bookings" TO "authenticated" USING (("auth"."uid"() IS NOT NULL));


--
-- Name: cleaning_tasks Require authentication for cleaning_tasks; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Require authentication for cleaning_tasks" ON "public"."cleaning_tasks" TO "authenticated" USING (("auth"."uid"() IS NOT NULL));


--
-- Name: expense_categories Require authentication for expense_categories; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Require authentication for expense_categories" ON "public"."expense_categories" TO "authenticated" USING (("auth"."uid"() IS NOT NULL));


--
-- Name: expenses Require authentication for expenses; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Require authentication for expenses" ON "public"."expenses" TO "authenticated" USING (("auth"."uid"() IS NOT NULL));


--
-- Name: general_settings Require authentication for general_settings; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Require authentication for general_settings" ON "public"."general_settings" TO "authenticated" USING (("auth"."uid"() IS NOT NULL));


--
-- Name: owners Require authentication for owners; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Require authentication for owners" ON "public"."owners" TO "authenticated" USING (("auth"."uid"() IS NOT NULL));


--
-- Name: payment_methods Require authentication for payment_methods; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Require authentication for payment_methods" ON "public"."payment_methods" TO "authenticated" USING (("auth"."uid"() IS NOT NULL));


--
-- Name: properties Require authentication for properties; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Require authentication for properties" ON "public"."properties" TO "authenticated" USING (("auth"."uid"() IS NOT NULL));


--
-- Name: room_ownership Require authentication for room_ownership; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Require authentication for room_ownership" ON "public"."room_ownership" TO "authenticated" USING (("auth"."uid"() IS NOT NULL));


--
-- Name: room_types Require authentication for room_types; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Require authentication for room_types" ON "public"."room_types" TO "authenticated" USING (("auth"."uid"() IS NOT NULL));


--
-- Name: rooms Require authentication for rooms; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Require authentication for rooms" ON "public"."rooms" TO "authenticated" USING (("auth"."uid"() IS NOT NULL));


--
-- Name: user_role_assignments Require authentication for user_role_assignments; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Require authentication for user_role_assignments" ON "public"."user_role_assignments" TO "authenticated" USING (("auth"."uid"() IS NOT NULL));


--
-- Name: user_roles Require authentication for user_roles; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Require authentication for user_roles" ON "public"."user_roles" TO "authenticated" USING (("auth"."uid"() IS NOT NULL));


--
-- Name: booking_agents Staff can create booking agents; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Staff can create booking agents" ON "public"."booking_agents" FOR INSERT WITH CHECK ("public"."has_permission"("auth"."uid"(), 'create_bookings'::"text"));


--
-- Name: bookings Staff can create bookings; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Staff can create bookings" ON "public"."bookings" FOR INSERT WITH CHECK ("public"."has_permission"("auth"."uid"(), 'create_bookings'::"text"));


--
-- Name: profiles Staff can create profiles; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Staff can create profiles" ON "public"."profiles" FOR INSERT WITH CHECK ("public"."has_permission"("auth"."uid"(), 'create_users'::"text"));


--
-- Name: booking_agents Staff can delete booking agents; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Staff can delete booking agents" ON "public"."booking_agents" FOR DELETE USING ("public"."has_permission"("auth"."uid"(), 'delete_bookings'::"text"));


--
-- Name: bookings Staff can delete bookings; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Staff can delete bookings" ON "public"."bookings" FOR DELETE USING ("public"."has_permission"("auth"."uid"(), 'create_bookings'::"text"));


--
-- Name: profiles Staff can delete profiles; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Staff can delete profiles" ON "public"."profiles" FOR DELETE USING ("public"."has_permission"("auth"."uid"(), 'delete_users'::"text"));


--
-- Name: booking_sources Staff can manage booking sources; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Staff can manage booking sources" ON "public"."booking_sources" TO "authenticated" USING ("public"."has_permission"("auth"."uid"(), 'create_bookings'::"text"));


--
-- Name: cleaning_tasks Staff can manage cleaning tasks; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Staff can manage cleaning tasks" ON "public"."cleaning_tasks" USING ("public"."has_permission"("auth"."uid"(), 'view_cleaning'::"text"));


--
-- Name: expense_categories Staff can manage expense categories; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Staff can manage expense categories" ON "public"."expense_categories" TO "authenticated" USING ("public"."has_permission"("auth"."uid"(), 'create_expenses'::"text"));


--
-- Name: expenses Staff can manage expenses; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Staff can manage expenses" ON "public"."expenses" USING ("public"."has_permission"("auth"."uid"(), 'create_expenses'::"text"));


--
-- Name: general_settings Staff can manage general settings; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Staff can manage general settings" ON "public"."general_settings" USING ("public"."has_permission"("auth"."uid"(), 'update_settings'::"text"));


--
-- Name: owners Staff can manage owners; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Staff can manage owners" ON "public"."owners" USING ("public"."has_permission"("auth"."uid"(), 'view_owners'::"text"));


--
-- Name: payment_methods Staff can manage payment methods; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Staff can manage payment methods" ON "public"."payment_methods" TO "authenticated" USING ("public"."has_permission"("auth"."uid"(), 'create_expenses'::"text"));


--
-- Name: properties Staff can manage properties; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Staff can manage properties" ON "public"."properties" USING ("public"."has_permission"("auth"."uid"(), 'create_rooms'::"text"));


--
-- Name: property_ownership Staff can manage property ownership; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Staff can manage property ownership" ON "public"."property_ownership" USING ("public"."has_permission"("auth"."uid"(), 'view_owners'::"text"));


--
-- Name: room_ownership Staff can manage room ownerships; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Staff can manage room ownerships" ON "public"."room_ownership" USING ("public"."has_permission"("auth"."uid"(), 'view_owners'::"text"));


--
-- Name: room_types Staff can manage room types; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Staff can manage room types" ON "public"."room_types" USING ("public"."has_permission"("auth"."uid"(), 'create_rooms'::"text"));


--
-- Name: rooms Staff can manage rooms; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Staff can manage rooms" ON "public"."rooms" USING ("public"."has_permission"("auth"."uid"(), 'create_rooms'::"text"));


--
-- Name: booking_agents Staff can update booking agents; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Staff can update booking agents" ON "public"."booking_agents" FOR UPDATE USING ("public"."has_permission"("auth"."uid"(), 'update_bookings'::"text"));


--
-- Name: bookings Staff can update bookings; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Staff can update bookings" ON "public"."bookings" FOR UPDATE USING ("public"."has_permission"("auth"."uid"(), 'create_bookings'::"text")) WITH CHECK ("public"."has_permission"("auth"."uid"(), 'create_bookings'::"text"));


--
-- Name: profiles Staff can update profiles; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Staff can update profiles" ON "public"."profiles" FOR UPDATE USING ("public"."has_permission"("auth"."uid"(), 'update_users'::"text"));


--
-- Name: bookings Staff can view all bookings; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Staff can view all bookings" ON "public"."bookings" FOR SELECT USING ("public"."has_permission"("auth"."uid"(), 'view_bookings'::"text"));


--
-- Name: expenses Staff can view all expenses; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Staff can view all expenses" ON "public"."expenses" FOR SELECT USING ("public"."has_permission"("auth"."uid"(), 'view_expenses'::"text"));


--
-- Name: profiles Staff can view all profiles; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Staff can view all profiles" ON "public"."profiles" FOR SELECT USING ("public"."has_permission"("auth"."uid"(), 'view_users'::"text"));


--
-- Name: properties Staff can view all properties; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Staff can view all properties" ON "public"."properties" FOR SELECT USING ("public"."has_permission"("auth"."uid"(), 'view_rooms'::"text"));


--
-- Name: room_ownership Staff can view all room ownerships; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Staff can view all room ownerships" ON "public"."room_ownership" FOR SELECT USING ("public"."has_permission"("auth"."uid"(), 'view_owners'::"text"));


--
-- Name: rooms Staff can view all rooms; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Staff can view all rooms" ON "public"."rooms" FOR SELECT USING ("public"."has_permission"("auth"."uid"(), 'view_rooms'::"text"));


--
-- Name: booking_agents Staff can view booking agents; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Staff can view booking agents" ON "public"."booking_agents" FOR SELECT USING ("public"."has_permission"("auth"."uid"(), 'view_bookings'::"text"));


--
-- Name: general_settings Staff can view general settings; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Staff can view general settings" ON "public"."general_settings" FOR SELECT USING ("public"."has_permission"("auth"."uid"(), 'view_settings'::"text"));


--
-- Name: room_types Staff can view room types; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Staff can view room types" ON "public"."room_types" FOR SELECT USING ("public"."has_permission"("auth"."uid"(), 'view_rooms'::"text"));


--
-- Name: login_anomalies System can create anomalies; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "System can create anomalies" ON "public"."login_anomalies" FOR INSERT WITH CHECK (true);


--
-- Name: notifications System can create notifications; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "System can create notifications" ON "public"."notifications" FOR INSERT WITH CHECK (true);


--
-- Name: audit_access_log System can insert audit access logs; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "System can insert audit access logs" ON "public"."audit_access_log" FOR INSERT WITH CHECK (true);


--
-- Name: admin_2fa_enforcement System can manage 2FA enforcement; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "System can manage 2FA enforcement" ON "public"."admin_2fa_enforcement" USING (true);


--
-- Name: account_lockouts System can manage account lockouts; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "System can manage account lockouts" ON "public"."account_lockouts" USING (true);


--
-- Name: secure_password_reset_tokens System can manage password reset tokens; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "System can manage password reset tokens" ON "public"."secure_password_reset_tokens" USING (true);


--
-- Name: user_sessions System can manage sessions; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "System can manage sessions" ON "public"."user_sessions" USING (true);


--
-- Name: guests Users can delete guests they have access to; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users can delete guests they have access to" ON "public"."guests" FOR DELETE USING (("public"."user_can_access_guest"("id") AND ("public"."has_permission"("auth"."uid"(), 'delete_bookings'::"text") OR "public"."has_permission"("auth"."uid"(), 'manage_guests'::"text"))));


--
-- Name: user_2fa_tokens Users can manage their own 2FA tokens; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users can manage their own 2FA tokens" ON "public"."user_2fa_tokens" TO "authenticated" USING (("auth"."uid"() = "user_id")) WITH CHECK (("auth"."uid"() = "user_id"));


--
-- Name: guests Users can update guests they have access to; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users can update guests they have access to" ON "public"."guests" FOR UPDATE USING ("public"."user_can_access_guest"("id")) WITH CHECK ("public"."user_can_access_guest"("id"));


--
-- Name: profiles Users can update own profile; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users can update own profile" ON "public"."profiles" FOR UPDATE USING (("auth"."uid"() = "id"));


--
-- Name: notifications Users can update their own notifications; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users can update their own notifications" ON "public"."notifications" FOR UPDATE USING (("auth"."uid"() = "user_id"));


--
-- Name: guests Users can view guests from their properties/bookings; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users can view guests from their properties/bookings" ON "public"."guests" FOR SELECT USING ("public"."user_can_access_guest"("id"));


--
-- Name: profiles Users can view own profile; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users can view own profile" ON "public"."profiles" FOR SELECT USING (("auth"."uid"() = "id"));


--
-- Name: security_events Users can view own security events; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users can view own security events" ON "public"."security_events" FOR SELECT USING (("user_id" = "auth"."uid"()));


--
-- Name: admin_2fa_enforcement Users can view their own 2FA enforcement; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users can view their own 2FA enforcement" ON "public"."admin_2fa_enforcement" FOR SELECT USING (("auth"."uid"() = "user_id"));


--
-- Name: notification_settings Users can view their own notification settings; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users can view their own notification settings" ON "public"."notification_settings" FOR SELECT USING (("auth"."uid"() = "user_id"));


--
-- Name: notifications Users can view their own notifications; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users can view their own notifications" ON "public"."notifications" FOR SELECT USING (("auth"."uid"() = "user_id"));


--
-- Name: user_sessions Users can view their own sessions; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users can view their own sessions" ON "public"."user_sessions" FOR SELECT USING (("auth"."uid"() = "user_id"));


--
-- Name: guest_data_classification Users with guest permissions can view classification; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users with guest permissions can view classification" ON "public"."guest_data_classification" FOR SELECT USING ("public"."has_permission"("auth"."uid"(), 'view_guests'::"text"));


--
-- Name: guests Users with manage permission can create guests; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY "Users with manage permission can create guests" ON "public"."guests" FOR INSERT WITH CHECK (("public"."has_permission"("auth"."uid"(), 'create_bookings'::"text") OR "public"."has_permission"("auth"."uid"(), 'manage_guests'::"text")));


--
-- Name: account_lockouts; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE "public"."account_lockouts" ENABLE ROW LEVEL SECURITY;

--
-- Name: admin_2fa_enforcement; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE "public"."admin_2fa_enforcement" ENABLE ROW LEVEL SECURITY;

--
-- Name: audit_access_log; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE "public"."audit_access_log" ENABLE ROW LEVEL SECURITY;

--
-- Name: audit_logs; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE "public"."audit_logs" ENABLE ROW LEVEL SECURITY;

--
-- Name: booking_agents; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE "public"."booking_agents" ENABLE ROW LEVEL SECURITY;

--
-- Name: booking_sources; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE "public"."booking_sources" ENABLE ROW LEVEL SECURITY;

--
-- Name: bookings; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE "public"."bookings" ENABLE ROW LEVEL SECURITY;

--
-- Name: cleaning_tasks; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE "public"."cleaning_tasks" ENABLE ROW LEVEL SECURITY;

--
-- Name: contract_templates; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE "public"."contract_templates" ENABLE ROW LEVEL SECURITY;

--
-- Name: expense_categories; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE "public"."expense_categories" ENABLE ROW LEVEL SECURITY;

--
-- Name: expenses; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE "public"."expenses" ENABLE ROW LEVEL SECURITY;

--
-- Name: general_settings; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE "public"."general_settings" ENABLE ROW LEVEL SECURITY;

--
-- Name: guest_data_classification; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE "public"."guest_data_classification" ENABLE ROW LEVEL SECURITY;

--
-- Name: guests; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE "public"."guests" ENABLE ROW LEVEL SECURITY;

--
-- Name: ip_access_rules; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE "public"."ip_access_rules" ENABLE ROW LEVEL SECURITY;

--
-- Name: login_anomalies; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE "public"."login_anomalies" ENABLE ROW LEVEL SECURITY;

--
-- Name: notification_settings; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE "public"."notification_settings" ENABLE ROW LEVEL SECURITY;

--
-- Name: notifications; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE "public"."notifications" ENABLE ROW LEVEL SECURITY;

--
-- Name: owners; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE "public"."owners" ENABLE ROW LEVEL SECURITY;

--
-- Name: payment_methods; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE "public"."payment_methods" ENABLE ROW LEVEL SECURITY;

--
-- Name: pdf_field_mappings; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE "public"."pdf_field_mappings" ENABLE ROW LEVEL SECURITY;

--
-- Name: profiles; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE "public"."profiles" ENABLE ROW LEVEL SECURITY;

--
-- Name: properties; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE "public"."properties" ENABLE ROW LEVEL SECURITY;

--
-- Name: property_ownership; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE "public"."property_ownership" ENABLE ROW LEVEL SECURITY;

--
-- Name: room_ownership; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE "public"."room_ownership" ENABLE ROW LEVEL SECURITY;

--
-- Name: room_types; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE "public"."room_types" ENABLE ROW LEVEL SECURITY;

--
-- Name: rooms; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE "public"."rooms" ENABLE ROW LEVEL SECURITY;

--
-- Name: secure_password_reset_tokens; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE "public"."secure_password_reset_tokens" ENABLE ROW LEVEL SECURITY;

--
-- Name: security_events; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE "public"."security_events" ENABLE ROW LEVEL SECURITY;

--
-- Name: security_incidents; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE "public"."security_incidents" ENABLE ROW LEVEL SECURITY;

--
-- Name: user_2fa_tokens; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE "public"."user_2fa_tokens" ENABLE ROW LEVEL SECURITY;

--
-- Name: user_role_assignments; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE "public"."user_role_assignments" ENABLE ROW LEVEL SECURITY;

--
-- Name: user_roles; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE "public"."user_roles" ENABLE ROW LEVEL SECURITY;

--
-- Name: user_sessions; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE "public"."user_sessions" ENABLE ROW LEVEL SECURITY;

--
-- Name: messages; Type: ROW SECURITY; Schema: realtime; Owner: -
--

ALTER TABLE "realtime"."messages" ENABLE ROW LEVEL SECURITY;

--
-- Name: objects Admins can delete booking contracts; Type: POLICY; Schema: storage; Owner: -
--

CREATE POLICY "Admins can delete booking contracts" ON "storage"."objects" FOR DELETE TO "authenticated" USING ((("bucket_id" = 'booking-contracts'::"text") AND (EXISTS ( SELECT 1
   FROM ("public"."user_role_assignments" "ura"
     JOIN "public"."user_roles" "ur" ON (("ura"."role_id" = "ur"."id")))
  WHERE (("ura"."user_id" = "auth"."uid"()) AND ("ur"."name" = ANY (ARRAY['admin'::"text", 'manager'::"text"])))))));


--
-- Name: objects Admins can delete contract previews; Type: POLICY; Schema: storage; Owner: -
--

CREATE POLICY "Admins can delete contract previews" ON "storage"."objects" FOR DELETE TO "authenticated" USING ((("bucket_id" = 'contract-previews'::"text") AND (EXISTS ( SELECT 1
   FROM ("public"."user_role_assignments" "ura"
     JOIN "public"."user_roles" "ur" ON (("ura"."role_id" = "ur"."id")))
  WHERE (("ura"."user_id" = "auth"."uid"()) AND ("ur"."name" = ANY (ARRAY['admin'::"text", 'manager'::"text"])))))));


--
-- Name: objects Admins can delete contract templates; Type: POLICY; Schema: storage; Owner: -
--

CREATE POLICY "Admins can delete contract templates" ON "storage"."objects" FOR DELETE TO "authenticated" USING ((("bucket_id" = 'contract-templates'::"text") AND (EXISTS ( SELECT 1
   FROM ("public"."user_role_assignments" "ura"
     JOIN "public"."user_roles" "ur" ON (("ura"."role_id" = "ur"."id")))
  WHERE (("ura"."user_id" = "auth"."uid"()) AND ("ur"."name" = ANY (ARRAY['admin'::"text", 'manager'::"text"])))))));


--
-- Name: objects Admins can read contract previews; Type: POLICY; Schema: storage; Owner: -
--

CREATE POLICY "Admins can read contract previews" ON "storage"."objects" FOR SELECT TO "authenticated" USING ((("bucket_id" = 'contract-previews'::"text") AND (EXISTS ( SELECT 1
   FROM ("public"."user_role_assignments" "ura"
     JOIN "public"."user_roles" "ur" ON (("ura"."role_id" = "ur"."id")))
  WHERE (("ura"."user_id" = "auth"."uid"()) AND ("ur"."name" = ANY (ARRAY['admin'::"text", 'manager'::"text"])))))));


--
-- Name: objects Admins can upload contract previews; Type: POLICY; Schema: storage; Owner: -
--

CREATE POLICY "Admins can upload contract previews" ON "storage"."objects" FOR INSERT TO "authenticated" WITH CHECK ((("bucket_id" = 'contract-previews'::"text") AND (EXISTS ( SELECT 1
   FROM ("public"."user_role_assignments" "ura"
     JOIN "public"."user_roles" "ur" ON (("ura"."role_id" = "ur"."id")))
  WHERE (("ura"."user_id" = "auth"."uid"()) AND ("ur"."name" = ANY (ARRAY['admin'::"text", 'manager'::"text"])))))));


--
-- Name: objects Admins can upload contract templates; Type: POLICY; Schema: storage; Owner: -
--

CREATE POLICY "Admins can upload contract templates" ON "storage"."objects" FOR INSERT TO "authenticated" WITH CHECK ((("bucket_id" = 'contract-templates'::"text") AND (EXISTS ( SELECT 1
   FROM ("public"."user_role_assignments" "ura"
     JOIN "public"."user_roles" "ur" ON (("ura"."role_id" = "ur"."id")))
  WHERE (("ura"."user_id" = "auth"."uid"()) AND ("ur"."name" = ANY (ARRAY['admin'::"text", 'manager'::"text"])))))));


--
-- Name: objects Allow authenticated users to upload PDF templates; Type: POLICY; Schema: storage; Owner: -
--

CREATE POLICY "Allow authenticated users to upload PDF templates" ON "storage"."objects" FOR INSERT TO "authenticated" WITH CHECK (("bucket_id" = 'pdf-contract-templates'::"text"));


--
-- Name: objects Allow users to delete PDF templates; Type: POLICY; Schema: storage; Owner: -
--

CREATE POLICY "Allow users to delete PDF templates" ON "storage"."objects" FOR DELETE TO "authenticated" USING (("bucket_id" = 'pdf-contract-templates'::"text"));


--
-- Name: objects Allow users to read PDF templates; Type: POLICY; Schema: storage; Owner: -
--

CREATE POLICY "Allow users to read PDF templates" ON "storage"."objects" FOR SELECT TO "authenticated" USING (("bucket_id" = 'pdf-contract-templates'::"text"));


--
-- Name: objects Authenticated users can read booking contracts; Type: POLICY; Schema: storage; Owner: -
--

CREATE POLICY "Authenticated users can read booking contracts" ON "storage"."objects" FOR SELECT TO "authenticated" USING (("bucket_id" = 'booking-contracts'::"text"));


--
-- Name: objects Authenticated users can read contract templates; Type: POLICY; Schema: storage; Owner: -
--

CREATE POLICY "Authenticated users can read contract templates" ON "storage"."objects" FOR SELECT TO "authenticated" USING (("bucket_id" = 'contract-templates'::"text"));


--
-- Name: objects Avatar images are publicly accessible; Type: POLICY; Schema: storage; Owner: -
--

CREATE POLICY "Avatar images are publicly accessible" ON "storage"."objects" FOR SELECT USING (("bucket_id" = 'avatars'::"text"));


--
-- Name: objects Room images are publicly accessible; Type: POLICY; Schema: storage; Owner: -
--

CREATE POLICY "Room images are publicly accessible" ON "storage"."objects" FOR SELECT USING (("bucket_id" = 'room-images'::"text"));


--
-- Name: objects Secure delete booking documents; Type: POLICY; Schema: storage; Owner: -
--

CREATE POLICY "Secure delete booking documents" ON "storage"."objects" FOR DELETE USING ((("bucket_id" = 'booking-documents'::"text") AND "public"."has_permission"("auth"."uid"(), 'delete_bookings'::"text") AND (NOT "public"."is_owner"("auth"."uid"()))));


--
-- Name: objects Secure delete expense receipts; Type: POLICY; Schema: storage; Owner: -
--

CREATE POLICY "Secure delete expense receipts" ON "storage"."objects" FOR DELETE USING ((("bucket_id" = 'expense-receipts'::"text") AND "public"."has_permission"("auth"."uid"(), 'delete_expenses'::"text") AND (NOT "public"."is_owner"("auth"."uid"()))));


--
-- Name: objects Secure delete guest documents; Type: POLICY; Schema: storage; Owner: -
--

CREATE POLICY "Secure delete guest documents" ON "storage"."objects" FOR DELETE USING ((("bucket_id" = 'guest-documents'::"text") AND "public"."has_permission"("auth"."uid"(), 'delete_bookings'::"text") AND (NOT "public"."is_owner"("auth"."uid"()))));


--
-- Name: objects Service role can upload booking contracts; Type: POLICY; Schema: storage; Owner: -
--

CREATE POLICY "Service role can upload booking contracts" ON "storage"."objects" FOR INSERT TO "authenticated" WITH CHECK (("bucket_id" = 'booking-contracts'::"text"));


--
-- Name: objects Staff can update booking documents; Type: POLICY; Schema: storage; Owner: -
--

CREATE POLICY "Staff can update booking documents" ON "storage"."objects" FOR UPDATE USING ((("bucket_id" = 'booking-documents'::"text") AND "public"."has_permission"("auth"."uid"(), 'update_bookings'::"text")));


--
-- Name: objects Staff can update expense receipts; Type: POLICY; Schema: storage; Owner: -
--

CREATE POLICY "Staff can update expense receipts" ON "storage"."objects" FOR UPDATE USING ((("bucket_id" = 'expense-receipts'::"text") AND "public"."has_permission"("auth"."uid"(), 'update_expenses'::"text")));


--
-- Name: objects Staff can update guest documents; Type: POLICY; Schema: storage; Owner: -
--

CREATE POLICY "Staff can update guest documents" ON "storage"."objects" FOR UPDATE USING ((("bucket_id" = 'guest-documents'::"text") AND "public"."has_permission"("auth"."uid"(), 'update_guests'::"text")));


--
-- Name: objects Staff can update room images; Type: POLICY; Schema: storage; Owner: -
--

CREATE POLICY "Staff can update room images" ON "storage"."objects" FOR UPDATE USING ((("bucket_id" = 'room-images'::"text") AND "public"."has_permission"("auth"."uid"(), 'update_rooms'::"text")));


--
-- Name: objects Staff can upload booking documents; Type: POLICY; Schema: storage; Owner: -
--

CREATE POLICY "Staff can upload booking documents" ON "storage"."objects" FOR INSERT WITH CHECK ((("bucket_id" = 'booking-documents'::"text") AND "public"."has_permission"("auth"."uid"(), 'create_bookings'::"text")));


--
-- Name: objects Staff can upload expense receipts; Type: POLICY; Schema: storage; Owner: -
--

CREATE POLICY "Staff can upload expense receipts" ON "storage"."objects" FOR INSERT WITH CHECK ((("bucket_id" = 'expense-receipts'::"text") AND "public"."has_permission"("auth"."uid"(), 'create_expenses'::"text")));


--
-- Name: objects Staff can upload guest documents; Type: POLICY; Schema: storage; Owner: -
--

CREATE POLICY "Staff can upload guest documents" ON "storage"."objects" FOR INSERT WITH CHECK ((("bucket_id" = 'guest-documents'::"text") AND "public"."has_permission"("auth"."uid"(), 'create_guests'::"text")));


--
-- Name: objects Staff can upload room images; Type: POLICY; Schema: storage; Owner: -
--

CREATE POLICY "Staff can upload room images" ON "storage"."objects" FOR INSERT WITH CHECK ((("bucket_id" = 'room-images'::"text") AND "public"."has_permission"("auth"."uid"(), 'create_rooms'::"text")));


--
-- Name: objects Users can delete documents for guests they have access to; Type: POLICY; Schema: storage; Owner: -
--

CREATE POLICY "Users can delete documents for guests they have access to" ON "storage"."objects" FOR DELETE USING ((("bucket_id" = 'guest-documents'::"text") AND ("auth"."uid"() IS NOT NULL) AND "public"."can_access_guest_document"("name") AND ("public"."has_permission"("auth"."uid"(), 'delete_bookings'::"text") OR "public"."has_permission"("auth"."uid"(), 'manage_guests'::"text"))));


--
-- Name: objects Users can update documents for guests they have access to; Type: POLICY; Schema: storage; Owner: -
--

CREATE POLICY "Users can update documents for guests they have access to" ON "storage"."objects" FOR UPDATE USING ((("bucket_id" = 'guest-documents'::"text") AND ("auth"."uid"() IS NOT NULL) AND "public"."can_access_guest_document"("name")));


--
-- Name: objects Users can update their own avatar; Type: POLICY; Schema: storage; Owner: -
--

CREATE POLICY "Users can update their own avatar" ON "storage"."objects" FOR UPDATE USING ((("bucket_id" = 'avatars'::"text") AND (("auth"."uid"())::"text" = ("storage"."foldername"("name"))[1])));


--
-- Name: objects Users can upload documents for guests they manage; Type: POLICY; Schema: storage; Owner: -
--

CREATE POLICY "Users can upload documents for guests they manage" ON "storage"."objects" FOR INSERT WITH CHECK ((("bucket_id" = 'guest-documents'::"text") AND ("auth"."uid"() IS NOT NULL) AND ("public"."has_permission"("auth"."uid"(), 'create_bookings'::"text") OR "public"."has_permission"("auth"."uid"(), 'manage_guests'::"text"))));


--
-- Name: objects Users can upload their own avatar; Type: POLICY; Schema: storage; Owner: -
--

CREATE POLICY "Users can upload their own avatar" ON "storage"."objects" FOR INSERT WITH CHECK ((("bucket_id" = 'avatars'::"text") AND (("auth"."uid"())::"text" = ("storage"."foldername"("name"))[1])));


--
-- Name: objects Users can view guest documents they have access to; Type: POLICY; Schema: storage; Owner: -
--

CREATE POLICY "Users can view guest documents they have access to" ON "storage"."objects" FOR SELECT USING ((("bucket_id" = 'guest-documents'::"text") AND ("auth"."uid"() IS NOT NULL) AND "public"."can_access_guest_document"("name")));


--
-- Name: objects booking_contracts_read_storage; Type: POLICY; Schema: storage; Owner: -
--

CREATE POLICY "booking_contracts_read_storage" ON "storage"."objects" FOR SELECT TO "authenticated" USING (("bucket_id" = 'booking-contracts'::"text"));


--
-- Name: objects booking_contracts_upload; Type: POLICY; Schema: storage; Owner: -
--

CREATE POLICY "booking_contracts_upload" ON "storage"."objects" FOR INSERT TO "authenticated" WITH CHECK (("bucket_id" = 'booking-contracts'::"text"));


--
-- Name: buckets; Type: ROW SECURITY; Schema: storage; Owner: -
--

ALTER TABLE "storage"."buckets" ENABLE ROW LEVEL SECURITY;

--
-- Name: buckets_analytics; Type: ROW SECURITY; Schema: storage; Owner: -
--

ALTER TABLE "storage"."buckets_analytics" ENABLE ROW LEVEL SECURITY;

--
-- Name: buckets_vectors; Type: ROW SECURITY; Schema: storage; Owner: -
--

ALTER TABLE "storage"."buckets_vectors" ENABLE ROW LEVEL SECURITY;

--
-- Name: objects contract_templates_delete_admins; Type: POLICY; Schema: storage; Owner: -
--

CREATE POLICY "contract_templates_delete_admins" ON "storage"."objects" FOR DELETE TO "authenticated" USING ((("bucket_id" = 'contract-templates'::"text") AND ((("auth"."jwt"() -> 'user_metadata'::"text") ->> 'role'::"text") = ANY (ARRAY['admin'::"text", 'manager'::"text", 'super_admin'::"text"]))));


--
-- Name: objects contract_templates_read_storage_any_auth; Type: POLICY; Schema: storage; Owner: -
--

CREATE POLICY "contract_templates_read_storage_any_auth" ON "storage"."objects" FOR SELECT TO "authenticated" USING (("bucket_id" = 'contract-templates'::"text"));


--
-- Name: objects contract_templates_upload_any_auth; Type: POLICY; Schema: storage; Owner: -
--

CREATE POLICY "contract_templates_upload_any_auth" ON "storage"."objects" FOR INSERT TO "authenticated" WITH CHECK (("bucket_id" = 'contract-templates'::"text"));


--
-- Name: migrations; Type: ROW SECURITY; Schema: storage; Owner: -
--

ALTER TABLE "storage"."migrations" ENABLE ROW LEVEL SECURITY;

--
-- Name: objects; Type: ROW SECURITY; Schema: storage; Owner: -
--

ALTER TABLE "storage"."objects" ENABLE ROW LEVEL SECURITY;

--
-- Name: prefixes; Type: ROW SECURITY; Schema: storage; Owner: -
--

ALTER TABLE "storage"."prefixes" ENABLE ROW LEVEL SECURITY;

--
-- Name: s3_multipart_uploads; Type: ROW SECURITY; Schema: storage; Owner: -
--

ALTER TABLE "storage"."s3_multipart_uploads" ENABLE ROW LEVEL SECURITY;

--
-- Name: s3_multipart_uploads_parts; Type: ROW SECURITY; Schema: storage; Owner: -
--

ALTER TABLE "storage"."s3_multipart_uploads_parts" ENABLE ROW LEVEL SECURITY;

--
-- Name: vector_indexes; Type: ROW SECURITY; Schema: storage; Owner: -
--

ALTER TABLE "storage"."vector_indexes" ENABLE ROW LEVEL SECURITY;

--
-- Name: supabase_realtime; Type: PUBLICATION; Schema: -; Owner: -
--

CREATE PUBLICATION "supabase_realtime" WITH (publish = 'insert, update, delete, truncate');


--
-- Name: supabase_realtime_messages_publication; Type: PUBLICATION; Schema: -; Owner: -
--

CREATE PUBLICATION "supabase_realtime_messages_publication" WITH (publish = 'insert, update, delete, truncate');


--
-- Name: supabase_realtime_messages_publication messages; Type: PUBLICATION TABLE; Schema: realtime; Owner: -
--

ALTER PUBLICATION "supabase_realtime_messages_publication" ADD TABLE ONLY "realtime"."messages";


--
-- Name: issue_graphql_placeholder; Type: EVENT TRIGGER; Schema: -; Owner: -
--

CREATE EVENT TRIGGER "issue_graphql_placeholder" ON "sql_drop"
         WHEN TAG IN ('DROP EXTENSION')
   EXECUTE FUNCTION "extensions"."set_graphql_placeholder"();


--
-- Name: issue_pg_cron_access; Type: EVENT TRIGGER; Schema: -; Owner: -
--

CREATE EVENT TRIGGER "issue_pg_cron_access" ON "ddl_command_end"
         WHEN TAG IN ('CREATE EXTENSION')
   EXECUTE FUNCTION "extensions"."grant_pg_cron_access"();


--
-- Name: issue_pg_graphql_access; Type: EVENT TRIGGER; Schema: -; Owner: -
--

CREATE EVENT TRIGGER "issue_pg_graphql_access" ON "ddl_command_end"
         WHEN TAG IN ('CREATE FUNCTION')
   EXECUTE FUNCTION "extensions"."grant_pg_graphql_access"();


--
-- Name: issue_pg_net_access; Type: EVENT TRIGGER; Schema: -; Owner: -
--

CREATE EVENT TRIGGER "issue_pg_net_access" ON "ddl_command_end"
         WHEN TAG IN ('CREATE EXTENSION')
   EXECUTE FUNCTION "extensions"."grant_pg_net_access"();


--
-- Name: pgrst_ddl_watch; Type: EVENT TRIGGER; Schema: -; Owner: -
--

CREATE EVENT TRIGGER "pgrst_ddl_watch" ON "ddl_command_end"
   EXECUTE FUNCTION "extensions"."pgrst_ddl_watch"();


--
-- Name: pgrst_drop_watch; Type: EVENT TRIGGER; Schema: -; Owner: -
--

CREATE EVENT TRIGGER "pgrst_drop_watch" ON "sql_drop"
   EXECUTE FUNCTION "extensions"."pgrst_drop_watch"();


--
-- PostgreSQL database dump complete
--

\unrestrict aPxfMzRoOk7OTOF61hS1d6jUVsZnBrf9zRW1S3cGJjkFdcgbGcwHcixYDH0XUO9

