


SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;


CREATE EXTENSION IF NOT EXISTS "pg_cron" WITH SCHEMA "pg_catalog";






CREATE EXTENSION IF NOT EXISTS "pg_net" WITH SCHEMA "extensions";






COMMENT ON SCHEMA "public" IS 'standard public schema';



CREATE EXTENSION IF NOT EXISTS "pg_graphql" WITH SCHEMA "graphql";






CREATE EXTENSION IF NOT EXISTS "pg_stat_statements" WITH SCHEMA "extensions";






CREATE EXTENSION IF NOT EXISTS "pgcrypto" WITH SCHEMA "extensions";






CREATE EXTENSION IF NOT EXISTS "supabase_vault" WITH SCHEMA "vault";






CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA "extensions";






CREATE TYPE "public"."booking_status" AS ENUM (
    'pending',
    'confirmed',
    'checked_in',
    'checked_out',
    'cancelled',
    'no_show'
);


ALTER TYPE "public"."booking_status" OWNER TO "postgres";


CREATE TYPE "public"."data_classification" AS ENUM (
    'PUBLIC',
    'RESTRICTED',
    'CONFIDENTIAL'
);


ALTER TYPE "public"."data_classification" OWNER TO "postgres";


CREATE TYPE "public"."expense_status" AS ENUM (
    'pending',
    'approved',
    'rejected',
    'paid'
);


ALTER TYPE "public"."expense_status" OWNER TO "postgres";


CREATE TYPE "public"."payment_status" AS ENUM (
    'pending',
    'partial',
    'paid',
    'refunded'
);


ALTER TYPE "public"."payment_status" OWNER TO "postgres";


CREATE TYPE "public"."room_status" AS ENUM (
    'occupied',
    'cleaning',
    'cleaned',
    'maintenance',
    'dirty',
    'available',
    'discontinued'
);


ALTER TYPE "public"."room_status" OWNER TO "postgres";


CREATE TYPE "public"."user_status" AS ENUM (
    'active',
    'inactive',
    'suspended'
);


ALTER TYPE "public"."user_status" OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."audit_trigger"() RETURNS "trigger"
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


ALTER FUNCTION "public"."audit_trigger"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."can_access_guest_document"("file_path" "text") RETURNS boolean
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


ALTER FUNCTION "public"."can_access_guest_document"("file_path" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."check_password_security"("password_text" "text") RETURNS "jsonb"
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


ALTER FUNCTION "public"."check_password_security"("password_text" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."check_rate_limit"("identifier" "text", "action_type" "text", "max_requests" integer DEFAULT 100, "window_minutes" integer DEFAULT 60) RETURNS "jsonb"
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


ALTER FUNCTION "public"."check_rate_limit"("identifier" "text", "action_type" "text", "max_requests" integer, "window_minutes" integer) OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."cleanup_expired_security_data"() RETURNS "void"
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


ALTER FUNCTION "public"."cleanup_expired_security_data"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."cleanup_old_audit_logs"() RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
BEGIN
  DELETE FROM public.audit_logs 
  WHERE timestamp < now() - interval '7 days';
END;
$$;


ALTER FUNCTION "public"."cleanup_old_audit_logs"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."create_notification"("p_user_id" "uuid", "p_title" "text", "p_message" "text", "p_type" "text" DEFAULT 'info'::"text", "p_category" "text" DEFAULT 'system'::"text", "p_related_id" "uuid" DEFAULT NULL::"uuid") RETURNS "uuid"
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


ALTER FUNCTION "public"."create_notification"("p_user_id" "uuid", "p_title" "text", "p_message" "text", "p_type" "text", "p_category" "text", "p_related_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."decrypt_audit_field"("encrypted_data" "text", "field_type" "text" DEFAULT 'json'::"text") RETURNS "text"
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


ALTER FUNCTION "public"."decrypt_audit_field"("encrypted_data" "text", "field_type" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."delete_booking_documents"() RETURNS "trigger"
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


ALTER FUNCTION "public"."delete_booking_documents"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."delete_expense_documents"() RETURNS "trigger"
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


ALTER FUNCTION "public"."delete_expense_documents"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."detect_login_anomalies"("user_email_param" "text", "user_id_param" "uuid", "current_ip" "inet", "current_user_agent" "text" DEFAULT NULL::"text", "location_data" "jsonb" DEFAULT NULL::"jsonb") RETURNS "jsonb"
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


ALTER FUNCTION "public"."detect_login_anomalies"("user_email_param" "text", "user_id_param" "uuid", "current_ip" "inet", "current_user_agent" "text", "location_data" "jsonb") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."enable_security_settings"() RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'pg_temp'
    AS $$
BEGIN
  RAISE NOTICE 'Enable MFA and enforce password policy manually (free plan).';
END;
$$;


ALTER FUNCTION "public"."enable_security_settings"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."encrypt_audit_data"() RETURNS "trigger"
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


ALTER FUNCTION "public"."encrypt_audit_data"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."enforce_admin_2fa"() RETURNS "void"
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


ALTER FUNCTION "public"."enforce_admin_2fa"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."ensure_single_default_pdf_template"() RETURNS "trigger"
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


ALTER FUNCTION "public"."ensure_single_default_pdf_template"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."generate_secure_password_reset_token"("user_email_param" "text", "client_ip" "inet" DEFAULT NULL::"inet", "user_agent_param" "text" DEFAULT NULL::"text") RETURNS "jsonb"
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


ALTER FUNCTION "public"."generate_secure_password_reset_token"("user_email_param" "text", "client_ip" "inet", "user_agent_param" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_auto_check_settings"() RETURNS TABLE("auto_checkin_enabled" boolean, "auto_checkout_enabled" boolean, "default_checkin_time" time without time zone, "default_checkout_time" time without time zone, "timezone" "text")
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


ALTER FUNCTION "public"."get_auto_check_settings"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_guest_secure"("guest_id" "uuid", "access_reason" "text" DEFAULT 'view'::"text") RETURNS TABLE("id" "uuid", "first_name" "text", "last_name" "text", "email" "text", "phone" "text", "address" "text", "city" "text", "state" "text", "country" "text", "zip_code" "text", "nationality" "text", "passport_number" "text", "id_document_url" "text", "notes" "text", "consent_data_processing" boolean, "consent_marketing" boolean, "consent_third_party_sharing" boolean, "consent_timestamp" timestamp with time zone, "privacy_level" "text", "created_at" timestamp with time zone, "updated_at" timestamp with time zone)
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


ALTER FUNCTION "public"."get_guest_secure"("guest_id" "uuid", "access_reason" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_ip_location"("ip_address" "text") RETURNS "jsonb"
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


ALTER FUNCTION "public"."get_ip_location"("ip_address" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_owner_bookings"("p_user_uuid" "uuid") RETURNS TABLE("id" "uuid", "guest_name" "text", "guest_email" "text", "guest_phone" "text", "room_number" "text", "room_type" "text", "property_name" "text", "check_in" "date", "check_out" "date", "status" "text", "total_amount" numeric)
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


ALTER FUNCTION "public"."get_owner_bookings"("p_user_uuid" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_owner_bookings_simple"("p_user_uuid" "uuid") RETURNS TABLE("id" "uuid", "guest_name" "text", "room_number" "text", "check_in_date" timestamp with time zone, "check_out_date" timestamp with time zone, "status" "text")
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


ALTER FUNCTION "public"."get_owner_bookings_simple"("p_user_uuid" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_owner_cleaning_tasks"("p_user_uuid" "uuid") RETURNS TABLE("id" "uuid", "room_number" "text", "property_name" "text", "status" "text", "assigned_to" "text", "priority" "text", "estimated_duration" integer, "notes" "text", "created_at" timestamp with time zone, "completed_at" timestamp with time zone)
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


ALTER FUNCTION "public"."get_owner_cleaning_tasks"("p_user_uuid" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_owner_dashboard_stats"("p_user_uuid" "uuid") RETURNS TABLE("available_rooms" bigint, "total_rooms" bigint, "check_ins" bigint, "check_outs" bigint, "occupancy_rate" numeric, "monthly_revenue" numeric, "occupied_rooms" bigint, "maintenance_rooms" bigint)
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


ALTER FUNCTION "public"."get_owner_dashboard_stats"("p_user_uuid" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_owner_properties"("user_uuid" "uuid") RETURNS "uuid"[]
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  SELECT ARRAY_AGG(po.property_id)
  FROM public.owners o
  JOIN public.property_ownership po ON o.id = po.owner_id
  WHERE o.auth_user_id = user_uuid AND o.active = true AND po.active = true;
$$;


ALTER FUNCTION "public"."get_owner_properties"("user_uuid" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_owner_reports_data"("p_user_uuid" "uuid") RETURNS TABLE("total_revenue" numeric, "total_bookings" bigint, "average_booking_value" numeric, "occupancy_rate" double precision)
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


ALTER FUNCTION "public"."get_owner_reports_data"("p_user_uuid" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_owner_rooms"("user_uuid" "uuid") RETURNS TABLE("room_id" "uuid")
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


ALTER FUNCTION "public"."get_owner_rooms"("user_uuid" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_real_client_ip"() RETURNS "text"
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


ALTER FUNCTION "public"."get_real_client_ip"() OWNER TO "postgres";


COMMENT ON FUNCTION "public"."get_real_client_ip"() IS 'Extracts real client IP from various proxy headers';



CREATE OR REPLACE FUNCTION "public"."get_room_status"("room_id" "uuid") RETURNS "jsonb"
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


ALTER FUNCTION "public"."get_room_status"("room_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_system_time_in_timezone"() RETURNS timestamp without time zone
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


ALTER FUNCTION "public"."get_system_time_in_timezone"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_unread_notification_count"("p_user_id" "uuid") RETURNS integer
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


ALTER FUNCTION "public"."get_unread_notification_count"("p_user_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_user_permissions"("user_uuid" "uuid") RETURNS "jsonb"
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


ALTER FUNCTION "public"."get_user_permissions"("user_uuid" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_user_role"("user_uuid" "uuid") RETURNS "text"
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  SELECT ur.name
  FROM public.user_role_assignments ura
  JOIN public.user_roles ur ON ura.role_id = ur.id
  WHERE ura.user_id = user_uuid
  LIMIT 1;
$$;


ALTER FUNCTION "public"."get_user_role"("user_uuid" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."handle_new_user"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
BEGIN
  INSERT INTO public.profiles (id, name, email, status)
  VALUES (NEW.id, COALESCE(NEW.raw_user_meta_data->>'name', NEW.email), NEW.email, 'active');
  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."handle_new_user"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."handle_progressive_lockout"("user_email_param" "text", "client_ip" "inet" DEFAULT NULL::"inet") RETURNS "jsonb"
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


ALTER FUNCTION "public"."handle_progressive_lockout"("user_email_param" "text", "client_ip" "inet") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."has_permission"("user_uuid" "uuid", "permission_name" "text") RETURNS boolean
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


ALTER FUNCTION "public"."has_permission"("user_uuid" "uuid", "permission_name" "text") OWNER TO "postgres";


COMMENT ON FUNCTION "public"."has_permission"("user_uuid" "uuid", "permission_name" "text") IS 'Checks if user has specific permission based on assigned roles';



CREATE OR REPLACE FUNCTION "public"."is_owner"("user_uuid" "uuid") RETURNS boolean
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


ALTER FUNCTION "public"."is_owner"("user_uuid" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."log_audit_access"("access_type" "text", "record_count" integer DEFAULT 0, "filters_applied" "jsonb" DEFAULT '{}'::"jsonb") RETURNS "uuid"
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


ALTER FUNCTION "public"."log_audit_access"("access_type" "text", "record_count" integer, "filters_applied" "jsonb") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."log_audit_action"() RETURNS "trigger"
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


ALTER FUNCTION "public"."log_audit_action"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."log_audit_with_location"("p_action" "text", "p_table_name" "text", "p_record_id" "uuid" DEFAULT NULL::"uuid", "p_old_values" "jsonb" DEFAULT NULL::"jsonb", "p_new_values" "jsonb" DEFAULT NULL::"jsonb", "p_real_ip" "text" DEFAULT NULL::"text") RETURNS "uuid"
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


ALTER FUNCTION "public"."log_audit_with_location"("p_action" "text", "p_table_name" "text", "p_record_id" "uuid", "p_old_values" "jsonb", "p_new_values" "jsonb", "p_real_ip" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."log_audit_with_real_ip"("p_action" "text", "p_table_name" "text", "p_record_id" "uuid" DEFAULT NULL::"uuid", "p_old_values" "jsonb" DEFAULT NULL::"jsonb", "p_new_values" "jsonb" DEFAULT NULL::"jsonb", "p_real_ip" "text" DEFAULT NULL::"text") RETURNS "uuid"
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


ALTER FUNCTION "public"."log_audit_with_real_ip"("p_action" "text", "p_table_name" "text", "p_record_id" "uuid", "p_old_values" "jsonb", "p_new_values" "jsonb", "p_real_ip" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."log_authentication_event"("event_type" "text", "user_email" "text" DEFAULT NULL::"text", "success" boolean DEFAULT true, "failure_reason" "text" DEFAULT NULL::"text", "metadata" "jsonb" DEFAULT '{}'::"jsonb") RETURNS "uuid"
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


ALTER FUNCTION "public"."log_authentication_event"("event_type" "text", "user_email" "text", "success" boolean, "failure_reason" "text", "metadata" "jsonb") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."log_guest_data_access"("guest_id" "uuid", "accessed_fields" "text"[], "access_reason" "text" DEFAULT 'view'::"text", "additional_metadata" "jsonb" DEFAULT '{}'::"jsonb") RETURNS "uuid"
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


ALTER FUNCTION "public"."log_guest_data_access"("guest_id" "uuid", "accessed_fields" "text"[], "access_reason" "text", "additional_metadata" "jsonb") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."log_html_content_access"("content_type" "text", "content_id" "uuid", "access_type" "text" DEFAULT 'view'::"text") RETURNS "void"
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


ALTER FUNCTION "public"."log_html_content_access"("content_type" "text", "content_id" "uuid", "access_type" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."log_security_event"("p_user_id" "uuid", "p_event" "text", "p_meta" "jsonb" DEFAULT '{}'::"jsonb") RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'pg_temp'
    AS $$
BEGIN
  INSERT INTO public.security_events(user_id, event_type, meta, created_at)
  VALUES (p_user_id, p_event, coalesce(p_meta, '{}'::jsonb), now());
END;
$$;


ALTER FUNCTION "public"."log_security_event"("p_user_id" "uuid", "p_event" "text", "p_meta" "jsonb") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."log_security_event"("event_type" "text", "severity" "text" DEFAULT 'medium'::"text", "description" "text" DEFAULT NULL::"text", "ip_address" "text" DEFAULT NULL::"text", "user_id" "uuid" DEFAULT NULL::"uuid", "metadata" "jsonb" DEFAULT '{}'::"jsonb") RETURNS "uuid"
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


ALTER FUNCTION "public"."log_security_event"("event_type" "text", "severity" "text", "description" "text", "ip_address" "text", "user_id" "uuid", "metadata" "jsonb") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."mask_guest_field"("field_value" "text", "field_name" "text", "user_permissions" "text"[] DEFAULT '{}'::"text"[], "classification_override" "public"."data_classification" DEFAULT NULL::"public"."data_classification") RETURNS "text"
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


ALTER FUNCTION "public"."mask_guest_field"("field_value" "text", "field_name" "text", "user_permissions" "text"[], "classification_override" "public"."data_classification") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."mask_sensitive_audit_data"("data_value" "text", "field_name" "text" DEFAULT NULL::"text", "user_role" "text" DEFAULT NULL::"text") RETURNS "text"
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


ALTER FUNCTION "public"."mask_sensitive_audit_data"("data_value" "text", "field_name" "text", "user_role" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."mask_sensitive_data"("data_value" "text", "user_role" "text" DEFAULT NULL::"text") RETURNS "text"
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


ALTER FUNCTION "public"."mask_sensitive_data"("data_value" "text", "user_role" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."process_auto_check_operations"() RETURNS TABLE("checkin_count" integer, "checkout_count" integer, "checkin_booking_ids" "uuid"[], "checkout_booking_ids" "uuid"[], "checkin_errors" "text"[], "checkout_errors" "text"[])
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


ALTER FUNCTION "public"."process_auto_check_operations"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."process_auto_checkins"() RETURNS TABLE("processed_count" integer, "booking_ids" "uuid"[], "errors" "text"[])
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


ALTER FUNCTION "public"."process_auto_checkins"() OWNER TO "postgres";


COMMENT ON FUNCTION "public"."process_auto_checkins"() IS 'Automatically processes eligible bookings for check-in';



CREATE OR REPLACE FUNCTION "public"."process_auto_checkouts"() RETURNS TABLE("processed_count" integer, "booking_ids" "uuid"[], "errors" "text"[])
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


ALTER FUNCTION "public"."process_auto_checkouts"() OWNER TO "postgres";


COMMENT ON FUNCTION "public"."process_auto_checkouts"() IS 'Automatically processes eligible bookings for check-out';



CREATE OR REPLACE FUNCTION "public"."safe_delete_owner"("owner_id_param" "uuid") RETURNS "jsonb"
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


ALTER FUNCTION "public"."safe_delete_owner"("owner_id_param" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."safe_delete_room"("room_id_param" "uuid") RETURNS "jsonb"
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


ALTER FUNCTION "public"."safe_delete_room"("room_id_param" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."sanitize_contract_template_content"() RETURNS "trigger"
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


ALTER FUNCTION "public"."sanitize_contract_template_content"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."sanitize_html_content"("input_html" "text") RETURNS "text"
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


ALTER FUNCTION "public"."sanitize_html_content"("input_html" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."set_pdf_contract_templates_user"() RETURNS "trigger"
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


ALTER FUNCTION "public"."set_pdf_contract_templates_user"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."trigger_admin_2fa_enforcement"() RETURNS "trigger"
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


ALTER FUNCTION "public"."trigger_admin_2fa_enforcement"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."update_guest_consent"("guest_id" "uuid", "data_processing" boolean DEFAULT NULL::boolean, "marketing" boolean DEFAULT NULL::boolean, "third_party_sharing" boolean DEFAULT NULL::boolean, "consent_metadata" "jsonb" DEFAULT '{}'::"jsonb") RETURNS boolean
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


ALTER FUNCTION "public"."update_guest_consent"("guest_id" "uuid", "data_processing" boolean, "marketing" boolean, "third_party_sharing" boolean, "consent_metadata" "jsonb") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."update_notification_timestamps"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    SET "search_path" TO 'public', 'pg_temp'
    AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."update_notification_timestamps"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."update_room_status"("room_uuid" "uuid", "new_status" "public"."room_status", "user_uuid" "uuid" DEFAULT "auth"."uid"()) RETURNS "void"
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


ALTER FUNCTION "public"."update_room_status"("room_uuid" "uuid", "new_status" "public"."room_status", "user_uuid" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."update_updated_at_column"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    SET "search_path" TO 'public'
    AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."update_updated_at_column"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."user_can_access_guest"("guest_id" "uuid") RETURNS boolean
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


ALTER FUNCTION "public"."user_can_access_guest"("guest_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."user_has_mfa"("uid" "uuid") RETURNS boolean
    LANGUAGE "sql" SECURITY DEFINER
    SET "search_path" TO 'public', 'pg_temp'
    AS $$
  SELECT EXISTS(SELECT 1 FROM auth.mfa_factors WHERE user_id = uid);
$$;


ALTER FUNCTION "public"."user_has_mfa"("uid" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."validate_document_access"("bucket_name" "text", "file_path" "text", "user_id" "uuid" DEFAULT "auth"."uid"()) RETURNS boolean
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


ALTER FUNCTION "public"."validate_document_access"("bucket_name" "text", "file_path" "text", "user_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."validate_email"("email_input" "text") RETURNS "jsonb"
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


ALTER FUNCTION "public"."validate_email"("email_input" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."validate_file_upload"("file_name" "text", "file_size" bigint, "content_type" "text", "bucket_name" "text") RETURNS "jsonb"
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


ALTER FUNCTION "public"."validate_file_upload"("file_name" "text", "file_size" bigint, "content_type" "text", "bucket_name" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."validate_guest_document_access"("guest_id" "uuid", "document_type" "text", "document_path" "text") RETURNS boolean
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


ALTER FUNCTION "public"."validate_guest_document_access"("guest_id" "uuid", "document_type" "text", "document_path" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."validate_html_content"("input_html" "text", "max_length" integer DEFAULT 50000) RETURNS boolean
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


ALTER FUNCTION "public"."validate_html_content"("input_html" "text", "max_length" integer) OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."validate_phone"("phone_input" "text") RETURNS "jsonb"
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


ALTER FUNCTION "public"."validate_phone"("phone_input" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."validate_session_security"("session_data" "jsonb" DEFAULT NULL::"jsonb") RETURNS "jsonb"
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


ALTER FUNCTION "public"."validate_session_security"("session_data" "jsonb") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."validate_user_session"("session_token_param" "text", "current_ip" "inet" DEFAULT NULL::"inet", "current_user_agent" "text" DEFAULT NULL::"text") RETURNS "jsonb"
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


ALTER FUNCTION "public"."validate_user_session"("session_token_param" "text", "current_ip" "inet", "current_user_agent" "text") OWNER TO "postgres";

SET default_tablespace = '';

SET default_table_access_method = "heap";


CREATE TABLE IF NOT EXISTS "public"."account_lockouts" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "user_email" "text" NOT NULL,
    "lockout_level" integer DEFAULT 1 NOT NULL,
    "attempts_count" integer DEFAULT 0 NOT NULL,
    "locked_until" timestamp with time zone NOT NULL,
    "ip_address" "inet",
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"()
);


ALTER TABLE "public"."account_lockouts" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."admin_2fa_enforcement" (
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


ALTER TABLE "public"."admin_2fa_enforcement" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."audit_access_log" (
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


ALTER TABLE "public"."audit_access_log" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."audit_logs" (
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


ALTER TABLE "public"."audit_logs" OWNER TO "postgres";


COMMENT ON TABLE "public"."audit_logs" IS 'Complete audit trail of system changes';



CREATE TABLE IF NOT EXISTS "public"."profiles" (
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


ALTER TABLE "public"."profiles" OWNER TO "postgres";


COMMENT ON TABLE "public"."profiles" IS 'Extended user profile information beyond auth.users';



CREATE OR REPLACE VIEW "public"."audit_logs_with_entities" WITH ("security_invoker"='true') AS
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


ALTER VIEW "public"."audit_logs_with_entities" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."booking_agents" (
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


ALTER TABLE "public"."booking_agents" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."booking_sources" (
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


ALTER TABLE "public"."booking_sources" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."bookings" (
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


ALTER TABLE "public"."bookings" OWNER TO "postgres";


COMMENT ON TABLE "public"."bookings" IS 'Main reservation/booking records';



COMMENT ON COLUMN "public"."bookings"."reference" IS 'Unique booking reference number for customer communication';



COMMENT ON COLUMN "public"."bookings"."net_to_owner" IS 'Amount payable to property owner after deductions';



CREATE TABLE IF NOT EXISTS "public"."cleaning_tasks" (
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


ALTER TABLE "public"."cleaning_tasks" OWNER TO "postgres";


COMMENT ON TABLE "public"."cleaning_tasks" IS 'Room cleaning schedules and tracking';



COMMENT ON COLUMN "public"."cleaning_tasks"."checklist" IS 'JSON array of cleaning tasks and completion status';



CREATE TABLE IF NOT EXISTS "public"."contract_templates" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "name" "text" NOT NULL,
    "description" "text",
    "file_url" "text" NOT NULL,
    "created_by" "uuid",
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "is_active" boolean DEFAULT true NOT NULL
);


ALTER TABLE "public"."contract_templates" OWNER TO "postgres";


COMMENT ON TABLE "public"."contract_templates" IS 'Stores uploaded PDF contract templates with visual field mapping';



CREATE TABLE IF NOT EXISTS "public"."expense_categories" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "name" "text" NOT NULL,
    "description" "text",
    "active" boolean DEFAULT true,
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"(),
    "created_by" "uuid",
    "updated_by" "uuid"
);


ALTER TABLE "public"."expense_categories" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."expenses" (
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


ALTER TABLE "public"."expenses" OWNER TO "postgres";


COMMENT ON TABLE "public"."expenses" IS 'Property-related expenses and receipts';



CREATE TABLE IF NOT EXISTS "public"."general_settings" (
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


ALTER TABLE "public"."general_settings" OWNER TO "postgres";


COMMENT ON TABLE "public"."general_settings" IS 'System-wide configuration settings';



CREATE TABLE IF NOT EXISTS "public"."guest_data_classification" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "field_name" "text" NOT NULL,
    "classification" "public"."data_classification" NOT NULL,
    "required_permission" "text" NOT NULL,
    "masking_rule" "text",
    "description" "text",
    "created_at" timestamp with time zone DEFAULT "now"()
);


ALTER TABLE "public"."guest_data_classification" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."guests" (
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


ALTER TABLE "public"."guests" OWNER TO "postgres";


COMMENT ON TABLE "public"."guests" IS 'Guest information and contact details';



CREATE TABLE IF NOT EXISTS "public"."ip_access_rules" (
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


ALTER TABLE "public"."ip_access_rules" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."login_anomalies" (
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


ALTER TABLE "public"."login_anomalies" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."notification_settings" (
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


ALTER TABLE "public"."notification_settings" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."notifications" (
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


ALTER TABLE "public"."notifications" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."owners" (
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


ALTER TABLE "public"."owners" OWNER TO "postgres";


COMMENT ON TABLE "public"."owners" IS 'Property owners and their payment information';



COMMENT ON COLUMN "public"."owners"."payment_info" IS 'JSON object containing payment preferences and banking details';



CREATE TABLE IF NOT EXISTS "public"."payment_methods" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "name" "text" NOT NULL,
    "description" "text",
    "active" boolean DEFAULT true,
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"(),
    "created_by" "uuid",
    "updated_by" "uuid"
);


ALTER TABLE "public"."payment_methods" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."pdf_field_mappings" (
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


ALTER TABLE "public"."pdf_field_mappings" OWNER TO "postgres";


COMMENT ON TABLE "public"."pdf_field_mappings" IS 'Stores field positions for PDF contract generation (normalized 0-1 coordinates)';



COMMENT ON COLUMN "public"."pdf_field_mappings"."page_number" IS 'Page number where field should be placed (1-indexed)';



COMMENT ON COLUMN "public"."pdf_field_mappings"."x_position" IS 'Normalized X position (0-1) from left edge of page';



COMMENT ON COLUMN "public"."pdf_field_mappings"."y_position" IS 'Normalized Y position (0-1) from top edge of page';



CREATE TABLE IF NOT EXISTS "public"."properties" (
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


ALTER TABLE "public"."properties" OWNER TO "postgres";


COMMENT ON TABLE "public"."properties" IS 'Physical properties/buildings being managed';



CREATE TABLE IF NOT EXISTS "public"."property_ownership" (
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


ALTER TABLE "public"."property_ownership" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."room_ownership" (
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


ALTER TABLE "public"."room_ownership" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."room_types" (
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


ALTER TABLE "public"."room_types" OWNER TO "postgres";


COMMENT ON TABLE "public"."room_types" IS 'Standardized room configurations and pricing';



CREATE TABLE IF NOT EXISTS "public"."rooms" (
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


ALTER TABLE "public"."rooms" OWNER TO "postgres";


COMMENT ON TABLE "public"."rooms" IS 'Individual rooms/units within properties';



COMMENT ON COLUMN "public"."rooms"."amenities" IS 'JSON array of room amenities and features';



CREATE TABLE IF NOT EXISTS "public"."secure_password_reset_tokens" (
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


ALTER TABLE "public"."secure_password_reset_tokens" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."security_events" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "user_id" "uuid" NOT NULL,
    "event_type" "text" NOT NULL,
    "meta" "jsonb" DEFAULT '{}'::"jsonb" NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL
);

ALTER TABLE ONLY "public"."security_events" FORCE ROW LEVEL SECURITY;


ALTER TABLE "public"."security_events" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."security_incidents" (
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


ALTER TABLE "public"."security_incidents" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."user_2fa_tokens" (
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


ALTER TABLE "public"."user_2fa_tokens" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."user_role_assignments" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "user_id" "uuid",
    "role_id" "uuid",
    "assigned_by" "uuid",
    "created_at" timestamp with time zone DEFAULT "now"()
);


ALTER TABLE "public"."user_role_assignments" OWNER TO "postgres";


COMMENT ON TABLE "public"."user_role_assignments" IS 'Many-to-many relationship between users and roles';



CREATE TABLE IF NOT EXISTS "public"."user_roles" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "name" "text" NOT NULL,
    "description" "text",
    "permissions" "jsonb" DEFAULT '{}'::"jsonb",
    "is_system" boolean DEFAULT false,
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"()
);


ALTER TABLE "public"."user_roles" OWNER TO "postgres";


COMMENT ON TABLE "public"."user_roles" IS 'System roles with granular permissions';



COMMENT ON COLUMN "public"."user_roles"."permissions" IS 'JSON object with hierarchical permission structure';



CREATE TABLE IF NOT EXISTS "public"."user_sessions" (
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


ALTER TABLE "public"."user_sessions" OWNER TO "postgres";


ALTER TABLE ONLY "public"."account_lockouts"
    ADD CONSTRAINT "account_lockouts_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."admin_2fa_enforcement"
    ADD CONSTRAINT "admin_2fa_enforcement_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."admin_2fa_enforcement"
    ADD CONSTRAINT "admin_2fa_enforcement_user_id_key" UNIQUE ("user_id");



ALTER TABLE ONLY "public"."audit_access_log"
    ADD CONSTRAINT "audit_access_log_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."audit_logs"
    ADD CONSTRAINT "audit_logs_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."booking_agents"
    ADD CONSTRAINT "booking_agents_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."booking_sources"
    ADD CONSTRAINT "booking_sources_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."bookings"
    ADD CONSTRAINT "bookings_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."bookings"
    ADD CONSTRAINT "bookings_reference_key" UNIQUE ("reference");



ALTER TABLE ONLY "public"."cleaning_tasks"
    ADD CONSTRAINT "cleaning_tasks_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."contract_templates"
    ADD CONSTRAINT "contract_templates_name_key" UNIQUE ("name");



ALTER TABLE ONLY "public"."contract_templates"
    ADD CONSTRAINT "contract_templates_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."expense_categories"
    ADD CONSTRAINT "expense_categories_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."expenses"
    ADD CONSTRAINT "expenses_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."general_settings"
    ADD CONSTRAINT "general_settings_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."guest_data_classification"
    ADD CONSTRAINT "guest_data_classification_field_name_key" UNIQUE ("field_name");



ALTER TABLE ONLY "public"."guest_data_classification"
    ADD CONSTRAINT "guest_data_classification_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."guests"
    ADD CONSTRAINT "guests_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."ip_access_rules"
    ADD CONSTRAINT "ip_access_rules_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."login_anomalies"
    ADD CONSTRAINT "login_anomalies_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."notification_settings"
    ADD CONSTRAINT "notification_settings_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."notification_settings"
    ADD CONSTRAINT "notification_settings_role_id_category_key" UNIQUE ("role_id", "category");



ALTER TABLE ONLY "public"."notification_settings"
    ADD CONSTRAINT "notification_settings_user_id_category_key" UNIQUE ("user_id", "category");



ALTER TABLE ONLY "public"."notifications"
    ADD CONSTRAINT "notifications_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."owners"
    ADD CONSTRAINT "owners_email_key" UNIQUE ("email");



ALTER TABLE ONLY "public"."owners"
    ADD CONSTRAINT "owners_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."payment_methods"
    ADD CONSTRAINT "payment_methods_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."pdf_field_mappings"
    ADD CONSTRAINT "pdf_field_mappings_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."pdf_field_mappings"
    ADD CONSTRAINT "pdf_field_mappings_unique_field" UNIQUE ("template_id", "field_name", "page_number");



ALTER TABLE ONLY "public"."profiles"
    ADD CONSTRAINT "profiles_email_key" UNIQUE ("email");



ALTER TABLE ONLY "public"."profiles"
    ADD CONSTRAINT "profiles_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."properties"
    ADD CONSTRAINT "properties_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."property_ownership"
    ADD CONSTRAINT "property_ownership_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."room_ownership"
    ADD CONSTRAINT "room_ownership_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."room_types"
    ADD CONSTRAINT "room_types_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."rooms"
    ADD CONSTRAINT "rooms_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."rooms"
    ADD CONSTRAINT "rooms_property_number_unique" UNIQUE ("property_id", "number");



ALTER TABLE ONLY "public"."secure_password_reset_tokens"
    ADD CONSTRAINT "secure_password_reset_tokens_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."secure_password_reset_tokens"
    ADD CONSTRAINT "secure_password_reset_tokens_token_hash_key" UNIQUE ("token_hash");



ALTER TABLE ONLY "public"."security_events"
    ADD CONSTRAINT "security_events_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."security_incidents"
    ADD CONSTRAINT "security_incidents_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."user_2fa_tokens"
    ADD CONSTRAINT "user_2fa_tokens_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."user_role_assignments"
    ADD CONSTRAINT "user_role_assignments_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."user_role_assignments"
    ADD CONSTRAINT "user_role_assignments_user_role_unique" UNIQUE ("user_id", "role_id");



ALTER TABLE ONLY "public"."user_roles"
    ADD CONSTRAINT "user_roles_name_key" UNIQUE ("name");



ALTER TABLE ONLY "public"."user_roles"
    ADD CONSTRAINT "user_roles_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."user_sessions"
    ADD CONSTRAINT "user_sessions_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."user_sessions"
    ADD CONSTRAINT "user_sessions_session_token_key" UNIQUE ("session_token");



CREATE INDEX "idx_account_lockouts_email_locked_until" ON "public"."account_lockouts" USING "btree" ("user_email", "locked_until");



CREATE INDEX "idx_admin_2fa_enforcement_deadline" ON "public"."admin_2fa_enforcement" USING "btree" ("enforcement_deadline", "is_2fa_enabled");



CREATE INDEX "idx_admin_2fa_enforcement_user_id" ON "public"."admin_2fa_enforcement" USING "btree" ("user_id");



CREATE INDEX "idx_audit_logs_table_name" ON "public"."audit_logs" USING "btree" ("table_name");



CREATE INDEX "idx_audit_logs_timestamp" ON "public"."audit_logs" USING "btree" ("timestamp");



CREATE INDEX "idx_audit_logs_user_id" ON "public"."audit_logs" USING "btree" ("user_id");



CREATE INDEX "idx_bookings_auto_checkin" ON "public"."bookings" USING "btree" ("status", "check_in_date") WHERE ("status" = 'confirmed'::"public"."booking_status");



CREATE INDEX "idx_bookings_auto_checkout" ON "public"."bookings" USING "btree" ("status", "check_out_date") WHERE ("status" = 'checked_in'::"public"."booking_status");



CREATE INDEX "idx_bookings_dates" ON "public"."bookings" USING "btree" ("check_in_date", "check_out_date");



CREATE INDEX "idx_bookings_guest_id" ON "public"."bookings" USING "btree" ("guest_id");



CREATE INDEX "idx_bookings_room_id" ON "public"."bookings" USING "btree" ("room_id");



CREATE INDEX "idx_cleaning_tasks_room_id" ON "public"."cleaning_tasks" USING "btree" ("room_id");



CREATE INDEX "idx_cleaning_tasks_scheduled_date" ON "public"."cleaning_tasks" USING "btree" ("scheduled_date");



CREATE INDEX "idx_cleaning_tasks_status" ON "public"."cleaning_tasks" USING "btree" ("status");



CREATE INDEX "idx_contract_templates_active" ON "public"."contract_templates" USING "btree" ("is_active");



CREATE INDEX "idx_contract_templates_created_by" ON "public"."contract_templates" USING "btree" ("created_by");



CREATE INDEX "idx_expenses_date" ON "public"."expenses" USING "btree" ("date");



CREATE INDEX "idx_expenses_owner_id" ON "public"."expenses" USING "btree" ("owner_id");



CREATE INDEX "idx_expenses_property_id" ON "public"."expenses" USING "btree" ("property_id");



CREATE INDEX "idx_general_settings_created_at" ON "public"."general_settings" USING "btree" ("created_at" DESC);



CREATE INDEX "idx_ip_access_rules_active" ON "public"."ip_access_rules" USING "btree" ("is_active") WHERE ("is_active" = true);



CREATE INDEX "idx_ip_access_rules_ip_address" ON "public"."ip_access_rules" USING "btree" ("ip_address");



CREATE INDEX "idx_login_anomalies_severity" ON "public"."login_anomalies" USING "btree" ("severity");



CREATE INDEX "idx_login_anomalies_type" ON "public"."login_anomalies" USING "btree" ("anomaly_type");



CREATE INDEX "idx_login_anomalies_unresolved" ON "public"."login_anomalies" USING "btree" ("is_resolved", "created_at");



CREATE INDEX "idx_login_anomalies_user_email" ON "public"."login_anomalies" USING "btree" ("user_email");



CREATE INDEX "idx_notification_settings_role_id" ON "public"."notification_settings" USING "btree" ("role_id");



CREATE INDEX "idx_notification_settings_user_id" ON "public"."notification_settings" USING "btree" ("user_id");



CREATE INDEX "idx_notifications_category" ON "public"."notifications" USING "btree" ("category");



CREATE INDEX "idx_notifications_created_at" ON "public"."notifications" USING "btree" ("created_at");



CREATE INDEX "idx_notifications_read" ON "public"."notifications" USING "btree" ("read");



CREATE INDEX "idx_notifications_user_id" ON "public"."notifications" USING "btree" ("user_id");



CREATE INDEX "idx_password_reset_tokens_email" ON "public"."secure_password_reset_tokens" USING "btree" ("user_email");



CREATE INDEX "idx_password_reset_tokens_expires" ON "public"."secure_password_reset_tokens" USING "btree" ("expires_at", "is_used");



CREATE INDEX "idx_password_reset_tokens_hash" ON "public"."secure_password_reset_tokens" USING "btree" ("token_hash");



CREATE INDEX "idx_pdf_field_mappings_template" ON "public"."pdf_field_mappings" USING "btree" ("template_id");



CREATE INDEX "idx_rooms_property_id" ON "public"."rooms" USING "btree" ("property_id");



CREATE INDEX "idx_rooms_status" ON "public"."rooms" USING "btree" ("status");



CREATE INDEX "idx_user_sessions_active" ON "public"."user_sessions" USING "btree" ("is_active", "expires_at");



CREATE INDEX "idx_user_sessions_token" ON "public"."user_sessions" USING "btree" ("session_token");



CREATE INDEX "idx_user_sessions_user_id" ON "public"."user_sessions" USING "btree" ("user_id");



CREATE OR REPLACE TRIGGER "audit_bookings_trigger" AFTER INSERT OR DELETE OR UPDATE ON "public"."bookings" FOR EACH ROW EXECUTE FUNCTION "public"."audit_trigger"();



CREATE OR REPLACE TRIGGER "audit_cleaning_tasks_trigger" AFTER INSERT OR DELETE OR UPDATE ON "public"."cleaning_tasks" FOR EACH ROW EXECUTE FUNCTION "public"."audit_trigger"();



CREATE OR REPLACE TRIGGER "audit_expenses_trigger" AFTER INSERT OR DELETE OR UPDATE ON "public"."expenses" FOR EACH ROW EXECUTE FUNCTION "public"."audit_trigger"();



CREATE OR REPLACE TRIGGER "audit_guests_trigger" AFTER INSERT OR DELETE OR UPDATE ON "public"."guests" FOR EACH ROW EXECUTE FUNCTION "public"."audit_trigger"();



CREATE OR REPLACE TRIGGER "audit_owners_trigger" AFTER INSERT OR DELETE OR UPDATE ON "public"."owners" FOR EACH ROW EXECUTE FUNCTION "public"."audit_trigger"();



CREATE OR REPLACE TRIGGER "audit_properties_trigger" AFTER INSERT OR DELETE OR UPDATE ON "public"."properties" FOR EACH ROW EXECUTE FUNCTION "public"."audit_trigger"();



CREATE OR REPLACE TRIGGER "audit_property_ownership_trigger" AFTER INSERT OR DELETE OR UPDATE ON "public"."property_ownership" FOR EACH ROW EXECUTE FUNCTION "public"."audit_trigger"();



CREATE OR REPLACE TRIGGER "audit_room_ownership_trigger" AFTER INSERT OR DELETE OR UPDATE ON "public"."room_ownership" FOR EACH ROW EXECUTE FUNCTION "public"."audit_trigger"();



CREATE OR REPLACE TRIGGER "audit_room_types_trigger" AFTER INSERT OR DELETE OR UPDATE ON "public"."room_types" FOR EACH ROW EXECUTE FUNCTION "public"."audit_trigger"();



CREATE OR REPLACE TRIGGER "audit_rooms_trigger" AFTER INSERT OR DELETE OR UPDATE ON "public"."rooms" FOR EACH ROW EXECUTE FUNCTION "public"."audit_trigger"();



CREATE OR REPLACE TRIGGER "audit_user_role_assignments_trigger" AFTER INSERT OR DELETE OR UPDATE ON "public"."user_role_assignments" FOR EACH ROW EXECUTE FUNCTION "public"."log_audit_action"();



CREATE OR REPLACE TRIGGER "audit_user_roles_trigger" AFTER INSERT OR DELETE OR UPDATE ON "public"."user_roles" FOR EACH ROW EXECUTE FUNCTION "public"."log_audit_action"();



CREATE OR REPLACE TRIGGER "delete_booking_documents_trigger" BEFORE DELETE ON "public"."bookings" FOR EACH ROW EXECUTE FUNCTION "public"."delete_booking_documents"();



CREATE OR REPLACE TRIGGER "delete_expense_documents_trigger" BEFORE DELETE ON "public"."expenses" FOR EACH ROW EXECUTE FUNCTION "public"."delete_expense_documents"();



CREATE OR REPLACE TRIGGER "encrypt_audit_data_trigger" BEFORE INSERT OR UPDATE ON "public"."audit_logs" FOR EACH ROW EXECUTE FUNCTION "public"."encrypt_audit_data"();



CREATE OR REPLACE TRIGGER "trigger_admin_2fa_enforcement_on_role_assignment" AFTER INSERT ON "public"."user_role_assignments" FOR EACH ROW EXECUTE FUNCTION "public"."trigger_admin_2fa_enforcement"();



CREATE OR REPLACE TRIGGER "update_booking_agents_updated_at" BEFORE UPDATE ON "public"."booking_agents" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at_column"();



CREATE OR REPLACE TRIGGER "update_booking_sources_updated_at" BEFORE UPDATE ON "public"."booking_sources" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at_column"();



CREATE OR REPLACE TRIGGER "update_bookings_updated_at" BEFORE UPDATE ON "public"."bookings" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at_column"();



CREATE OR REPLACE TRIGGER "update_cleaning_tasks_updated_at" BEFORE UPDATE ON "public"."cleaning_tasks" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at_column"();



CREATE OR REPLACE TRIGGER "update_contract_templates_updated_at" BEFORE UPDATE ON "public"."contract_templates" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at_column"();



CREATE OR REPLACE TRIGGER "update_expense_categories_updated_at" BEFORE UPDATE ON "public"."expense_categories" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at_column"();



CREATE OR REPLACE TRIGGER "update_expenses_updated_at" BEFORE UPDATE ON "public"."expenses" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at_column"();



CREATE OR REPLACE TRIGGER "update_general_settings_updated_at" BEFORE UPDATE ON "public"."general_settings" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at_column"();



CREATE OR REPLACE TRIGGER "update_guests_updated_at" BEFORE UPDATE ON "public"."guests" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at_column"();



CREATE OR REPLACE TRIGGER "update_notification_settings_updated_at" BEFORE UPDATE ON "public"."notification_settings" FOR EACH ROW EXECUTE FUNCTION "public"."update_notification_timestamps"();



CREATE OR REPLACE TRIGGER "update_notifications_updated_at" BEFORE UPDATE ON "public"."notifications" FOR EACH ROW EXECUTE FUNCTION "public"."update_notification_timestamps"();



CREATE OR REPLACE TRIGGER "update_owners_updated_at" BEFORE UPDATE ON "public"."owners" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at_column"();



CREATE OR REPLACE TRIGGER "update_payment_methods_updated_at" BEFORE UPDATE ON "public"."payment_methods" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at_column"();



CREATE OR REPLACE TRIGGER "update_pdf_field_mappings_updated_at" BEFORE UPDATE ON "public"."pdf_field_mappings" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at_column"();



CREATE OR REPLACE TRIGGER "update_profiles_updated_at" BEFORE UPDATE ON "public"."profiles" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at_column"();



CREATE OR REPLACE TRIGGER "update_properties_updated_at" BEFORE UPDATE ON "public"."properties" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at_column"();



CREATE OR REPLACE TRIGGER "update_property_ownership_updated_at" BEFORE UPDATE ON "public"."property_ownership" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at_column"();



CREATE OR REPLACE TRIGGER "update_room_ownership_updated_at" BEFORE UPDATE ON "public"."room_ownership" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at_column"();



CREATE OR REPLACE TRIGGER "update_room_types_updated_at" BEFORE UPDATE ON "public"."room_types" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at_column"();



CREATE OR REPLACE TRIGGER "update_rooms_updated_at" BEFORE UPDATE ON "public"."rooms" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at_column"();



CREATE OR REPLACE TRIGGER "update_user_roles_updated_at" BEFORE UPDATE ON "public"."user_roles" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at_column"();



ALTER TABLE ONLY "public"."audit_access_log"
    ADD CONSTRAINT "audit_access_log_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id");



ALTER TABLE ONLY "public"."bookings"
    ADD CONSTRAINT "bookings_guest_id_fkey" FOREIGN KEY ("guest_id") REFERENCES "public"."guests"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."bookings"
    ADD CONSTRAINT "bookings_room_id_fkey" FOREIGN KEY ("room_id") REFERENCES "public"."rooms"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."cleaning_tasks"
    ADD CONSTRAINT "cleaning_tasks_room_id_fkey" FOREIGN KEY ("room_id") REFERENCES "public"."rooms"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."contract_templates"
    ADD CONSTRAINT "contract_templates_created_by_fkey" FOREIGN KEY ("created_by") REFERENCES "auth"."users"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."expenses"
    ADD CONSTRAINT "expenses_category_id_fkey" FOREIGN KEY ("category_id") REFERENCES "public"."expense_categories"("id");



ALTER TABLE ONLY "public"."expenses"
    ADD CONSTRAINT "expenses_created_by_fkey" FOREIGN KEY ("created_by") REFERENCES "public"."profiles"("id");



ALTER TABLE ONLY "public"."expenses"
    ADD CONSTRAINT "expenses_owner_id_fkey" FOREIGN KEY ("owner_id") REFERENCES "public"."owners"("id");



ALTER TABLE ONLY "public"."expenses"
    ADD CONSTRAINT "expenses_payment_method_id_fkey" FOREIGN KEY ("payment_method_id") REFERENCES "public"."payment_methods"("id");



ALTER TABLE ONLY "public"."expenses"
    ADD CONSTRAINT "expenses_property_id_fkey" FOREIGN KEY ("property_id") REFERENCES "public"."properties"("id");



ALTER TABLE ONLY "public"."expenses"
    ADD CONSTRAINT "expenses_updated_by_fkey" FOREIGN KEY ("updated_by") REFERENCES "public"."profiles"("id");



ALTER TABLE ONLY "public"."room_ownership"
    ADD CONSTRAINT "fk_room_ownership_owner" FOREIGN KEY ("owner_id") REFERENCES "public"."owners"("id");



ALTER TABLE ONLY "public"."room_ownership"
    ADD CONSTRAINT "fk_room_ownership_room" FOREIGN KEY ("room_id") REFERENCES "public"."rooms"("id");



ALTER TABLE ONLY "public"."user_role_assignments"
    ADD CONSTRAINT "fk_user_role_assignments_role_id" FOREIGN KEY ("role_id") REFERENCES "public"."user_roles"("id");



ALTER TABLE ONLY "public"."ip_access_rules"
    ADD CONSTRAINT "ip_access_rules_created_by_fkey" FOREIGN KEY ("created_by") REFERENCES "auth"."users"("id");



ALTER TABLE ONLY "public"."notification_settings"
    ADD CONSTRAINT "notification_settings_role_id_fkey" FOREIGN KEY ("role_id") REFERENCES "public"."user_roles"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."notification_settings"
    ADD CONSTRAINT "notification_settings_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."notifications"
    ADD CONSTRAINT "notifications_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."pdf_field_mappings"
    ADD CONSTRAINT "pdf_field_mappings_template_id_fkey" FOREIGN KEY ("template_id") REFERENCES "public"."contract_templates"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."property_ownership"
    ADD CONSTRAINT "property_ownership_owner_id_fkey" FOREIGN KEY ("owner_id") REFERENCES "public"."owners"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."property_ownership"
    ADD CONSTRAINT "property_ownership_property_id_fkey" FOREIGN KEY ("property_id") REFERENCES "public"."properties"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."room_ownership"
    ADD CONSTRAINT "room_ownership_owner_id_fkey" FOREIGN KEY ("owner_id") REFERENCES "public"."owners"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."room_ownership"
    ADD CONSTRAINT "room_ownership_room_id_fkey" FOREIGN KEY ("room_id") REFERENCES "public"."rooms"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."rooms"
    ADD CONSTRAINT "rooms_property_id_fkey" FOREIGN KEY ("property_id") REFERENCES "public"."properties"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."rooms"
    ADD CONSTRAINT "rooms_room_type_id_fkey" FOREIGN KEY ("room_type_id") REFERENCES "public"."room_types"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."user_role_assignments"
    ADD CONSTRAINT "user_role_assignments_role_id_fkey" FOREIGN KEY ("role_id") REFERENCES "public"."user_roles"("id") ON DELETE CASCADE;



CREATE POLICY "Admins can delete contract templates" ON "public"."contract_templates" FOR DELETE TO "authenticated" USING ((EXISTS ( SELECT 1
   FROM ("public"."user_role_assignments" "ura"
     JOIN "public"."user_roles" "ur" ON (("ura"."role_id" = "ur"."id")))
  WHERE (("ura"."user_id" = "auth"."uid"()) AND ("ur"."name" = ANY (ARRAY['admin'::"text", 'manager'::"text"]))))));



CREATE POLICY "Admins can delete pdf field mappings" ON "public"."pdf_field_mappings" FOR DELETE TO "authenticated" USING ((EXISTS ( SELECT 1
   FROM ("public"."user_role_assignments" "ura"
     JOIN "public"."user_roles" "ur" ON (("ura"."role_id" = "ur"."id")))
  WHERE (("ura"."user_id" = "auth"."uid"()) AND ("ur"."name" = ANY (ARRAY['admin'::"text", 'manager'::"text"]))))));



CREATE POLICY "Admins can insert contract templates" ON "public"."contract_templates" FOR INSERT TO "authenticated" WITH CHECK ((EXISTS ( SELECT 1
   FROM ("public"."user_role_assignments" "ura"
     JOIN "public"."user_roles" "ur" ON (("ura"."role_id" = "ur"."id")))
  WHERE (("ura"."user_id" = "auth"."uid"()) AND ("ur"."name" = ANY (ARRAY['admin'::"text", 'manager'::"text"]))))));



CREATE POLICY "Admins can insert pdf field mappings" ON "public"."pdf_field_mappings" FOR INSERT TO "authenticated" WITH CHECK ((EXISTS ( SELECT 1
   FROM ("public"."user_role_assignments" "ura"
     JOIN "public"."user_roles" "ur" ON (("ura"."role_id" = "ur"."id")))
  WHERE (("ura"."user_id" = "auth"."uid"()) AND ("ur"."name" = ANY (ARRAY['admin'::"text", 'manager'::"text"]))))));



CREATE POLICY "Admins can manage IP access rules" ON "public"."ip_access_rules" USING ("public"."has_permission"("auth"."uid"(), 'view_audit_logs'::"text"));



CREATE POLICY "Admins can manage data classification" ON "public"."guest_data_classification" USING ("public"."has_permission"("auth"."uid"(), 'view_audit_logs'::"text"));



CREATE POLICY "Admins can manage notification settings" ON "public"."notification_settings" USING ("public"."has_permission"("auth"."uid"(), 'manage_users'::"text"));



CREATE POLICY "Admins can manage role assignments" ON "public"."user_role_assignments" USING ("public"."has_permission"("auth"."uid"(), 'manage_users'::"text"));



CREATE POLICY "Admins can manage user roles" ON "public"."user_roles" USING ("public"."has_permission"("auth"."uid"(), 'manage_users'::"text"));



CREATE POLICY "Admins can resolve anomalies" ON "public"."login_anomalies" FOR UPDATE USING ("public"."has_permission"("auth"."uid"(), 'view_audit_logs'::"text"));



CREATE POLICY "Admins can update contract templates" ON "public"."contract_templates" FOR UPDATE TO "authenticated" USING ((EXISTS ( SELECT 1
   FROM ("public"."user_role_assignments" "ura"
     JOIN "public"."user_roles" "ur" ON (("ura"."role_id" = "ur"."id")))
  WHERE (("ura"."user_id" = "auth"."uid"()) AND ("ur"."name" = ANY (ARRAY['admin'::"text", 'manager'::"text"])))))) WITH CHECK ((EXISTS ( SELECT 1
   FROM ("public"."user_role_assignments" "ura"
     JOIN "public"."user_roles" "ur" ON (("ura"."role_id" = "ur"."id")))
  WHERE (("ura"."user_id" = "auth"."uid"()) AND ("ur"."name" = ANY (ARRAY['admin'::"text", 'manager'::"text"]))))));



CREATE POLICY "Admins can update pdf field mappings" ON "public"."pdf_field_mappings" FOR UPDATE TO "authenticated" USING ((EXISTS ( SELECT 1
   FROM ("public"."user_role_assignments" "ura"
     JOIN "public"."user_roles" "ur" ON (("ura"."role_id" = "ur"."id")))
  WHERE (("ura"."user_id" = "auth"."uid"()) AND ("ur"."name" = ANY (ARRAY['admin'::"text", 'manager'::"text"])))))) WITH CHECK ((EXISTS ( SELECT 1
   FROM ("public"."user_role_assignments" "ura"
     JOIN "public"."user_roles" "ur" ON (("ura"."role_id" = "ur"."id")))
  WHERE (("ura"."user_id" = "auth"."uid"()) AND ("ur"."name" = ANY (ARRAY['admin'::"text", 'manager'::"text"]))))));



CREATE POLICY "Admins can view 2FA enforcement" ON "public"."admin_2fa_enforcement" FOR SELECT USING ("public"."has_permission"("auth"."uid"(), 'manage_users'::"text"));



CREATE POLICY "Admins can view 2FA tokens for security" ON "public"."user_2fa_tokens" FOR SELECT TO "authenticated" USING ("public"."has_permission"("auth"."uid"(), 'manage_users'::"text"));



CREATE POLICY "Admins can view all anomalies" ON "public"."login_anomalies" FOR SELECT USING ("public"."has_permission"("auth"."uid"(), 'view_audit_logs'::"text"));



CREATE POLICY "Admins can view audit access logs" ON "public"."audit_access_log" FOR SELECT USING ("public"."has_permission"("auth"."uid"(), 'view_audit_logs'::"text"));



CREATE POLICY "Admins with audit permission can view logs" ON "public"."audit_logs" FOR SELECT USING (("public"."has_permission"("auth"."uid"(), 'view_audit_logs'::"text") AND (EXISTS ( SELECT 1
   FROM ("public"."user_roles" "ur"
     JOIN "public"."user_role_assignments" "ura" ON (("ur"."id" = "ura"."role_id")))
  WHERE (("ura"."user_id" = "auth"."uid"()) AND ("ur"."name" = 'admin'::"text"))))));



CREATE POLICY "Anyone can view contract templates" ON "public"."contract_templates" FOR SELECT TO "authenticated" USING (true);



CREATE POLICY "Anyone can view pdf field mappings" ON "public"."pdf_field_mappings" FOR SELECT TO "authenticated" USING (true);



CREATE POLICY "Authorized admins can view security events" ON "public"."security_events" FOR SELECT USING ("public"."has_permission"("auth"."uid"(), 'view_security_events'::"text"));



CREATE POLICY "Disable delete on security_events" ON "public"."security_events" FOR DELETE USING (false);



CREATE POLICY "Disable direct insert into security_events" ON "public"."security_events" FOR INSERT TO "authenticated" WITH CHECK (false);



CREATE POLICY "Disable update on security_events" ON "public"."security_events" FOR UPDATE USING (false) WITH CHECK (false);



CREATE POLICY "Only security admins can manage incidents" ON "public"."security_incidents" TO "authenticated" USING ("public"."has_permission"("auth"."uid"(), 'view_audit_logs'::"text"));



CREATE POLICY "Only system functions can create audit logs" ON "public"."audit_logs" FOR INSERT WITH CHECK ((("current_setting"('role'::"text", true) = 'service_role'::"text") OR (CURRENT_USER = 'postgres'::"name")));



CREATE POLICY "Owners can update their own data" ON "public"."owners" FOR UPDATE USING (("auth"."uid"() = "auth_user_id"));



CREATE POLICY "Owners can view their own data" ON "public"."owners" FOR SELECT USING (("auth"."uid"() = "auth_user_id"));



CREATE POLICY "Owners can view their own room ownerships" ON "public"."room_ownership" FOR SELECT USING (("auth"."uid"() = "owner_id"));



CREATE POLICY "Owners can view their properties" ON "public"."properties" FOR SELECT USING (("public"."is_owner"("auth"."uid"()) AND ("id" = ANY ("public"."get_owner_properties"("auth"."uid"())))));



CREATE POLICY "Owners can view their property expenses" ON "public"."expenses" FOR SELECT USING (("public"."is_owner"("auth"."uid"()) AND ("property_id" IN ( SELECT "r"."property_id"
   FROM "public"."rooms" "r"
  WHERE ("r"."id" IN ( SELECT "get_owner_rooms"."room_id"
           FROM "public"."get_owner_rooms"("auth"."uid"()) "get_owner_rooms"("room_id")))))));



CREATE POLICY "Owners can view their property ownership" ON "public"."property_ownership" FOR SELECT USING (("public"."is_owner"("auth"."uid"()) AND ("owner_id" IN ( SELECT "owners"."id"
   FROM "public"."owners"
  WHERE ("owners"."auth_user_id" = "auth"."uid"())))));



CREATE POLICY "Owners can view their room bookings" ON "public"."bookings" FOR SELECT USING (("public"."is_owner"("auth"."uid"()) AND ("room_id" IN ( SELECT "get_owner_rooms"."room_id"
   FROM "public"."get_owner_rooms"("auth"."uid"()) "get_owner_rooms"("room_id")))));



CREATE POLICY "Owners can view their rooms" ON "public"."rooms" FOR SELECT USING (("public"."is_owner"("auth"."uid"()) AND ("id" IN ( SELECT "get_owner_rooms"."room_id"
   FROM "public"."get_owner_rooms"("auth"."uid"()) "get_owner_rooms"("room_id")))));



CREATE POLICY "Require authentication for booking_sources" ON "public"."booking_sources" TO "authenticated" USING (("auth"."uid"() IS NOT NULL));



CREATE POLICY "Require authentication for bookings" ON "public"."bookings" TO "authenticated" USING (("auth"."uid"() IS NOT NULL));



CREATE POLICY "Require authentication for cleaning_tasks" ON "public"."cleaning_tasks" TO "authenticated" USING (("auth"."uid"() IS NOT NULL));



CREATE POLICY "Require authentication for expense_categories" ON "public"."expense_categories" TO "authenticated" USING (("auth"."uid"() IS NOT NULL));



CREATE POLICY "Require authentication for expenses" ON "public"."expenses" TO "authenticated" USING (("auth"."uid"() IS NOT NULL));



CREATE POLICY "Require authentication for general_settings" ON "public"."general_settings" TO "authenticated" USING (("auth"."uid"() IS NOT NULL));



CREATE POLICY "Require authentication for owners" ON "public"."owners" TO "authenticated" USING (("auth"."uid"() IS NOT NULL));



CREATE POLICY "Require authentication for payment_methods" ON "public"."payment_methods" TO "authenticated" USING (("auth"."uid"() IS NOT NULL));



CREATE POLICY "Require authentication for properties" ON "public"."properties" TO "authenticated" USING (("auth"."uid"() IS NOT NULL));



CREATE POLICY "Require authentication for room_ownership" ON "public"."room_ownership" TO "authenticated" USING (("auth"."uid"() IS NOT NULL));



CREATE POLICY "Require authentication for room_types" ON "public"."room_types" TO "authenticated" USING (("auth"."uid"() IS NOT NULL));



CREATE POLICY "Require authentication for rooms" ON "public"."rooms" TO "authenticated" USING (("auth"."uid"() IS NOT NULL));



CREATE POLICY "Require authentication for user_role_assignments" ON "public"."user_role_assignments" TO "authenticated" USING (("auth"."uid"() IS NOT NULL));



CREATE POLICY "Require authentication for user_roles" ON "public"."user_roles" TO "authenticated" USING (("auth"."uid"() IS NOT NULL));



CREATE POLICY "Staff can create booking agents" ON "public"."booking_agents" FOR INSERT WITH CHECK ("public"."has_permission"("auth"."uid"(), 'create_bookings'::"text"));



CREATE POLICY "Staff can create bookings" ON "public"."bookings" FOR INSERT WITH CHECK ("public"."has_permission"("auth"."uid"(), 'create_bookings'::"text"));



CREATE POLICY "Staff can create profiles" ON "public"."profiles" FOR INSERT WITH CHECK ("public"."has_permission"("auth"."uid"(), 'create_users'::"text"));



CREATE POLICY "Staff can delete booking agents" ON "public"."booking_agents" FOR DELETE USING ("public"."has_permission"("auth"."uid"(), 'delete_bookings'::"text"));



CREATE POLICY "Staff can delete bookings" ON "public"."bookings" FOR DELETE USING ("public"."has_permission"("auth"."uid"(), 'create_bookings'::"text"));



CREATE POLICY "Staff can delete profiles" ON "public"."profiles" FOR DELETE USING ("public"."has_permission"("auth"."uid"(), 'delete_users'::"text"));



CREATE POLICY "Staff can manage booking sources" ON "public"."booking_sources" TO "authenticated" USING ("public"."has_permission"("auth"."uid"(), 'create_bookings'::"text"));



CREATE POLICY "Staff can manage cleaning tasks" ON "public"."cleaning_tasks" USING ("public"."has_permission"("auth"."uid"(), 'view_cleaning'::"text"));



CREATE POLICY "Staff can manage expense categories" ON "public"."expense_categories" TO "authenticated" USING ("public"."has_permission"("auth"."uid"(), 'create_expenses'::"text"));



CREATE POLICY "Staff can manage expenses" ON "public"."expenses" USING ("public"."has_permission"("auth"."uid"(), 'create_expenses'::"text"));



CREATE POLICY "Staff can manage general settings" ON "public"."general_settings" USING ("public"."has_permission"("auth"."uid"(), 'update_settings'::"text"));



CREATE POLICY "Staff can manage owners" ON "public"."owners" USING ("public"."has_permission"("auth"."uid"(), 'view_owners'::"text"));



CREATE POLICY "Staff can manage payment methods" ON "public"."payment_methods" TO "authenticated" USING ("public"."has_permission"("auth"."uid"(), 'create_expenses'::"text"));



CREATE POLICY "Staff can manage properties" ON "public"."properties" USING ("public"."has_permission"("auth"."uid"(), 'create_rooms'::"text"));



CREATE POLICY "Staff can manage property ownership" ON "public"."property_ownership" USING ("public"."has_permission"("auth"."uid"(), 'view_owners'::"text"));



CREATE POLICY "Staff can manage room ownerships" ON "public"."room_ownership" USING ("public"."has_permission"("auth"."uid"(), 'view_owners'::"text"));



CREATE POLICY "Staff can manage room types" ON "public"."room_types" USING ("public"."has_permission"("auth"."uid"(), 'create_rooms'::"text"));



CREATE POLICY "Staff can manage rooms" ON "public"."rooms" USING ("public"."has_permission"("auth"."uid"(), 'create_rooms'::"text"));



CREATE POLICY "Staff can update booking agents" ON "public"."booking_agents" FOR UPDATE USING ("public"."has_permission"("auth"."uid"(), 'update_bookings'::"text"));



CREATE POLICY "Staff can update bookings" ON "public"."bookings" FOR UPDATE USING ("public"."has_permission"("auth"."uid"(), 'create_bookings'::"text")) WITH CHECK ("public"."has_permission"("auth"."uid"(), 'create_bookings'::"text"));



CREATE POLICY "Staff can update profiles" ON "public"."profiles" FOR UPDATE USING ("public"."has_permission"("auth"."uid"(), 'update_users'::"text"));



CREATE POLICY "Staff can view all bookings" ON "public"."bookings" FOR SELECT USING ("public"."has_permission"("auth"."uid"(), 'view_bookings'::"text"));



CREATE POLICY "Staff can view all expenses" ON "public"."expenses" FOR SELECT USING ("public"."has_permission"("auth"."uid"(), 'view_expenses'::"text"));



CREATE POLICY "Staff can view all profiles" ON "public"."profiles" FOR SELECT USING ("public"."has_permission"("auth"."uid"(), 'view_users'::"text"));



CREATE POLICY "Staff can view all properties" ON "public"."properties" FOR SELECT USING ("public"."has_permission"("auth"."uid"(), 'view_rooms'::"text"));



CREATE POLICY "Staff can view all room ownerships" ON "public"."room_ownership" FOR SELECT USING ("public"."has_permission"("auth"."uid"(), 'view_owners'::"text"));



CREATE POLICY "Staff can view all rooms" ON "public"."rooms" FOR SELECT USING ("public"."has_permission"("auth"."uid"(), 'view_rooms'::"text"));



CREATE POLICY "Staff can view booking agents" ON "public"."booking_agents" FOR SELECT USING ("public"."has_permission"("auth"."uid"(), 'view_bookings'::"text"));



CREATE POLICY "Staff can view general settings" ON "public"."general_settings" FOR SELECT USING ("public"."has_permission"("auth"."uid"(), 'view_settings'::"text"));



CREATE POLICY "Staff can view room types" ON "public"."room_types" FOR SELECT USING ("public"."has_permission"("auth"."uid"(), 'view_rooms'::"text"));



CREATE POLICY "System can create anomalies" ON "public"."login_anomalies" FOR INSERT WITH CHECK (true);



CREATE POLICY "System can create notifications" ON "public"."notifications" FOR INSERT WITH CHECK (true);



CREATE POLICY "System can insert audit access logs" ON "public"."audit_access_log" FOR INSERT WITH CHECK (true);



CREATE POLICY "System can manage 2FA enforcement" ON "public"."admin_2fa_enforcement" USING (true);



CREATE POLICY "System can manage account lockouts" ON "public"."account_lockouts" USING (true);



CREATE POLICY "System can manage password reset tokens" ON "public"."secure_password_reset_tokens" USING (true);



CREATE POLICY "System can manage sessions" ON "public"."user_sessions" USING (true);



CREATE POLICY "Users can delete guests they have access to" ON "public"."guests" FOR DELETE USING (("public"."user_can_access_guest"("id") AND ("public"."has_permission"("auth"."uid"(), 'delete_bookings'::"text") OR "public"."has_permission"("auth"."uid"(), 'manage_guests'::"text"))));



CREATE POLICY "Users can manage their own 2FA tokens" ON "public"."user_2fa_tokens" TO "authenticated" USING (("auth"."uid"() = "user_id")) WITH CHECK (("auth"."uid"() = "user_id"));



CREATE POLICY "Users can update guests they have access to" ON "public"."guests" FOR UPDATE USING ("public"."user_can_access_guest"("id")) WITH CHECK ("public"."user_can_access_guest"("id"));



CREATE POLICY "Users can update own profile" ON "public"."profiles" FOR UPDATE USING (("auth"."uid"() = "id"));



CREATE POLICY "Users can update their own notifications" ON "public"."notifications" FOR UPDATE USING (("auth"."uid"() = "user_id"));



CREATE POLICY "Users can view guests from their properties/bookings" ON "public"."guests" FOR SELECT USING ("public"."user_can_access_guest"("id"));



CREATE POLICY "Users can view own profile" ON "public"."profiles" FOR SELECT USING (("auth"."uid"() = "id"));



CREATE POLICY "Users can view own security events" ON "public"."security_events" FOR SELECT USING (("user_id" = "auth"."uid"()));



CREATE POLICY "Users can view their own 2FA enforcement" ON "public"."admin_2fa_enforcement" FOR SELECT USING (("auth"."uid"() = "user_id"));



CREATE POLICY "Users can view their own notification settings" ON "public"."notification_settings" FOR SELECT USING (("auth"."uid"() = "user_id"));



CREATE POLICY "Users can view their own notifications" ON "public"."notifications" FOR SELECT USING (("auth"."uid"() = "user_id"));



CREATE POLICY "Users can view their own sessions" ON "public"."user_sessions" FOR SELECT USING (("auth"."uid"() = "user_id"));



CREATE POLICY "Users with guest permissions can view classification" ON "public"."guest_data_classification" FOR SELECT USING ("public"."has_permission"("auth"."uid"(), 'view_guests'::"text"));



CREATE POLICY "Users with manage permission can create guests" ON "public"."guests" FOR INSERT WITH CHECK (("public"."has_permission"("auth"."uid"(), 'create_bookings'::"text") OR "public"."has_permission"("auth"."uid"(), 'manage_guests'::"text")));



ALTER TABLE "public"."account_lockouts" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."admin_2fa_enforcement" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."audit_access_log" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."audit_logs" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."booking_agents" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."booking_sources" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."bookings" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."cleaning_tasks" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."contract_templates" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."expense_categories" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."expenses" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."general_settings" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."guest_data_classification" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."guests" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."ip_access_rules" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."login_anomalies" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."notification_settings" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."notifications" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."owners" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."payment_methods" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."pdf_field_mappings" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."profiles" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."properties" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."property_ownership" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."room_ownership" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."room_types" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."rooms" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."secure_password_reset_tokens" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."security_events" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."security_incidents" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."user_2fa_tokens" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."user_role_assignments" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."user_roles" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."user_sessions" ENABLE ROW LEVEL SECURITY;




ALTER PUBLICATION "supabase_realtime" OWNER TO "postgres";












GRANT USAGE ON SCHEMA "public" TO "postgres";
GRANT USAGE ON SCHEMA "public" TO "anon";
GRANT USAGE ON SCHEMA "public" TO "authenticated";
GRANT USAGE ON SCHEMA "public" TO "service_role";














































































































































































GRANT ALL ON FUNCTION "public"."audit_trigger"() TO "anon";
GRANT ALL ON FUNCTION "public"."audit_trigger"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."audit_trigger"() TO "service_role";



GRANT ALL ON FUNCTION "public"."can_access_guest_document"("file_path" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."can_access_guest_document"("file_path" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."can_access_guest_document"("file_path" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."check_password_security"("password_text" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."check_password_security"("password_text" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."check_password_security"("password_text" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."check_rate_limit"("identifier" "text", "action_type" "text", "max_requests" integer, "window_minutes" integer) TO "anon";
GRANT ALL ON FUNCTION "public"."check_rate_limit"("identifier" "text", "action_type" "text", "max_requests" integer, "window_minutes" integer) TO "authenticated";
GRANT ALL ON FUNCTION "public"."check_rate_limit"("identifier" "text", "action_type" "text", "max_requests" integer, "window_minutes" integer) TO "service_role";



GRANT ALL ON FUNCTION "public"."cleanup_expired_security_data"() TO "anon";
GRANT ALL ON FUNCTION "public"."cleanup_expired_security_data"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."cleanup_expired_security_data"() TO "service_role";



GRANT ALL ON FUNCTION "public"."cleanup_old_audit_logs"() TO "anon";
GRANT ALL ON FUNCTION "public"."cleanup_old_audit_logs"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."cleanup_old_audit_logs"() TO "service_role";



GRANT ALL ON FUNCTION "public"."create_notification"("p_user_id" "uuid", "p_title" "text", "p_message" "text", "p_type" "text", "p_category" "text", "p_related_id" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."create_notification"("p_user_id" "uuid", "p_title" "text", "p_message" "text", "p_type" "text", "p_category" "text", "p_related_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."create_notification"("p_user_id" "uuid", "p_title" "text", "p_message" "text", "p_type" "text", "p_category" "text", "p_related_id" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."decrypt_audit_field"("encrypted_data" "text", "field_type" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."decrypt_audit_field"("encrypted_data" "text", "field_type" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."decrypt_audit_field"("encrypted_data" "text", "field_type" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."delete_booking_documents"() TO "anon";
GRANT ALL ON FUNCTION "public"."delete_booking_documents"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."delete_booking_documents"() TO "service_role";



GRANT ALL ON FUNCTION "public"."delete_expense_documents"() TO "anon";
GRANT ALL ON FUNCTION "public"."delete_expense_documents"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."delete_expense_documents"() TO "service_role";



GRANT ALL ON FUNCTION "public"."detect_login_anomalies"("user_email_param" "text", "user_id_param" "uuid", "current_ip" "inet", "current_user_agent" "text", "location_data" "jsonb") TO "anon";
GRANT ALL ON FUNCTION "public"."detect_login_anomalies"("user_email_param" "text", "user_id_param" "uuid", "current_ip" "inet", "current_user_agent" "text", "location_data" "jsonb") TO "authenticated";
GRANT ALL ON FUNCTION "public"."detect_login_anomalies"("user_email_param" "text", "user_id_param" "uuid", "current_ip" "inet", "current_user_agent" "text", "location_data" "jsonb") TO "service_role";



GRANT ALL ON FUNCTION "public"."enable_security_settings"() TO "anon";
GRANT ALL ON FUNCTION "public"."enable_security_settings"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."enable_security_settings"() TO "service_role";



GRANT ALL ON FUNCTION "public"."encrypt_audit_data"() TO "anon";
GRANT ALL ON FUNCTION "public"."encrypt_audit_data"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."encrypt_audit_data"() TO "service_role";



GRANT ALL ON FUNCTION "public"."enforce_admin_2fa"() TO "anon";
GRANT ALL ON FUNCTION "public"."enforce_admin_2fa"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."enforce_admin_2fa"() TO "service_role";



GRANT ALL ON FUNCTION "public"."ensure_single_default_pdf_template"() TO "anon";
GRANT ALL ON FUNCTION "public"."ensure_single_default_pdf_template"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."ensure_single_default_pdf_template"() TO "service_role";



GRANT ALL ON FUNCTION "public"."generate_secure_password_reset_token"("user_email_param" "text", "client_ip" "inet", "user_agent_param" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."generate_secure_password_reset_token"("user_email_param" "text", "client_ip" "inet", "user_agent_param" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."generate_secure_password_reset_token"("user_email_param" "text", "client_ip" "inet", "user_agent_param" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."get_auto_check_settings"() TO "anon";
GRANT ALL ON FUNCTION "public"."get_auto_check_settings"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_auto_check_settings"() TO "service_role";



GRANT ALL ON FUNCTION "public"."get_guest_secure"("guest_id" "uuid", "access_reason" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."get_guest_secure"("guest_id" "uuid", "access_reason" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_guest_secure"("guest_id" "uuid", "access_reason" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."get_ip_location"("ip_address" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."get_ip_location"("ip_address" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_ip_location"("ip_address" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."get_owner_bookings"("p_user_uuid" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."get_owner_bookings"("p_user_uuid" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_owner_bookings"("p_user_uuid" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."get_owner_bookings_simple"("p_user_uuid" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."get_owner_bookings_simple"("p_user_uuid" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_owner_bookings_simple"("p_user_uuid" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."get_owner_cleaning_tasks"("p_user_uuid" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."get_owner_cleaning_tasks"("p_user_uuid" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_owner_cleaning_tasks"("p_user_uuid" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."get_owner_dashboard_stats"("p_user_uuid" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."get_owner_dashboard_stats"("p_user_uuid" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_owner_dashboard_stats"("p_user_uuid" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."get_owner_properties"("user_uuid" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."get_owner_properties"("user_uuid" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_owner_properties"("user_uuid" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."get_owner_reports_data"("p_user_uuid" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."get_owner_reports_data"("p_user_uuid" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_owner_reports_data"("p_user_uuid" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."get_owner_rooms"("user_uuid" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."get_owner_rooms"("user_uuid" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_owner_rooms"("user_uuid" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."get_real_client_ip"() TO "anon";
GRANT ALL ON FUNCTION "public"."get_real_client_ip"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_real_client_ip"() TO "service_role";



GRANT ALL ON FUNCTION "public"."get_room_status"("room_id" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."get_room_status"("room_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_room_status"("room_id" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."get_system_time_in_timezone"() TO "anon";
GRANT ALL ON FUNCTION "public"."get_system_time_in_timezone"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_system_time_in_timezone"() TO "service_role";



GRANT ALL ON FUNCTION "public"."get_unread_notification_count"("p_user_id" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."get_unread_notification_count"("p_user_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_unread_notification_count"("p_user_id" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."get_user_permissions"("user_uuid" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."get_user_permissions"("user_uuid" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_user_permissions"("user_uuid" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."get_user_role"("user_uuid" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."get_user_role"("user_uuid" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_user_role"("user_uuid" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."handle_new_user"() TO "anon";
GRANT ALL ON FUNCTION "public"."handle_new_user"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."handle_new_user"() TO "service_role";



GRANT ALL ON FUNCTION "public"."handle_progressive_lockout"("user_email_param" "text", "client_ip" "inet") TO "anon";
GRANT ALL ON FUNCTION "public"."handle_progressive_lockout"("user_email_param" "text", "client_ip" "inet") TO "authenticated";
GRANT ALL ON FUNCTION "public"."handle_progressive_lockout"("user_email_param" "text", "client_ip" "inet") TO "service_role";



GRANT ALL ON FUNCTION "public"."has_permission"("user_uuid" "uuid", "permission_name" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."has_permission"("user_uuid" "uuid", "permission_name" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."has_permission"("user_uuid" "uuid", "permission_name" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."is_owner"("user_uuid" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."is_owner"("user_uuid" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."is_owner"("user_uuid" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."log_audit_access"("access_type" "text", "record_count" integer, "filters_applied" "jsonb") TO "anon";
GRANT ALL ON FUNCTION "public"."log_audit_access"("access_type" "text", "record_count" integer, "filters_applied" "jsonb") TO "authenticated";
GRANT ALL ON FUNCTION "public"."log_audit_access"("access_type" "text", "record_count" integer, "filters_applied" "jsonb") TO "service_role";



GRANT ALL ON FUNCTION "public"."log_audit_action"() TO "anon";
GRANT ALL ON FUNCTION "public"."log_audit_action"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."log_audit_action"() TO "service_role";



GRANT ALL ON FUNCTION "public"."log_audit_with_location"("p_action" "text", "p_table_name" "text", "p_record_id" "uuid", "p_old_values" "jsonb", "p_new_values" "jsonb", "p_real_ip" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."log_audit_with_location"("p_action" "text", "p_table_name" "text", "p_record_id" "uuid", "p_old_values" "jsonb", "p_new_values" "jsonb", "p_real_ip" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."log_audit_with_location"("p_action" "text", "p_table_name" "text", "p_record_id" "uuid", "p_old_values" "jsonb", "p_new_values" "jsonb", "p_real_ip" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."log_audit_with_real_ip"("p_action" "text", "p_table_name" "text", "p_record_id" "uuid", "p_old_values" "jsonb", "p_new_values" "jsonb", "p_real_ip" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."log_audit_with_real_ip"("p_action" "text", "p_table_name" "text", "p_record_id" "uuid", "p_old_values" "jsonb", "p_new_values" "jsonb", "p_real_ip" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."log_audit_with_real_ip"("p_action" "text", "p_table_name" "text", "p_record_id" "uuid", "p_old_values" "jsonb", "p_new_values" "jsonb", "p_real_ip" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."log_authentication_event"("event_type" "text", "user_email" "text", "success" boolean, "failure_reason" "text", "metadata" "jsonb") TO "anon";
GRANT ALL ON FUNCTION "public"."log_authentication_event"("event_type" "text", "user_email" "text", "success" boolean, "failure_reason" "text", "metadata" "jsonb") TO "authenticated";
GRANT ALL ON FUNCTION "public"."log_authentication_event"("event_type" "text", "user_email" "text", "success" boolean, "failure_reason" "text", "metadata" "jsonb") TO "service_role";



GRANT ALL ON FUNCTION "public"."log_guest_data_access"("guest_id" "uuid", "accessed_fields" "text"[], "access_reason" "text", "additional_metadata" "jsonb") TO "anon";
GRANT ALL ON FUNCTION "public"."log_guest_data_access"("guest_id" "uuid", "accessed_fields" "text"[], "access_reason" "text", "additional_metadata" "jsonb") TO "authenticated";
GRANT ALL ON FUNCTION "public"."log_guest_data_access"("guest_id" "uuid", "accessed_fields" "text"[], "access_reason" "text", "additional_metadata" "jsonb") TO "service_role";



GRANT ALL ON FUNCTION "public"."log_html_content_access"("content_type" "text", "content_id" "uuid", "access_type" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."log_html_content_access"("content_type" "text", "content_id" "uuid", "access_type" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."log_html_content_access"("content_type" "text", "content_id" "uuid", "access_type" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."log_security_event"("p_user_id" "uuid", "p_event" "text", "p_meta" "jsonb") TO "anon";
GRANT ALL ON FUNCTION "public"."log_security_event"("p_user_id" "uuid", "p_event" "text", "p_meta" "jsonb") TO "authenticated";
GRANT ALL ON FUNCTION "public"."log_security_event"("p_user_id" "uuid", "p_event" "text", "p_meta" "jsonb") TO "service_role";



GRANT ALL ON FUNCTION "public"."log_security_event"("event_type" "text", "severity" "text", "description" "text", "ip_address" "text", "user_id" "uuid", "metadata" "jsonb") TO "anon";
GRANT ALL ON FUNCTION "public"."log_security_event"("event_type" "text", "severity" "text", "description" "text", "ip_address" "text", "user_id" "uuid", "metadata" "jsonb") TO "authenticated";
GRANT ALL ON FUNCTION "public"."log_security_event"("event_type" "text", "severity" "text", "description" "text", "ip_address" "text", "user_id" "uuid", "metadata" "jsonb") TO "service_role";



GRANT ALL ON FUNCTION "public"."mask_guest_field"("field_value" "text", "field_name" "text", "user_permissions" "text"[], "classification_override" "public"."data_classification") TO "anon";
GRANT ALL ON FUNCTION "public"."mask_guest_field"("field_value" "text", "field_name" "text", "user_permissions" "text"[], "classification_override" "public"."data_classification") TO "authenticated";
GRANT ALL ON FUNCTION "public"."mask_guest_field"("field_value" "text", "field_name" "text", "user_permissions" "text"[], "classification_override" "public"."data_classification") TO "service_role";



GRANT ALL ON FUNCTION "public"."mask_sensitive_audit_data"("data_value" "text", "field_name" "text", "user_role" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."mask_sensitive_audit_data"("data_value" "text", "field_name" "text", "user_role" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."mask_sensitive_audit_data"("data_value" "text", "field_name" "text", "user_role" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."mask_sensitive_data"("data_value" "text", "user_role" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."mask_sensitive_data"("data_value" "text", "user_role" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."mask_sensitive_data"("data_value" "text", "user_role" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."process_auto_check_operations"() TO "anon";
GRANT ALL ON FUNCTION "public"."process_auto_check_operations"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."process_auto_check_operations"() TO "service_role";



GRANT ALL ON FUNCTION "public"."process_auto_checkins"() TO "anon";
GRANT ALL ON FUNCTION "public"."process_auto_checkins"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."process_auto_checkins"() TO "service_role";



GRANT ALL ON FUNCTION "public"."process_auto_checkouts"() TO "anon";
GRANT ALL ON FUNCTION "public"."process_auto_checkouts"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."process_auto_checkouts"() TO "service_role";



GRANT ALL ON FUNCTION "public"."safe_delete_owner"("owner_id_param" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."safe_delete_owner"("owner_id_param" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."safe_delete_owner"("owner_id_param" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."safe_delete_room"("room_id_param" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."safe_delete_room"("room_id_param" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."safe_delete_room"("room_id_param" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."sanitize_contract_template_content"() TO "anon";
GRANT ALL ON FUNCTION "public"."sanitize_contract_template_content"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."sanitize_contract_template_content"() TO "service_role";



GRANT ALL ON FUNCTION "public"."sanitize_html_content"("input_html" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."sanitize_html_content"("input_html" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."sanitize_html_content"("input_html" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."set_pdf_contract_templates_user"() TO "anon";
GRANT ALL ON FUNCTION "public"."set_pdf_contract_templates_user"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."set_pdf_contract_templates_user"() TO "service_role";



GRANT ALL ON FUNCTION "public"."trigger_admin_2fa_enforcement"() TO "anon";
GRANT ALL ON FUNCTION "public"."trigger_admin_2fa_enforcement"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."trigger_admin_2fa_enforcement"() TO "service_role";



GRANT ALL ON FUNCTION "public"."update_guest_consent"("guest_id" "uuid", "data_processing" boolean, "marketing" boolean, "third_party_sharing" boolean, "consent_metadata" "jsonb") TO "anon";
GRANT ALL ON FUNCTION "public"."update_guest_consent"("guest_id" "uuid", "data_processing" boolean, "marketing" boolean, "third_party_sharing" boolean, "consent_metadata" "jsonb") TO "authenticated";
GRANT ALL ON FUNCTION "public"."update_guest_consent"("guest_id" "uuid", "data_processing" boolean, "marketing" boolean, "third_party_sharing" boolean, "consent_metadata" "jsonb") TO "service_role";



GRANT ALL ON FUNCTION "public"."update_notification_timestamps"() TO "anon";
GRANT ALL ON FUNCTION "public"."update_notification_timestamps"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."update_notification_timestamps"() TO "service_role";



GRANT ALL ON FUNCTION "public"."update_room_status"("room_uuid" "uuid", "new_status" "public"."room_status", "user_uuid" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."update_room_status"("room_uuid" "uuid", "new_status" "public"."room_status", "user_uuid" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."update_room_status"("room_uuid" "uuid", "new_status" "public"."room_status", "user_uuid" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."update_updated_at_column"() TO "anon";
GRANT ALL ON FUNCTION "public"."update_updated_at_column"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."update_updated_at_column"() TO "service_role";



GRANT ALL ON FUNCTION "public"."user_can_access_guest"("guest_id" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."user_can_access_guest"("guest_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."user_can_access_guest"("guest_id" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."user_has_mfa"("uid" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."user_has_mfa"("uid" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."user_has_mfa"("uid" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."validate_document_access"("bucket_name" "text", "file_path" "text", "user_id" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."validate_document_access"("bucket_name" "text", "file_path" "text", "user_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."validate_document_access"("bucket_name" "text", "file_path" "text", "user_id" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."validate_email"("email_input" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."validate_email"("email_input" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."validate_email"("email_input" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."validate_file_upload"("file_name" "text", "file_size" bigint, "content_type" "text", "bucket_name" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."validate_file_upload"("file_name" "text", "file_size" bigint, "content_type" "text", "bucket_name" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."validate_file_upload"("file_name" "text", "file_size" bigint, "content_type" "text", "bucket_name" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."validate_guest_document_access"("guest_id" "uuid", "document_type" "text", "document_path" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."validate_guest_document_access"("guest_id" "uuid", "document_type" "text", "document_path" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."validate_guest_document_access"("guest_id" "uuid", "document_type" "text", "document_path" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."validate_html_content"("input_html" "text", "max_length" integer) TO "anon";
GRANT ALL ON FUNCTION "public"."validate_html_content"("input_html" "text", "max_length" integer) TO "authenticated";
GRANT ALL ON FUNCTION "public"."validate_html_content"("input_html" "text", "max_length" integer) TO "service_role";



GRANT ALL ON FUNCTION "public"."validate_phone"("phone_input" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."validate_phone"("phone_input" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."validate_phone"("phone_input" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."validate_session_security"("session_data" "jsonb") TO "anon";
GRANT ALL ON FUNCTION "public"."validate_session_security"("session_data" "jsonb") TO "authenticated";
GRANT ALL ON FUNCTION "public"."validate_session_security"("session_data" "jsonb") TO "service_role";



GRANT ALL ON FUNCTION "public"."validate_user_session"("session_token_param" "text", "current_ip" "inet", "current_user_agent" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."validate_user_session"("session_token_param" "text", "current_ip" "inet", "current_user_agent" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."validate_user_session"("session_token_param" "text", "current_ip" "inet", "current_user_agent" "text") TO "service_role";
























GRANT ALL ON TABLE "public"."account_lockouts" TO "anon";
GRANT ALL ON TABLE "public"."account_lockouts" TO "authenticated";
GRANT ALL ON TABLE "public"."account_lockouts" TO "service_role";



GRANT ALL ON TABLE "public"."admin_2fa_enforcement" TO "anon";
GRANT ALL ON TABLE "public"."admin_2fa_enforcement" TO "authenticated";
GRANT ALL ON TABLE "public"."admin_2fa_enforcement" TO "service_role";



GRANT ALL ON TABLE "public"."audit_access_log" TO "anon";
GRANT ALL ON TABLE "public"."audit_access_log" TO "authenticated";
GRANT ALL ON TABLE "public"."audit_access_log" TO "service_role";



GRANT ALL ON TABLE "public"."audit_logs" TO "anon";
GRANT ALL ON TABLE "public"."audit_logs" TO "authenticated";
GRANT ALL ON TABLE "public"."audit_logs" TO "service_role";



GRANT ALL ON TABLE "public"."profiles" TO "anon";
GRANT ALL ON TABLE "public"."profiles" TO "authenticated";
GRANT ALL ON TABLE "public"."profiles" TO "service_role";



GRANT ALL ON TABLE "public"."audit_logs_with_entities" TO "anon";
GRANT ALL ON TABLE "public"."audit_logs_with_entities" TO "authenticated";
GRANT ALL ON TABLE "public"."audit_logs_with_entities" TO "service_role";



GRANT ALL ON TABLE "public"."booking_agents" TO "anon";
GRANT ALL ON TABLE "public"."booking_agents" TO "authenticated";
GRANT ALL ON TABLE "public"."booking_agents" TO "service_role";



GRANT ALL ON TABLE "public"."booking_sources" TO "anon";
GRANT ALL ON TABLE "public"."booking_sources" TO "authenticated";
GRANT ALL ON TABLE "public"."booking_sources" TO "service_role";



GRANT ALL ON TABLE "public"."bookings" TO "anon";
GRANT ALL ON TABLE "public"."bookings" TO "authenticated";
GRANT ALL ON TABLE "public"."bookings" TO "service_role";



GRANT ALL ON TABLE "public"."cleaning_tasks" TO "anon";
GRANT ALL ON TABLE "public"."cleaning_tasks" TO "authenticated";
GRANT ALL ON TABLE "public"."cleaning_tasks" TO "service_role";



GRANT ALL ON TABLE "public"."contract_templates" TO "anon";
GRANT ALL ON TABLE "public"."contract_templates" TO "authenticated";
GRANT ALL ON TABLE "public"."contract_templates" TO "service_role";



GRANT ALL ON TABLE "public"."expense_categories" TO "anon";
GRANT ALL ON TABLE "public"."expense_categories" TO "authenticated";
GRANT ALL ON TABLE "public"."expense_categories" TO "service_role";



GRANT ALL ON TABLE "public"."expenses" TO "anon";
GRANT ALL ON TABLE "public"."expenses" TO "authenticated";
GRANT ALL ON TABLE "public"."expenses" TO "service_role";



GRANT ALL ON TABLE "public"."general_settings" TO "anon";
GRANT ALL ON TABLE "public"."general_settings" TO "authenticated";
GRANT ALL ON TABLE "public"."general_settings" TO "service_role";



GRANT ALL ON TABLE "public"."guest_data_classification" TO "anon";
GRANT ALL ON TABLE "public"."guest_data_classification" TO "authenticated";
GRANT ALL ON TABLE "public"."guest_data_classification" TO "service_role";



GRANT ALL ON TABLE "public"."guests" TO "anon";
GRANT ALL ON TABLE "public"."guests" TO "authenticated";
GRANT ALL ON TABLE "public"."guests" TO "service_role";



GRANT ALL ON TABLE "public"."ip_access_rules" TO "anon";
GRANT ALL ON TABLE "public"."ip_access_rules" TO "authenticated";
GRANT ALL ON TABLE "public"."ip_access_rules" TO "service_role";



GRANT ALL ON TABLE "public"."login_anomalies" TO "anon";
GRANT ALL ON TABLE "public"."login_anomalies" TO "authenticated";
GRANT ALL ON TABLE "public"."login_anomalies" TO "service_role";



GRANT ALL ON TABLE "public"."notification_settings" TO "anon";
GRANT ALL ON TABLE "public"."notification_settings" TO "authenticated";
GRANT ALL ON TABLE "public"."notification_settings" TO "service_role";



GRANT ALL ON TABLE "public"."notifications" TO "anon";
GRANT ALL ON TABLE "public"."notifications" TO "authenticated";
GRANT ALL ON TABLE "public"."notifications" TO "service_role";



GRANT ALL ON TABLE "public"."owners" TO "anon";
GRANT ALL ON TABLE "public"."owners" TO "authenticated";
GRANT ALL ON TABLE "public"."owners" TO "service_role";



GRANT ALL ON TABLE "public"."payment_methods" TO "anon";
GRANT ALL ON TABLE "public"."payment_methods" TO "authenticated";
GRANT ALL ON TABLE "public"."payment_methods" TO "service_role";



GRANT ALL ON TABLE "public"."pdf_field_mappings" TO "anon";
GRANT ALL ON TABLE "public"."pdf_field_mappings" TO "authenticated";
GRANT ALL ON TABLE "public"."pdf_field_mappings" TO "service_role";



GRANT ALL ON TABLE "public"."properties" TO "anon";
GRANT ALL ON TABLE "public"."properties" TO "authenticated";
GRANT ALL ON TABLE "public"."properties" TO "service_role";



GRANT ALL ON TABLE "public"."property_ownership" TO "anon";
GRANT ALL ON TABLE "public"."property_ownership" TO "authenticated";
GRANT ALL ON TABLE "public"."property_ownership" TO "service_role";



GRANT ALL ON TABLE "public"."room_ownership" TO "anon";
GRANT ALL ON TABLE "public"."room_ownership" TO "authenticated";
GRANT ALL ON TABLE "public"."room_ownership" TO "service_role";



GRANT ALL ON TABLE "public"."room_types" TO "anon";
GRANT ALL ON TABLE "public"."room_types" TO "authenticated";
GRANT ALL ON TABLE "public"."room_types" TO "service_role";



GRANT ALL ON TABLE "public"."rooms" TO "anon";
GRANT ALL ON TABLE "public"."rooms" TO "authenticated";
GRANT ALL ON TABLE "public"."rooms" TO "service_role";



GRANT ALL ON TABLE "public"."secure_password_reset_tokens" TO "anon";
GRANT ALL ON TABLE "public"."secure_password_reset_tokens" TO "authenticated";
GRANT ALL ON TABLE "public"."secure_password_reset_tokens" TO "service_role";



GRANT ALL ON TABLE "public"."security_events" TO "anon";
GRANT ALL ON TABLE "public"."security_events" TO "authenticated";
GRANT ALL ON TABLE "public"."security_events" TO "service_role";



GRANT ALL ON TABLE "public"."security_incidents" TO "anon";
GRANT ALL ON TABLE "public"."security_incidents" TO "authenticated";
GRANT ALL ON TABLE "public"."security_incidents" TO "service_role";



GRANT ALL ON TABLE "public"."user_2fa_tokens" TO "anon";
GRANT ALL ON TABLE "public"."user_2fa_tokens" TO "authenticated";
GRANT ALL ON TABLE "public"."user_2fa_tokens" TO "service_role";



GRANT ALL ON TABLE "public"."user_role_assignments" TO "anon";
GRANT ALL ON TABLE "public"."user_role_assignments" TO "authenticated";
GRANT ALL ON TABLE "public"."user_role_assignments" TO "service_role";



GRANT ALL ON TABLE "public"."user_roles" TO "anon";
GRANT ALL ON TABLE "public"."user_roles" TO "authenticated";
GRANT ALL ON TABLE "public"."user_roles" TO "service_role";



GRANT ALL ON TABLE "public"."user_sessions" TO "anon";
GRANT ALL ON TABLE "public"."user_sessions" TO "authenticated";
GRANT ALL ON TABLE "public"."user_sessions" TO "service_role";









ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON SEQUENCES TO "postgres";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON SEQUENCES TO "anon";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON SEQUENCES TO "authenticated";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON SEQUENCES TO "service_role";






ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON FUNCTIONS TO "postgres";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON FUNCTIONS TO "anon";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON FUNCTIONS TO "authenticated";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON FUNCTIONS TO "service_role";






ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON TABLES TO "postgres";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON TABLES TO "anon";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON TABLES TO "authenticated";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON TABLES TO "service_role";































