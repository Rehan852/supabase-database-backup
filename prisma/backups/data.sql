SET session_replication_role = replica;

--
-- PostgreSQL database dump
--

-- \restrict C96VwJZO5ssVrRqmKMbWIlXodSaCZEy5B8INjBs67Tgdw6jabRvMxO8hBWGom3m

-- Dumped from database version 17.6
-- Dumped by pg_dump version 17.6

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
-- Data for Name: audit_log_entries; Type: TABLE DATA; Schema: auth; Owner: supabase_auth_admin
--

COPY "auth"."audit_log_entries" ("instance_id", "id", "payload", "created_at", "ip_address") FROM stdin;
\.


--
-- Data for Name: flow_state; Type: TABLE DATA; Schema: auth; Owner: supabase_auth_admin
--

COPY "auth"."flow_state" ("id", "user_id", "auth_code", "code_challenge_method", "code_challenge", "provider_type", "provider_access_token", "provider_refresh_token", "created_at", "updated_at", "authentication_method", "auth_code_issued_at") FROM stdin;
\.


--
-- Data for Name: users; Type: TABLE DATA; Schema: auth; Owner: supabase_auth_admin
--

COPY "auth"."users" ("instance_id", "id", "aud", "role", "email", "encrypted_password", "email_confirmed_at", "invited_at", "confirmation_token", "confirmation_sent_at", "recovery_token", "recovery_sent_at", "email_change_token_new", "email_change", "email_change_sent_at", "last_sign_in_at", "raw_app_meta_data", "raw_user_meta_data", "is_super_admin", "created_at", "updated_at", "phone", "phone_confirmed_at", "phone_change", "phone_change_token", "phone_change_sent_at", "email_change_token_current", "email_change_confirm_status", "banned_until", "reauthentication_token", "reauthentication_sent_at", "is_sso_user", "deleted_at", "is_anonymous") FROM stdin;
00000000-0000-0000-0000-000000000000	a69a63d4-5a72-47c5-9f74-189e6d5b3a92	authenticated	authenticated	staff@hotel.com	$2a$10$fFBOg0kL6iO67Fcw5x6G5eXYxHJraVoVop3bWHthzGnrP0cAVmZS.	2025-11-05 04:20:54.614973+00	\N		\N		\N			\N	\N	{"provider": "email", "providers": ["email"]}	{}	\N	2025-11-05 03:59:03.2391+00	2025-11-05 03:59:03.243858+00	\N	\N			\N		0	\N		\N	f	\N	f
00000000-0000-0000-0000-000000000000	1ff73fef-fe5c-4eb9-84d5-7d02b9ccdafe	authenticated	authenticated	manager@hotel.com	$2a$10$fZVL.w/93BlnmpnqahVd0eKUKtf/CPjw666cgMurR64tXvkg4nnoy	2025-11-05 04:20:54.614973+00	\N		\N		\N			\N	\N	{"provider": "email", "providers": ["email"]}	{}	\N	2025-11-05 03:59:21.633764+00	2025-11-05 03:59:21.63775+00	\N	\N			\N		0	\N		\N	f	\N	f
00000000-0000-0000-0000-000000000000	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	authenticated	authenticated	amer@gmail.com	$2a$10$4AUQEYW5SZYwWTsTeM/s6e0awSF5MUcMXryKxd4LSCptX0h5RzLwu	2025-11-05 04:54:05.920273+00	\N		\N		\N			\N	2025-11-11 16:39:03.747461+00	{"provider": "email", "providers": ["email"]}	{"name": "Rehan", "roleName": "admin", "email_verified": true}	\N	2025-11-05 04:54:05.890132+00	2025-11-12 19:21:44.039955+00	\N	\N			\N		0	\N		\N	f	\N	f
00000000-0000-0000-0000-000000000000	679c2251-78d4-4d83-ab54-54ac1c790ed5	authenticated	authenticated	owner@hotel.com	$2a$10$zHTku6txH8q4SISkANYPhuu6Db5Q3sQ0O4LuAsjQ44TFn41pxIrtu	2025-11-05 04:20:54.614973+00	\N		\N		\N			\N	2025-11-10 19:17:17.124251+00	{"provider": "email", "providers": ["email"]}	{}	\N	2025-11-05 03:59:35.379966+00	2025-11-11 07:12:26.213477+00	\N	\N			\N		0	\N		\N	f	\N	f
00000000-0000-0000-0000-000000000000	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	authenticated	authenticated	admin@hotel.com	$2a$10$Un2H9fe9y/96ARcbWyOP6.kO5.ol7Txd7OWQqWi8tMng93KF/LsBy	2025-11-05 04:20:54.614973+00	\N		\N	acddf4785013ddd731dc75160ee8d6183a17342a99e972d8cbad1fd6	2025-11-05 20:09:12.676542+00			\N	2025-11-17 16:36:03.338226+00	{"provider": "email", "providers": ["email"]}	{}	\N	2025-11-05 03:58:51.268906+00	2025-11-17 16:36:03.396114+00	\N	\N			\N		0	\N		\N	f	\N	f
\.


--
-- Data for Name: identities; Type: TABLE DATA; Schema: auth; Owner: supabase_auth_admin
--

COPY "auth"."identities" ("provider_id", "user_id", "identity_data", "provider", "last_sign_in_at", "created_at", "updated_at", "id") FROM stdin;
a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	{"sub": "a28dedd7-1b1b-4ed2-8d6a-52984f7223d6", "email": "admin@hotel.com", "email_verified": false, "phone_verified": false}	email	2025-11-05 03:58:51.287604+00	2025-11-05 03:58:51.288309+00	2025-11-05 03:58:51.288309+00	ace21117-0c01-429f-bd14-a58fb7d659d5
a69a63d4-5a72-47c5-9f74-189e6d5b3a92	a69a63d4-5a72-47c5-9f74-189e6d5b3a92	{"sub": "a69a63d4-5a72-47c5-9f74-189e6d5b3a92", "email": "staff@hotel.com", "email_verified": false, "phone_verified": false}	email	2025-11-05 03:59:03.241579+00	2025-11-05 03:59:03.241641+00	2025-11-05 03:59:03.241641+00	66f79c31-1d10-40a3-b4f0-fdd6aa9e3e16
1ff73fef-fe5c-4eb9-84d5-7d02b9ccdafe	1ff73fef-fe5c-4eb9-84d5-7d02b9ccdafe	{"sub": "1ff73fef-fe5c-4eb9-84d5-7d02b9ccdafe", "email": "manager@hotel.com", "email_verified": false, "phone_verified": false}	email	2025-11-05 03:59:21.63551+00	2025-11-05 03:59:21.635559+00	2025-11-05 03:59:21.635559+00	86409a75-197b-4b84-8d92-32dc9f9dd38b
679c2251-78d4-4d83-ab54-54ac1c790ed5	679c2251-78d4-4d83-ab54-54ac1c790ed5	{"sub": "679c2251-78d4-4d83-ab54-54ac1c790ed5", "email": "owner@hotel.com", "email_verified": false, "phone_verified": false}	email	2025-11-05 03:59:35.382995+00	2025-11-05 03:59:35.383044+00	2025-11-05 03:59:35.383044+00	625a222a-996f-4a10-9e0a-262c8510da69
9734db5d-cccf-4f1c-84b2-cdd5e094e9da	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	{"sub": "9734db5d-cccf-4f1c-84b2-cdd5e094e9da", "email": "amer@gmail.com", "email_verified": false, "phone_verified": false}	email	2025-11-05 04:54:05.911417+00	2025-11-05 04:54:05.91148+00	2025-11-05 04:54:05.91148+00	1d36355d-b8f1-44fd-85da-65b29d2382fd
\.


--
-- Data for Name: instances; Type: TABLE DATA; Schema: auth; Owner: supabase_auth_admin
--

COPY "auth"."instances" ("id", "uuid", "raw_base_config", "created_at", "updated_at") FROM stdin;
\.


--
-- Data for Name: oauth_clients; Type: TABLE DATA; Schema: auth; Owner: supabase_auth_admin
--

COPY "auth"."oauth_clients" ("id", "client_secret_hash", "registration_type", "redirect_uris", "grant_types", "client_name", "client_uri", "logo_uri", "created_at", "updated_at", "deleted_at", "client_type") FROM stdin;
\.


--
-- Data for Name: sessions; Type: TABLE DATA; Schema: auth; Owner: supabase_auth_admin
--

COPY "auth"."sessions" ("id", "user_id", "created_at", "updated_at", "factor_id", "aal", "not_after", "refreshed_at", "user_agent", "ip", "tag", "oauth_client_id", "refresh_token_hmac_key", "refresh_token_counter") FROM stdin;
bf8c0852-853c-4941-924d-d80130f2efcb	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	2025-11-11 16:48:21.49088+00	2025-11-11 16:48:21.49088+00	\N	aal1	\N	\N	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	152.59.200.116	\N	\N	\N	\N
9ef11119-3dd7-408d-a90f-1b8a920cdd95	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	2025-11-12 08:59:37.920227+00	2025-11-12 08:59:37.920227+00	\N	aal1	\N	\N	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36	152.59.205.16	\N	\N	\N	\N
08423489-c081-4e8a-8e1b-4a6db85ca270	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	2025-11-12 06:34:10.087309+00	2025-11-12 19:11:36.567797+00	\N	aal1	\N	2025-11-12 19:11:36.56769	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36	152.57.233.15	\N	\N	\N	\N
c0321131-a6f1-472b-b18c-fa8a93a37de4	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	2025-11-11 16:39:03.751277+00	2025-11-12 19:21:44.044088+00	\N	aal1	\N	2025-11-12 19:21:44.043434	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	152.57.233.15	\N	\N	\N	\N
8f133826-ec81-42f0-9266-957b085863b8	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	2025-11-17 16:36:03.338954+00	2025-11-17 16:36:03.338954+00	\N	aal1	\N	\N	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	152.57.232.104	\N	\N	\N	\N
\.


--
-- Data for Name: mfa_amr_claims; Type: TABLE DATA; Schema: auth; Owner: supabase_auth_admin
--

COPY "auth"."mfa_amr_claims" ("session_id", "created_at", "updated_at", "authentication_method", "id") FROM stdin;
c0321131-a6f1-472b-b18c-fa8a93a37de4	2025-11-11 16:39:03.792042+00	2025-11-11 16:39:03.792042+00	password	f0b2ed6e-3e8a-4ae0-8514-44cdd7bfc345
bf8c0852-853c-4941-924d-d80130f2efcb	2025-11-11 16:48:21.508535+00	2025-11-11 16:48:21.508535+00	password	895181e6-8230-40f5-900d-e09b23c13150
08423489-c081-4e8a-8e1b-4a6db85ca270	2025-11-12 06:34:10.146167+00	2025-11-12 06:34:10.146167+00	password	fcedd947-fe97-405a-b604-7a94341c671b
9ef11119-3dd7-408d-a90f-1b8a920cdd95	2025-11-12 08:59:37.958294+00	2025-11-12 08:59:37.958294+00	password	92b591d4-6845-4aee-b777-490eb99fd5e2
8f133826-ec81-42f0-9266-957b085863b8	2025-11-17 16:36:03.400008+00	2025-11-17 16:36:03.400008+00	password	2b607c9c-353f-4079-8e53-5d95c817f176
\.


--
-- Data for Name: mfa_factors; Type: TABLE DATA; Schema: auth; Owner: supabase_auth_admin
--

COPY "auth"."mfa_factors" ("id", "user_id", "friendly_name", "factor_type", "status", "created_at", "updated_at", "secret", "phone", "last_challenged_at", "web_authn_credential", "web_authn_aaguid", "last_webauthn_challenge_data") FROM stdin;
\.


--
-- Data for Name: mfa_challenges; Type: TABLE DATA; Schema: auth; Owner: supabase_auth_admin
--

COPY "auth"."mfa_challenges" ("id", "factor_id", "created_at", "verified_at", "ip_address", "otp_code", "web_authn_session_data") FROM stdin;
\.


--
-- Data for Name: oauth_authorizations; Type: TABLE DATA; Schema: auth; Owner: supabase_auth_admin
--

COPY "auth"."oauth_authorizations" ("id", "authorization_id", "client_id", "user_id", "redirect_uri", "scope", "state", "resource", "code_challenge", "code_challenge_method", "response_type", "status", "authorization_code", "created_at", "expires_at", "approved_at") FROM stdin;
\.


--
-- Data for Name: oauth_consents; Type: TABLE DATA; Schema: auth; Owner: supabase_auth_admin
--

COPY "auth"."oauth_consents" ("id", "user_id", "client_id", "scopes", "granted_at", "revoked_at") FROM stdin;
\.


--
-- Data for Name: one_time_tokens; Type: TABLE DATA; Schema: auth; Owner: supabase_auth_admin
--

COPY "auth"."one_time_tokens" ("id", "user_id", "token_type", "token_hash", "relates_to", "created_at", "updated_at") FROM stdin;
25bb8bc7-4a94-4f22-9db1-ea16c38d771a	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	recovery_token	acddf4785013ddd731dc75160ee8d6183a17342a99e972d8cbad1fd6	admin@hotel.com	2025-11-05 20:09:14.679807	2025-11-05 20:09:14.679807
\.


--
-- Data for Name: refresh_tokens; Type: TABLE DATA; Schema: auth; Owner: supabase_auth_admin
--

COPY "auth"."refresh_tokens" ("instance_id", "id", "token", "user_id", "revoked", "created_at", "updated_at", "parent", "session_id") FROM stdin;
00000000-0000-0000-0000-000000000000	63	fxdrryim54ym	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	f	2025-11-11 16:48:21.500339+00	2025-11-11 16:48:21.500339+00	\N	bf8c0852-853c-4941-924d-d80130f2efcb
00000000-0000-0000-0000-000000000000	64	totzfpklf334	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	t	2025-11-12 06:34:10.118754+00	2025-11-12 08:20:17.824377+00	\N	08423489-c081-4e8a-8e1b-4a6db85ca270
00000000-0000-0000-0000-000000000000	66	njmk24cidftg	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	f	2025-11-12 08:59:37.945278+00	2025-11-12 08:59:37.945278+00	\N	9ef11119-3dd7-408d-a90f-1b8a920cdd95
00000000-0000-0000-0000-000000000000	65	z4go7373rhtd	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	t	2025-11-12 08:20:17.846963+00	2025-11-12 15:41:37.138768+00	totzfpklf334	08423489-c081-4e8a-8e1b-4a6db85ca270
00000000-0000-0000-0000-000000000000	67	f6eyrkx6wa6k	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	t	2025-11-12 15:41:37.148778+00	2025-11-12 16:39:47.932326+00	z4go7373rhtd	08423489-c081-4e8a-8e1b-4a6db85ca270
00000000-0000-0000-0000-000000000000	68	q37mf53yuvgc	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	t	2025-11-12 16:39:47.943805+00	2025-11-12 18:08:37.589523+00	f6eyrkx6wa6k	08423489-c081-4e8a-8e1b-4a6db85ca270
00000000-0000-0000-0000-000000000000	62	dsabuevrcxsl	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	t	2025-11-11 16:39:03.776101+00	2025-11-12 18:22:50.253956+00	\N	c0321131-a6f1-472b-b18c-fa8a93a37de4
00000000-0000-0000-0000-000000000000	69	7denqvyb4rto	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	t	2025-11-12 18:08:37.617101+00	2025-11-12 19:11:36.542526+00	q37mf53yuvgc	08423489-c081-4e8a-8e1b-4a6db85ca270
00000000-0000-0000-0000-000000000000	71	tp7yx4rahyat	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	f	2025-11-12 19:11:36.554445+00	2025-11-12 19:11:36.554445+00	7denqvyb4rto	08423489-c081-4e8a-8e1b-4a6db85ca270
00000000-0000-0000-0000-000000000000	70	mpl2swchaem7	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	t	2025-11-12 18:22:50.25935+00	2025-11-12 19:21:44.028262+00	dsabuevrcxsl	c0321131-a6f1-472b-b18c-fa8a93a37de4
00000000-0000-0000-0000-000000000000	72	774bcao6yl7o	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	f	2025-11-12 19:21:44.035926+00	2025-11-12 19:21:44.035926+00	mpl2swchaem7	c0321131-a6f1-472b-b18c-fa8a93a37de4
00000000-0000-0000-0000-000000000000	73	c2jdohkqiwsu	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	f	2025-11-17 16:36:03.370432+00	2025-11-17 16:36:03.370432+00	\N	8f133826-ec81-42f0-9266-957b085863b8
\.


--
-- Data for Name: sso_providers; Type: TABLE DATA; Schema: auth; Owner: supabase_auth_admin
--

COPY "auth"."sso_providers" ("id", "resource_id", "created_at", "updated_at", "disabled") FROM stdin;
\.


--
-- Data for Name: saml_providers; Type: TABLE DATA; Schema: auth; Owner: supabase_auth_admin
--

COPY "auth"."saml_providers" ("id", "sso_provider_id", "entity_id", "metadata_xml", "metadata_url", "attribute_mapping", "created_at", "updated_at", "name_id_format") FROM stdin;
\.


--
-- Data for Name: saml_relay_states; Type: TABLE DATA; Schema: auth; Owner: supabase_auth_admin
--

COPY "auth"."saml_relay_states" ("id", "sso_provider_id", "request_id", "for_email", "redirect_to", "created_at", "updated_at", "flow_state_id") FROM stdin;
\.


--
-- Data for Name: sso_domains; Type: TABLE DATA; Schema: auth; Owner: supabase_auth_admin
--

COPY "auth"."sso_domains" ("id", "sso_provider_id", "domain", "created_at", "updated_at") FROM stdin;
\.


--
-- Data for Name: account_lockouts; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."account_lockouts" ("id", "user_email", "lockout_level", "attempts_count", "locked_until", "ip_address", "created_at", "updated_at") FROM stdin;
\.


--
-- Data for Name: admin_2fa_enforcement; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."admin_2fa_enforcement" ("id", "user_id", "user_email", "admin_role_assigned_at", "enforcement_deadline", "is_2fa_enabled", "reminder_sent_count", "last_reminder_sent", "is_enforced", "enforced_at", "created_at", "updated_at") FROM stdin;
b27094ab-453e-460f-9811-04eb8807d394	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	Amer@gmail.com	2025-11-05 04:54:06.207912+00	2025-11-06 04:54:06.207912+00	f	0	\N	f	\N	2025-11-05 04:54:06.207912+00	2025-11-05 04:54:06.207912+00
f3b79f30-f381-46a0-bbaa-94f3b8194bbc	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	admin@hotel.com	2025-11-05 04:01:46.785371+00	2025-11-06 04:01:46.785371+00	f	0	\N	f	\N	2025-11-05 04:54:06.207912+00	2025-11-05 04:54:06.207912+00
\.


--
-- Data for Name: audit_access_log; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."audit_access_log" ("id", "user_id", "accessed_at", "access_type", "record_count", "filters_applied", "ip_address", "user_agent", "session_id") FROM stdin;
f5e4d2be-3888-4b76-9aab-6c6945b11fc6	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	2025-11-11 16:38:40.856004+00	user_view	0	{"limit": 5, "user_id": "9734db5d-cccf-4f1c-84b2-cdd5e094e9da"}	152.59.200.116	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	\N
22f5dd69-8d6f-41d5-9c27-4844f7df6e8e	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	2025-11-11 16:38:41.567928+00	user_view_complete	1	{"limit": 5, "user_id": "9734db5d-cccf-4f1c-84b2-cdd5e094e9da"}	152.59.200.116	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	\N
859fe958-b60b-4b34-a80e-7fb9c3784262	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	2025-11-12 06:38:46.989307+00	user_view	0	{"limit": 5, "user_id": "9734db5d-cccf-4f1c-84b2-cdd5e094e9da"}	152.59.205.16	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36	\N
d72228d6-d470-40c5-98a4-d8d0accdbef3	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	2025-11-12 06:38:47.898099+00	user_view_complete	1	{"limit": 5, "user_id": "9734db5d-cccf-4f1c-84b2-cdd5e094e9da"}	152.59.205.16	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36	\N
\.


--
-- Data for Name: audit_logs; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."audit_logs" ("id", "user_id", "action", "table_name", "record_id", "old_values", "new_values", "ip_address", "user_agent", "session_id", "timestamp", "location_country", "location_region", "location_city", "old_values_encrypted", "new_values_encrypted", "user_agent_encrypted") FROM stdin;
77affc74-1e3e-4824-8406-3cf32b5a6538	\N	INSERT	user_role_assignments	b62b1b36-8e67-44e5-ab4f-40386dd15f42	\N	{"id": "b62b1b36-8e67-44e5-ab4f-40386dd15f42", "role_id": "c2723abb-0273-449f-8254-742b4c464b7e", "user_id": "a28dedd7-1b1b-4ed2-8d6a-52984f7223d6", "created_at": "2025-11-05T04:01:46.785371+00:00", "assigned_by": "a28dedd7-1b1b-4ed2-8d6a-52984f7223d6"}	2406:da18:96a:8201:9d77:cc07:f20a:966e	\N	\N	2025-11-05 04:01:46.785371+00	\N	\N	\N	\N	\N	\N
eb6238b3-af56-491e-9249-8732d914b2b3	\N	INSERT	user_role_assignments	ab14d08d-0a80-4ca8-a6f6-c1e9fae8ab51	\N	{"id": "ab14d08d-0a80-4ca8-a6f6-c1e9fae8ab51", "role_id": "f0f7fe0b-e70e-4df3-bc8f-1235d9dc1fa3", "user_id": "1ff73fef-fe5c-4eb9-84d5-7d02b9ccdafe", "created_at": "2025-11-05T04:01:46.785371+00:00", "assigned_by": "a28dedd7-1b1b-4ed2-8d6a-52984f7223d6"}	2406:da18:96a:8201:9d77:cc07:f20a:966e	\N	\N	2025-11-05 04:01:46.785371+00	\N	\N	\N	\N	\N	\N
e2270329-2366-47dd-9721-82218e47feb4	\N	INSERT	user_role_assignments	257d3421-c0b4-4fe2-ae1b-44e64ab916d8	\N	{"id": "257d3421-c0b4-4fe2-ae1b-44e64ab916d8", "role_id": "4d73be21-fb46-4ec6-aabd-bc3472e7fb58", "user_id": "a69a63d4-5a72-47c5-9f74-189e6d5b3a92", "created_at": "2025-11-05T04:01:46.785371+00:00", "assigned_by": "a28dedd7-1b1b-4ed2-8d6a-52984f7223d6"}	2406:da18:96a:8201:9d77:cc07:f20a:966e	\N	\N	2025-11-05 04:01:46.785371+00	\N	\N	\N	\N	\N	\N
693c925d-c052-4a3e-88ab-cf1ebb50a8ee	\N	INSERT	user_role_assignments	ca2fc9e5-7294-4682-8df0-ce788e8b2ed2	\N	{"id": "ca2fc9e5-7294-4682-8df0-ce788e8b2ed2", "role_id": "30dda24d-18b0-4fdb-b051-66535aa5669c", "user_id": "679c2251-78d4-4d83-ab54-54ac1c790ed5", "created_at": "2025-11-05T04:01:46.785371+00:00", "assigned_by": "a28dedd7-1b1b-4ed2-8d6a-52984f7223d6"}	2406:da18:96a:8201:9d77:cc07:f20a:966e	\N	\N	2025-11-05 04:01:46.785371+00	\N	\N	\N	\N	\N	\N
9565882a-04db-4a28-b004-5b9a50b67f6d	\N	INSERT	owners	06952e8b-bda7-4a4c-b406-94442f799a62	\N	{"id": "06952e8b-bda7-4a4c-b406-94442f799a62", "city": null, "name": "Owner User", "email": "owner@hotel.com", "phone": null, "state": null, "active": true, "address": null, "country": null, "zip_code": null, "created_at": "2025-11-05T04:01:46.785371+00:00", "created_by": null, "updated_at": "2025-11-05T04:01:46.785371+00:00", "updated_by": null, "auth_user_id": "679c2251-78d4-4d83-ab54-54ac1c790ed5", "payment_info": {}}	2406:da18:96a:8201:9d77:cc07:f20a:966e	\N	\N	2025-11-05 04:01:46.785371+00	\N	\N	\N	\N	\N	\N
f63716ad-21ca-4283-8f0d-e1f51135d34e	\N	SECURITY_FAILED_LOGIN	auth	\N	\N	{"details": {"email": "admin@example.com", "reason": "Invalid password", "timestamp": "2025-11-05 02:04:38.245775+00"}, "severity": "medium"}	192.168.1.100	Mozilla/5.0 (Windows NT 10.0; Win64; x64)	anon_session_1	2025-11-05 02:04:38.245775+00	Russia	\N	Moscow	\N	\N	\N
84c66df6-7471-4349-b170-2ca7e482e075	\N	SECURITY_FAILED_LOGIN	auth	\N	\N	{"details": {"email": "admin@example.com", "reason": "Invalid password", "timestamp": "2025-11-05 02:14:38.245775+00"}, "severity": "medium"}	192.168.1.100	Mozilla/5.0 (Windows NT 10.0; Win64; x64)	anon_session_2	2025-11-05 02:14:38.245775+00	Russia	\N	Moscow	\N	\N	\N
6e5c5517-c8b6-445e-84ee-b3cbab9d179a	\N	SECURITY_FAILED_LOGIN	auth	\N	\N	{"details": {"email": "staff@example.com", "reason": "Invalid password", "timestamp": "2025-11-05 02:24:38.245775+00"}, "severity": "medium"}	192.168.1.100	Mozilla/5.0 (Windows NT 10.0; Win64; x64)	anon_session_3	2025-11-05 02:24:38.245775+00	Russia	\N	Moscow	\N	\N	\N
6f92fefb-786d-4747-bacb-a1ebf20edb72	\N	SECURITY_FAILED_LOGIN	auth	\N	\N	{"details": {"email": "root@example.com", "reason": "Invalid password", "timestamp": "2025-11-05 02:34:38.245775+00"}, "severity": "medium"}	192.168.1.100	Mozilla/5.0 (Windows NT 10.0; Win64; x64)	anon_session_4	2025-11-05 02:34:38.245775+00	Russia	\N	Moscow	\N	\N	\N
5fd5d16d-379f-4652-b0f3-3f23ee627efc	\N	SECURITY_FAILED_LOGIN	auth	\N	\N	{"details": {"email": "administrator@example.com", "reason": "Invalid password", "timestamp": "2025-11-05 02:44:38.245775+00"}, "severity": "medium"}	192.168.1.100	Mozilla/5.0 (Windows NT 10.0; Win64; x64)	anon_session_5	2025-11-05 02:44:38.245775+00	Russia	\N	Moscow	\N	\N	\N
64b2eeb0-3651-4d64-bf93-f090c0cb9e1e	\N	SECURITY_FAILED_LOGIN	auth	\N	\N	{"details": {"email": "test@example.com", "reason": "Invalid password", "timestamp": "2025-11-05 02:54:38.245775+00"}, "severity": "medium"}	192.168.1.100	Mozilla/5.0 (Windows NT 10.0; Win64; x64)	anon_session_6	2025-11-05 02:54:38.245775+00	Russia	\N	Moscow	\N	\N	\N
7fa49fdc-5148-4d56-bf9e-bbe4b005cddd	\N	SECURITY_FAILED_LOGIN	auth	\N	\N	{"details": {"email": "admin@example.com", "reason": "Account locked", "timestamp": "2025-11-05 01:04:38.245775+00"}, "severity": "medium"}	10.0.0.50	curl/7.68.0	anon_session_7	2025-11-05 01:04:38.245775+00	China	\N	Beijing	\N	\N	\N
498a99d3-7f0e-4d5a-bc5c-4a07bdb42c5b	\N	SECURITY_FAILED_LOGIN	auth	\N	\N	{"details": {"email": "system@example.com", "reason": "Invalid password", "timestamp": "2025-11-05 01:24:38.245775+00"}, "severity": "medium"}	10.0.0.50	curl/7.68.0	anon_session_9	2025-11-05 01:24:38.245775+00	China	\N	Beijing	\N	\N	\N
f7af45b5-09a0-4328-aa5c-412c3a2a4b3a	\N	SECURITY_RATE_LIMIT_EXCEEDED	auth	\N	\N	{"details": {"attempts": 15, "endpoint": "/auth/login", "timestamp": "2025-11-05 03:04:38.245775+00"}, "severity": "high"}	192.168.1.100	Mozilla/5.0 (Windows NT 10.0; Win64; x64)	anon_session_14	2025-11-05 03:04:38.245775+00	Russia	\N	Moscow	\N	\N	\N
1ad73245-a55a-461d-8801-ceb888d4cfd1	\N	SECURITY_SUSPICIOUS_ACTIVITY	users	\N	\N	{"details": {"pattern": "Sequential user ID scanning", "activity": "Multiple user enumeration attempts", "timestamp": "2025-11-05 03:19:38.245775+00"}, "severity": "high"}	172.16.0.10	Python-requests/2.28.1	anon_session_16	2025-11-05 03:19:38.245775+00	North Korea	\N	Pyongyang	\N	\N	\N
66624b1c-43df-453e-9d92-8a2db22a5792	\N	SECURITY_UNAUTHORIZED_ACCESS	admin_panel	\N	\N	{"details": {"action": "unauthorized access attempt", "resource": "admin dashboard", "timestamp": "2025-11-05 03:49:38.245775+00"}, "severity": "critical"}	192.168.1.100	Mozilla/5.0 (Windows NT 10.0; Win64; x64)	anon_session_18	2025-11-05 03:49:38.245775+00	Russia	\N	Moscow	\N	\N	\N
42eb58e6-5fef-4408-9f07-07aa6faa20fc	\N	SECURITY_PASSWORD_BREACH_ATTEMPT	auth	\N	\N	{"details": {"email": "admin@example.com", "timestamp": "2025-11-05 03:59:38.245775+00", "attack_type": "dictionary_attack"}, "severity": "critical"}	192.168.1.100	Mozilla/5.0 (Windows NT 10.0; Win64; x64)	anon_session_20	2025-11-05 03:59:38.245775+00	Russia	\N	Moscow	\N	\N	\N
14b6aa61-291d-4ead-b2ed-7c3d273436b7	\N	UPDATE	user_roles	c2723abb-0273-449f-8254-742b4c464b7e	{"id": "c2723abb-0273-449f-8254-742b4c464b7e", "name": "admin", "is_system": true, "created_at": "2025-11-05T03:57:09.449803+00:00", "updated_at": "2025-11-05T03:57:26.48137+00:00", "description": "System Administrator with full access", "permissions": {"rooms": {"view": true, "create": true, "delete": true, "update": true}, "users": {"view": true, "create": true, "delete": true, "update": true}, "guests": {"view": true, "create": true, "delete": true, "update": true}, "owners": {"view": true, "create": true, "delete": true, "update": true}, "reports": {"view": true, "create": true}, "bookings": {"view": true, "create": true, "delete": true, "update": true}, "cleaning": {"view": true, "create": true, "delete": true, "update": true}, "expenses": {"view": true, "create": true, "delete": true, "update": true}, "settings": {"view": true, "update": true}, "auditLogs": {"view": true}}}	{"id": "c2723abb-0273-449f-8254-742b4c464b7e", "name": "admin", "is_system": true, "created_at": "2025-11-05T03:57:09.449803+00:00", "updated_at": "2025-11-05T04:07:27.470773+00:00", "description": "System Administrator with full access", "permissions": {"rooms": {"view": true, "create": true, "delete": true, "update": true}, "users": {"view": true, "create": true, "delete": true, "update": true}, "guests": {"view": true, "create": true, "delete": true, "update": true}, "owners": {"view": true, "create": true, "delete": true, "update": true}, "reports": {"view": true, "create": true}, "bookings": {"view": true, "create": true, "delete": true, "update": true}, "cleaning": {"view": true, "create": true, "delete": true, "update": true}, "expenses": {"view": true, "create": true, "delete": true, "update": true}, "settings": {"view": true, "update": true}, "auditLogs": {"view": true}, "view_bookings": true, "create_bookings": true, "delete_bookings": true, "update_bookings": true}}	2406:da18:96a:8201:9d77:cc07:f20a:966e	\N	\N	2025-11-05 04:07:27.470773+00	\N	\N	\N	\N	\N	\N
f49d0df5-590a-4056-b89b-508e2b40f644	\N	INSERT	user_role_assignments	6deb256f-0e1e-44ad-8612-a9dc5ca77ffb	\N	{"id": "6deb256f-0e1e-44ad-8612-a9dc5ca77ffb", "role_id": "c2723abb-0273-449f-8254-742b4c464b7e", "user_id": "9734db5d-cccf-4f1c-84b2-cdd5e094e9da", "created_at": "2025-11-05T04:54:06.207912+00:00", "assigned_by": null}	15.206.190.90	Deno/2.1.4 (variant; SupabaseEdgeRuntime/1.69.4)	\N	2025-11-05 04:54:06.207912+00	\N	\N	\N	\N	\N	5gVq2/qOzearWcn1veb7mD4I/qCqnOk0pfcxWVg7Fq+1rU0MvMQuy5sGbo1k5dkgzi9kcqHEUGO9\nWUnZdc4YRQ==
1c1f5f55-97e7-4e44-91fc-f8364667475b	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	SECURITY_EVENT	security_events	\N	\N	{"metadata": {"role_assigned_at": "2025-11-05T04:54:06.207912+00:00", "enforcement_deadline": "2025-11-06T04:54:06.207912+00:00"}, "severity": "high", "timestamp": "2025-11-05T04:54:06.207912+00:00", "event_type": "ADMIN_2FA_ENFORCEMENT_CREATED", "description": "2FA enforcement initiated for admin user: Amer@gmail.com"}	15.206.190.90	Deno/2.1.4 (variant; SupabaseEdgeRuntime/1.69.4)	\N	2025-11-05 04:54:06.207912+00	\N	\N	\N	\N	\N	5gVq2/qOzearWcn1veb7mD4I/qCqnOk0pfcxWVg7Fq+1rU0MvMQuy5sGbo1k5dkgzi9kcqHEUGO9\nWUnZdc4YRQ==
de8ab982-99d6-4fed-9037-244789e29bfe	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	SECURITY_EVENT	security_events	\N	\N	{"metadata": {"role_assigned_at": "2025-11-05T04:01:46.785371+00:00", "enforcement_deadline": "2025-11-06T04:01:46.785371+00:00"}, "severity": "high", "timestamp": "2025-11-05T04:54:06.207912+00:00", "event_type": "ADMIN_2FA_ENFORCEMENT_CREATED", "description": "2FA enforcement initiated for admin user: admin@hotel.com"}	15.206.190.90	Deno/2.1.4 (variant; SupabaseEdgeRuntime/1.69.4)	\N	2025-11-05 04:54:06.207912+00	\N	\N	\N	\N	\N	5gVq2/qOzearWcn1veb7mD4I/qCqnOk0pfcxWVg7Fq+1rU0MvMQuy5sGbo1k5dkgzi9kcqHEUGO9\nWUnZdc4YRQ==
b4467180-d7a3-4a73-9d48-f7232823ef2d	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	INSERT	room_types	958ec744-4d84-4764-a8f8-b232a3f448a2	\N	{"id": "958ec744-4d84-4764-a8f8-b232a3f448a2", "name": "Deluxe", "active": true, "amenities": [], "base_rate": 500, "created_at": "2025-11-05T04:54:57.964544+00:00", "created_by": "a28dedd7-1b1b-4ed2-8d6a-52984f7223d6", "max_adults": 2, "updated_at": "2025-11-05T04:54:57.964544+00:00", "updated_by": null, "description": "", "max_children": 0}	152.59.203.17	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	\N	2025-11-05 04:54:57.964544+00	\N	\N	\N	\N	\N	OiUuTUvBSPtuU528uaAKwrq7ia5K6cbfde6p3plQlYP3DQCGmh5TUSR3Vqs3VsZ56wnPKAHyzNBO\n8m9ufrY5ZM1Vh29zUQAGPR0I/1G6bHrwAhZZuN2LWbcyijl3ygutOKqsbZ51VlYeaB19QmrXzw==
a75217a7-1fac-4dd7-a9d6-d0df04537320	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	INSERT	properties	4a2e8fa0-1049-4ebd-9402-c15da8f2796e	\N	{"id": "4a2e8fa0-1049-4ebd-9402-c15da8f2796e", "city": "kjdlskjs", "name": "Rehan", "email": "admin@hotel.com", "phone": "+1-305-555-9999", "state": "lksdflk", "active": true, "address": "hyderea", "country": null, "zip_code": "kjds", "created_at": "2025-11-05T04:55:08.31288+00:00", "created_by": "a28dedd7-1b1b-4ed2-8d6a-52984f7223d6", "updated_at": "2025-11-05T04:55:08.31288+00:00", "updated_by": null, "description": ""}	152.59.203.17	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	\N	2025-11-05 04:55:08.31288+00	\N	\N	\N	\N	qlUOItiR0yN24SaKb7XpF8JNJiTDU0O856BrKww+s341q8l0Hr2xGSlYJheEY9ZMYZWQ7utz0MOn\nOIHtkETqRHiYxlqouvJD5fPmAKtVvNS7YVe2oB7eVwScwIdBWSG4SrnBEwy/dMfcpCMDipdCRyk1\nIJd+E2Q/Fi9m1lfiM0NgLbQslfb4/QjNaR1ROK5f/2nGk8gkcatHcvU4J+xkg164dCFfFRqF/ynH\nmgtlXeLJBx1ApVE+qFFC15o7gzHDb05xZB6ez2mgDR7sHzcxIxz1ksBsKdZZ4WXi8n/TeV+UZb+t\nKVSolo056tjzSRgAm+DN4IU2OlrdMbf9SM+mrRIOSpOTKGB+WKeqqdZOYePiRtmTcqcVxJEY43/b\nAedX8SdegrCEiVPPLycbZlZ+krl8Bl5c1/icvrxO1bMZ7NRpyjHDt9ALD1a/Fa4yYCHvfD1p+9Ph\nDP7WztSihTyu3tJXmkD/DLtylabGM5ghjIq5kK5tI4clzK6WJGxg66J+oFGRgyPH9psMonOAeWyb\n1yvZrI7INOtXZuzeRlBWax7S8xN5li9ORRVIx+4fY078	OiUuTUvBSPtuU528uaAKwrq7ia5K6cbfde6p3plQlYP3DQCGmh5TUSR3Vqs3VsZ56wnPKAHyzNBO\n8m9ufrY5ZM1Vh29zUQAGPR0I/1G6bHrwAhZZuN2LWbcyijl3ygutOKqsbZ51VlYeaB19QmrXzw==
31c80e09-539b-41fe-be9f-ff328a888709	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	DELETE	user_role_assignments	ab14d08d-0a80-4ca8-a6f6-c1e9fae8ab51	{"id": "ab14d08d-0a80-4ca8-a6f6-c1e9fae8ab51", "role_id": "f0f7fe0b-e70e-4df3-bc8f-1235d9dc1fa3", "user_id": "1ff73fef-fe5c-4eb9-84d5-7d02b9ccdafe", "created_at": "2025-11-05T04:01:46.785371+00:00", "assigned_by": "a28dedd7-1b1b-4ed2-8d6a-52984f7223d6"}	\N	152.59.203.17	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	\N	2025-11-05 04:56:25.108803+00	\N	\N	\N	\N	\N	OiUuTUvBSPtuU528uaAKwrq7ia5K6cbfde6p3plQlYP3DQCGmh5TUSR3Vqs3VsZ56wnPKAHyzNBO\n8m9ufrY5ZM1Vh29zUQAGPR0I/1G6bHrwAhZZuN2LWbcyijl3ygutOKqsbZ51VlYeaB19QmrXzw==
afb69283-854f-413d-a045-cdd6f4297a56	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	INSERT	rooms	134f45d8-b8a6-4204-a0ad-e673583a89fd	\N	{"id": "134f45d8-b8a6-4204-a0ad-e673583a89fd", "name": null, "size": null, "floor": null, "notes": null, "active": true, "number": "908", "status": "available", "amenities": [], "base_rate": 500, "created_at": "2025-11-05T04:57:01.826057+00:00", "created_by": "a28dedd7-1b1b-4ed2-8d6a-52984f7223d6", "image_urls": null, "max_adults": 2, "updated_at": "2025-11-05T04:57:01.826057+00:00", "updated_by": null, "description": "r", "property_id": "4a2e8fa0-1049-4ebd-9402-c15da8f2796e", "last_cleaned": null, "max_children": 0, "room_type_id": "958ec744-4d84-4764-a8f8-b232a3f448a2", "next_maintenance": null}	152.59.203.17	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	\N	2025-11-05 04:57:01.826057+00	\N	\N	\N	\N	\N	OiUuTUvBSPtuU528uaAKwrq7ia5K6cbfde6p3plQlYP3DQCGmh5TUSR3Vqs3VsZ56wnPKAHyzNBO\n8m9ufrY5ZM1Vh29zUQAGPR0I/1G6bHrwAhZZuN2LWbcyijl3ygutOKqsbZ51VlYeaB19QmrXzw==
b9b4074f-d202-4526-8cb8-bce83ea4fc2e	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	UPDATE	rooms	134f45d8-b8a6-4204-a0ad-e673583a89fd	{"id": "134f45d8-b8a6-4204-a0ad-e673583a89fd", "name": null, "size": null, "floor": null, "notes": null, "active": true, "number": "908", "status": "available", "amenities": [], "base_rate": 500, "created_at": "2025-11-05T04:57:01.826057+00:00", "created_by": "a28dedd7-1b1b-4ed2-8d6a-52984f7223d6", "image_urls": null, "max_adults": 2, "updated_at": "2025-11-05T04:57:01.826057+00:00", "updated_by": null, "description": "r", "property_id": "4a2e8fa0-1049-4ebd-9402-c15da8f2796e", "last_cleaned": null, "max_children": 0, "room_type_id": "958ec744-4d84-4764-a8f8-b232a3f448a2", "next_maintenance": null}	{"id": "134f45d8-b8a6-4204-a0ad-e673583a89fd", "name": null, "size": null, "floor": null, "notes": null, "active": true, "number": "908", "status": "dirty", "amenities": [], "base_rate": 500, "created_at": "2025-11-05T04:57:01.826057+00:00", "created_by": "a28dedd7-1b1b-4ed2-8d6a-52984f7223d6", "image_urls": null, "max_adults": 2, "updated_at": "2025-11-05T04:57:11.009285+00:00", "updated_by": null, "description": "r", "property_id": "4a2e8fa0-1049-4ebd-9402-c15da8f2796e", "last_cleaned": null, "max_children": 0, "room_type_id": "958ec744-4d84-4764-a8f8-b232a3f448a2", "next_maintenance": null}	152.59.203.17	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	\N	2025-11-05 04:57:11.009285+00	\N	\N	\N	\N	\N	OiUuTUvBSPtuU528uaAKwrq7ia5K6cbfde6p3plQlYP3DQCGmh5TUSR3Vqs3VsZ56wnPKAHyzNBO\n8m9ufrY5ZM1Vh29zUQAGPR0I/1G6bHrwAhZZuN2LWbcyijl3ygutOKqsbZ51VlYeaB19QmrXzw==
3823b450-13d1-4ed1-ad87-c22736d8d1e9	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	INSERT	properties	ed92b3ec-4951-4fa9-b36b-adc08bd4af52	\N	{"id": "ed92b3ec-4951-4fa9-b36b-adc08bd4af52", "city": "kjdlskjs", "name": "Rehan", "email": "admin@hotel.com", "phone": "+1-305-555-9999", "state": "lksdflk", "active": true, "address": "hyderea", "country": null, "zip_code": "kjds", "created_at": "2025-11-10T08:01:13.953662+00:00", "created_by": "a28dedd7-1b1b-4ed2-8d6a-52984f7223d6", "updated_at": "2025-11-10T08:01:13.953662+00:00", "updated_by": null, "description": ""}	149.40.62.27	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	\N	2025-11-10 08:01:13.953662+00	\N	\N	\N	\N	gahw0JjOBpz6JJj3chuEvgkP7i3c8eXXBTqP80iTVhnhUxj+qQoWOhV7osGZpLVDfYLSTmTIgzT8\nwLNR2FKjkrVnL5+gqtOhxwiXIQhYvq0p3wfgSl60LDAJWChYlMgAKyGOLiBIqkxYGUsKRq8/bKgZ\nDssoenptJz4aF0MYhbMH7nncL0R70c+DwoFurrzsTd74liUn0/B2ForN2aODnFvlMVBigMXIJuGT\n1x8CACGvI8Ln/53M1VardGgz0VpqmuEjkjEiRwMBDFtYTP+svFM0hq3j+vSbhtk/SMuKaNcGtW9d\n4H/k1EZ7SM4DRTiKwgjEbwo0QfX62+EUNZQYP8G27RpBG6AeYITHYLTqIIUXBsYGXPrv2qLzEUCk\ns7KDmsWsTwHQDXJYrAFSaCNlzE9GPvIkTs0ZVZF/KZsVm2AHze5TKjYf0dzZwXCJyXpEUdKa3y0U\nNP7kspTiKef2GDrR4QEd7zmRc38NBOMcOemvpY1s/IzGUedwI/PzTTYaPHMbe2jqyjTCMKF+M39H\njYPz6fA4QAQDlFzK3RvNGr9kpl4x1aO/1gbwe6CUrdwx	OiUuTUvBSPtuU528uaAKwrq7ia5K6cbfde6p3plQlYP3DQCGmh5TUSR3Vqs3VsZ56wnPKAHyzNBO\n8m9ufrY5ZM1Vh29zUQAGPR0I/1G6bHrwAhZZuN2LWbcyijl3ygutOKqsbZ51VlYeaB19QmrXzw==
c1284d88-3bfc-45b4-af6e-f90589006e8b	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	UPDATE	rooms	134f45d8-b8a6-4204-a0ad-e673583a89fd	{"id": "134f45d8-b8a6-4204-a0ad-e673583a89fd", "name": null, "size": null, "floor": null, "notes": null, "active": true, "number": "908", "status": "dirty", "amenities": [], "base_rate": 500, "created_at": "2025-11-05T04:57:01.826057+00:00", "created_by": "a28dedd7-1b1b-4ed2-8d6a-52984f7223d6", "image_urls": null, "max_adults": 2, "updated_at": "2025-11-05T04:57:11.009285+00:00", "updated_by": null, "description": "r", "property_id": "4a2e8fa0-1049-4ebd-9402-c15da8f2796e", "last_cleaned": null, "max_children": 0, "room_type_id": "958ec744-4d84-4764-a8f8-b232a3f448a2", "next_maintenance": null}	{"id": "134f45d8-b8a6-4204-a0ad-e673583a89fd", "name": null, "size": null, "floor": null, "notes": null, "active": true, "number": "908", "status": "cleaned", "amenities": [], "base_rate": 500, "created_at": "2025-11-05T04:57:01.826057+00:00", "created_by": "a28dedd7-1b1b-4ed2-8d6a-52984f7223d6", "image_urls": null, "max_adults": 2, "updated_at": "2025-11-05T04:57:14.914905+00:00", "updated_by": null, "description": "r", "property_id": "4a2e8fa0-1049-4ebd-9402-c15da8f2796e", "last_cleaned": null, "max_children": 0, "room_type_id": "958ec744-4d84-4764-a8f8-b232a3f448a2", "next_maintenance": null}	152.59.203.17	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	\N	2025-11-05 04:57:14.914905+00	\N	\N	\N	\N	\N	OiUuTUvBSPtuU528uaAKwrq7ia5K6cbfde6p3plQlYP3DQCGmh5TUSR3Vqs3VsZ56wnPKAHyzNBO\n8m9ufrY5ZM1Vh29zUQAGPR0I/1G6bHrwAhZZuN2LWbcyijl3ygutOKqsbZ51VlYeaB19QmrXzw==
72404e2f-7b67-46bb-b63b-ff90510f5ecb	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	INSERT	guests	06a738f7-ac24-4230-bc3b-b3d0b3139b4f	\N	{"id": "06a738f7-ac24-4230-bc3b-b3d0b3139b4f", "city": null, "email": "admin@hotel.com", "notes": null, "phone": "8688238150", "state": null, "address": null, "country": null, "zip_code": null, "last_name": "Rehan", "created_at": "2025-11-05T07:23:58.012993+00:00", "created_by": null, "first_name": "cregoraz", "updated_at": "2025-11-05T07:23:58.012993+00:00", "updated_by": null, "nationality": null, "access_log_id": null, "privacy_level": "standard", "id_document_url": null, "passport_number": null, "last_data_access": null, "consent_marketing": false, "consent_timestamp": null, "consent_ip_address": null, "data_retention_expiry": null, "consent_data_processing": false, "consent_third_party_sharing": false}	152.59.203.17	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	\N	2025-11-05 07:23:58.012993+00	\N	\N	\N	\N	t2l+1YrFQWk0O75TAOcWBt0VB+/USh2bDJ9A8Z71pLQuNIDD9VdqHFA9Y1T2FYM8X3C9//bLZEfZ\njDpkHg+eAjrY+Z8CF3FRhJJ7hYs9LbpWFjGIcNsRJ4BjUzYaXvZvxGWMmC0bcR5/ZJWq81QiypOx\nQ1xPXxYDSIShz7nQk/oImpvx6FR7qidNGNSWBaBL3iU2/v81Evxn9H7bz2vEUImIsJ6t3IkyblBg\niJGE/RgRCyRBGStEHMM/h13QK9WPsEIuTaXj36rC9e8msr/lvdhmT808qIdX4NHwH0l0YfTJrJz8\nyp2HbpAo4BfA0cUib/tMwE1xs0KvxVckbxTXXgR4CCuR5bRuSDO8kq858DkXUOpKKAEhQNRcrurO\nfZ/+oxTUTREa8L5aLtVoVWgNk8vhCw0NTnOn9Uakk5+3aLMjbuRALdjlV89PFk4G1uMEMncJ4Hu7\ngJ7hZPELZeBVraFrkBc1PGyEUTtqQvd7EAiwEti553tgdDlPcB9RJH9TmqyFsOIq0Mt4vre7co91\ntiRi9gvAeBxwWS57BEPcWPHY9N/VpXwa8tB3Zjx+2KI/m5oXFQl2Z+EoxsrXgYUx5EZgniuzHYFS\nGKBpX8erYAfT/GMzt/YvDCdbogHW5oiy6l2DyYnTNnQsdtAwb6PRsK8mO9gy0H+rV/ZytHYhN8/Z\n68POClrhyiymo2yZrss+oyfy1PMAB7nAExV7bBmR6VpgvxM7vzgxFsamZH4CUxN9tJqVki2i7vqO\n39D5Rk5KCjR1a839v9dDjnQFav2G+do/4hA8SKYTyX+CwRXuXpCz0zDMKwTFhNaqsAaemRwgGSzZ\nfcHYC0V3RKIHMsG8FA0oYT6U7Mw1WMh8Y23xlsvptHOzyJGfL4uH+sLWoueAbyqpkYJ6TpbFpFdP\n6ZiFWSzjUbSNO9EZKgdtvfGxYLa9bKDp6jkWvcHMEwCpudbu	OiUuTUvBSPtuU528uaAKwrq7ia5K6cbfde6p3plQlYP3DQCGmh5TUSR3Vqs3VsZ56wnPKAHyzNBO\n8m9ufrY5ZM1Vh29zUQAGPR0I/1G6bHrwAhZZuN2LWbcyijl3ygutOKqsbZ51VlYeaB19QmrXzw==
654821d4-6ced-43b4-b7cc-8321bc182a5b	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	INSERT	bookings	89c57c05-2c39-48a4-ab47-2b4db597cada	\N	{"id": "89c57c05-2c39-48a4-ab47-2b4db597cada", "vat": 400, "adults": 2, "status": "confirmed", "room_id": "134f45d8-b8a6-4204-a0ad-e673583a89fd", "agent_id": "e1fdd56e-e4ee-4461-98d4-5e3a8d00d461", "children": 0, "guest_id": "06a738f7-ac24-4230-bc3b-b3d0b3139b4f", "base_rate": 500, "reference": "BK-383615", "source_id": "2dea551b-caf2-4664-a887-a933c677956a", "commission": 600, "created_at": "2025-11-05T07:23:58.295993+00:00", "created_by": null, "updated_at": "2025-11-05T07:23:58.295993+00:00", "updated_by": null, "amount_paid": 0, "tourism_fee": 500, "net_to_owner": 0, "total_amount": 500, "check_in_date": "2025-11-05", "document_urls": ["guest-ids/1762327436248_ldqmd5b0ukp.pdf"], "check_out_date": "2025-11-08", "internal_notes": "", "payment_status": "pending", "pending_amount": null, "security_deposit": 100, "special_requests": null}	152.59.203.17	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	\N	2025-11-05 07:23:58.295993+00	\N	\N	\N	\N	\N	OiUuTUvBSPtuU528uaAKwrq7ia5K6cbfde6p3plQlYP3DQCGmh5TUSR3Vqs3VsZ56wnPKAHyzNBO\n8m9ufrY5ZM1Vh29zUQAGPR0I/1G6bHrwAhZZuN2LWbcyijl3ygutOKqsbZ51VlYeaB19QmrXzw==
1b3ea927-b318-4646-9184-0857e6344c0f	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	INSERT	expenses	21f3dbc0-b284-4052-a86c-b14debec39eb	\N	{"id": "21f3dbc0-b284-4052-a86c-b14debec39eb", "date": "2025-11-05", "notes": null, "amount": 500, "status": "pending", "vendor": null, "room_id": null, "owner_id": null, "created_at": "2025-11-05T07:26:36.278847+00:00", "created_by": null, "updated_at": "2025-11-05T07:26:36.278847+00:00", "updated_by": null, "approved_at": null, "approved_by": null, "category_id": "6f106316-ae93-490e-92a8-c7de9bfbb046", "description": "AC repair in room 905", "property_id": "4a2e8fa0-1049-4ebd-9402-c15da8f2796e", "receipt_urls": null, "document_urls": ["receipts/1762327594361_gfdpocv5xtj.pdf"], "payment_method_id": null}	152.59.203.17	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	\N	2025-11-05 07:26:36.278847+00	\N	\N	\N	\N	\N	OiUuTUvBSPtuU528uaAKwrq7ia5K6cbfde6p3plQlYP3DQCGmh5TUSR3Vqs3VsZ56wnPKAHyzNBO\n8m9ufrY5ZM1Vh29zUQAGPR0I/1G6bHrwAhZZuN2LWbcyijl3ygutOKqsbZ51VlYeaB19QmrXzw==
ccc62897-a153-4cce-9fc6-aaee75f3a64a	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	INSERT	room_ownership	e397495e-cd21-4a37-a5f8-d8e9a15762fc	\N	{"id": "e397495e-cd21-4a37-a5f8-d8e9a15762fc", "active": true, "room_id": "134f45d8-b8a6-4204-a0ad-e673583a89fd", "owner_id": "06952e8b-bda7-4a4c-b406-94442f799a62", "created_at": "2025-11-05T08:24:18.784556+00:00", "created_by": null, "updated_at": "2025-11-05T08:24:18.784556+00:00", "updated_by": null, "commission_rate": 0, "contract_end_date": null, "contract_start_date": "2025-11-05"}	152.59.203.17	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	\N	2025-11-05 08:24:18.784556+00	\N	\N	\N	\N	\N	OiUuTUvBSPtuU528uaAKwrq7ia5K6cbfde6p3plQlYP3DQCGmh5TUSR3Vqs3VsZ56wnPKAHyzNBO\n8m9ufrY5ZM1Vh29zUQAGPR0I/1G6bHrwAhZZuN2LWbcyijl3ygutOKqsbZ51VlYeaB19QmrXzw==
e8713ad5-3909-4e12-9eff-25588968e38c	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	DELETE	room_types	23c0c43f-f4ee-4a9e-97e7-995437bf74c6	{"id": "23c0c43f-f4ee-4a9e-97e7-995437bf74c6", "name": "rehan", "active": true, "amenities": [], "base_rate": 500, "created_at": "2025-11-10T08:00:56.848096+00:00", "created_by": "a28dedd7-1b1b-4ed2-8d6a-52984f7223d6", "max_adults": 2, "updated_at": "2025-11-10T08:00:56.848096+00:00", "updated_by": null, "description": "", "max_children": 0}	\N	152.59.201.46	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	\N	2025-11-11 07:15:44.961761+00	\N	\N	\N	\N	\N	OiUuTUvBSPtuU528uaAKwrq7ia5K6cbfde6p3plQlYP3DQCGmh5TUSR3Vqs3VsZ56wnPKAHyzNBO\n8m9ufrY5ZM1Vh29zUQAGPR0I/1G6bHrwAhZZuN2LWbcyijl3ygutOKqsbZ51VlYeaB19QmrXzw==
bf774ded-df12-405c-8b9b-f9865bd2e588	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	UPDATE	owners	06952e8b-bda7-4a4c-b406-94442f799a62	{"id": "06952e8b-bda7-4a4c-b406-94442f799a62", "city": null, "name": "Owner User", "email": "owner@hotel.com", "phone": null, "state": null, "active": true, "address": null, "country": null, "zip_code": null, "created_at": "2025-11-05T04:01:46.785371+00:00", "created_by": null, "updated_at": "2025-11-05T04:01:46.785371+00:00", "updated_by": null, "auth_user_id": "679c2251-78d4-4d83-ab54-54ac1c790ed5", "payment_info": {}}	{"id": "06952e8b-bda7-4a4c-b406-94442f799a62", "city": null, "name": "Owner User", "email": "owner@hotel.com", "phone": null, "state": null, "active": true, "address": null, "country": null, "zip_code": null, "created_at": "2025-11-05T04:01:46.785371+00:00", "created_by": null, "updated_at": "2025-11-05T08:24:21.578695+00:00", "updated_by": "a28dedd7-1b1b-4ed2-8d6a-52984f7223d6", "auth_user_id": "679c2251-78d4-4d83-ab54-54ac1c790ed5", "payment_info": {"bank": "", "account_number": "", "routing_number": ""}}	152.59.203.17	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	\N	2025-11-05 08:24:21.578695+00	\N	\N	\N	ct5eq2JJ4fmZzqsv9eLWtNDanNBaJ0sj9KEabxvJAgRVb9e+ChX5STFVxBGWrw1VmkRa1/ElHxfF\n/SDbeWY4377/uXwzU0QlEUO1HNJVxzx4DlKcCD+6jOglCCatoSDQtDKGKc73aD+Vu0+jIZNSfOlh\nq+pSBIoAakh3l1d+xMZZEWlJNUlKirpQGNYEB0Qkp2sNi14qV1vtRVf4xj4sJwB50csrSDdzOhia\n+A78qJyfj75GZ370PyS9qek6ZMsUxOxVaINIoZO9fxSnEMC8ZNdI/pJzu5n/1nofxYRZ/jpOQllw\nDEhP457UafvMYvisaOSU19Jiw7+aJIoaeRe6s/z3YA3xy2WJLcM+sUg3uFzPdSG+u09iNIbBi6mE\nWM5u/j3Yeyo5vYO+5g/qC8CJWxUHCAlLFMvzUQCcORZe8OPVTNX0Fd9nr9PhUCulVMxUAuEWxu08\nbvtdIKqYw/C9oteYs5LA+BtbQ5mZB7ASKsEKJfy4Y4I+0GaYBy3PvTclfq8Oj1Rz1g10rWKYhE5w\n+sUpGbhvlTiNdHJKdg87SSo0/S2uu/nzwdQc+zBn2TwB	ct5eq2JJ4fmZzqsv9eLWtNDanNBaJ0sj9KEabxvJAgRVb9e+ChX5STFVxBGWrw1VmkRa1/ElHxfF\n/SDbeWY4377/uXwzU0QlEUO1HNJVxzx4DlKcCD+6jOglCCatoSDQtDKGKc73aD+Vu0+jIZNSfOlh\nq+pSBIoAakh3l1d+xMZZEWlJNUlKirpQGNYEB0Qkp2sNi14qV1vtRVf4xj4sJwB50csrSDdzOhia\n+A78qJyfj75GZ370PyS9qek6ZMsUxOxVaINIoZO9fxSnEMC8ZNdI/pJzu5n/1nofxYRZ/jpOQllw\nDEhP457UafvMYvisaOSU19Jiw7+aJIoaeRe6s/z3YA3xy2WJLcM+sUg3uFzPdSG+u09iNIbBi6mE\nWM5u/j3Yeyo5vYO+5g/qC8CJW48dvaccDNelOLr75OBAQyMrCUbBsIJUheUy4Cu1f2sfd4MlmMod\nFgAFa28zc2H+scbYIXKO9x+AQDcHmHlBk+VDo6QtAmc7bVOUyKSO8Dmk6U2mv7v11K5O3OCOZCX6\ngH9h3NG9YP2yaM8dxXr8NDvzXho4UeU9eWvqq3oyB0edhJrpBcK3UsbUBPolBNOZb7+/gyuAA/Tm\ne086U9irnrQjdSssQOfOQs1YHmvXLqtVOvFuW2GlvJPnsj9clsw0mGvZTPg6bnoAhMZhVjVimHyA\ntWJ/oJ1wyzjqUrqig9Qs	OiUuTUvBSPtuU528uaAKwrq7ia5K6cbfde6p3plQlYP3DQCGmh5TUSR3Vqs3VsZ56wnPKAHyzNBO\n8m9ufrY5ZM1Vh29zUQAGPR0I/1G6bHrwAhZZuN2LWbcyijl3ygutOKqsbZ51VlYeaB19QmrXzw==
7b612116-5843-42c8-bdcf-a0b970fcdaf0	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	UPDATE	bookings	89c57c05-2c39-48a4-ab47-2b4db597cada	{"id": "89c57c05-2c39-48a4-ab47-2b4db597cada", "vat": 400, "adults": 2, "status": "confirmed", "room_id": "134f45d8-b8a6-4204-a0ad-e673583a89fd", "agent_id": "e1fdd56e-e4ee-4461-98d4-5e3a8d00d461", "children": 0, "guest_id": "06a738f7-ac24-4230-bc3b-b3d0b3139b4f", "base_rate": 500, "reference": "BK-383615", "source_id": "2dea551b-caf2-4664-a887-a933c677956a", "commission": 600, "created_at": "2025-11-05T07:23:58.295993+00:00", "created_by": null, "updated_at": "2025-11-05T07:23:58.295993+00:00", "updated_by": null, "amount_paid": 0, "tourism_fee": 500, "net_to_owner": 0, "total_amount": 500, "check_in_date": "2025-11-05", "document_urls": ["guest-ids/1762327436248_ldqmd5b0ukp.pdf"], "check_out_date": "2025-11-08", "internal_notes": "", "payment_status": "pending", "pending_amount": null, "security_deposit": 100, "special_requests": null}	{"id": "89c57c05-2c39-48a4-ab47-2b4db597cada", "vat": 400, "adults": 2, "status": "checked_in", "room_id": "134f45d8-b8a6-4204-a0ad-e673583a89fd", "agent_id": "e1fdd56e-e4ee-4461-98d4-5e3a8d00d461", "children": 0, "guest_id": "06a738f7-ac24-4230-bc3b-b3d0b3139b4f", "base_rate": 500, "reference": "BK-383615", "source_id": "2dea551b-caf2-4664-a887-a933c677956a", "commission": 600, "created_at": "2025-11-05T07:23:58.295993+00:00", "created_by": null, "updated_at": "2025-11-05T19:47:58.005553+00:00", "updated_by": null, "amount_paid": 0, "tourism_fee": 500, "net_to_owner": 0, "total_amount": 500, "check_in_date": "2025-11-05", "document_urls": ["guest-ids/1762327436248_ldqmd5b0ukp.pdf"], "check_out_date": "2025-11-08", "internal_notes": "", "payment_status": "pending", "pending_amount": null, "security_deposit": 100, "special_requests": null}	152.57.237.97	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	\N	2025-11-05 19:47:58.005553+00	\N	\N	\N	\N	\N	OiUuTUvBSPtuU528uaAKwrq7ia5K6cbfde6p3plQlYP3DQCGmh5TUSR3Vqs3VsZ56wnPKAHyzNBO\n8m9ufrY5ZM1Vh29zUQAGPR0I/1G6bHrwAhZZuN2LWbcyijl3ygutOKqsbZ51VlYeaB19QmrXzw==
2a39a4cb-8dfa-48ce-9448-7bf82542d520	\N	UPDATE	bookings	89c57c05-2c39-48a4-ab47-2b4db597cada	{"id": "89c57c05-2c39-48a4-ab47-2b4db597cada", "vat": 400, "adults": 2, "status": "checked_in", "room_id": "134f45d8-b8a6-4204-a0ad-e673583a89fd", "agent_id": "e1fdd56e-e4ee-4461-98d4-5e3a8d00d461", "children": 0, "guest_id": "06a738f7-ac24-4230-bc3b-b3d0b3139b4f", "base_rate": 500, "reference": "BK-383615", "source_id": "2dea551b-caf2-4664-a887-a933c677956a", "commission": 600, "created_at": "2025-11-05T07:23:58.295993+00:00", "created_by": null, "updated_at": "2025-11-05T19:47:58.005553+00:00", "updated_by": null, "amount_paid": 0, "tourism_fee": 500, "net_to_owner": 0, "total_amount": 500, "check_in_date": "2025-11-05", "document_urls": ["guest-ids/1762327436248_ldqmd5b0ukp.pdf"], "check_out_date": "2025-11-08", "internal_notes": "", "payment_status": "pending", "pending_amount": null, "actual_check_in": null, "actual_check_out": null, "security_deposit": 100, "special_requests": null}	{"id": "89c57c05-2c39-48a4-ab47-2b4db597cada", "vat": 400, "adults": 2, "status": "checked_out", "room_id": "134f45d8-b8a6-4204-a0ad-e673583a89fd", "agent_id": "e1fdd56e-e4ee-4461-98d4-5e3a8d00d461", "children": 0, "guest_id": "06a738f7-ac24-4230-bc3b-b3d0b3139b4f", "base_rate": 500, "reference": "BK-383615", "source_id": "2dea551b-caf2-4664-a887-a933c677956a", "commission": 600, "created_at": "2025-11-05T07:23:58.295993+00:00", "created_by": null, "updated_at": "2025-11-08T07:00:02.043954+00:00", "updated_by": null, "amount_paid": 0, "tourism_fee": 500, "net_to_owner": 0, "total_amount": 500, "check_in_date": "2025-11-05", "document_urls": ["guest-ids/1762327436248_ldqmd5b0ukp.pdf"], "check_out_date": "2025-11-08", "internal_notes": "", "payment_status": "pending", "pending_amount": null, "actual_check_in": null, "actual_check_out": null, "security_deposit": 100, "special_requests": null}	13.212.12.214	Deno/2.1.4 (variant; SupabaseEdgeRuntime/1.69.22)	\N	2025-11-08 07:00:02.043954+00	\N	\N	\N	\N	\N	5gVq2/qOzearWcn1veb7mD4I/qCqnOk0pfcxWVg7Fq/jIdSkvi8cLi97yXxYLZJAa2nH5qo53uSd\npV7nknf6Rw==
c8ee7f80-de88-493d-abc3-46537eca27b8	\N	UPDATE	rooms	134f45d8-b8a6-4204-a0ad-e673583a89fd	{"id": "134f45d8-b8a6-4204-a0ad-e673583a89fd", "name": null, "size": null, "floor": null, "notes": null, "active": true, "number": "908", "status": "cleaned", "amenities": [], "base_rate": 500, "created_at": "2025-11-05T04:57:01.826057+00:00", "created_by": "a28dedd7-1b1b-4ed2-8d6a-52984f7223d6", "image_urls": null, "max_adults": 2, "updated_at": "2025-11-05T04:57:14.914905+00:00", "updated_by": null, "description": "r", "property_id": "4a2e8fa0-1049-4ebd-9402-c15da8f2796e", "last_cleaned": null, "max_children": 0, "room_type_id": "958ec744-4d84-4764-a8f8-b232a3f448a2", "next_maintenance": null}	{"id": "134f45d8-b8a6-4204-a0ad-e673583a89fd", "name": null, "size": null, "floor": null, "notes": null, "active": true, "number": "908", "status": "available", "amenities": [], "base_rate": 500, "created_at": "2025-11-05T04:57:01.826057+00:00", "created_by": "a28dedd7-1b1b-4ed2-8d6a-52984f7223d6", "image_urls": null, "max_adults": 2, "updated_at": "2025-11-08T07:00:02.043954+00:00", "updated_by": null, "description": "r", "property_id": "4a2e8fa0-1049-4ebd-9402-c15da8f2796e", "last_cleaned": null, "max_children": 0, "room_type_id": "958ec744-4d84-4764-a8f8-b232a3f448a2", "next_maintenance": null}	13.212.12.214	Deno/2.1.4 (variant; SupabaseEdgeRuntime/1.69.22)	\N	2025-11-08 07:00:02.043954+00	\N	\N	\N	\N	\N	5gVq2/qOzearWcn1veb7mD4I/qCqnOk0pfcxWVg7Fq/jIdSkvi8cLi97yXxYLZJAa2nH5qo53uSd\npV7nknf6Rw==
db76948d-9b29-40d9-84f3-5773cbfffd25	\N	AUTO_CHECKOUT	bookings	89c57c05-2c39-48a4-ab47-2b4db597cada	\N	{"reference": "BK-383615", "guest_name": "cregoraz Rehan", "room_number": "908", "processed_at": "2025-11-08T11:00:02.043954", "check_out_date": "2025-11-08"}	127.0.0.1	\N	\N	2025-11-08 07:00:02.043954+00	\N	\N	\N	\N	\N	\N
0f146039-c93a-484b-8a9e-1934c1fbad4b	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	INSERT	room_types	23c0c43f-f4ee-4a9e-97e7-995437bf74c6	\N	{"id": "23c0c43f-f4ee-4a9e-97e7-995437bf74c6", "name": "rehan", "active": true, "amenities": [], "base_rate": 500, "created_at": "2025-11-10T08:00:56.848096+00:00", "created_by": "a28dedd7-1b1b-4ed2-8d6a-52984f7223d6", "max_adults": 2, "updated_at": "2025-11-10T08:00:56.848096+00:00", "updated_by": null, "description": "", "max_children": 0}	149.40.62.27	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	\N	2025-11-10 08:00:56.848096+00	\N	\N	\N	\N	\N	OiUuTUvBSPtuU528uaAKwrq7ia5K6cbfde6p3plQlYP3DQCGmh5TUSR3Vqs3VsZ56wnPKAHyzNBO\n8m9ufrY5ZM1Vh29zUQAGPR0I/1G6bHrwAhZZuN2LWbcyijl3ygutOKqsbZ51VlYeaB19QmrXzw==
6e298ab3-da34-41fd-bf89-56a55d2fd76e	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	INSERT	expenses	5177639c-2a88-4bb3-ade1-26da0508a76d	\N	{"id": "5177639c-2a88-4bb3-ade1-26da0508a76d", "date": "2025-11-10", "notes": "\\n", "amount": 600, "status": "pending", "vendor": null, "room_id": null, "owner_id": null, "created_at": "2025-11-10T18:06:34.638416+00:00", "created_by": null, "updated_at": "2025-11-10T18:06:34.638416+00:00", "updated_by": null, "approved_at": null, "approved_by": null, "category_id": "0096fd54-dfcc-4223-b040-5962ccfced92", "description": "Amer", "property_id": "4a2e8fa0-1049-4ebd-9402-c15da8f2796e", "receipt_urls": null, "document_urls": null, "payment_method_id": null}	37.19.199.142	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	\N	2025-11-10 18:06:34.638416+00	\N	\N	\N	\N	\N	OiUuTUvBSPtuU528uaAKwrq7ia5K6cbfde6p3plQlYP3DQCGmh5TUSR3Vqs3VsZ56wnPKAHyzNBO\n8m9ufrY5ZM1Vh29zUQAGPR0I/1G6bHrwAhZZuN2LWbcyijl3ygutOKqsbZ51VlYeaB19QmrXzw==
503fb1b4-f1b8-4acd-a3cb-78e31e67389d	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	DELETE	properties	ed92b3ec-4951-4fa9-b36b-adc08bd4af52	{"id": "ed92b3ec-4951-4fa9-b36b-adc08bd4af52", "city": "kjdlskjs", "name": "Rehan", "email": "admin@hotel.com", "phone": "+1-305-555-9999", "state": "lksdflk", "active": true, "address": "hyderea", "country": null, "zip_code": "kjds", "created_at": "2025-11-10T08:01:13.953662+00:00", "created_by": "a28dedd7-1b1b-4ed2-8d6a-52984f7223d6", "updated_at": "2025-11-10T08:01:13.953662+00:00", "updated_by": null, "description": ""}	\N	152.59.201.46	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	\N	2025-11-11 07:15:49.680901+00	\N	\N	\N	gahw0JjOBpz6JJj3chuEvgkP7i3c8eXXBTqP80iTVhnhUxj+qQoWOhV7osGZpLVDfYLSTmTIgzT8\nwLNR2FKjkrVnL5+gqtOhxwiXIQhYvq0p3wfgSl60LDAJWChYlMgAKyGOLiBIqkxYGUsKRq8/bKgZ\nDssoenptJz4aF0MYhbMH7nncL0R70c+DwoFurrzsTd74liUn0/B2ForN2aODnFvlMVBigMXIJuGT\n1x8CACGvI8Ln/53M1VardGgz0VpqmuEjkjEiRwMBDFtYTP+svFM0hq3j+vSbhtk/SMuKaNcGtW9d\n4H/k1EZ7SM4DRTiKwgjEbwo0QfX62+EUNZQYP8G27RpBG6AeYITHYLTqIIUXBsYGXPrv2qLzEUCk\ns7KDmsWsTwHQDXJYrAFSaCNlzE9GPvIkTs0ZVZF/KZsVm2AHze5TKjYf0dzZwXCJyXpEUdKa3y0U\nNP7kspTiKef2GDrR4QEd7zmRc38NBOMcOemvpY1s/IzGUedwI/PzTTYaPHMbe2jqyjTCMKF+M39H\njYPz6fA4QAQDlFzK3RvNGr9kpl4x1aO/1gbwe6CUrdwx	\N	OiUuTUvBSPtuU528uaAKwrq7ia5K6cbfde6p3plQlYP3DQCGmh5TUSR3Vqs3VsZ56wnPKAHyzNBO\n8m9ufrY5ZM1Vh29zUQAGPR0I/1G6bHrwAhZZuN2LWbcyijl3ygutOKqsbZ51VlYeaB19QmrXzw==
431305b4-0bb8-4314-992c-3867380e9905	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	user_role_assignments DELETE	user_role_assignments	6deb256f-0e1e-44ad-8612-a9dc5ca77ffb	{"id": "6deb256f-0e1e-44ad-8612-a9dc5ca77ffb", "role_id": "c2723abb-0273-449f-8254-742b4c464b7e", "user_id": "9734db5d-cccf-4f1c-84b2-cdd5e094e9da", "created_at": "2025-11-05T04:54:06.207912+00:00", "assigned_by": null}	\N	\N	\N	\N	2025-11-12 06:38:45.79109+00	\N	\N	\N	\N	\N	\N
e01f5f58-91d1-4552-9810-4a2011c4b0ea	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	user_role_assignments INSERT	user_role_assignments	70ee1b50-5e67-46ab-bae1-57c9b2d394a8	\N	{"id": "70ee1b50-5e67-46ab-bae1-57c9b2d394a8", "role_id": "c2723abb-0273-449f-8254-742b4c464b7e", "user_id": "9734db5d-cccf-4f1c-84b2-cdd5e094e9da", "created_at": "2025-11-12T06:38:46.593572+00:00", "assigned_by": "a28dedd7-1b1b-4ed2-8d6a-52984f7223d6"}	\N	\N	\N	2025-11-12 06:38:46.593572+00	\N	\N	\N	\N	\N	\N
092158e1-7f2c-48e8-88ff-d95979a1db93	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	user_roles INSERT	user_roles	8223dffa-e3b5-45f4-9cd7-15de52e733b5	\N	{"id": "8223dffa-e3b5-45f4-9cd7-15de52e733b5", "name": "amer", "is_system": false, "created_at": "2025-11-12T08:40:43.167145+00:00", "updated_at": "2025-11-12T08:40:43.167145+00:00", "description": null, "permissions": {"rooms": {"view": true, "create": true, "update": true}, "guests": {"view": true, "create": true, "update": true}, "owners": {"view": true, "create": true, "update": true}, "reports": {"view": true, "export": true}, "bookings": {"view": true, "create": true, "update": true}, "cleaning": {"view": true, "update": true}, "expenses": {"view": true, "create": true, "update": true}, "dashboard": {"view": true}}}	\N	\N	\N	2025-11-12 08:40:43.167145+00	\N	\N	\N	\N	\N	\N
6800ff62-e30f-4504-a80d-f178196b5809	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	UPDATE	rooms	134f45d8-b8a6-4204-a0ad-e673583a89fd	{"id": "134f45d8-b8a6-4204-a0ad-e673583a89fd", "name": null, "size": null, "floor": null, "notes": null, "active": true, "number": "908", "status": "available", "amenities": [], "base_rate": 500, "created_at": "2025-11-05T04:57:01.826057+00:00", "created_by": "a28dedd7-1b1b-4ed2-8d6a-52984f7223d6", "image_urls": null, "max_adults": 2, "updated_at": "2025-11-08T07:00:02.043954+00:00", "updated_by": null, "description": "r", "property_id": "4a2e8fa0-1049-4ebd-9402-c15da8f2796e", "last_cleaned": null, "max_children": 0, "room_type_id": "958ec744-4d84-4764-a8f8-b232a3f448a2", "next_maintenance": null}	{"id": "134f45d8-b8a6-4204-a0ad-e673583a89fd", "name": null, "size": null, "floor": null, "notes": null, "active": true, "number": "908", "status": "dirty", "amenities": [], "base_rate": 500, "created_at": "2025-11-05T04:57:01.826057+00:00", "created_by": "a28dedd7-1b1b-4ed2-8d6a-52984f7223d6", "image_urls": null, "max_adults": 2, "updated_at": "2025-11-12T16:17:22.20002+00:00", "updated_by": null, "description": "r", "property_id": "4a2e8fa0-1049-4ebd-9402-c15da8f2796e", "last_cleaned": null, "max_children": 0, "room_type_id": "958ec744-4d84-4764-a8f8-b232a3f448a2", "next_maintenance": null}	152.57.233.15	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36	\N	2025-11-12 16:17:22.20002+00	\N	\N	\N	\N	\N	OiUuTUvBSPtuU528uaAKwrq7ia5K6cbfde6p3plQlYP3DQCGmh5TUSR3Vqs3VsZ56wnPKAHyzNBO\n8m9ufrY5ZM1Vh29zUQAGPR0I/1G6bHreyPvvVJw6tgNZlhVoEq87xc89V+66z0g/6JsG+FwZjcFz\nd1lpSa8BJJE9HVwXBYFVf6VjNwqjwpsHforP1YeOZpF4AKETa9ILGORCvS50aw==
3626c91d-3c10-4029-8bef-b96ff5083a77	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	DELETE	expenses	21f3dbc0-b284-4052-a86c-b14debec39eb	{"id": "21f3dbc0-b284-4052-a86c-b14debec39eb", "date": "2025-11-05", "notes": null, "amount": 500, "status": "pending", "vendor": null, "room_id": null, "owner_id": null, "created_at": "2025-11-05T07:26:36.278847+00:00", "created_by": null, "updated_at": "2025-11-05T07:26:36.278847+00:00", "updated_by": null, "approved_at": null, "approved_by": null, "category_id": "6f106316-ae93-490e-92a8-c7de9bfbb046", "description": "AC repair in room 905", "property_id": "4a2e8fa0-1049-4ebd-9402-c15da8f2796e", "receipt_urls": null, "document_urls": ["receipts/1762327594361_gfdpocv5xtj.pdf"], "payment_method_id": null}	\N	152.57.233.15	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36	\N	2025-11-12 16:17:35.903403+00	\N	\N	\N	\N	\N	OiUuTUvBSPtuU528uaAKwrq7ia5K6cbfde6p3plQlYP3DQCGmh5TUSR3Vqs3VsZ56wnPKAHyzNBO\n8m9ufrY5ZM1Vh29zUQAGPR0I/1G6bHreyPvvVJw6tgNZlhVoEq87xc89V+66z0g/6JsG+FwZjcFz\nd1lpSa8BJJE9HVwXBYFVf6VjNwqjwpsHforP1YeOZpF4AKETa9ILGORCvS50aw==
fd8b993f-32bd-41fa-bded-31ef4e2a28b9	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	UPDATE	rooms	134f45d8-b8a6-4204-a0ad-e673583a89fd	{"id": "134f45d8-b8a6-4204-a0ad-e673583a89fd", "name": null, "size": null, "floor": null, "notes": null, "active": true, "number": "908", "status": "dirty", "amenities": [], "base_rate": 500, "created_at": "2025-11-05T04:57:01.826057+00:00", "created_by": "a28dedd7-1b1b-4ed2-8d6a-52984f7223d6", "image_urls": null, "max_adults": 2, "updated_at": "2025-11-12T16:17:22.20002+00:00", "updated_by": null, "description": "r", "property_id": "4a2e8fa0-1049-4ebd-9402-c15da8f2796e", "last_cleaned": null, "max_children": 0, "room_type_id": "958ec744-4d84-4764-a8f8-b232a3f448a2", "next_maintenance": null}	{"id": "134f45d8-b8a6-4204-a0ad-e673583a89fd", "name": null, "size": null, "floor": null, "notes": null, "active": true, "number": "908", "status": "cleaned", "amenities": [], "base_rate": 500, "created_at": "2025-11-05T04:57:01.826057+00:00", "created_by": "a28dedd7-1b1b-4ed2-8d6a-52984f7223d6", "image_urls": null, "max_adults": 2, "updated_at": "2025-11-12T19:22:41.529087+00:00", "updated_by": null, "description": "r", "property_id": "4a2e8fa0-1049-4ebd-9402-c15da8f2796e", "last_cleaned": null, "max_children": 0, "room_type_id": "958ec744-4d84-4764-a8f8-b232a3f448a2", "next_maintenance": null}	152.57.233.15	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	\N	2025-11-12 19:22:41.529087+00	\N	\N	\N	\N	\N	OiUuTUvBSPtuU528uaAKwrq7ia5K6cbfde6p3plQlYP3DQCGmh5TUSR3Vqs3VsZ56wnPKAHyzNBO\n8m9ufrY5ZM1Vh29zUQAGPR0I/1G6bHrwAhZZuN2LWbcyijl3ygutOKqsbZ51VlYeaB19QmrXzw==
f9ed1570-b03f-4077-8067-bc608e1d1dbc	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	UPDATE	guests	06a738f7-ac24-4230-bc3b-b3d0b3139b4f	{"id": "06a738f7-ac24-4230-bc3b-b3d0b3139b4f", "city": null, "email": "admin@hotel.com", "notes": null, "phone": "8688238150", "state": null, "address": null, "country": null, "zip_code": null, "last_name": "Rehan", "created_at": "2025-11-05T07:23:58.012993+00:00", "created_by": null, "first_name": "cregoraz", "updated_at": "2025-11-05T07:23:58.012993+00:00", "updated_by": null, "nationality": null, "access_log_id": null, "privacy_level": "standard", "id_document_url": null, "passport_number": null, "last_data_access": null, "consent_marketing": false, "consent_timestamp": null, "consent_ip_address": null, "data_retention_expiry": null, "consent_data_processing": false, "consent_third_party_sharing": false}	{"id": "06a738f7-ac24-4230-bc3b-b3d0b3139b4f", "city": null, "email": "admin@hotel.com", "notes": null, "phone": "8688238150", "state": null, "address": null, "country": null, "zip_code": null, "last_name": "Rehan", "created_at": "2025-11-05T07:23:58.012993+00:00", "created_by": null, "first_name": "cregoraz", "updated_at": "2025-11-12T19:22:58.224664+00:00", "updated_by": null, "nationality": null, "access_log_id": null, "privacy_level": "standard", "id_document_url": null, "passport_number": null, "last_data_access": null, "consent_marketing": false, "consent_timestamp": null, "consent_ip_address": null, "data_retention_expiry": null, "consent_data_processing": false, "consent_third_party_sharing": false}	152.57.233.15	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	\N	2025-11-12 19:22:58.224664+00	\N	\N	\N	t2l+1YrFQWk0O75TAOcWBt0VB+/USh2bDJ9A8Z71pLQuNIDD9VdqHFA9Y1T2FYM8X3C9//bLZEfZ\njDpkHg+eAjrY+Z8CF3FRhJJ7hYs9LbpWFjGIcNsRJ4BjUzYaXvZvxGWMmC0bcR5/ZJWq81QiypOx\nQ1xPXxYDSIShz7nQk/oImpvx6FR7qidNGNSWBaBL3iU2/v81Evxn9H7bz2vEUImIsJ6t3IkyblBg\niJGE/RgRCyRBGStEHMM/h13QK9WPsEIuTaXj36rC9e8msr/lvdhmT808qIdX4NHwH0l0YfTJrJz8\nyp2HbpAo4BfA0cUib/tMwE1xs0KvxVckbxTXXgR4CCuR5bRuSDO8kq858DkXUOpKKAEhQNRcrurO\nfZ/+oxTUTREa8L5aLtVoVWgNk8vhCw0NTnOn9Uakk5+3aLMjbuRALdjlV89PFk4G1uMEMncJ4Hu7\ngJ7hZPELZeBVraFrkBc1PGyEUTtqQvd7EAiwEti553tgdDlPcB9RJH9TmqyFsOIq0Mt4vre7co91\ntiRi9gvAeBxwWS57BEPcWPHY9N/VpXwa8tB3Zjx+2KI/m5oXFQl2Z+EoxsrXgYUx5EZgniuzHYFS\nGKBpX8erYAfT/GMzt/YvDCdbogHW5oiy6l2DyYnTNnQsdtAwb6PRsK8mO9gy0H+rV/ZytHYhN8/Z\n68POClrhyiymo2yZrss+oyfy1PMAB7nAExV7bBmR6VpgvxM7vzgxFsamZH4CUxN9tJqVki2i7vqO\n39D5Rk5KCjR1a839v9dDjnQFav2G+do/4hA8SKYTyX+CwRXuXpCz0zDMKwTFhNaqsAaemRwgGSzZ\nfcHYC0V3RKIHMsG8FA0oYT6U7Mw1WMh8Y23xlsvptHOzyJGfL4uH+sLWoueAbyqpkYJ6TpbFpFdP\n6ZiFWSzjUbSNO9EZKgdtvfGxYLa9bKDp6jkWvcHMEwCpudbu	t2l+1YrFQWk0O75TAOcWBt0VB+/USh2bDJ9A8Z71pLQuNIDD9VdqHFA9Y1T2FYM8X3C9//bLZEfZ\njDpkHg+eAjrY+Z8CF3FRhJJ7hYs9LbpWFjGIcNsRJ4BjUzYaXvZvxGWMmC0bcR5/ZJWq81QiypOx\nQ1xPXxYDSIShz7nQk/oImpvx6FR7qidNGNSWBaBL3iU2/v81Evxn9H7bz2vEUImIsJ6t3IkyblBg\niJGE/RgRCyRBGStEHMM/h13QK9WPsEIuTaXj36rC9e8msr/lvdhmT808qIdX4NHwH0l0YfTJrJz8\nyp2HbpAo4BfA0cUib/tMwE1xs0KvxVckbxTXXgR4CCuR5bRuSDO8kq858DkXUOpKKAEhQNRcrurO\nfZ/+oxTUTREa8L5aLtVoVWgNk8vhCw0NTnOn9Uakk5+3aLNlHzM8UR5jCizG9ucbP0RSeuo5OX/0\nk7G+UkAVkfVnrSu3EcwHUnzj+/jiyYHg/pgOp2szktXeYxYnFFMTOymvhD5PxoKkZVackiNwpVVb\nRUGzos3p74zeYaT1VdKF5Qp8pJ1FozglVhUcOE/5/fz9l4u4gX3KUcJAujtF4x6zguYBVfixYH8E\ntOWphrFKi28pXKTGMNtuNfN9X3q2Z73yCIDSyKAhlFYNTY7XgRayXjtiKWSb8z/g0rQH7lNhqKkq\nmmFrrQaJ870As0/l+mv/6x/xzHA7xI+hYw3T4mEcYP+7hQvw2PLcSGinHrZhqVOLRmOiNc+MZg8K\n4HmcGFBIg3Ybn4rszL0ddSqEhlFSD68IQaX0Zbzk1ayihf1tpJiihIOiImWoMY+tgOjKfd1/KuY4\nDmWAHfT2emczzBSRy//7nVQ1W5Y0ZXErgD3JUWj6QQQ6qbJ8WdQKozvYMbW5mnRDSqdq0q5tWWHN\nBUVfbO28E5DYrYW6Mm5CQgpK48eMyD0ItnCtvJYfE6LLWhPg	OiUuTUvBSPtuU528uaAKwrq7ia5K6cbfde6p3plQlYP3DQCGmh5TUSR3Vqs3VsZ56wnPKAHyzNBO\n8m9ufrY5ZM1Vh29zUQAGPR0I/1G6bHrwAhZZuN2LWbcyijl3ygutOKqsbZ51VlYeaB19QmrXzw==
f01d20e1-9669-4ed2-b0ec-5658b21b54d8	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	UPDATE	bookings	89c57c05-2c39-48a4-ab47-2b4db597cada	{"id": "89c57c05-2c39-48a4-ab47-2b4db597cada", "vat": 400, "adults": 2, "status": "checked_out", "room_id": "134f45d8-b8a6-4204-a0ad-e673583a89fd", "agent_id": "e1fdd56e-e4ee-4461-98d4-5e3a8d00d461", "children": 0, "guest_id": "06a738f7-ac24-4230-bc3b-b3d0b3139b4f", "base_rate": 500, "reference": "BK-383615", "source_id": "2dea551b-caf2-4664-a887-a933c677956a", "commission": 600, "created_at": "2025-11-05T07:23:58.295993+00:00", "created_by": null, "updated_at": "2025-11-08T07:00:02.043954+00:00", "updated_by": null, "amount_paid": 0, "tourism_fee": 500, "net_to_owner": 0, "total_amount": 500, "check_in_date": "2025-11-05", "document_urls": ["guest-ids/1762327436248_ldqmd5b0ukp.pdf"], "check_out_date": "2025-11-08", "internal_notes": "", "payment_status": "pending", "pending_amount": null, "actual_check_in": null, "actual_check_out": null, "security_deposit": 100, "special_requests": null}	{"id": "89c57c05-2c39-48a4-ab47-2b4db597cada", "vat": 400, "adults": 2, "status": "checked_out", "room_id": "134f45d8-b8a6-4204-a0ad-e673583a89fd", "agent_id": "e1fdd56e-e4ee-4461-98d4-5e3a8d00d461", "children": 0, "guest_id": "06a738f7-ac24-4230-bc3b-b3d0b3139b4f", "base_rate": 500, "reference": "BK-383615", "source_id": "2dea551b-caf2-4664-a887-a933c677956a", "commission": 600, "created_at": "2025-11-05T07:23:58.295993+00:00", "created_by": null, "updated_at": "2025-11-12T19:22:58.611628+00:00", "updated_by": null, "amount_paid": 600, "tourism_fee": 500, "net_to_owner": 0, "total_amount": 500, "check_in_date": "2025-11-04", "document_urls": null, "check_out_date": "2025-11-07", "internal_notes": "", "payment_status": "pending", "pending_amount": null, "actual_check_in": null, "actual_check_out": null, "security_deposit": 100, "special_requests": null}	152.57.233.15	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	\N	2025-11-12 19:22:58.611628+00	\N	\N	\N	\N	\N	OiUuTUvBSPtuU528uaAKwrq7ia5K6cbfde6p3plQlYP3DQCGmh5TUSR3Vqs3VsZ56wnPKAHyzNBO\n8m9ufrY5ZM1Vh29zUQAGPR0I/1G6bHrwAhZZuN2LWbcyijl3ygutOKqsbZ51VlYeaB19QmrXzw==
f0e0d855-f9d9-4ece-9d57-4a2f8421899e	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	user_role_assignments DELETE	user_role_assignments	70ee1b50-5e67-46ab-bae1-57c9b2d394a8	{"id": "70ee1b50-5e67-46ab-bae1-57c9b2d394a8", "role_id": "c2723abb-0273-449f-8254-742b4c464b7e", "user_id": "9734db5d-cccf-4f1c-84b2-cdd5e094e9da", "created_at": "2025-11-12T06:38:46.593572+00:00", "assigned_by": "a28dedd7-1b1b-4ed2-8d6a-52984f7223d6"}	\N	\N	\N	\N	2025-11-12 19:27:02.000624+00	\N	\N	\N	\N	\N	\N
cd21a9f9-dade-4072-af48-1a2ffb1e1945	\N	user_role_assignments INSERT	user_role_assignments	d024a961-8753-4b77-a7fe-1222c6ca6922	\N	{"id": "d024a961-8753-4b77-a7fe-1222c6ca6922", "role_id": "4d73be21-fb46-4ec6-aabd-bc3472e7fb58", "user_id": "9734db5d-cccf-4f1c-84b2-cdd5e094e9da", "created_at": "2025-11-12T19:32:22.352588+00:00", "assigned_by": null}	\N	\N	\N	2025-11-12 19:32:22.352588+00	\N	\N	\N	\N	\N	\N
\.


--
-- Data for Name: booking_agents; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."booking_agents" ("id", "name", "email", "phone", "commission_rate", "active", "created_at", "updated_at", "created_by", "updated_by") FROM stdin;
e1fdd56e-e4ee-4461-98d4-5e3a8d00d461	amer	\N	\N	0	t	2025-11-05 07:23:18.077861+00	2025-11-05 07:23:18.077861+00	\N	\N
\.


--
-- Data for Name: booking_sources; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."booking_sources" ("id", "name", "description", "commission_rate", "active", "created_at", "updated_at", "created_by", "updated_by") FROM stdin;
2dea551b-caf2-4664-a887-a933c677956a	rehan	\N	0	t	2025-11-05 07:23:11.869107+00	2025-11-05 07:23:11.869107+00	\N	\N
\.


--
-- Data for Name: guests; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."guests" ("id", "first_name", "last_name", "email", "phone", "address", "city", "state", "zip_code", "country", "nationality", "passport_number", "id_document_url", "notes", "created_at", "updated_at", "created_by", "updated_by", "consent_data_processing", "consent_marketing", "consent_third_party_sharing", "consent_timestamp", "consent_ip_address", "data_retention_expiry", "privacy_level", "last_data_access", "access_log_id") FROM stdin;
06a738f7-ac24-4230-bc3b-b3d0b3139b4f	cregoraz	Rehan	admin@hotel.com	8688238150	\N	\N	\N	\N	\N	\N	\N	\N	\N	2025-11-05 07:23:58.012993+00	2025-11-12 19:22:58.224664+00	\N	\N	f	f	f	\N	\N	\N	standard	\N	\N
\.


--
-- Data for Name: properties; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."properties" ("id", "name", "description", "address", "city", "state", "zip_code", "country", "phone", "email", "active", "created_at", "updated_at", "created_by", "updated_by") FROM stdin;
4a2e8fa0-1049-4ebd-9402-c15da8f2796e	Rehan		hyderea	kjdlskjs	lksdflk	kjds	\N	+1-305-555-9999	admin@hotel.com	t	2025-11-05 04:55:08.31288+00	2025-11-05 04:55:08.31288+00	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	\N
\.


--
-- Data for Name: room_types; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."room_types" ("id", "name", "description", "max_adults", "max_children", "base_rate", "amenities", "active", "created_at", "updated_at", "created_by", "updated_by") FROM stdin;
958ec744-4d84-4764-a8f8-b232a3f448a2	Deluxe		2	0	500	[]	t	2025-11-05 04:54:57.964544+00	2025-11-05 04:54:57.964544+00	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	\N
\.


--
-- Data for Name: rooms; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."rooms" ("id", "property_id", "room_type_id", "number", "name", "description", "floor", "size", "max_adults", "max_children", "base_rate", "amenities", "image_urls", "status", "notes", "last_cleaned", "next_maintenance", "active", "created_at", "updated_at", "created_by", "updated_by") FROM stdin;
134f45d8-b8a6-4204-a0ad-e673583a89fd	4a2e8fa0-1049-4ebd-9402-c15da8f2796e	958ec744-4d84-4764-a8f8-b232a3f448a2	908	\N	r	\N	\N	2	0	500	[]	\N	cleaned	\N	\N	\N	t	2025-11-05 04:57:01.826057+00	2025-11-12 19:22:41.529087+00	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	\N
\.


--
-- Data for Name: bookings; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."bookings" ("id", "reference", "room_id", "guest_id", "source_id", "agent_id", "check_in_date", "check_out_date", "adults", "children", "base_rate", "total_amount", "security_deposit", "commission", "tourism_fee", "vat", "net_to_owner", "status", "payment_status", "amount_paid", "pending_amount", "special_requests", "internal_notes", "document_urls", "created_at", "updated_at", "created_by", "updated_by", "actual_check_in", "actual_check_out") FROM stdin;
89c57c05-2c39-48a4-ab47-2b4db597cada	BK-383615	134f45d8-b8a6-4204-a0ad-e673583a89fd	06a738f7-ac24-4230-bc3b-b3d0b3139b4f	2dea551b-caf2-4664-a887-a933c677956a	e1fdd56e-e4ee-4461-98d4-5e3a8d00d461	2025-11-04	2025-11-07	2	0	500	500	100	600	500	400	0	checked_out	pending	600	\N	\N		\N	2025-11-05 07:23:58.295993+00	2025-11-12 19:22:58.611628+00	\N	\N	\N	\N
\.


--
-- Data for Name: cleaning_tasks; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."cleaning_tasks" ("id", "room_id", "status", "assigned_to", "scheduled_date", "completed_date", "notes", "checklist", "created_at", "updated_at", "created_by", "updated_by") FROM stdin;
\.


--
-- Data for Name: contract_templates; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."contract_templates" ("id", "name", "description", "file_url", "created_by", "created_at", "updated_at", "is_active") FROM stdin;
f768a467-e56a-47b0-9047-6fc5fc775896	Rehan	\N	67b059db-2e65-4c25-b3f3-07f05c2cd0bb.pdf	\N	2025-11-12 18:52:53.731345+00	2025-11-12 18:52:53.731345+00	t
\.


--
-- Data for Name: expense_categories; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."expense_categories" ("id", "name", "description", "active", "created_at", "updated_at", "created_by", "updated_by") FROM stdin;
c27f34b9-6237-42c7-894b-49ae8fcfcbbe	Maintenance	General maintenance and repairs	t	2025-11-05 03:57:09.449803+00	2025-11-05 03:57:09.449803+00	\N	\N
3dee4cb3-bef9-4810-b358-648c9f964859	Utilities	Electricity, water, gas, internet	t	2025-11-05 03:57:09.449803+00	2025-11-05 03:57:09.449803+00	\N	\N
65063cc6-8bd8-42f1-8fef-2d7e6184e7b9	Cleaning	Cleaning supplies and services	t	2025-11-05 03:57:09.449803+00	2025-11-05 03:57:09.449803+00	\N	\N
0096fd54-dfcc-4223-b040-5962ccfced92	Marketing	Advertising and promotional expenses	t	2025-11-05 03:57:09.449803+00	2025-11-05 03:57:09.449803+00	\N	\N
6f106316-ae93-490e-92a8-c7de9bfbb046	Insurance	Property and liability insurance	t	2025-11-05 03:57:09.449803+00	2025-11-05 03:57:09.449803+00	\N	\N
57555bf4-f113-48f6-a2af-4d60811685b3	Taxes	Property taxes and fees	t	2025-11-05 03:57:09.449803+00	2025-11-05 03:57:09.449803+00	\N	\N
da7a2884-2dcd-45e7-952b-bee57271ff26	Supplies	General supplies and equipment	t	2025-11-05 03:57:09.449803+00	2025-11-05 03:57:09.449803+00	\N	\N
7bd5d732-42e3-4bb3-8527-4fb7b6bdcfcb	Professional Services	Legal, accounting, consulting	t	2025-11-05 03:57:09.449803+00	2025-11-05 03:57:09.449803+00	\N	\N
\.


--
-- Data for Name: owners; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."owners" ("id", "auth_user_id", "name", "email", "phone", "address", "city", "state", "zip_code", "country", "payment_info", "active", "created_at", "updated_at", "created_by", "updated_by") FROM stdin;
06952e8b-bda7-4a4c-b406-94442f799a62	679c2251-78d4-4d83-ab54-54ac1c790ed5	Owner User	owner@hotel.com	\N	\N	\N	\N	\N	\N	{"bank": "", "account_number": "", "routing_number": ""}	t	2025-11-05 04:01:46.785371+00	2025-11-05 08:24:21.578695+00	\N	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6
\.


--
-- Data for Name: payment_methods; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."payment_methods" ("id", "name", "description", "active", "created_at", "updated_at", "created_by", "updated_by") FROM stdin;
5c55706c-53ca-4a96-87ac-55a616f1c46e	Cash	Cash payment	t	2025-11-05 03:57:09.449803+00	2025-11-05 03:57:09.449803+00	\N	\N
7cee3469-c90c-4812-bbe2-7efd0a8a014e	Credit Card	Credit card payment	t	2025-11-05 03:57:09.449803+00	2025-11-05 03:57:09.449803+00	\N	\N
1eb96b97-b2d1-45e8-b171-3b97cb26afe6	Debit Card	Debit card payment	t	2025-11-05 03:57:09.449803+00	2025-11-05 03:57:09.449803+00	\N	\N
63bbe2b0-22cf-4314-8fa0-9c2f56552eea	Bank Transfer	Bank wire transfer	t	2025-11-05 03:57:09.449803+00	2025-11-05 03:57:09.449803+00	\N	\N
8afc792c-5eac-45d3-8aff-35c1422c1609	Check	Check payment	t	2025-11-05 03:57:09.449803+00	2025-11-05 03:57:09.449803+00	\N	\N
528b9452-3994-4d46-86bb-dd7507d1ac7e	Online Payment	Online payment gateway	t	2025-11-05 03:57:09.449803+00	2025-11-05 03:57:09.449803+00	\N	\N
\.


--
-- Data for Name: profiles; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."profiles" ("id", "name", "email", "phone", "avatar_url", "status", "last_active", "onboarding_step", "tutorial_completed", "tutorial_completed_at", "tutorial_skipped", "tutorial_skipped_at", "created_at", "updated_at") FROM stdin;
a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	Admin User	admin@hotel.com	\N	\N	active	2025-11-05 03:58:51.265967+00	0	f	\N	f	\N	2025-11-05 03:58:51.265967+00	2025-11-05 04:01:46.785371+00
679c2251-78d4-4d83-ab54-54ac1c790ed5	Owner User	owner@hotel.com	\N	\N	active	2025-11-05 03:59:35.37896+00	0	f	\N	f	\N	2025-11-05 03:59:35.37896+00	2025-11-05 04:01:46.785371+00
9734db5d-cccf-4f1c-84b2-cdd5e094e9da	amer	Amer@gmail.com	\N	\N	active	2025-11-11 16:58:50.761507+00	0	f	\N	f	\N	2025-11-11 16:58:50.761507+00	2025-11-12 19:27:23.530563+00
\.


--
-- Data for Name: expenses; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."expenses" ("id", "property_id", "room_id", "owner_id", "category_id", "payment_method_id", "date", "amount", "description", "vendor", "notes", "receipt_urls", "document_urls", "status", "approved_by", "approved_at", "created_at", "updated_at", "created_by", "updated_by") FROM stdin;
5177639c-2a88-4bb3-ade1-26da0508a76d	4a2e8fa0-1049-4ebd-9402-c15da8f2796e	\N	\N	0096fd54-dfcc-4223-b040-5962ccfced92	\N	2025-11-10	600	Amer	\N	\n	\N	\N	pending	\N	\N	2025-11-10 18:06:34.638416+00	2025-11-10 18:06:34.638416+00	\N	\N
\.


--
-- Data for Name: general_settings; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."general_settings" ("id", "company_name", "currency_code", "currency_symbol", "default_checkin_time", "default_checkout_time", "default_tax_rate", "auto_checkin_enabled", "auto_checkout_enabled", "notifications_enabled", "reminder_days", "data_retention_days", "timezone", "date_format", "backup_frequency", "created_at", "updated_at", "created_by", "updated_by") FROM stdin;
c69fc927-d56e-40df-a8d5-dc3d013100e4	Hotel Management System	AED	د.إ	12:05:00	11:00:00	0	t	t	t	1	365	Asia/Dubai	MM/dd/yyyy	daily	2025-11-05 03:57:09.449803+00	2025-11-05 08:03:23.209121+00	\N	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6
\.


--
-- Data for Name: guest_data_classification; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."guest_data_classification" ("id", "field_name", "classification", "required_permission", "masking_rule", "description", "created_at") FROM stdin;
59ad2941-10fc-4a5d-93ae-14a3d617c53b	first_name	PUBLIC	view_guests	none	Guest first name	2025-11-05 04:06:03.10624+00
ec0e6e79-9581-4245-bbfe-7a4078d753c8	last_name	PUBLIC	view_guests	none	Guest last name	2025-11-05 04:06:03.10624+00
f094be56-9e5a-456c-bd55-1ba99dbf469c	email	RESTRICTED	view_sensitive_guest_data	email_partial	Guest email address	2025-11-05 04:06:03.10624+00
fa0a80a2-bc96-4367-9d97-09a71d3d5eca	phone	RESTRICTED	view_sensitive_guest_data	phone_partial	Guest phone number	2025-11-05 04:06:03.10624+00
54842977-6a08-4060-91ad-86a23af544e3	passport_number	CONFIDENTIAL	view_sensitive_guest_data	passport_masked	Passport or ID number	2025-11-05 04:06:03.10624+00
7d0cf89b-665a-4ee3-ba84-dbe3689801a2	address	CONFIDENTIAL	view_sensitive_guest_data	address_partial	Full address information	2025-11-05 04:06:03.10624+00
b9bf588e-78b8-4e76-ae0b-f470b5428544	city	RESTRICTED	view_sensitive_guest_data	none	City information	2025-11-05 04:06:03.10624+00
4109b5dd-7d42-4514-9c27-8495c7fa5f27	state	RESTRICTED	view_sensitive_guest_data	none	State/Province	2025-11-05 04:06:03.10624+00
9f510558-fafd-4ecf-a424-6cfb514e7868	country	PUBLIC	view_guests	none	Country information	2025-11-05 04:06:03.10624+00
c4c3b3ef-09e0-46d9-8655-d697844c23a8	zip_code	RESTRICTED	view_sensitive_guest_data	partial	Postal code	2025-11-05 04:06:03.10624+00
99fdd124-540a-4716-828c-0ffd573734eb	nationality	RESTRICTED	view_sensitive_guest_data	none	Nationality	2025-11-05 04:06:03.10624+00
d3a70ea0-f02b-47c6-b6d8-9b3c34240d51	id_document_url	CONFIDENTIAL	view_sensitive_guest_data	access_restricted	ID document file	2025-11-05 04:06:03.10624+00
b2b9f76b-4808-4949-b206-9ce060c8c4bf	notes	RESTRICTED	view_sensitive_guest_data	summary_only	Internal notes	2025-11-05 04:06:03.10624+00
\.


--
-- Data for Name: ip_access_rules; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."ip_access_rules" ("id", "ip_address", "rule_type", "description", "created_at", "created_by", "expires_at", "is_active", "reason", "failed_attempts") FROM stdin;
\.


--
-- Data for Name: login_anomalies; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."login_anomalies" ("id", "user_id", "user_email", "anomaly_type", "severity", "ip_address", "user_agent", "location_country", "location_region", "location_city", "metadata", "is_resolved", "resolved_by", "resolved_at", "created_at") FROM stdin;
c2d411f9-f662-4e67-9b1d-7f852e0afb42	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	admin@hotel.com	outside_hours	low	152.59.203.17	\N	\N	\N	\N	{"is_weekend": false, "login_hour": 7}	f	\N	\N	2025-11-05 07:03:31.436429+00
\.


--
-- Data for Name: user_roles; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."user_roles" ("id", "name", "description", "permissions", "is_system", "created_at", "updated_at") FROM stdin;
f0f7fe0b-e70e-4df3-bc8f-1235d9dc1fa3	manager	Property Manager	{"rooms": {"view": true, "create": true, "update": true}, "guests": {"view": true, "create": true, "update": true}, "reports": {"view": true}, "bookings": {"view": true, "create": true, "update": true}, "cleaning": {"view": true, "create": true, "update": true}, "expenses": {"view": true, "create": true, "update": true}}	t	2025-11-05 03:57:09.449803+00	2025-11-05 03:57:09.449803+00
30dda24d-18b0-4fdb-b051-66535aa5669c	owner	Property Owner	{"rooms": {"view": true}, "reports": {"view": true}, "bookings": {"view": true}, "expenses": {"view": true}}	t	2025-11-05 03:57:09.449803+00	2025-11-05 03:57:09.449803+00
4d73be21-fb46-4ec6-aabd-bc3472e7fb58	staff	Staff member with limited access	{"rooms": {"view": true, "update": true}, "guests": {"view": true, "create": true, "update": true}, "bookings": {"view": true, "create": true, "update": true}, "cleaning": {"view": true, "update": true}}	t	2025-11-05 03:57:09.449803+00	2025-11-05 03:57:26.48137+00
c2723abb-0273-449f-8254-742b4c464b7e	admin	System Administrator with full access	{"rooms": {"view": true, "create": true, "delete": true, "update": true}, "users": {"view": true, "create": true, "delete": true, "update": true}, "guests": {"view": true, "create": true, "delete": true, "update": true}, "owners": {"view": true, "create": true, "delete": true, "update": true}, "reports": {"view": true, "create": true}, "bookings": {"view": true, "create": true, "delete": true, "update": true}, "cleaning": {"view": true, "create": true, "delete": true, "update": true}, "expenses": {"view": true, "create": true, "delete": true, "update": true}, "settings": {"view": true, "update": true}, "auditLogs": {"view": true}, "view_bookings": true, "create_bookings": true, "delete_bookings": true, "update_bookings": true}	t	2025-11-05 03:57:09.449803+00	2025-11-05 04:07:27.470773+00
8223dffa-e3b5-45f4-9cd7-15de52e733b5	amer	\N	{"rooms": {"view": true, "create": true, "update": true}, "guests": {"view": true, "create": true, "update": true}, "owners": {"view": true, "create": true, "update": true}, "reports": {"view": true, "export": true}, "bookings": {"view": true, "create": true, "update": true}, "cleaning": {"view": true, "update": true}, "expenses": {"view": true, "create": true, "update": true}, "dashboard": {"view": true}}	f	2025-11-12 08:40:43.167145+00	2025-11-12 08:40:43.167145+00
\.


--
-- Data for Name: notification_settings; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."notification_settings" ("id", "user_id", "role_id", "category", "enabled", "email_enabled", "browser_enabled", "mobile_enabled", "created_at", "updated_at") FROM stdin;
\.


--
-- Data for Name: notifications; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."notifications" ("id", "user_id", "title", "message", "type", "category", "related_id", "read", "created_at", "updated_at") FROM stdin;
e1ccec1b-de09-44f5-8ef1-f173283e168d	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	🔐 2FA Required for Admin Access	As an administrator, you must enable Two-Factor Authentication within 24 hours. Please visit Security Settings to set up 2FA.	warning	security	\N	f	2025-11-05 04:54:06.207912+00	2025-11-05 04:54:06.207912+00
c248e38b-a6ba-4feb-b95e-e2157ebfd030	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	🔐 2FA Required for Admin Access	As an administrator, you must enable Two-Factor Authentication within 24 hours. Please visit Security Settings to set up 2FA.	warning	security	\N	f	2025-11-05 04:54:06.207912+00	2025-11-05 04:54:06.207912+00
\.


--
-- Data for Name: pdf_field_mappings; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."pdf_field_mappings" ("id", "template_id", "field_name", "page_number", "x_position", "y_position", "font_size", "created_at", "updated_at") FROM stdin;
\.


--
-- Data for Name: property_ownership; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."property_ownership" ("id", "owner_id", "property_id", "commission_rate", "contract_start_date", "contract_end_date", "active", "created_at", "updated_at", "created_by", "updated_by") FROM stdin;
\.


--
-- Data for Name: room_ownership; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."room_ownership" ("id", "owner_id", "room_id", "commission_rate", "contract_start_date", "contract_end_date", "active", "created_at", "updated_at", "created_by", "updated_by") FROM stdin;
e397495e-cd21-4a37-a5f8-d8e9a15762fc	06952e8b-bda7-4a4c-b406-94442f799a62	134f45d8-b8a6-4204-a0ad-e673583a89fd	0	2025-11-05	\N	t	2025-11-05 08:24:18.784556+00	2025-11-05 08:24:18.784556+00	\N	\N
\.


--
-- Data for Name: secure_password_reset_tokens; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."secure_password_reset_tokens" ("id", "user_id", "user_email", "token_hash", "expires_at", "is_used", "used_at", "ip_address", "user_agent", "created_at") FROM stdin;
\.


--
-- Data for Name: security_events; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."security_events" ("id", "user_id", "event_type", "meta", "created_at") FROM stdin;
150dad48-3768-4539-afb0-929a09303cd0	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 06:35:30.56545+00
2915a46b-471c-4efd-95aa-12ea5695169f	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 06:36:10.061132+00
8a115890-1aef-4521-b620-38f5749dd0e3	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 06:36:18.901716+00
3cc4477d-7d1b-438b-b9fb-a289b44c1476	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 06:36:36.313553+00
a207d26e-5847-4217-ac57-45a413d106b8	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 06:36:59.72612+00
36e60cbf-08e9-48fa-bd86-cc15ea09d56d	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 06:41:00.401969+00
7f8dedd3-3f42-4735-888f-07ab28f62920	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 06:42:35.106086+00
0734f35f-bad2-4aa8-95d1-b63a9bd010ff	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 06:42:52.365057+00
54c5b392-3498-45e6-aa8b-cd8ff5943159	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 06:43:51.163006+00
020523af-9a4e-4df4-8e4f-cf9bea9ffcb8	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 06:44:03.425973+00
62fe9095-def0-448f-a621-e71d6e76efd9	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 06:45:11.478065+00
e726c497-6678-43f1-ae83-df772cbbc656	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 06:45:14.942792+00
4e26ecd3-c77d-4a11-80fa-9f92b9ee4df6	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 06:49:03.065103+00
13e8ee59-9c40-4190-a15d-8beed6d8fb19	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 06:49:12.157651+00
5787cab3-5406-4080-946a-43563dde7b3c	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 06:49:19.709128+00
68253c10-2ca7-4654-90b2-eb191359f38a	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 06:49:40.577305+00
90b97ddf-d29b-47b8-8d8d-9235381881f4	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 06:55:48.211803+00
3d058cc5-95ed-44bc-8c5c-2f2e2776ae18	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 06:55:49.147552+00
03999a9e-7a52-4f31-ab21-d3df0ea33faf	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 06:56:31.835167+00
fdee179b-3cba-47fc-8fe0-b9baa138a32c	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 06:57:11.738471+00
4212a2e4-76ae-4292-ba1b-0651d212f518	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 06:57:11.95551+00
d02b5341-348e-4dbc-86b3-50a9d5d70b97	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 06:57:36.492192+00
17c38641-1dd3-45ee-a336-db8f02a8a969	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 06:57:44.374214+00
f73d42d2-24b3-4174-aa0d-a92efb9c237d	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 07:00:50.633096+00
099a8d32-ee0f-4d6c-96bd-6a3454164a44	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 07:00:51.930883+00
20c28dbc-2d29-407b-ac59-82d4c20bd626	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 07:00:51.925419+00
ed865eac-d9f0-44e2-a1cc-ed9d297e3319	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 07:03:28.188535+00
b0352433-4eb5-4275-b6f4-a23de54dd39e	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 07:03:31.385685+00
a17c4199-3bbc-4dc8-9d39-5bd8c60a40f0	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 07:06:13.50514+00
a80a1a2d-879e-40b1-bbe5-5cef9af1070b	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 07:09:20.013046+00
e81c0b12-b4c7-4258-b430-c84f5fa57903	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 07:10:18.782575+00
d58d629f-8eab-441c-bd80-e91f9a794480	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 07:10:25.851342+00
32d102a7-3333-4867-9d38-1616b5dcf20e	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 07:13:47.399619+00
f3a62fdf-9089-4e10-a54d-40292e90ecac	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 07:14:54.146806+00
1a787fe9-0845-40a5-8e60-2225e1e261b4	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 07:15:09.263099+00
11a4d30a-e974-4150-ab47-a3ef2ce867e4	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 07:20:31.783575+00
82e295ba-575a-4fac-b104-1121ba786795	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 07:20:43.868037+00
1c3a36d0-b163-4db3-bc73-f8b4f779b209	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 07:20:58.268939+00
57031c86-50be-4857-8489-468a286d6133	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 07:21:23.281507+00
825b8e75-e45c-4847-bed1-05cde85433a7	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 07:21:39.734393+00
303c6d26-ea52-4812-ad93-eb20591db74b	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 07:22:23.327595+00
c2ceffd2-7189-4fa0-b08b-28818ba3b997	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 07:22:29.523799+00
6e9601e9-e521-4525-83c6-575020963bb7	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 07:22:42.895264+00
97989cdc-5851-426d-9276-58040e0a445b	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 07:22:44.739123+00
a8cda30f-06c6-411c-a031-a7fd62c8b075	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 07:22:56.776275+00
b30c5948-a0b1-4419-84d7-888dd329712e	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 07:24:15.013924+00
6272648a-6299-4230-989c-03d5531142b1	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 07:25:05.474073+00
722ea183-d9af-4012-8209-0d98df78082f	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 07:25:20.121849+00
a6eeb247-d01d-47e0-bfbe-af1a077d75fe	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 07:25:27.643846+00
8ae6a13c-f3ac-4553-9451-e056936ff007	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 07:25:35.090155+00
7aeae1df-5165-492e-aa0a-bd9e1acead77	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 07:25:53.638702+00
063076a0-19dc-4c99-955c-a8da55406b6f	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 07:25:55.681475+00
697d51f3-825e-4e0d-8b22-e32d11f38634	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 07:26:03.52541+00
b4f405c2-3f06-48d0-bfa5-156eafe453a9	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 07:26:13.133093+00
a37374de-2050-4949-a0e8-19ff6406fb53	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 07:33:08.026919+00
a750f945-990e-4179-b4c0-1325e7b029c0	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 07:33:08.480477+00
9d1e65ad-9971-4d2a-97e8-67da899b8f88	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 07:34:41.046884+00
80cdc589-93a5-4f63-b6bb-1b5e7972a867	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 07:39:03.501669+00
059273e8-f7c5-4f77-b39b-df7fbe6d0add	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 07:40:25.121872+00
1edffe36-1d00-4187-b16b-27dcff39844e	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 07:40:39.874283+00
efd22c72-dcd0-4f9b-9dc4-7044a971904a	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 07:41:27.772297+00
763be2a4-a4a3-450b-87b2-763938b48ede	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 07:42:42.386903+00
ee4690e7-9bcb-4e99-b87f-72411e056eaa	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 07:42:42.761269+00
df734a6c-007a-404e-bd52-d938dfe8b9eb	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 07:42:42.74725+00
fb506ea6-925c-477f-99dc-df6d210b54ea	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 07:42:56.376758+00
97b4300a-2dfb-4a22-9920-4236bf7d2edf	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 07:43:08.842117+00
4da94340-586e-4893-831e-9675a70bdfa7	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 07:43:18.907822+00
92ced18d-c90b-48b9-a473-406475456efd	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 07:43:26.390917+00
4417d1fd-815b-4e2e-8cba-0e5091d69d59	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 07:44:30.03677+00
6c22c3f7-ef31-41c3-bbb0-3fadcc1912ca	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 07:45:37.71303+00
994d63fa-059a-4536-96a2-a2d82da1225d	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 07:48:52.370473+00
3e747989-5d3a-4d72-b216-b4779bbb31c8	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 07:49:16.911078+00
c58716c4-3647-4641-ae66-0cefa204d4f6	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 07:49:17.067028+00
46c7d62a-a851-4b87-b396-279b307c484f	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 07:49:17.24893+00
2b90e35e-44d1-471b-865f-5f03a6648128	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 07:51:03.327719+00
7a075d80-2f8d-494d-beb2-c596a0765f5b	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 07:51:03.569813+00
2aa4180d-f17e-4495-887f-110fcf3ec997	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 07:51:03.601597+00
ba4e35b7-9ac2-4413-af39-471360e1bb69	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 07:51:10.5858+00
106e28cf-89fb-45c5-a7a4-9e4a571f6c6a	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 07:51:10.835781+00
71ccd2c1-6a7f-472c-95b4-3f629990eeb3	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 07:51:10.98392+00
2271cc50-b6ee-432e-bc6f-88d8b7aa9f0e	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 07:51:27.275749+00
70463a1a-3af2-4553-8cd8-21b0f6a3bd9c	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 07:51:27.506847+00
9a66d792-e88a-4f20-ba64-f665edeae968	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 07:51:27.715698+00
f7dba0f5-cff8-4385-86cf-4ce23d27395e	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 07:53:10.118361+00
e72ac58d-801f-4630-850a-44fb77d4188b	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 07:54:38.715636+00
663042b8-af18-48ec-af09-2d220fb57e31	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 07:56:00.40895+00
cd4cbbf4-753a-4669-a9b1-617976adb425	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:01:57.394579+00
865cc783-880f-4651-a966-d4c34133811e	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:01:58.638297+00
63ffedb8-311f-4aaa-b034-af5149bafdee	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:02:14.560804+00
163864fe-1db4-4dd6-824d-1750cce7c92a	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:02:15.522972+00
e272443c-69bc-4178-aeaa-447c7a690d51	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:02:21.347863+00
3f8d8603-7365-423b-8091-bdbed4a94c8b	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:02:21.601888+00
3d663336-0736-44dc-9f28-932b4967d052	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:02:21.617201+00
6d790743-ce46-401d-be1a-2691522c55b4	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:03:10.873202+00
1b95babc-0cd1-478c-a6da-a47e5e163dd0	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:03:11.161699+00
fc1bac62-87ba-4b15-8032-1470a5eafabf	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:03:11.357965+00
50ec64ec-0f58-486d-8a3f-6d9b88f7d482	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:03:55.054938+00
bfb957af-da37-4303-9156-dc71b435f47c	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:04:13.336674+00
b2fe1cf6-762a-4392-a771-2f71f5f76b7e	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:06:11.990118+00
4ccba55b-6d94-49d9-99e0-4152e9688ad6	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:08:00.929723+00
6e69b585-bb3f-4b9e-80d8-fe7396df9c21	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:08:02.381497+00
24eb9014-b347-4639-9e15-09ab8b05c19b	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:08:03.853338+00
54771660-8cae-4f89-9c34-f60051015c0a	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:08:28.883896+00
ba6c5171-920a-443a-af7b-62cb359fd0b2	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:08:36.114271+00
ed354e61-3a6c-4e0e-b20e-d96e6ec17915	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:09:13.454931+00
885db303-5e3f-4aba-8cc2-d6a80584eb66	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:09:55.997036+00
78d35c7f-3c4c-4728-a540-53bc5ceeb429	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:09:58.61035+00
7d471b4d-cb0e-4af1-85c4-992d0d3175a4	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:09:58.758572+00
dd1819b2-7543-4dd0-b1c0-e6084f82d455	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:09:58.891744+00
5889b66a-b666-43b4-8d62-7d6a81a5a5e2	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:11:25.298184+00
78f30a63-373d-4546-8bc2-ba9c57e7f734	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:12:39.028785+00
db9a2f18-4c00-43d8-92b1-f1e34b90285a	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:12:39.125516+00
7aa578fc-0c80-47a7-b73b-eac1ec9d727d	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:12:39.261906+00
a7c456cd-6fb6-46b1-8f38-2d3506e23256	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:13:44.606545+00
96b0a212-f400-49ea-822b-c6d13424c0bc	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:15:51.134104+00
2d4a3aa8-024d-4832-bcd1-ec9e312f5fa5	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:16:03.111046+00
377f8536-c62a-496d-9623-9402d8be94dd	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:18:38.473744+00
25f3226d-27b8-4d87-9b5c-8ff8de1741e8	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:19:26.350243+00
fe2e399c-b7b9-499a-8daf-13eab5ef0c41	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:24:53.285804+00
ab0a9cfa-4233-46ef-9845-afb5e83578c3	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:25:34.932088+00
aaa30e02-07c4-4811-b87f-84417eb1280b	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:25:41.857787+00
88612cf0-6a16-4ff2-8333-ce9a6814f61d	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:25:55.322509+00
b4804dd7-099c-481b-9776-a7f826a985eb	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:26:00.485771+00
e7c96dc7-11f7-41e1-8aa4-af50b5d2facd	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:26:32.744954+00
107653d5-a317-4523-8a60-705d9bcdefb0	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:29:36.365266+00
fbb7851b-2b9e-454d-bd7b-23df510545e7	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:29:36.575202+00
05acff1f-c8c4-434e-8a04-cb29730cfccf	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:29:36.737776+00
1a9f1e56-e7b3-4ace-bdc3-cb658e67b3d2	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:29:43.596786+00
cb3bb640-5968-4bf1-ac89-ba14506dc5ed	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:30:42.806823+00
0646fef8-5f74-4e1a-a66c-eedb46815663	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:32:43.939636+00
919642fd-085c-43a5-894b-691e3fc11ee8	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:32:44.162809+00
fc61139b-c2c9-4779-b53c-0aca8349346b	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:32:44.330056+00
99ef8ef6-f424-4d99-b58d-b5453c20ad63	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:32:47.221707+00
e7674d4e-88fb-4106-aba7-b3c5b468d89d	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:32:54.269626+00
2ef5305d-7512-4b57-af23-1a0354a3c1fa	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:33:44.894279+00
3b8805a8-c45b-4529-a202-19023c8d4c3b	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:33:45.031744+00
2fe93573-5ac3-413a-9796-b11f340f973c	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:33:45.362441+00
ed9ed3bf-4803-4604-85d4-22e1c905e3df	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:35:17.601197+00
64ca33f3-24ba-4124-b065-f3540c625006	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:35:19.564347+00
a0972265-0fa5-4cea-b05b-9122132ccf23	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:35:19.727982+00
6c4ae8ee-6d6f-4abf-9f13-d8c57d124277	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:35:19.891746+00
7fc9fff7-84fc-4285-aab1-3f832d48d4de	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:35:27.376301+00
04fa8582-9201-4244-9f18-6b96a5917909	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:37:31.593195+00
5e88d60b-07af-455f-8fa4-2453ead7bac0	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:37:31.835826+00
5276ba29-2ac1-47c5-aafb-799984c86a71	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:37:31.99279+00
6a4787ad-f463-451c-8cf6-661c85750df5	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:37:34.000034+00
3789d0c8-f456-479d-8151-aa366e494661	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:37:37.730155+00
bb818c18-8a2a-4e86-8105-baab3bc8e06e	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:38:07.62883+00
248a5c33-f5aa-4eb6-895a-4339c08e3e45	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:38:09.616769+00
b8e5d797-50d5-4a30-afed-5120205c6569	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:38:09.725294+00
d89835fc-15ae-446e-8838-b574ffb89474	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:38:09.870371+00
40a438bf-e6fd-4086-a3d8-a52142cec887	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:38:20.562758+00
a29d641d-c94c-41aa-b5d9-9144fd0e5116	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:38:20.861428+00
8fcde6e5-2320-490c-b72b-a11503bfb6e1	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 08:38:20.872469+00
3d337e8d-c480-4550-a1b9-c41851bfdebd	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 17:16:21.686648+00
fabf3e7c-c511-493f-89d2-15b53eedbb36	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 17:16:40.336077+00
5b64c457-a364-4f2c-9692-d02393984830	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 17:17:04.140131+00
2b420790-d63d-447f-bac0-f6a9f38d21a5	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 17:17:05.291771+00
f6d62bac-f782-4a92-8dd8-8266e7541e45	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 17:17:08.019854+00
25cca0c6-8cf5-4735-bb97-3ea1a3fc0f61	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 17:17:08.807018+00
9ffbfd87-dd32-49a9-994b-aab2f79b3dcf	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 17:17:37.428933+00
7ca4a143-00f7-408e-9757-f4444dbbb1a5	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 17:17:38.577513+00
b32c8321-fed2-42f0-b622-161c26d401fb	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 17:20:24.220092+00
09ce92fe-f425-450d-9d82-034191d2621d	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 17:20:51.763701+00
43524de4-5655-4a9b-9d9a-d7df3d83cf8b	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 17:21:32.052639+00
9f31821d-1288-47ec-8a44-6265fd0f6dd4	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 17:21:45.639092+00
09cc23b5-5770-443f-b7a2-4e97e30ff3bb	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 17:21:45.649231+00
9b6637f3-741f-488a-8753-bbc79ecd8ad9	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 17:21:45.86002+00
51f779cc-ad01-4de6-a46f-e587a5156170	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 17:22:08.673885+00
b6394ecf-56b8-4393-b956-1f68a92c3653	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 17:24:22.652889+00
0460ee6f-3848-41f0-b9e3-775408c01d71	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 17:40:02.176812+00
2efc26c2-4e5e-4e8d-90c1-563e8e702c58	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 17:41:17.753343+00
50dc4d6f-c07d-4731-b68f-bf9c15d9601b	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 17:45:47.972504+00
1501ae73-bf18-4737-a245-ee0a90f33a33	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 17:49:25.304559+00
25470e50-606a-41b3-9402-0a19d9262341	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 17:49:25.526473+00
08da2324-7d5e-4e83-a7f7-d080f07d84e9	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 17:49:25.625822+00
6db5d26b-7cdb-460b-95b7-2b3a13cb5194	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 17:50:43.41234+00
73a5240c-f698-48ca-8200-5a102666bdd1	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 17:50:43.845134+00
82143e92-f330-42eb-a7d0-987cf93168b3	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 17:50:45.039117+00
b4d5562a-7b78-4544-990f-7d5f08a12d51	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 17:50:48.965254+00
aa9ccf90-a495-4a20-bc40-c47315bec0de	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 17:50:49.212635+00
9e8c8a90-a889-4a97-abd5-00314795ebf7	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 17:50:49.531264+00
fac62047-55a9-481d-bca1-7638188c6a4b	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 17:50:58.51528+00
9dedac1b-a04c-4fa8-bce6-b13d644ddeeb	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 17:51:05.304495+00
2e2faee3-0c68-4d16-ab70-ebc7edd322c9	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 17:51:11.141971+00
06ccdaa2-bcac-43dc-844e-39d75abe06dd	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 17:51:16.805055+00
7fd1375d-2ae9-41f8-b1eb-be6538de9909	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 17:51:25.117115+00
fba3cb0a-9506-4d80-8a8c-2599ea8e1653	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 18:00:56.788851+00
0e7c3660-e29e-4d2d-b1d0-602f002c2472	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 18:01:13.105828+00
6e350d3a-10a5-44f6-b467-f776e80a8393	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 18:05:39.970626+00
631c0c40-06ff-4b84-8173-ea16ef753783	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 18:05:40.376963+00
83f7cd1f-26f8-4e71-96a6-6a317d6964f6	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 18:05:40.640716+00
806f716a-f284-41af-b051-aa9484cdd3b0	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 18:06:09.926244+00
befbd255-f59a-4360-bf93-a8bda23b1f86	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 18:06:10.168771+00
3d7295c7-02da-4556-928b-b4e988c26541	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 18:06:10.441721+00
cf97ce3b-086a-460b-9c44-35700378756e	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 18:06:19.005525+00
8dbe86ee-65aa-4ff3-9a49-7d774a0e40f8	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 18:07:05.125545+00
712d63ba-0376-4a7b-8228-49ae608ddfbc	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 18:07:13.586616+00
34599ad3-02f3-47b8-9c17-ec38cf24e0d3	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 18:08:40.477909+00
1125f284-65b1-4e83-ab6c-130bdecb49ee	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 18:08:40.746037+00
5dee4212-bc49-43a1-b82d-86fe32ed256d	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 18:08:40.940031+00
dcb0abcc-212b-4718-899c-fb3b7e7b621d	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 18:10:54.633069+00
87477554-f17f-4058-9a3d-172c8432c2f6	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 18:14:09.382075+00
2c62d45c-2a1e-48b9-8f74-1db421a3d624	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 18:14:11.237607+00
3fad2c83-2195-453d-889c-349bf5e7039c	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 18:14:14.950723+00
3c12af70-600c-4479-9b66-d921a80146b9	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 18:15:05.004923+00
5cf2e02a-031f-4fca-8636-4cf694c25c8f	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 18:15:07.828063+00
fd303066-f2b8-470e-9705-ac2b4675c623	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 18:15:08.729049+00
b9e2d6fd-9ec2-45cd-8790-9d98b55c4a79	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 18:23:18.115907+00
b593e2dc-1fb3-4f34-91cb-3be666ac4b73	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 18:23:18.152016+00
e010c74e-069a-475c-a8cd-91603a2f7e6f	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 18:23:18.223214+00
67f2c613-1402-4df1-b017-f109a4fa0d6e	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 18:25:39.001791+00
178ce3af-fe22-4edc-86e6-a52c45ac9d04	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 18:25:40.358191+00
c4e5c4fc-b199-4e77-91a5-8e1df6d963fd	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 18:25:40.595274+00
fc8a2704-5c63-4e0e-bffb-d2b40b3cf690	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 18:25:40.763777+00
651d6c4e-4625-4f18-95ba-e77bcd56ccfc	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 18:25:49.650444+00
4046677f-20d8-4ee0-bac8-96455b93101b	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 18:25:49.770474+00
6327f20c-42b3-42c7-877a-215d5f63a7e1	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 18:25:49.89901+00
1307da71-255f-4b83-97f2-6f90242d30d9	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 18:26:29.426652+00
645e4d30-0b7c-4002-986f-825a189b2451	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 18:27:04.605159+00
c2b53733-03ff-4c75-ba15-7fa415840336	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 18:29:23.913536+00
eee7db43-6ccf-4871-acbb-e9ae60e15975	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 18:29:24.04906+00
a503feaa-12e2-4f2d-9afc-12022b95f0d5	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 18:29:24.218236+00
5e4fb9f0-c124-4048-9643-378ce9830c67	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 18:29:35.742052+00
47f408b2-3df9-4313-90e4-f7739fb7205f	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 18:33:14.435166+00
ddd0b728-a473-4abb-9979-4cc3be7585a1	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 18:33:14.626094+00
165b015a-f543-4fed-9622-e9212ebd7bee	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 18:35:00.141606+00
60a676bc-7709-49d2-a4fb-c558d148fc91	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 18:35:50.254167+00
5401b396-a19c-4941-8836-ea3401e09b99	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 18:35:50.510911+00
a01c6632-e0eb-439c-bcfe-2d25e123aa31	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 18:35:50.680466+00
f586dbb0-cd02-4723-9c31-c21822c852a5	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 18:36:06.811056+00
0ed91378-2180-4d1d-ad22-ff507c79814c	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 18:36:06.931618+00
992fc333-7dce-48fc-becf-c1e228214ce8	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 18:36:07.287941+00
be62e865-ef67-4540-9460-0f6c62dae67e	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 18:37:27.508006+00
a769267c-0189-4823-b963-6f868438431d	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 18:37:31.154381+00
acdcfa2e-2ab4-4503-a372-4ed992cdd762	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 18:37:36.029535+00
1813574a-3773-45f7-84c7-38077b407887	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 18:40:36.077858+00
25823a90-16a4-4894-bdd4-dcddfc50f477	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 18:40:40.028118+00
8884fe2a-1c2d-4f78-addb-dd9f3ada056d	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 18:40:40.354897+00
7f6a566a-25ed-419a-871f-e6d0a55affd4	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 18:40:40.412864+00
22e39805-b4b2-4a96-b0ac-2db32f4418a2	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 18:41:01.924917+00
d2e9843d-5598-4e33-a3ef-d81bb9056c68	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 18:48:47.04077+00
34e79f85-25ce-43b8-a987-4b655d37254e	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 18:48:47.065591+00
8889681f-4566-48cc-b957-cf8235c859cd	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 18:48:47.227292+00
822eab4e-ab9e-4a19-b6f1-bb94179bd9a3	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 18:49:04.932873+00
85479f36-cd24-4ecb-b059-fdcbcaf01e37	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 18:49:21.180856+00
a4742608-abc3-4222-a5d4-051e3a959f71	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 18:49:37.6533+00
9d9bc978-e128-48f9-8ae8-d5017e71cd68	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 18:56:03.633932+00
116852d7-e707-4a1c-b2e2-cd16c5c165c2	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 18:56:05.765664+00
eb8f112e-e017-43ae-8da7-58eea9ab52a4	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:00:27.435448+00
52ea2a95-d3db-49bc-be8b-4019576ed566	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:00:27.456905+00
c650a7bc-e2cd-441a-85fe-e44479f49270	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:00:27.639132+00
8bbd1c36-d271-4bcd-afe5-317e89c0652d	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:03:02.28695+00
1c33da2c-a925-4a65-bd4b-10f7bbfd3c8e	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:03:17.657381+00
4baf89ee-f180-4c59-978d-ca4dc65fabd7	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:03:19.34762+00
4c940916-828b-478f-86d9-041cef2bf9f0	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:03:20.739008+00
2136f521-4248-4960-b7c1-2bdb5854d805	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:03:24.577534+00
444c06a0-abfd-4615-94df-a8061aa5baf8	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:14:01.856992+00
9d77c530-e4cb-47f0-80c7-bd1b3be88dd8	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:15:10.670678+00
9bab00f6-0b6a-4036-9d18-ed81b99c4700	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:15:33.393697+00
8f0caffb-636c-428d-aca5-2280ce04dda0	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:18:51.628624+00
b7ffbd28-d103-4bef-a485-08acff6d2fa6	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:18:51.903467+00
b9545f2e-317c-4807-b7df-54c49e2f24de	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:20:37.909583+00
d18c24fa-1991-44f3-bdfe-472c664b83c5	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:20:38.070166+00
ef1579e4-41ee-4e48-9985-38542c4feba3	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:20:38.282191+00
68034ba8-0e6a-4cf0-9f16-45cddfd0ba60	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:20:55.630789+00
03f55439-990c-4e95-8cf2-98fa4ba0a1b9	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:20:55.708513+00
303fe1c4-55c3-4160-a2b6-69c8a99b6f34	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:21:26.957195+00
e83d16c1-d489-4615-8fc4-6e072785c44a	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:23:00.29082+00
ab819a78-2bcf-4d09-a4b0-b7a79f1bb5f3	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:23:09.556+00
6160c735-2a65-4f2a-9c7d-f0533cb5fca7	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:23:09.884504+00
965c4e27-48da-4f57-aa12-223103ecde1a	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:23:09.981934+00
778b6855-7ac0-4219-ab47-984f83633f39	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:23:26.111247+00
83c23fb6-d3db-4551-a89c-3578cf7a6f84	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:23:34.297602+00
b8072921-695e-403d-af4a-b409a08fc5e1	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:23:34.47186+00
c9a29347-ad6f-4fbf-87cd-99d53c1047c6	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:23:34.599648+00
c3b32d30-acc7-4ee4-8db2-536a7702dbcc	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:23:37.855095+00
091a8db0-68db-4019-8ca0-19bcd8a0aaa8	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:23:38.040196+00
efc34bc9-9b0d-4b6d-aee4-3143fd891838	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:23:38.086039+00
a2d502ab-33e1-4a33-9032-3428b9af1275	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:24:10.942158+00
d20571ad-65a4-4b3d-9ea1-6d9f3a07e5f3	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:25:18.219073+00
be3fac5b-65e3-4d10-9c56-fba6b2e9ba87	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:25:22.745888+00
3eaa1528-1253-4fd9-af11-7a9f0572615d	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:25:24.739377+00
903efcbd-b1e3-4cbd-810c-fee12de15135	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:25:24.865199+00
57e53f77-a4b7-4ce5-bf44-661741c992df	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:25:25.001079+00
b155a2ca-7137-48a4-8319-c4b39a55d235	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:25:38.422697+00
af8d0d68-5527-492a-9802-bb8b7a7d39de	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:25:38.505335+00
b29ac561-633f-4338-8d24-dbf213f70134	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:25:38.667691+00
6e2042b7-07d2-4c24-8be1-4d4fbc4bc7bd	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:25:44.956104+00
a788ac22-24c9-4a19-a95b-25b7cee3604d	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:25:45.137156+00
556d64cb-af96-4157-844a-14ce1b962457	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:26:05.044067+00
98fa5eed-a40b-41d2-aff6-994a8a288917	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:25:45.267723+00
b85697ff-4e19-4e58-a43b-c5c88b3b24dc	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:26:14.325573+00
27cecc93-5c80-417a-9046-562f3f79d910	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:26:53.586897+00
bc96200b-2976-4501-bad8-b4bbafab5ed0	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:27:05.284547+00
a209a9aa-a9d7-4009-84ed-3888d08ff6e4	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:29:26.580452+00
82671d4a-8722-4b3b-89ae-70469bf14ced	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:31:35.720008+00
a801426a-75e1-4c29-a6c6-888c921125a9	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:34:07.947853+00
c12b1945-a28c-4d82-a59c-b72b837e28d3	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:34:20.045687+00
34c17fa7-c103-461b-8348-98add25d8d9a	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:34:22.557437+00
a7583a01-1f35-4e00-8074-9b438d8fde4b	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:34:22.736925+00
20ce391d-638e-447b-b7b0-a3564e4df6c5	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:34:22.879442+00
17800308-a6ce-4aa8-b6ed-04807ff581b7	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:35:05.692125+00
b985ff14-500e-4913-89f7-f876f004cad5	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:35:23.961133+00
7734339e-f58b-4f5f-81ca-e875580e1bd7	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:37:26.026747+00
f548cf4d-9b79-4c1e-8962-57b86fcc8a29	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:37:36.062508+00
fb4aae18-b4e3-4694-9ba5-34694c513e55	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:38:03.912073+00
cd11991c-3d84-4df1-a9e7-8c6be9cf27be	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:40:59.386625+00
106f810b-08ce-4b8f-b2bd-0b1c2c3ef788	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-05 19:41:19.059081+00
512bb20c-edea-4b25-819d-d4d605c1bd72	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-05 19:41:29.228997+00
2ac83453-01d7-489d-9c5d-530caca72187	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-05 19:43:36.65866+00
ff9bec8a-49d7-49e6-b740-96a32033a224	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-05 19:43:36.661185+00
9e82a2aa-40c4-4714-9d3f-ff64d3b78bef	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-05 19:43:36.659214+00
274ee6f7-8730-40aa-83af-8630217a4e27	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:44:03.328162+00
680f655b-1821-43f9-b6b3-604429dc843f	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-05 19:44:47.749055+00
9164372a-f00a-42ea-bb96-1aa23843076d	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-05 19:44:47.751857+00
ed9064f5-04c8-4247-95c0-79f0c843af6f	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-05 19:44:47.82446+00
13965a4e-c098-48fd-9ecb-15274d7a2630	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-05 19:46:53.507656+00
6dee5847-8daf-4594-aacb-dd6013b98f35	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-05 19:46:53.512079+00
3597478e-d90f-4989-ad56-b290a84abbdf	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-05 19:46:53.514723+00
f0a72a66-a1d6-4196-80bc-70e512a24b55	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:47:31.043+00
65627a7b-74a8-4f32-8ed1-d3590b8b182e	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:50:15.558875+00
e665b5f8-cb42-405b-b2ac-4b06ed0726e0	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:50:53.851132+00
8cf038d9-9d04-47e1-a5ce-cb6a14ee60b3	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:50:56.662526+00
c81be208-967b-4308-9d34-a141b3a6920c	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:51:34.097507+00
4a2d046d-04bd-485d-8d8b-6c43ac0f26de	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:52:08.501857+00
fa38a591-4619-4ee1-82ce-e63c0051c7ad	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:52:39.583598+00
40210efe-46d2-432f-9b44-2a657e563000	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:53:20.152347+00
63113bb5-a5e7-4635-a290-863a9b2e8883	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:53:36.155294+00
0cb7cc09-9d9d-467f-920c-404449dd2a1d	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:54:18.783636+00
ed864f4f-2a43-46f0-a0b1-0345fe96bc52	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:54:24.339309+00
4c2389dd-9048-4723-9a62-b47a0bfb62e9	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:55:23.696312+00
84ea2e95-74ca-4e8c-907a-7b70dfb67efd	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:57:29.672412+00
20e24b85-bfe4-4fbb-af6e-675280c68054	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:57:36.505039+00
2edd7e2c-ff16-486c-ab15-ad6f63e84978	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:57:36.843608+00
b1ea0881-8630-4e95-a57f-fc44055d0368	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:57:37.128507+00
7bf31a8c-24c1-4473-b800-22f693e4f88e	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:59:44.986628+00
d6fb207d-013c-446d-9a93-c56751489d65	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 19:59:54.986547+00
8d590c6f-f0a6-4f24-8d23-9c3f34ae84b6	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 20:00:26.095536+00
f0e79d2a-8d47-44f8-9956-6a3a94584a91	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 20:00:52.729883+00
bfb1c174-c542-44b2-b5f0-40e3b1f885b8	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 20:01:30.20187+00
bdfa741b-b37c-4ecc-8f9f-a6a48470584f	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 20:03:39.667912+00
67c2dd7a-9df7-4de8-936a-12c6a385b1a9	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 20:04:14.809135+00
6dabf8b9-c3a6-4e47-9107-0a52dc907af6	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 20:04:23.24537+00
320d222e-6fbf-4eb4-ab28-74b04824cc9b	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 20:06:24.194077+00
8f6cadad-26fc-4206-b3a9-8344bd327fa3	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-05 20:06:40.416496+00
3017da51-d92f-4a82-83e2-d98c2a394e3c	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-05 20:06:40.418408+00
72c5e394-8ad4-4cc8-8eed-79d414608acc	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-05 20:06:40.539246+00
bf8cb2dc-f6e8-4196-b5fe-1dae2e7ad469	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-05 20:06:57.338987+00
51049935-6931-4557-998e-00ae401773e4	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 20:07:04.272805+00
e7c9fb76-9eb9-4f52-91cc-d5e75bd49661	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 20:07:15.342843+00
0c985e29-dbe8-48f0-89c5-997f21ae60d2	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 20:07:49.065671+00
a52949fc-e49b-4120-b58f-627041d45e79	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 20:08:29.446252+00
e3935b6a-a785-4d61-ab51-481f3cffab09	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 20:08:33.5791+00
73ae1bc8-2fd1-441a-9cbc-36074c5f122d	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-05 20:08:48.872602+00
d5da9872-ad9b-42b3-a1f3-8323d22b4ed2	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 07:51:45.552536+00
699830d1-5451-4aab-81b1-7863e84e95db	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 07:52:02.210006+00
453456a1-d6b2-4340-8c86-193283afe41d	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 07:52:17.455308+00
49700622-dcb2-48d1-b71d-b99c6c19e414	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 07:52:32.548418+00
5abbf029-a9f3-48e0-ae23-ca8c3e4d8119	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 07:52:34.900434+00
272e79ec-af9f-4610-9b4a-1fd17a26c8cd	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 07:53:16.013942+00
dbb5803f-98b0-4d4f-98ed-355a2f7f52d8	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 07:54:00.34405+00
8bd72e66-e158-4939-8aa7-342587cd2b91	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 07:54:25.176049+00
4ac21f83-b693-43da-b29a-7a11a3165c55	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 07:55:32.942513+00
960d1d68-21d7-4cc0-bc8b-a56f2505f9da	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 07:57:17.561313+00
c9c4d0ea-bfce-4898-aa78-9d312b4c681e	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 07:57:19.020582+00
22c62501-0f5f-44e4-b7be-d5a1867d4468	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 07:58:38.048658+00
58ef3ee0-e9d4-4d0d-93e9-cd9ffce948d0	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 07:58:48.402963+00
427bbf79-0d47-4675-9924-20f1956c8ef0	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 07:59:18.913247+00
182f995b-82bf-430a-bb5a-3b80edd90fef	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 07:59:19.615012+00
9223db66-dd4a-4848-ad8b-895361e76b28	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 07:59:20.921359+00
aab2679b-f2a9-4424-9e81-58cd6a41cd10	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 07:59:23.219027+00
43cf9a06-60c2-4d1e-8971-682305688f1b	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 08:00:12.978876+00
52b4cec4-be0c-46ed-b5f0-d4c54a47d0cc	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 08:02:52.748524+00
ae48f685-076e-450a-8caa-9ffbfa2b283f	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 08:04:05.051718+00
4207aa92-10c9-4513-9d01-356c8d9d7cb3	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 08:04:11.306587+00
61ca092c-3294-4551-9982-6c7fa34a4e9c	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 08:04:31.927835+00
2f97b998-03b8-4cfd-a337-f16879a30e8a	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 08:04:36.923284+00
8dc46309-e18a-4400-8473-8643e01c61b8	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 08:05:11.688364+00
0e155f7f-3f80-401d-9016-e073577bd623	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 08:06:15.341253+00
e0c7ed5c-1f40-4579-bedd-17c11323f780	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 08:06:16.190767+00
f6c19eeb-727b-461f-bf64-d59e63839394	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 08:06:16.593861+00
cebe8384-f331-4434-a5d2-8186df88c93a	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 08:06:17.110808+00
f71ca9dd-a625-43a3-af44-4034f41d6621	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 08:06:34.979825+00
779940d8-9195-438d-8be6-76cc5aa3711b	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 08:06:48.638003+00
92dec705-3595-4402-9320-517cb6993260	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 08:07:01.730128+00
e7b6105b-cc0d-4268-b3ec-a32a4c00a5c3	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 08:07:07.227228+00
df309f4c-28b4-4c94-8726-621ffe56280b	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 08:07:15.072388+00
43ce51c8-ee15-4899-96aa-f053c0829665	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 08:07:21.723659+00
b915ce2e-8bc4-467f-8340-e0ec5371a712	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 08:07:22.986434+00
7048e2af-8ecd-4ba7-af77-44f4fd39efb3	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 08:07:25.881784+00
05cc8585-8ed8-437f-a96a-9a45e61ef431	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 08:07:39.77706+00
0aed49ab-8df9-4ce2-88d1-63e43a68b1c7	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 08:08:53.821825+00
065368de-b726-4b4d-b44d-60b1a282531a	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 08:10:03.182885+00
9ed70c87-6203-4c15-8160-27490d427c07	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 08:10:06.951558+00
b3e76203-c1ff-4356-89d6-a0635f8756c0	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 08:10:11.667968+00
d3c2c10b-a367-41c0-b367-7b9f24e2a061	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 08:11:40.108812+00
a18dfc1a-9a71-4363-995a-4352eea0172e	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 08:12:03.628328+00
c87ebc36-6aed-487b-8550-e2278f87b480	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 08:12:33.851547+00
dbe22d38-64e2-4ff7-b4e0-b344e7bbe136	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 08:12:34.763318+00
3ee3de21-854b-4063-a2c3-a06316968a49	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 08:12:35.130456+00
4a3caf3f-ac13-48e2-8c9d-1843278c2d39	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 08:13:21.656659+00
3880d814-d9d6-4f6e-8c99-610831b3d548	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 08:13:31.884947+00
68c2d5e0-051c-4ae4-b849-d3bb3ec8bb81	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 08:13:34.755512+00
478976a6-3950-477e-b740-2b9d1d4b004b	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 08:13:40.757777+00
3b716236-9d9a-4f0a-bb3f-6cde819e3b63	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 08:13:43.658321+00
efd32b1b-c57e-4b25-b81f-fb8f052ce2f6	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 08:14:13.4903+00
73db87b6-c9b0-4881-b1c8-67396f6bde22	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 08:15:02.803591+00
4e443d07-bb75-42fa-89a3-15c2aa281c40	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 08:16:26.697801+00
73c7a072-dfe8-4f09-8bc3-65de8605cc1b	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 08:17:33.764826+00
0951a455-15f8-40b4-94d4-cf8585331d34	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 08:17:39.450628+00
fd69f657-83c4-4288-9200-75faf524e693	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 08:18:41.790404+00
ac72f9bc-fb35-4d84-b002-19b564151c54	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 08:18:42.811716+00
daf1aca8-0c21-49ae-a639-85211098a4ea	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 08:18:43.110582+00
fa6f02d2-1711-43bd-baea-90dddf2edf92	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 08:20:05.940853+00
f6a8e5b1-0dfa-47c9-a02d-4ad7c5d05446	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 08:21:13.639892+00
5cfd1c27-a89d-46fb-a324-257782fcca69	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 08:21:15.551999+00
c473e6dc-2147-4866-812c-f92782581a86	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 08:22:19.017307+00
a7e59b48-5fc8-415f-bc5b-301b26437e8c	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 08:22:33.029349+00
8a8e4d67-a730-4de9-9c4e-30d5e6e29759	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 08:35:15.92556+00
b3d6fc99-4fe6-49d3-9f3f-16c67751c85d	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 08:51:27.781165+00
aa96aaee-d711-4640-b0db-302fa30c40cd	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 08:52:21.988511+00
a90d1665-d395-4c93-b189-c455ea2aa99b	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 08:52:21.996318+00
3eabe0e3-0a77-49fd-910d-1e3bba781768	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 08:52:22.000648+00
764d8e16-f9ae-46be-9f00-33c1d10917fc	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 08:52:22.287951+00
af8e043b-c1ad-43ab-a1ee-cfe0f84c0d11	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 09:01:03.376545+00
55e396bb-0add-4ff2-bd8f-1a2142afa654	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 09:01:03.929963+00
f5d74721-6657-4a46-9863-523445fb6263	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 09:02:43.925666+00
139f1953-a7b4-45da-9fe5-71dad08e5d60	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 09:02:44.781665+00
e9328b15-c377-408a-8965-7b8faf1b2f85	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 09:03:45.138527+00
cc1bf179-609c-4e73-b222-eed3f52fe010	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 09:03:46.00585+00
0f5017c1-19b7-4ce2-821a-3500b0fe5ef8	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 09:04:00.926397+00
362d0b64-e04f-4bc3-b499-e4886c57921a	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 09:07:35.247291+00
5d931dc0-5d3b-4c27-a176-51d5fda6929c	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 09:07:37.318588+00
6f18c24b-683f-4fe5-9d8d-a66be96a6c7f	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 09:07:39.204016+00
e3b63220-5134-40d1-955c-95c78419af2f	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 17:07:38.989752+00
3a1ac09b-b207-45c6-976c-8b28f73dd4cf	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 17:07:39.22655+00
69032460-840e-4e5d-8411-eae3659fb604	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 17:07:46.716929+00
a4533870-ee49-4888-ac9f-76dec585756b	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 17:07:57.680948+00
dd5b9bd1-c910-4984-95f8-f87d663ddbf0	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 17:08:44.128934+00
5aba5d38-6b90-4371-88ed-afc425b966a1	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 17:49:46.018714+00
42ba1a90-fc1e-46ff-bd51-9b35a798814b	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 17:49:50.960516+00
19760b05-e934-4479-a653-35e126749e9e	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 17:49:54.759947+00
02fd490f-671f-4df5-af7d-d0d2b9bf6827	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 17:50:10.124202+00
e201ce52-72aa-4392-ba3f-ff8ce24da26a	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 17:51:38.897532+00
2608d552-564e-40d4-bb02-89c0ca936be2	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 17:52:34.736821+00
6296714c-65d4-41a7-a288-4e065d19f2b0	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 17:52:56.383189+00
47cb0962-5d39-4ed7-a8ab-f71079cec8f7	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 17:53:17.760244+00
d94212c2-8a1a-4ad2-9cf3-d61675248dcd	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 17:53:29.669009+00
803bd84d-8731-4874-bb78-45faded8953f	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 17:53:34.371475+00
a06c4f36-5d83-461b-a29d-9dc8eaaa5878	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-10 17:53:48.284229+00
25782a00-4634-44f1-89c6-6a0b04bd94e7	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-10 17:54:21.958153+00
53bcda09-76a2-47a1-8a7d-6cb583fea5e4	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 17:55:28.831886+00
099ae347-fabc-429d-b78a-fe82379c2bbd	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 17:55:53.616178+00
7a72da76-8e6f-44ea-81bd-a5e6bb2a495e	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 17:56:05.689524+00
ca198b60-57b5-4cb0-9b07-efc4638dfde9	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 17:57:10.994813+00
988c280b-ab29-4964-94d7-dbad8ac08df6	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 17:57:25.294486+00
1fddfbbd-5ba5-4ea4-bf4c-a4aab4a3a010	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 17:59:15.158341+00
1ca0ea2c-9df1-41a6-aed7-9cfbddd55ae4	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 17:59:33.369999+00
33d18d33-746c-4bfb-a3f3-49bd328c0295	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 18:02:45.35027+00
67033eb6-b9f6-4039-b03b-1805a79dab76	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 18:02:56.449494+00
1a24cd56-c5c3-4524-8e09-e57e8ab61874	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 18:04:24.718623+00
599ae385-d047-4f50-a492-2bce141080fe	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 18:04:42.480004+00
b1089932-cf6e-458e-93c2-430d85dc705f	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 18:04:52.425063+00
1aabbfb4-879a-4b82-9ffb-926c674abfee	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 18:04:52.746444+00
cd5d7c85-6884-4b21-8788-bd2d26195e1c	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 18:04:53.533539+00
78991716-adf4-4fd5-9ab3-c682f2b5c042	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 18:04:56.90927+00
8c3adae9-ba34-47cd-9305-7b516bc2e6a0	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 18:06:46.006148+00
bf1a54da-327d-4095-ae98-f48720c187c9	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 18:06:46.930865+00
3b402612-4c51-4522-b56e-a3a84c6012bd	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 18:06:47.649183+00
a3042217-3729-4b93-a535-9e60666067a9	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 18:07:41.76854+00
3f99da27-41c3-4214-865a-709a31dcff69	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 18:07:50.439753+00
6ac9d441-273c-463f-8691-c5f0311ec182	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 18:08:03.316567+00
35fba1fb-be07-479a-897a-fed380505327	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-10 18:08:07.650625+00
ed5610e1-499c-48fd-8a5b-3f3a27cbda82	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 18:11:39.486896+00
3445e1de-5d50-40f2-bb9b-a74da9a7193e	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-10 18:12:04.964435+00
8834e17b-af73-4425-9999-6d51b6ea767e	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-10 18:12:05.18978+00
d2fc01e5-a9ac-4a83-a021-c09901049251	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-10 18:12:05.370995+00
07ca49da-8567-444f-a275-e08ba910d0df	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 18:12:15.203386+00
b1a690ab-a919-4182-8761-5baa62e80c00	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 18:12:51.705477+00
3da50283-6a72-49d7-8ac8-cd33c3698213	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-10 18:14:40.46453+00
cae90741-4c18-477e-846b-7c78612e2506	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-10 18:14:40.551351+00
7304f9d7-adf3-4836-8f8c-39dae08b7550	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-10 18:14:41.129377+00
95d85ded-bf46-4b49-9367-da35874c584f	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 18:14:48.811139+00
10332c13-fca7-492b-a71c-f32fc8aa18d2	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 18:15:04.664458+00
3d4382df-bd4a-488e-a7ca-4bf07af7bbb0	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 18:16:11.609488+00
daa3252a-5ba0-43d9-82af-5d4f89c2ff71	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 18:16:16.256914+00
5801ae25-e263-4c17-8d90-100640c6e3f5	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 18:16:29.749661+00
4d578fbe-907b-4f63-8346-c9fb3a752eb1	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-10 18:16:50.354998+00
4d073506-fba0-4ce7-91d9-002bcaf5f4a3	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-10 18:16:50.494633+00
478e3e03-dbc4-4690-89ab-96a0b68c5dcf	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-10 18:16:50.676776+00
24c3a564-55cc-4306-9211-92a6cb9ed045	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 18:17:02.736811+00
91e8e719-7042-41f6-b768-803f0c623e20	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 18:19:10.151391+00
5407cee6-45da-4bbb-977f-c9a483ed6002	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 18:20:26.359988+00
038e02a2-8334-4689-9e02-7e6d90e5d4ab	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-10 18:20:28.291812+00
aa80e3f1-9823-43da-bc08-934e163609a4	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-10 18:20:28.398681+00
e19be395-3a08-4f42-a66e-16efb37e28bb	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-10 18:20:28.875822+00
0183fcf0-60cb-4eba-a7ad-f82f167606ee	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 18:21:18.660332+00
1059e3a2-7541-41d2-9139-e01854953317	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 18:22:28.258046+00
5c9ac0ed-e851-4e96-83f3-e88c1dc305f9	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 18:23:09.695494+00
f327c26d-6ed3-4178-bbc2-62a7639d7c09	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 18:23:50.834623+00
9616032b-c62f-4679-80b2-16dd59d916e7	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 18:24:00.017603+00
ba5e55d2-c0ae-46b2-a0cd-63424079780b	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-10 18:24:24.508603+00
c42b0cc2-2c2c-4cca-95e5-ce20cb57115f	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-10 18:24:24.892368+00
4e74e4b5-7ea0-4b0c-b0b2-792705f7c927	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-10 18:24:25.016544+00
66b49112-c040-488c-aa1a-1a7a2f8bf92d	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 18:24:57.484471+00
707964be-7912-4c3d-91b0-36c0663ea156	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 18:25:26.059033+00
39eb6239-9057-40a9-9e35-c348f2e17992	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 18:25:36.085585+00
a87b2c4d-bf5a-4664-807d-2eda41339888	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 18:26:54.160883+00
ff7bafa0-6d74-4c3d-aea9-2949fc898a78	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 18:26:58.144814+00
288655b1-ea5a-4003-a36d-d9b6d01aad6a	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 18:26:59.623537+00
39200d8e-e2fe-4b1d-86b1-f4cd4efd8db8	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 18:27:00.871198+00
7e13719a-7427-4a82-b658-d242e7479de2	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 18:27:02.89247+00
9078df37-376d-4576-8d31-70e28454dfb5	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 18:28:13.156679+00
bd6fbd49-4d71-48aa-9527-061c034eed33	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-10 18:28:23.558343+00
8314e46d-fe52-40b9-a1e7-e1dd4805034b	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-10 18:28:23.73378+00
768a9d3b-9f09-4c84-8c37-cca38e42413c	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 18:28:26.738082+00
5d6402d4-2103-426f-9ad2-dc0cb01e075f	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 18:28:27.01707+00
e2da3ce6-5834-4ab9-a0da-0d80dcc9f01b	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-10 18:28:42.893136+00
c7399ef9-804c-4f32-8ad7-8be893dc1e52	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-10 18:28:42.895137+00
6c53984c-999f-4691-967f-a5c134e1bddc	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-10 18:28:43.153844+00
f7312334-e17e-4eca-953d-d01d8b39815a	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 18:28:52.458127+00
0b1555b2-b72e-4798-9036-2dc0df0b7a03	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 18:32:10.894281+00
a1231339-da19-4820-a9e8-049c45a5816e	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 18:32:13.751134+00
31452537-a16a-4988-8141-01a3edf9d4b5	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-10 18:33:03.535383+00
906b7b23-2729-4ab2-b19e-0db7151822b2	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-10 18:33:03.764383+00
fbce48fe-8bad-4568-b57f-2f8b38da7f15	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-10 18:33:44.301147+00
413444b4-a3fb-4911-a0e4-249adaa96b7a	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-10 18:33:44.393888+00
1ddabc31-7b4c-46d2-92a5-bafc8d856fa1	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 18:33:49.189295+00
c5fc7e77-5000-4da3-9e15-95e92039465f	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 18:33:50.100564+00
2b5ef6a8-305a-42ba-bbda-b5e27d54ab63	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-10 18:34:21.497873+00
c9c34781-e008-4efc-b9ee-4623777cdd96	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-10 18:34:21.910283+00
468d67ef-4dd1-4fc0-bd88-b1d5ebb66213	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-10 18:34:21.9387+00
92418eac-b76b-4019-b8a5-ad049b8d042b	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 18:34:47.12085+00
0558d885-d725-43e3-a9bd-da67653ebd6d	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 18:36:39.467089+00
6bf694af-0cd2-49e2-89ba-3f1263f383d1	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 18:37:03.126823+00
cda3e382-ba4d-47ed-bc14-8175b35916ac	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 18:37:15.881563+00
b405ad28-6e88-46c5-b663-6fc6968890b4	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-10 18:40:35.573256+00
5b08c400-5580-48fa-8ac7-0c3443239615	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-10 18:40:35.667346+00
6607b2fc-317e-440c-b247-59c3dc6c976d	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-10 18:40:35.840134+00
30e96951-8069-4362-a1d6-3222b45d5437	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-10 18:55:51.978363+00
170af052-50a3-430b-990c-8ff7f17e4594	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-10 18:55:52.075698+00
188ba973-03c6-4ba7-97f6-8d3957ac641e	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-10 18:55:53.000567+00
7abff924-bcd4-44eb-8980-0fa53e4087be	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-10 19:05:46.840481+00
4e34ad0e-cb38-4cb7-b38c-83e0de13a032	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-10 19:05:48.599871+00
cf93fc2f-fd04-47f8-96f1-948f6b50c9f1	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-10 19:05:49.039567+00
e4a65f1a-6da8-458c-92ec-b057db3e0e00	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-10 19:05:49.04851+00
6bfa5c7e-69f7-41f5-916e-c76c81125380	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 19:06:01.219328+00
474441f0-1529-40be-a1a7-d902b6846102	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-10 19:06:18.674451+00
808356b7-b036-495e-9fef-e5e3391b055a	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 19:06:53.725859+00
6c3740db-41af-4b26-8ad4-e067d37222af	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 19:07:32.50479+00
a60489ba-3375-4701-8fd2-bac495d422d7	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 19:09:29.016144+00
b7ee309c-1556-4595-b944-7630490afe36	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-10 19:09:31.282223+00
e4c0ac02-07cd-4118-a540-f42b28599d7f	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-10 19:09:31.30097+00
bead67dc-e941-4727-9dea-ceb7d850330c	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-10 19:09:31.378996+00
de621402-d88d-4608-97e2-e4ae50d9cb8e	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 19:09:54.214791+00
004a557a-15c6-43a5-aa29-3ced2eddb0ae	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 19:10:25.443158+00
af51dbbc-880f-4c22-adfd-139a34c08f26	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 19:14:46.578754+00
1e12c0d1-92b2-4f84-87e0-07fe24efa023	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 19:14:56.441426+00
6841a6f5-3cfe-4807-a239-131a8df8ce01	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-10 19:15:24.840999+00
f3447bf2-aa64-4c38-b2d9-bdc2b892aa68	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-10 19:15:24.99382+00
763a0f6e-54e3-4e9b-99ff-b3834e5345df	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-10 19:15:32.993093+00
2d6dfa55-2790-4f05-8005-fc298cd2589e	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-10 19:15:33.178686+00
5f648389-7c55-446c-b985-46faf60cbee2	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-10 19:15:33.251173+00
c6345b3c-0886-4859-9c67-d6237a2bde6e	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-10 19:15:57.300542+00
f76ecdd4-72d2-4963-972c-cbc33ed2a4ca	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-10 19:15:57.4128+00
58dbc12d-a740-4903-a145-772280ff867b	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-10 19:16:20.95509+00
1fffe161-bfbf-4fc3-aea2-5aad093b35b3	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-10 19:15:57.537795+00
d2a8ac0c-bb8c-43fa-ac65-68bad0ce9285	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-10 19:16:21.22868+00
d42c6956-702c-4c32-b695-bf460a599038	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-10 19:16:21.428054+00
66a6148f-4817-4d6d-8103-cd5d0645b74e	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 19:17:22.040539+00
5ccd946f-51a8-440b-a855-64d05f01550c	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 19:18:11.578608+00
81daa80c-0873-4cb4-8ca2-69b063c1da27	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 19:18:17.957213+00
5ab29f6f-bd3b-469b-ae30-777ae10674d5	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 19:18:23.957457+00
a7a0d355-f29d-49c0-b75d-81d77a82630e	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 19:18:59.941175+00
b3233e68-1fde-4256-8839-753042b2ca8c	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-10 19:20:51.560014+00
50e59065-976b-4c9f-9974-801ffde5c46c	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-10 19:20:51.821435+00
b4dc1f5a-849d-4e76-b6eb-4dea8109ae0d	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-10 19:20:51.964704+00
5443756e-e4a9-4938-9bde-86ec43db0917	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 19:21:11.83089+00
794cdfd7-6ba9-428d-aba2-63255556ba87	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 19:23:17.378399+00
9ea3a25a-d396-492c-9462-15c9d11f85b6	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 19:23:29.739225+00
a202de08-9c1d-4478-ab2c-e9491de8e0e3	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 19:35:03.077643+00
ee41994d-ed99-4a85-8098-626fcb4ec4a1	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-10 19:36:03.651004+00
51d8b8ea-4bb4-4ae6-8aa6-be6d581b6552	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Mobile Safari/537.36"}	2025-11-10 20:24:36.809656+00
241eeac1-e37b-43cd-9cd0-a958081ec2b0	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Mobile Safari/537.36"}	2025-11-11 05:14:20.07884+00
6194e43b-44c8-4b89-a1a3-579b88e27ce6	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Mobile Safari/537.36"}	2025-11-11 05:14:20.092967+00
1eda1ba7-308f-4fd0-9f39-e401da6ba830	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Mobile Safari/537.36"}	2025-11-11 05:14:20.202814+00
982bd4c8-08f3-4f66-bf44-cad141e4b0d3	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 05:48:21.691322+00
5e0354b7-86f8-4d70-a686-a7b0ff1e7f1e	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 05:51:47.205038+00
679a982d-1d3b-48df-880e-d8a2106cc5bd	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 05:57:12.505173+00
f1ad710a-ad22-4e1c-b392-6fa9f2c980da	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 05:57:31.852118+00
09e00917-f88e-4ead-b658-cde2cb879f5c	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 05:57:47.770756+00
fec03aa3-26f8-4430-975f-34946fbda66f	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 06:07:03.474509+00
ea071575-6346-40be-8fab-928c8ec988c0	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 06:17:31.236957+00
637b9255-5007-436a-9575-2daf18c2340a	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 06:19:41.790661+00
147c3ce4-4a20-4bfc-a7a9-14f4334668f1	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 06:21:39.41889+00
ca97cd6f-1ae8-4a66-a89e-9e6368a92d3b	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 06:21:48.940246+00
9c2080c8-fd3f-4e95-aea7-b128d5155e55	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 06:22:18.408008+00
6c68577c-0976-476b-9a96-366b15d39141	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 06:22:50.356302+00
80ab1f04-9919-4605-ba94-9a6a2a7362b4	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 06:22:54.531945+00
893c1548-7594-46ef-958e-a99d8e66ee48	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 06:23:15.051925+00
1c97d496-074a-4ce4-bb79-8c359e88ff13	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 06:23:37.001962+00
0ae3552d-0ad4-44eb-91f0-b621fbd27cbf	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 06:23:47.432487+00
67faff13-53ab-4b24-badf-9834d2ff440c	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 06:24:51.319892+00
a6f16d30-0003-4ae2-8c95-294568382e9b	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 06:25:25.555123+00
2a57ef36-f449-471e-9301-463b97dea3cb	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 06:26:02.32048+00
96aa074f-1b2d-4455-8f2a-fa8262831586	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 06:26:02.439426+00
ccad5a24-678c-407a-90a9-bd8a10bba159	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 06:26:02.761473+00
bc1952f2-6955-4f32-9309-788bc1f9fa4c	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 06:28:51.068782+00
abe02422-0e44-4352-99ab-08d822530239	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 06:29:17.326944+00
1d064428-a15d-456f-8c26-24166590c0cb	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 06:33:50.215993+00
66d8041b-11d2-4eaf-bd7d-0f40cbceab27	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 06:34:38.571158+00
739cb809-ff91-4275-a71e-d023a763c257	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 07:12:28.26643+00
4aa6ec00-9ff5-4426-a392-56c730bf0752	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 07:12:28.353384+00
a0b39ac0-a537-4700-940d-72a2f823c42a	679c2251-78d4-4d83-ab54-54ac1c790ed5	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 07:12:28.409559+00
788e8ac2-80f8-4c69-ada8-e8a632192fb8	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 07:13:27.541384+00
e7b1b6b6-5e20-4bc7-9aed-20607d9c8382	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 07:13:30.242197+00
de36dfff-ab83-4d8e-884b-d0d41e575517	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 07:13:35.839899+00
e91d1d8b-a9b8-4919-999c-4c326cef3780	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 07:15:33.539621+00
0716dd46-7550-4d35-b6ad-3978d60aa1ef	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 07:16:18.170178+00
7a2dbe86-e800-4366-bce3-417844b81a3f	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 07:19:04.898837+00
15cea239-4898-4388-92b8-f8692a248155	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 07:21:50.408708+00
2b5370b8-0a1d-45e0-9a72-d3365ac272a2	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 12:27:38.666718+00
61380f13-fbd7-47a7-be3d-67481db4c0d3	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 12:27:38.70308+00
708ed4ce-a22f-41b0-b5b0-794ad11d4de1	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 12:27:38.745289+00
e07e4531-ef09-4a93-936a-ab92341e7d56	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 12:28:20.675213+00
a7e3b75b-862e-49d9-a8c5-52a47988c428	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 12:28:23.446818+00
33cdceb8-5c0d-4907-9cfa-2b896bf17425	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 12:28:26.906399+00
7cd07731-fbd6-4d3a-8679-9b0871d537de	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 12:28:44.358468+00
696e464e-bee7-48a2-b2f0-ef60a9fd467b	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 12:29:36.602283+00
e1c53b3c-8beb-40e4-926d-74c37f484aa5	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 12:29:44.747481+00
b703818e-65ca-44b7-86ac-b7de15594927	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 12:29:46.748779+00
b1927fe2-f7dc-4133-92ce-5bfb48ce3c17	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 12:29:47.813608+00
c768f65e-5a29-4138-9ef7-20f1513375b3	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 12:32:04.827262+00
99e403a1-9d09-449c-8c46-b08b065916ca	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 12:37:31.869313+00
6c3375c7-74b2-4794-9efb-2eb944ae8205	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 12:37:50.766563+00
24aca9eb-feb9-422a-8bee-b295fb56d2af	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 12:37:53.606047+00
8b2eb7c4-d5d2-4953-91f3-a74d795766a3	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 12:39:32.780479+00
e503737e-e1a4-4e08-bdf4-d07a3f7bb35d	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 12:40:11.840704+00
9e67b815-e3e0-486f-afe0-8f593e1669aa	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 12:40:15.947395+00
0669edd6-8c47-440e-8f63-370ce026cb2d	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 12:41:04.584699+00
81eeffb6-8aa9-4b6f-87e8-a4d9587f0bb4	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 12:41:14.467139+00
91df2c8d-288c-4146-9705-11a7bac97a30	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 12:45:36.749742+00
a281f663-2596-4914-8010-cace1dbac33f	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 12:46:03.287778+00
cc29010c-daf0-476b-ba09-976a0f8da847	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 12:46:29.801782+00
ef3d9265-1468-49ad-a9b8-cf7a4620c882	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 12:46:54.419313+00
69e4456a-30d4-4ebb-9a21-73e50249fbbf	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 12:48:22.305547+00
0c71533c-defe-4062-9faa-f1fc08af2ebe	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 12:48:35.187201+00
bf4cc3d5-a58e-4005-b7ff-27c7fc492e31	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 12:48:46.893677+00
cacda3ba-3f27-4e4f-8110-300da1e3c53d	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 12:48:46.923711+00
f726413b-5a5e-4a16-89bd-d2f361deca39	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 12:48:47.190741+00
0eeb05e9-4d7a-4577-958c-2ac73c8233fe	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 12:57:35.314593+00
1d9461ff-e83c-4f09-9ad6-9a4b03caf11a	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 12:58:12.818867+00
b1c5ed46-9af2-4c2e-9669-3708b3aa3bd6	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 13:06:54.80527+00
def9d8a1-0912-48fa-a10d-f0dd8e9fec41	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 13:10:12.78445+00
9d56081f-2b47-4ec3-afe0-305fbcf2400a	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 13:11:29.337803+00
a3c5bc55-3286-4862-8991-dceaa9be5a83	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 13:12:25.709751+00
2790cdb9-6bc8-40ed-a27e-ccac35237c87	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 13:22:28.373825+00
e4126dd3-828b-4b8b-a13e-0f02b249892c	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 13:22:38.042425+00
e2ee23a0-0bfc-4733-9097-54f3c2eaa778	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 13:23:22.645589+00
659c3697-b351-4c5b-bad1-1c8cc674372a	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 13:28:53.232744+00
311f7f4a-17b4-491d-a654-180bd6738ccd	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 13:28:56.942149+00
efcb1b85-ed39-4754-bd3b-ce06d48954d7	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 13:28:57.715923+00
19b4ce85-15ce-4ac2-8140-2837c023585a	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 13:32:37.703211+00
cf2836f3-9ef5-4be2-9ce9-7d9e7f72d9a5	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 13:32:47.681157+00
7970bf42-8b5f-45a3-8a1d-3a6b98a59358	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 13:32:51.853383+00
01e6f657-77aa-4766-bdba-08089105d7cf	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 13:43:58.092057+00
7d152599-f722-4ac1-a0a9-471c089edf32	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 13:43:58.213396+00
26af9d7c-03fc-4590-85e6-700a3898630c	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 13:47:39.931396+00
ced06abc-d4ff-4ca6-aa00-f686a38b9430	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 13:51:16.872535+00
73438449-842f-47b4-832c-7ec6c13f2043	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 13:53:09.039022+00
85df31b6-3601-4417-b6fa-f7c0bff9e019	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Mobile Safari/537.36"}	2025-11-11 13:53:25.083856+00
761344cd-7c32-4e36-9b79-4f785e530c51	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 13:56:26.856512+00
5dfcb146-f140-4e97-b477-9e662966e8b6	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 13:59:54.534192+00
a52805bc-2bcf-42e5-a7e0-d307f7376cec	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 13:59:58.176671+00
cf8a4be7-dd86-444f-a039-797f08dc6c55	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 14:00:01.219032+00
1495a654-f15a-4066-a2b3-6830e2e4538c	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 14:01:38.336636+00
7ea5301e-1fa7-4833-8ddc-4556111ad929	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 14:01:39.982369+00
77fc0661-d0f5-4113-8079-88adc9a754a8	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 14:07:39.052571+00
386d7e5d-cef7-4874-a8ca-81799b1a8c67	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 14:07:39.187197+00
39c2e031-0cef-4aea-b27c-8dbe4ce73158	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 14:07:39.34618+00
8a395b13-9cdc-4794-a04d-a40c02c64dde	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 14:12:09.926176+00
bb517710-8a0c-449d-ab64-ce9f34cdf803	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 14:12:11.020712+00
55872ec0-b5bf-4e3b-b963-1a71854901cd	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 16:02:26.418574+00
d23156ae-d26c-4f6e-8ceb-43e532bcbb2b	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 16:02:26.610522+00
71dde4ea-9013-459d-8885-f92748225f62	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 16:02:27.054503+00
cc08ac81-4e7d-472a-8e95-82327e41d554	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 16:14:02.656114+00
ae052999-af65-4a3e-9714-8bb0c118a2a4	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Mobile Safari/537.36"}	2025-11-11 16:15:12.891702+00
bb86ef35-87b5-4859-9bc1-a19e4462340e	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Mobile Safari/537.36"}	2025-11-11 16:15:49.782282+00
c5411676-2e3c-40a8-8d28-65c9847e2e75	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 16:16:21.987576+00
1cd6bbdc-4705-496b-86a5-4df30471223b	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 16:18:53.389041+00
dfb71b1e-0a2c-4b09-9972-973e54d586c9	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 16:22:31.181517+00
d9deccd2-f66a-4e52-9e6e-9a9b2a82de45	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 16:22:40.496724+00
3c18541a-07d0-4188-8922-a962f340d875	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 16:23:58.797597+00
23dee569-2218-478c-a40b-1e24e5b0e982	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 16:25:29.583653+00
978ab438-c9e8-4e41-868b-7e915fa7095a	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Mobile Safari/537.36"}	2025-11-11 16:33:46.638112+00
04b3ae04-e3a8-4944-8bd1-d70c74777800	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Mobile Safari/537.36"}	2025-11-11 16:38:17.762971+00
3822c920-a1af-4d02-acd7-5ab60c36fca8	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Mobile Safari/537.36"}	2025-11-11 16:38:17.783524+00
34351df3-ec12-4923-9d1c-a42b704824f5	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Mobile Safari/537.36"}	2025-11-11 16:38:18.323865+00
7d9d7072-38ca-487f-97a5-a71de14fffc5	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Mobile Safari/537.36"}	2025-11-11 16:38:28.904987+00
69e8496c-9aeb-4a08-a5fa-e1457dc56f37	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 16:39:04.795538+00
33d3269e-49bc-40c7-b2ac-28c593ec9f27	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 16:40:06.703627+00
2ecb427b-f1e6-4f06-82d8-7f4ec18c7973	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 16:41:16.849639+00
e5e06134-7b0b-4a5f-83c1-497efb6ae614	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 16:41:34.016058+00
26dfd165-c97c-43b0-9784-82318dcaf8d2	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 16:41:34.813224+00
52002ac0-0146-45a1-891f-be670e087eb1	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 16:48:23.007885+00
7cb3df93-40dd-4cd7-9536-c456e6f72cfd	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 16:52:35.370695+00
1442f359-bcf8-45d2-85eb-019c1a3c51ad	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 16:53:04.489233+00
e2cd3f73-b462-4cbc-a6e3-8a77dd38ddf5	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 16:54:39.570294+00
ff8422eb-0011-4c6f-80b6-c30f7ee74722	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 16:58:16.335614+00
baffb4c0-c317-4987-b551-8c1b38f15eca	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 16:59:08.285932+00
f9c9a25c-d4b3-4db7-85fc-9c37831713f4	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 16:59:09.312889+00
18a8c85e-d21b-4c65-b889-9913a4d475bf	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-11 17:00:19.34749+00
8a5ea2c9-e2d3-4bd7-bd77-5a0550c90406	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 06:34:11.961989+00
907f9a8c-6b5c-4986-8e69-f051e2716691	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 06:37:55.274364+00
23269fbf-70cc-480f-9892-25e6f89782dd	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 06:38:40.928203+00
b5533010-6764-419b-b2e9-2dec000eea58	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 06:38:41.069529+00
59c45c45-1df9-4f9e-9416-6199028bf2b1	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 06:38:41.163746+00
6b8fa117-877b-48ba-a440-4b4479499fa6	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 06:38:41.834882+00
cb236c8e-48c9-4301-aefe-e476ae3ca954	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 06:38:42.024087+00
82580330-1634-49e2-b8e2-6843e7fc744d	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 06:38:42.150361+00
5bed9e44-04af-4b99-9d6c-9d5c059377c5	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 06:38:42.267518+00
f7a9034f-1fb2-466e-bc74-1c3386f599da	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 06:43:51.928082+00
3d23ba6e-8ccf-44df-82d9-167ea907fd17	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 06:44:05.925024+00
7f70b501-be82-4dd0-b057-dff1229b6147	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 06:44:06.10383+00
6c065add-6370-4741-9074-697fcaa67b21	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 06:44:06.262188+00
6289a3e1-c40c-4469-ae81-f3a990ed16b4	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 06:45:29.291447+00
47466acc-71a0-41e3-9661-213d27172efb	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 06:46:36.777952+00
844b921a-5fdb-4993-b494-ae06cad6ffec	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 06:46:36.899039+00
28e15fbc-0edd-4724-8297-9feb7bf0a78f	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 06:46:37.170645+00
710fc928-798a-488f-8c72-5165d7583b22	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 07:03:04.518026+00
a73e58c2-3edb-436d-8cb9-2b4ab1dd270d	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 07:03:09.725462+00
e7e4dc1b-5a67-4ea9-a278-c30d6d1dc04e	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 07:03:09.883824+00
5ab0353b-4811-413f-a4c4-9b8808d0a611	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 07:03:10.030376+00
03146c26-071f-4d7f-8216-a22e400d42cc	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 07:10:17.942642+00
380c17b9-99ee-42dc-88ad-ccf7b1e93802	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 07:10:20.100977+00
bb99bf15-14b1-446e-9d4a-6d1060f2ed3c	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 07:10:20.154251+00
be2bb8d0-4d01-4725-98cf-ff9c7a6dd73f	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 07:10:20.31003+00
bd7ff5c0-cdc3-4213-9b9d-5f92a121878d	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 07:10:44.160528+00
059173c0-aaa6-4604-94c9-62115538eb55	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 07:10:48.983053+00
11a41607-ffad-435d-b89f-275c3ec48528	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 07:10:49.311514+00
c93ac86d-2c27-4183-8127-48b33d74c029	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 07:10:49.446784+00
0d9b900b-693e-45c5-9e0b-ec1f6688a7db	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 07:10:51.099725+00
7fec1fe9-2105-42d5-83d0-1cea3b9872d0	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 08:20:19.90219+00
0828d60e-c30a-4b04-8862-43927daa7758	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 08:20:19.954353+00
9f5c5f5d-f924-48d3-baca-392203ba38e3	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 08:20:20.049717+00
4816893d-cc05-4ce0-a2be-3d3d5229224a	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 08:35:14.722091+00
61d5f126-196d-440a-84dd-62b825a243b9	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 08:36:13.408602+00
fdc8675b-e358-4a32-8793-06a7db0d219c	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 08:36:13.503841+00
b864a7aa-accd-490a-aebc-e498f6340527	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 08:36:13.66189+00
092ac0fa-fd7d-4a66-919f-fa7271753edd	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 08:54:47.066478+00
669508e7-4b80-4b5e-b1b6-331834567cb3	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 08:54:47.189692+00
1590e628-9111-4f68-b086-e244a90e6faf	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 08:54:47.350206+00
ca29acf4-e556-4ee5-86f3-949077382f80	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 08:54:58.500929+00
f56babec-2c9a-4e0e-aab4-14330543d4ea	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 08:54:58.598912+00
c3a4d4dd-47cd-4549-a5c2-d8dd032e4022	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 08:55:01.155295+00
ad4a33ae-cba6-404c-afe4-92264439cdf1	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 08:55:01.278161+00
408c417e-16b5-4470-af94-8d275f0e483a	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 08:55:01.46037+00
0012856e-afec-445b-a3c0-32556c9176a0	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 08:59:39.162681+00
c6db68f2-f969-4810-a3e6-ea53b37afda8	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 09:15:22.07564+00
6712385f-d201-447d-ac95-273d8bba4618	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 09:15:22.218003+00
14caadb7-a938-487a-a08d-579270a5ce2e	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 09:15:22.417701+00
2ad747d6-df76-4bf6-bb19-83f705edc12c	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 09:24:03.798495+00
2f5c292e-41b6-4681-89c7-09ca0a00f923	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 09:28:40.64102+00
c7418606-0b1f-4d89-a2ea-4fd51512fccb	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 09:28:40.861828+00
e5e4dd56-d4bd-4029-9fbf-3ccf666f712e	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 09:28:40.892019+00
b551f976-aaa0-4b90-9ae0-12a986da41a5	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 15:41:39.115002+00
47ef90f3-ffdb-449e-aaa7-e66b215f34f2	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 15:41:39.142118+00
cee36a4e-f7ae-4ff2-b0e7-6132cc1d3f3e	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 15:41:39.483196+00
e8d7ba5d-1205-4864-80cb-aea25ada57b0	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 15:42:01.701309+00
e8a82024-7a34-4516-b36b-c45157a9745b	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 15:42:01.900072+00
48d5ae56-e7b2-48c7-b9ad-564738cc68d0	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 15:42:02.09258+00
779f1437-9381-4edb-b403-795644a46450	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 15:42:50.816594+00
69a41b81-7c72-468c-b2ae-1109e665ff68	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 15:42:50.927536+00
937be840-3f88-40e5-84cf-31a0022f295e	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 15:42:51.274533+00
451fda44-cb45-4508-b145-94c991f8a0c7	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 15:42:55.202325+00
6625bb9c-63c8-496d-8076-5efdde87e30b	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 15:42:55.519708+00
c167ebec-8ca9-4ba7-ae06-53c75f89f28a	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 15:48:32.259105+00
5f1c4b8e-1145-4a74-88e4-b333a01cdbce	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 15:49:17.136451+00
1d365ed6-9ea6-41d2-951c-446af4c226be	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 15:49:17.242217+00
e798623a-8e77-4250-b239-e9766ee7f7d6	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 15:49:17.324252+00
dd9062c1-63d4-4371-97e3-5e2a73d9b73f	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 15:49:18.931077+00
38c09f9e-b3ac-4b4b-a837-32dd0766a088	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 15:49:23.945811+00
5c87a524-2ed0-4c7a-9e71-849ce128e99a	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 15:49:24.082709+00
44c821dd-1d56-4daf-9a11-6e52acc1c0aa	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 15:49:24.194057+00
28f273d2-8429-4651-8863-444915905ff5	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 15:50:25.108034+00
4c085a64-5b83-4b04-b3a8-a87c59ff96ed	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 15:50:25.226825+00
f3de5430-39bd-4e48-bf57-7cf007ad0675	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 15:58:06.746226+00
97d382ad-2981-4bf0-9b30-cb72ab1e87de	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 15:58:06.867028+00
fbb013cd-f002-4d72-aeb4-1493ac0109c5	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 15:58:07.167322+00
f2bc4eb5-fc49-4fd3-868d-eebe50f01cab	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 15:58:20.832252+00
db67e62a-d987-4a03-844a-3287961e58d6	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 15:58:21.123038+00
bfd0e356-aa96-46ff-9f54-ac3f1bd7169a	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 15:58:21.320274+00
1e6fee95-c4e8-4c05-8bb4-cd0014450a92	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 16:01:25.975748+00
a5a48dd3-d9b3-44e5-a943-2eb2c3d6b4bc	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 16:01:26.087421+00
40d1e150-9644-4f30-8c65-5f3795ce2904	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 16:01:26.747219+00
997dd91b-9543-4de4-bb49-981b287fc297	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 16:02:21.723307+00
b855f961-fc72-47e6-b623-b4e8611cdca8	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 16:02:21.88876+00
469ee207-5b63-419b-9697-1d9ee3bc9793	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 16:02:22.089992+00
b748ff02-1635-439d-9a04-a0ad926db534	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 16:05:26.669791+00
3c0ce1d9-af96-4b2e-b60b-d21ef599e949	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 16:05:26.779141+00
aa68ba14-ea18-4fb6-b226-81a7a967d112	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 16:05:26.929666+00
f5b3d21e-f1cd-4198-867c-c58ab5af37c9	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 16:13:41.543068+00
b0da9a5f-064f-414f-a95e-6a22f7a9ea67	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 16:13:41.675838+00
2cedf6e4-3672-4da1-a819-36d8382c952a	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 16:13:42.09047+00
82b29cdb-4094-4dbf-9632-59b6f4a759e4	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 16:14:43.231835+00
772a5313-ba4f-4b4c-a2e6-f11e6dc64139	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 16:14:43.546101+00
f8ab2cea-3bc5-4758-b24d-1d9e26256622	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 16:14:43.786355+00
668fbf31-1315-4bc9-a16c-23475e6ef348	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 16:14:45.724717+00
876b451c-5b4d-40a3-a63c-103231771c2a	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 16:14:51.801536+00
22995b66-e1d0-4ebe-9e2d-6a63f26bdc3d	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 16:14:51.933316+00
179a32e6-5ff4-4389-8de5-43017db50325	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 16:14:52.366565+00
c2a8e9ed-998e-4bc4-8895-882b0b10000d	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 16:14:53.812859+00
43ca69e7-08cd-49b3-8a07-ec56b4bac349	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 16:15:21.086198+00
526b834f-a88a-4505-8248-ea55f1e1b132	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 16:15:21.205823+00
d67621b3-06cb-4490-940a-af854230e69e	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 16:15:21.59214+00
dda18b58-d1fc-4151-85ea-d235c8004405	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 16:15:22.891749+00
f22e1ca6-1a8f-4fda-a45f-434e39182b66	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 16:15:32.655716+00
c9f5b151-a862-4672-b8ad-92aa71123e2d	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 16:15:32.893995+00
33aa8566-46b9-4e21-962c-4db48e288b5f	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 16:15:32.895667+00
e8762ac8-ef80-475b-8440-f6983076d09e	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 16:15:34.347415+00
92e519f6-3eb6-4e3d-8f8c-80e555dded79	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 16:15:36.336855+00
570849d4-f920-4479-90d1-2e1fd8d4f3d0	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 16:15:36.711874+00
956f1ad3-f6cb-42c7-a6d0-ca061c131e20	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 16:15:36.716005+00
69624ae5-a233-47c6-aac4-b3055cf4cee7	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 16:15:42.02475+00
f53be4ee-838c-4df4-bf69-97fd3b13c69f	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 16:15:42.235925+00
0b91aefa-a76c-45d0-964d-65eec3edca8b	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 16:15:42.4812+00
38ede9c9-65e1-47e1-a6f1-2721d6ead383	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 16:15:54.620777+00
ea3f6497-d95e-4857-9a83-aa8bab5fa21b	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 16:16:47.96983+00
486d767c-59e8-4c4f-89bc-4b70e260e4ad	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 16:17:45.557046+00
63d5d15a-633a-415f-ad22-00ba004d809b	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 16:17:45.893156+00
06ceac0b-98b8-4965-a823-d2010b13dc80	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 16:17:46.011102+00
eb049cfa-e5a2-4028-85de-e5b13d008860	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 16:37:09.619939+00
d31cb270-5950-45a5-9eb6-620310a67909	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 16:37:09.755748+00
d8cf7ab0-82ee-4af1-9c20-34e6c6285030	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 16:37:09.936128+00
e05322c5-c8b5-4fc2-b4c2-ecb5cc733ee2	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 16:37:18.87408+00
a4db5f82-e129-48dd-8d6e-44b383ca8c47	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 16:37:19.051986+00
234161a9-fbe1-4938-b645-8369f7339886	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 16:37:19.167432+00
e076cea6-4ece-4069-8dd4-6057b9ff58ff	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 16:39:49.214146+00
3b9e1d28-a4ce-46ae-a080-c8b7c135ebbd	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 17:06:11.365328+00
e69b328d-476f-41b0-b59b-f19aba48df15	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 17:06:11.437497+00
bcf4259a-cd90-4f75-bd16-45aec4ae0888	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 17:06:11.479584+00
fd80e633-e9ee-4cd6-8a22-479c2f8cae9f	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 17:09:26.100572+00
64c7a291-1ad2-4b02-a5ce-424da0eb9dd4	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 18:08:49.14652+00
bea8a584-e694-4e15-a0bd-78ed82270eda	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 18:08:49.139466+00
4ddf83cd-62b1-40ef-a0cc-c7b821ebbeea	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 18:08:49.234668+00
e41504f0-881b-4b91-bdcd-460f0bf1a813	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-12 18:22:57.283671+00
6e939c64-46af-4770-855e-c9c89c62063c	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-12 18:22:57.469095+00
70a4f112-b5fc-4f87-81ff-8f47e632fe5f	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-12 18:22:57.471948+00
6729a96b-38c3-44ee-a163-769b595611b1	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-12 18:23:16.475366+00
041faabc-6f84-48d2-a0bf-2cedc2b56b30	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-12 18:23:24.300538+00
085a531e-dc7a-4f69-8227-69bc76f85d52	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-12 18:23:24.981712+00
4c5ad0ad-68a6-4ef5-8b7d-e9adc309c3ab	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-12 18:23:26.261196+00
03770116-8f1e-41a1-91f6-1a85c325e07d	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-12 18:28:03.16728+00
a1c5bf57-afb0-4c61-b9e6-aa287ec2ca78	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-12 18:28:03.589989+00
64bd3a3b-4844-4c8d-b6ab-72b90fcb23c0	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-12 18:28:47.091041+00
d9fe308e-ae05-4dbe-8502-31b060fffd0b	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-12 18:35:27.262764+00
998effd3-5ea7-4bda-897b-7a949678d27a	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-12 18:35:27.375648+00
affd3168-01c5-4424-807f-05b30837c071	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-12 18:35:27.491081+00
6391b35e-cd97-44d6-bcba-eecb669172b7	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 18:35:34.960259+00
bb73b2c5-49ee-4275-a813-e654435f8970	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 18:35:35.06965+00
d0bdbf9d-e801-4be1-8319-ef68b30105b0	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 18:35:35.57918+00
a2cf259b-c3f0-4489-bb94-91216d0e64f1	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-12 18:37:07.141995+00
0ab7aa1e-3d8e-4d14-8d6a-667934de1149	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-12 18:41:46.108654+00
99e18243-3429-4fa1-a3c9-db6abd240760	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-12 18:41:47.390255+00
210a121a-8b03-48b0-9504-f1f399b6a935	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-12 18:41:49.089674+00
6c85103a-0b85-4c32-990a-48693da35f0b	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-12 18:47:21.486311+00
c7c9e7b2-da0b-486b-8c86-585afc7ce3c0	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-12 18:47:46.664771+00
65ad95c6-f28a-452b-90ab-cc97b15bc159	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-12 18:48:15.877411+00
0555a3a3-7d2f-4f55-9857-fbca3345e85c	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Mobile Safari/537.36"}	2025-11-12 18:52:10.458678+00
9cd18dde-fe4f-4452-a30d-56023410017d	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Mobile Safari/537.36"}	2025-11-12 18:52:10.542984+00
91ed57e4-d399-4341-9fbc-f3f327f0120c	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Mobile Safari/537.36"}	2025-11-12 18:52:10.854966+00
30d107e5-3107-46b2-bdef-4c03b648fe95	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 18:52:13.338567+00
3049be5c-0363-41fe-a84e-d8d5f73cc3d1	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 18:52:14.029353+00
16231fcf-8816-45a5-b9e3-8e1aab779ada	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 18:52:14.289603+00
322ef923-7e68-42c4-bca4-405ea1666059	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Mobile Safari/537.36"}	2025-11-12 18:52:44.000566+00
fe190b0d-67d0-4e36-b6ee-b22d34760895	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Mobile Safari/537.36"}	2025-11-12 18:53:24.828315+00
952454b3-80eb-4a29-a143-2d15d2fd215e	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Mobile Safari/537.36"}	2025-11-12 18:53:25.09082+00
ae4496b9-fb57-4f3a-aa89-86dd07745393	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Mobile Safari/537.36"}	2025-11-12 18:53:26.333069+00
ab3a1e21-0026-414b-9b3c-e5e20d7cc993	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Mobile Safari/537.36"}	2025-11-12 18:53:34.473097+00
44535cb4-1637-4bce-bf09-9e5212a67713	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Mobile Safari/537.36"}	2025-11-12 18:53:42.937609+00
b910a976-7677-44f0-8c8e-481c87725eee	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Mobile Safari/537.36"}	2025-11-12 18:55:12.015823+00
fae0a885-a6e0-487b-8ed5-bea7beba3379	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Mobile Safari/537.36"}	2025-11-12 18:55:12.167775+00
9a1f4562-348c-49de-b04e-c2bc15521053	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Mobile Safari/537.36"}	2025-11-12 18:55:12.350207+00
dec92d5a-8a1d-4988-b957-305a96431e94	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Mobile Safari/537.36"}	2025-11-12 18:55:29.777388+00
05bed35e-e89b-4274-a03e-849f23767124	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Mobile Safari/537.36"}	2025-11-12 18:55:35.863449+00
7ac7dd5e-6e90-4b88-9284-a39657395c81	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Mobile Safari/537.36"}	2025-11-12 18:55:43.908129+00
4b4bf1d0-8fa3-40e1-b114-7344e7f4eb8c	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Mobile Safari/537.36"}	2025-11-12 18:56:59.707402+00
932b221b-0fae-494c-9eb8-3a94b6bae9ba	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Mobile Safari/537.36"}	2025-11-12 18:56:59.822105+00
aec1653e-a13e-4166-b2c5-3690eee8869f	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Mobile Safari/537.36"}	2025-11-12 18:57:00.032572+00
469cc82e-d350-46a6-babe-cc90d5ec7023	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Mobile Safari/537.36"}	2025-11-12 18:57:07.285415+00
f74fc0ff-bd09-4cd6-9bff-737f7f4af276	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Mobile Safari/537.36"}	2025-11-12 18:57:07.600108+00
b2a0af66-8412-4d86-bf72-1570de43782e	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Mobile Safari/537.36"}	2025-11-12 18:57:07.675391+00
90dceb5a-cd21-449c-bad9-11b049616442	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Mobile Safari/537.36"}	2025-11-12 18:58:00.125052+00
7c829773-355a-48e9-8f1a-d605e7d2e2b8	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Mobile Safari/537.36"}	2025-11-12 18:58:00.22235+00
9e375b45-b3bc-47f2-849b-10a236192d46	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Mobile Safari/537.36"}	2025-11-12 18:58:16.726866+00
e5c09c90-a04c-428f-a0fe-a1fc31b3e157	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Mobile Safari/537.36"}	2025-11-12 18:58:16.977438+00
7706acd0-6816-4994-b019-1d6c3adfc435	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Mobile Safari/537.36"}	2025-11-12 18:58:17.126325+00
3e226f28-82f7-415e-8c5b-4792f5436596	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Mobile Safari/537.36"}	2025-11-12 18:58:59.346783+00
c027ad2f-9509-40f9-b3ab-0b24e194e138	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Mobile Safari/537.36"}	2025-11-12 18:58:59.486699+00
274a6182-d8aa-4dd9-97d6-94ad05567914	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Mobile Safari/537.36"}	2025-11-12 18:58:59.60765+00
29bf12f0-a7b5-4dd6-9016-d2c4411552df	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-12 18:59:20.428403+00
2dab5ac7-546c-41bb-9fe6-327171fef6fa	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-12 19:00:08.379039+00
4322bd0f-2d79-4a13-bab8-00f28500b2b1	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-12 19:00:08.607123+00
eba2bf97-df8a-43cb-ab27-188ee88c4e4e	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-12 19:00:08.769905+00
f9d3ef27-d29d-4da2-a832-b2f9fccdb237	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-12 19:00:11.573444+00
ad93d253-6980-4533-9168-b3389ff3cf91	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-12 19:00:59.457131+00
e7b280d8-f695-43e7-8639-3a595be21266	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-12 19:01:02.964839+00
a5e7831b-578d-4752-a367-366e2c9cb324	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-12 19:01:03.140533+00
f14dd36f-99b3-4b35-a3b7-4327517c8229	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-12 19:01:03.389055+00
a6b2bfa8-d952-4979-a9a4-b14ab3a6225e	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.104.3 Chrome/138.0.7204.251 Electron/37.6.1 Safari/537.36"}	2025-11-12 19:11:39.106086+00
2bfa488a-cd35-4e5a-b476-b4860b369b8c	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-12 19:21:45.580314+00
51f1c3c3-54cc-49df-a451-aa2ca8dda98c	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-12 19:21:45.629658+00
02c6c1e1-7aa4-4303-b31f-f21bff460621	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-12 19:21:45.900388+00
b89911f6-c8b7-46e3-951d-e22083f820fb	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-12 19:22:32.607772+00
e857518f-83e3-4439-8a50-ac8e33bc844c	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-12 19:26:30.847756+00
e3fd226c-a468-4a4b-b8fe-45ffd51764a0	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-12 19:26:57.49717+00
c3ec49d1-d71e-40cf-b9ab-4f126d0bdba4	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-17 16:36:04.990773+00
1e5acb12-a40f-470c-be3f-7146de267821	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-17 16:36:25.161402+00
7ca66130-27d4-4383-9106-fa3a814f93b5	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-17 16:36:35.058154+00
eb65ee2c-3317-4a60-a645-947deb296c46	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-17 16:36:42.964587+00
582cc10a-1044-489d-861d-45fc9f19276d	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-17 16:36:45.412608+00
1d9c10b3-6220-468e-a928-feb8d746e55b	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-17 16:37:27.248389+00
eb05b123-fac5-409c-9c50-e96dab5fda19	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-17 16:39:09.268905+00
daf233d5-7cbd-4826-bc11-dce4202c91d1	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-17 16:39:56.425201+00
c5b18aa7-0628-4e01-9b37-e3e54fdedbcc	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-17 16:40:09.807692+00
37d4e8fa-7eb9-428e-b53b-46c8dec92dbc	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-17 16:40:31.623934+00
70473f5d-e256-4233-bedf-b721ba63e869	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-17 16:40:42.012036+00
e3319f81-d526-4277-ad60-47374fc3ff1f	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-17 16:40:50.946387+00
abd11c47-0114-4f2e-b0ad-ded5f5f6e80b	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-17 16:40:52.096475+00
a81a6e9a-d66f-48f4-8042-40248fc60795	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-17 16:40:58.304843+00
a521f4d2-a5a8-4023-b96c-fc59f01253be	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-17 16:41:01.451434+00
92378d61-3ccf-4634-85ea-5b85f2628cc2	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-17 16:42:22.070935+00
ddfb780d-04b3-474f-804b-7eb546fc951b	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-17 16:42:22.637052+00
ccd7b83e-440f-424a-8d9b-be42953bac33	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-17 16:42:31.599314+00
6f168963-7767-419d-984c-07889d32d8f0	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-17 16:43:21.16538+00
c6333aa7-ec74-4253-8400-50ab2d76efb4	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-17 16:43:49.280759+00
ebc75cde-9ed5-4e81-93bd-2a72301ef4cf	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-17 16:43:56.130817+00
f0ef32f5-bdf9-48c3-95e2-730c4e59e13d	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-17 16:44:18.627579+00
1b74ffa6-f947-40f6-82a3-ba640c92c56c	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-17 16:47:08.69651+00
98ec2c5f-e7bc-4996-8008-a0a44b18d800	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-17 16:49:01.146378+00
fda3cba2-d96e-4690-abb5-a98b238bd687	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-17 16:49:23.056189+00
9e4d7130-2a63-484a-9e18-5cb870a6ecd0	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-17 16:49:45.054656+00
53e29b66-9de6-4fa5-916e-8744493d8f95	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-17 16:50:29.272096+00
2ac3daa5-aa9d-4c1c-88c6-16f3ce42f322	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	LOGIN	{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"}	2025-11-17 16:50:33.63345+00
\.


--
-- Data for Name: security_incidents; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."security_incidents" ("id", "incident_type", "severity", "description", "ip_address", "user_id", "user_agent", "request_details", "response_details", "is_resolved", "resolved_by", "resolved_at", "resolution_notes", "created_at") FROM stdin;
\.


--
-- Data for Name: user_2fa_tokens; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."user_2fa_tokens" ("id", "user_id", "token_type", "secret_encrypted", "is_verified", "backup_codes_encrypted", "created_at", "last_used_at", "expires_at") FROM stdin;
\.


--
-- Data for Name: user_role_assignments; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."user_role_assignments" ("id", "user_id", "role_id", "assigned_by", "created_at") FROM stdin;
b62b1b36-8e67-44e5-ab4f-40386dd15f42	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	c2723abb-0273-449f-8254-742b4c464b7e	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	2025-11-05 04:01:46.785371+00
257d3421-c0b4-4fe2-ae1b-44e64ab916d8	a69a63d4-5a72-47c5-9f74-189e6d5b3a92	4d73be21-fb46-4ec6-aabd-bc3472e7fb58	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	2025-11-05 04:01:46.785371+00
ca2fc9e5-7294-4682-8df0-ce788e8b2ed2	679c2251-78d4-4d83-ab54-54ac1c790ed5	30dda24d-18b0-4fdb-b051-66535aa5669c	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	2025-11-05 04:01:46.785371+00
d024a961-8753-4b77-a7fe-1222c6ca6922	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	4d73be21-fb46-4ec6-aabd-bc3472e7fb58	\N	2025-11-12 19:32:22.352588+00
\.


--
-- Data for Name: user_sessions; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY "public"."user_sessions" ("id", "user_id", "session_token", "ip_address", "user_agent", "location_country", "location_region", "location_city", "is_active", "created_at", "last_activity", "expires_at") FROM stdin;
53b280f6-c3c9-4f19-84d9-9c15411361cd	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	eyJhbGciOiJIUzI1NiIs	152.59.203.17	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36	\N	\N	\N	f	2025-11-05 04:22:34.114082+00	2025-11-05 04:22:34.114082+00	2025-11-05 04:52:34.601+00
\.


--
-- Data for Name: buckets; Type: TABLE DATA; Schema: storage; Owner: supabase_storage_admin
--

COPY "storage"."buckets" ("id", "name", "owner", "created_at", "updated_at", "public", "avif_autodetection", "file_size_limit", "allowed_mime_types", "owner_id", "type") FROM stdin;
room-images	room-images	\N	2025-11-05 03:57:09.449803+00	2025-11-05 03:57:09.449803+00	t	f	\N	\N	\N	STANDARD
guest-documents	guest-documents	\N	2025-11-05 03:57:09.449803+00	2025-11-05 03:57:09.449803+00	f	f	\N	\N	\N	STANDARD
booking-documents	booking-documents	\N	2025-11-05 03:57:09.449803+00	2025-11-05 03:57:09.449803+00	f	f	\N	\N	\N	STANDARD
avatars	avatars	\N	2025-11-05 03:57:09.449803+00	2025-11-05 03:57:09.449803+00	t	f	\N	\N	\N	STANDARD
expense-receipts	expense-receipts	\N	2025-11-05 03:57:09.449803+00	2025-11-05 03:57:09.449803+00	f	f	\N	\N	\N	STANDARD
pdf-contract-templates	pdf-contract-templates	\N	2025-11-12 15:45:10.200175+00	2025-11-12 15:45:10.200175+00	f	f	10485760	{application/pdf}	\N	STANDARD
contract-templates	contract-templates	\N	2025-11-12 16:23:54.181253+00	2025-11-12 16:23:54.181253+00	t	f	\N	\N	\N	STANDARD
booking-contracts	booking-contracts	\N	2025-11-12 16:23:54.181253+00	2025-11-12 16:23:54.181253+00	t	f	\N	\N	\N	STANDARD
contract-previews	contract-previews	\N	2025-11-12 16:23:54.181253+00	2025-11-12 16:23:54.181253+00	t	f	\N	\N	\N	STANDARD
\.


--
-- Data for Name: buckets_analytics; Type: TABLE DATA; Schema: storage; Owner: supabase_storage_admin
--

COPY "storage"."buckets_analytics" ("name", "type", "format", "created_at", "updated_at", "id", "deleted_at") FROM stdin;
\.


--
-- Data for Name: buckets_vectors; Type: TABLE DATA; Schema: storage; Owner: supabase_storage_admin
--

COPY "storage"."buckets_vectors" ("id", "type", "created_at", "updated_at") FROM stdin;
\.


--
-- Data for Name: objects; Type: TABLE DATA; Schema: storage; Owner: supabase_storage_admin
--

COPY "storage"."objects" ("id", "bucket_id", "name", "owner", "created_at", "updated_at", "last_accessed_at", "metadata", "version", "owner_id", "user_metadata", "level") FROM stdin;
77c7a97d-8a39-48d3-af49-a421d839333a	guest-documents	guest-ids/1762327436248_ldqmd5b0ukp.pdf	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	2025-11-05 07:23:57.343504+00	2025-11-05 07:23:57.343504+00	2025-11-05 07:23:57.343504+00	{"eTag": "\\"3f62a011dc8838541c9b8ae1e9ee832c\\"", "size": 1040297, "mimetype": "application/pdf", "cacheControl": "max-age=3600", "lastModified": "2025-11-05T07:23:58.000Z", "contentLength": 1040297, "httpStatusCode": 200}	9fa97d7a-1b02-4217-b37b-d2a5c806c7c9	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	{}	2
1b7d88d9-7464-4b53-8200-0b81780554e3	expense-receipts	receipts/1762327594361_gfdpocv5xtj.pdf	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	2025-11-05 07:26:35.772933+00	2025-11-05 07:26:35.772933+00	2025-11-05 07:26:35.772933+00	{"eTag": "\\"3f62a011dc8838541c9b8ae1e9ee832c\\"", "size": 1040297, "mimetype": "application/pdf", "cacheControl": "max-age=3600", "lastModified": "2025-11-05T07:26:36.000Z", "contentLength": 1040297, "httpStatusCode": 200}	f3fe7d86-ff92-4ce3-962b-1b623ebbb4fe	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	{}	2
733dea9d-bd83-48be-a9d7-f13af5680cf9	pdf-contract-templates	1762962345131-MohdAbdulKhadeerResume (1).pdf	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	2025-11-12 15:45:45.764831+00	2025-11-12 15:45:45.764831+00	2025-11-12 15:45:45.764831+00	{"eTag": "\\"da4a4afbcc2afe3ed7099f58050fcc9a\\"", "size": 123306, "mimetype": "application/pdf", "cacheControl": "max-age=3600", "lastModified": "2025-11-12T15:45:46.000Z", "contentLength": 123306, "httpStatusCode": 200}	54caa4ab-a0af-43c6-9a06-5df4dfa72e59	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	{}	1
805f30a0-5577-4732-b219-4b284175854a	pdf-contract-templates	1762963114857-MohdAbdulKhadeerResume (1).pdf	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	2025-11-12 15:58:35.906631+00	2025-11-12 15:58:35.906631+00	2025-11-12 15:58:35.906631+00	{"eTag": "\\"da4a4afbcc2afe3ed7099f58050fcc9a\\"", "size": 123306, "mimetype": "application/pdf", "cacheControl": "max-age=3600", "lastModified": "2025-11-12T15:58:36.000Z", "contentLength": 123306, "httpStatusCode": 200}	890923bf-d906-4d9b-860f-665507f811da	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	{}	1
e5bdb6af-038f-4979-a8ad-dccec96b44e8	pdf-contract-templates	1762963353105-MohdAbdulKhadeerResume (1).pdf	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	2025-11-12 16:02:33.955583+00	2025-11-12 16:02:33.955583+00	2025-11-12 16:02:33.955583+00	{"eTag": "\\"da4a4afbcc2afe3ed7099f58050fcc9a\\"", "size": 123306, "mimetype": "application/pdf", "cacheControl": "max-age=3600", "lastModified": "2025-11-12T16:02:34.000Z", "contentLength": 123306, "httpStatusCode": 200}	6910f59e-a5d9-42d4-ad48-c80d2bd73643	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	{}	1
4c4db5ca-1c1d-46ce-bb56-c0575c783427	pdf-contract-templates	1762964152044-MohdAbdulKhadeerResume (1).pdf	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	2025-11-12 16:15:52.830846+00	2025-11-12 16:15:52.830846+00	2025-11-12 16:15:52.830846+00	{"eTag": "\\"da4a4afbcc2afe3ed7099f58050fcc9a\\"", "size": 123306, "mimetype": "application/pdf", "cacheControl": "max-age=3600", "lastModified": "2025-11-12T16:15:53.000Z", "contentLength": 123306, "httpStatusCode": 200}	4f17bec8-2640-4586-b6c4-852eaafb47aa	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	{}	1
6175ccfc-b6d0-47c7-ac35-9ac9bd7d2b81	contract-templates	1762965549676-MohdAbdulKhadeerResume (1).pdf	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	2025-11-12 16:39:11.250705+00	2025-11-12 16:39:11.250705+00	2025-11-12 16:39:11.250705+00	{"eTag": "\\"da4a4afbcc2afe3ed7099f58050fcc9a\\"", "size": 123306, "mimetype": "application/pdf", "cacheControl": "max-age=3600", "lastModified": "2025-11-12T16:39:12.000Z", "contentLength": 123306, "httpStatusCode": 200}	8b1a4d3c-abbc-4474-8895-a79c87b8b7bd	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	{}	1
a05fa067-85cd-4d80-8136-ccd425550fb0	contract-templates	1762965605596-MohdAbdulKhadeerResume (1).pdf	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	2025-11-12 16:40:06.276867+00	2025-11-12 16:40:06.276867+00	2025-11-12 16:40:06.276867+00	{"eTag": "\\"da4a4afbcc2afe3ed7099f58050fcc9a\\"", "size": 123306, "mimetype": "application/pdf", "cacheControl": "max-age=3600", "lastModified": "2025-11-12T16:40:07.000Z", "contentLength": 123306, "httpStatusCode": 200}	43ba08ef-66d4-45a0-a11a-96aaecad58cf	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	{}	1
ab14ef01-0095-4e9e-9df3-ab4aa0da22fb	contract-templates	1762965613415-MohdAbdulKhadeerResume (1).pdf	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	2025-11-12 16:40:13.935866+00	2025-11-12 16:40:13.935866+00	2025-11-12 16:40:13.935866+00	{"eTag": "\\"da4a4afbcc2afe3ed7099f58050fcc9a\\"", "size": 123306, "mimetype": "application/pdf", "cacheControl": "max-age=3600", "lastModified": "2025-11-12T16:40:14.000Z", "contentLength": 123306, "httpStatusCode": 200}	0cd202ec-26d2-44fe-b29a-4607d9f406fe	a28dedd7-1b1b-4ed2-8d6a-52984f7223d6	{}	1
3a3d2254-8166-441c-ac28-461eba017aaa	contract-templates	93d29a31-75e2-4b74-98e1-317de8b37085.pdf	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	2025-11-12 18:47:49.178758+00	2025-11-12 18:47:49.178758+00	2025-11-12 18:47:49.178758+00	{"eTag": "\\"fbb0111c5281a09d186844e233773e87\\"", "size": 50204, "mimetype": "application/pdf", "cacheControl": "max-age=3600", "lastModified": "2025-11-12T18:47:50.000Z", "contentLength": 50204, "httpStatusCode": 200}	aae4dedc-943f-4401-8cd2-8ba57befdd6a	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	{}	1
5fa3ccd2-f2a4-42ef-92cb-4b4d7e337339	contract-templates	bc1908b1-cedf-477c-ba6c-70707e05409e.pdf	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	2025-11-12 18:48:17.305982+00	2025-11-12 18:48:17.305982+00	2025-11-12 18:48:17.305982+00	{"eTag": "\\"fbb0111c5281a09d186844e233773e87\\"", "size": 50204, "mimetype": "application/pdf", "cacheControl": "max-age=3600", "lastModified": "2025-11-12T18:48:18.000Z", "contentLength": 50204, "httpStatusCode": 200}	b77356af-d7c9-4ded-bd57-90fb7b53aef9	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	{}	1
14d0cd69-3909-4d56-8ec0-44e7b8a84a22	contract-templates	67b059db-2e65-4c25-b3f3-07f05c2cd0bb.pdf	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	2025-11-12 18:52:53.587753+00	2025-11-12 18:52:53.587753+00	2025-11-12 18:52:53.587753+00	{"eTag": "\\"fbb0111c5281a09d186844e233773e87\\"", "size": 50204, "mimetype": "application/pdf", "cacheControl": "max-age=3600", "lastModified": "2025-11-12T18:52:54.000Z", "contentLength": 50204, "httpStatusCode": 200}	145b7190-d372-4bf4-b53d-3ee8f4641bc5	9734db5d-cccf-4f1c-84b2-cdd5e094e9da	{}	1
\.


--
-- Data for Name: prefixes; Type: TABLE DATA; Schema: storage; Owner: supabase_storage_admin
--

COPY "storage"."prefixes" ("bucket_id", "name", "created_at", "updated_at") FROM stdin;
guest-documents	guest-ids	2025-11-05 07:23:57.343504+00	2025-11-05 07:23:57.343504+00
expense-receipts	receipts	2025-11-05 07:26:35.772933+00	2025-11-05 07:26:35.772933+00
\.


--
-- Data for Name: s3_multipart_uploads; Type: TABLE DATA; Schema: storage; Owner: supabase_storage_admin
--

COPY "storage"."s3_multipart_uploads" ("id", "in_progress_size", "upload_signature", "bucket_id", "key", "version", "owner_id", "created_at", "user_metadata") FROM stdin;
\.


--
-- Data for Name: s3_multipart_uploads_parts; Type: TABLE DATA; Schema: storage; Owner: supabase_storage_admin
--

COPY "storage"."s3_multipart_uploads_parts" ("id", "upload_id", "size", "part_number", "bucket_id", "key", "etag", "owner_id", "version", "created_at") FROM stdin;
\.


--
-- Data for Name: vector_indexes; Type: TABLE DATA; Schema: storage; Owner: supabase_storage_admin
--

COPY "storage"."vector_indexes" ("id", "name", "bucket_id", "data_type", "dimension", "distance_metric", "metadata_configuration", "created_at", "updated_at") FROM stdin;
\.


--
-- Name: refresh_tokens_id_seq; Type: SEQUENCE SET; Schema: auth; Owner: supabase_auth_admin
--

SELECT pg_catalog.setval('"auth"."refresh_tokens_id_seq"', 73, true);


--
-- PostgreSQL database dump complete
--

-- \unrestrict C96VwJZO5ssVrRqmKMbWIlXodSaCZEy5B8INjBs67Tgdw6jabRvMxO8hBWGom3m

RESET ALL;
