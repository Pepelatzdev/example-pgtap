BEGIN;

-- Load pgTAP extension functions into search_path
SET LOCAL search_path TO extensions, public, auth;

-- Exact assertion plan
SELECT plan(27);

-- ============================================================================
-- Test Fixtures & Context Switching Helpers (executed as privileged role)
-- ============================================================================

CREATE SCHEMA test_helpers;

CREATE OR REPLACE FUNCTION test_helpers.switch_to_authenticated(p_user_id UUID)
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
    RESET ROLE;
    PERFORM set_config(
        'request.jwt.claims',
        json_build_object('sub', p_user_id::text, 'role', 'authenticated')::text,
        true
    );
    PERFORM set_config('request.jwt.claim.sub', p_user_id::text, true);
    PERFORM set_config('request.jwt.claim.role', 'authenticated', true);
    SET LOCAL ROLE authenticated;
END;
$$;

CREATE OR REPLACE FUNCTION test_helpers.switch_to_anon()
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
    RESET ROLE;
    PERFORM set_config('request.jwt.claims', '{}', true);
    PERFORM set_config('request.jwt.claim.sub', '', true);
    PERFORM set_config('request.jwt.claim.role', 'anon', true);
    SET LOCAL ROLE anon;
END;
$$;

CREATE OR REPLACE FUNCTION test_helpers.reset_to_privileged()
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
    RESET ROLE;
    PERFORM set_config('request.jwt.claims', '{}', true);
    PERFORM set_config('request.jwt.claim.sub', '', true);
    PERFORM set_config('request.jwt.claim.role', 'postgres', true);
END;
$$;

GRANT USAGE ON SCHEMA test_helpers TO authenticated, anon;
GRANT EXECUTE ON FUNCTION test_helpers.switch_to_authenticated(UUID) TO authenticated, anon;
GRANT EXECUTE ON FUNCTION test_helpers.switch_to_anon() TO authenticated, anon;
GRANT EXECUTE ON FUNCTION test_helpers.reset_to_privileged() TO authenticated, anon;

-- Seed fictional users A and B in auth.users
INSERT INTO auth.users (id, email, raw_app_meta_data, raw_user_meta_data, aud, role, created_at, updated_at)
VALUES
    (
        '11111111-1111-4111-8111-111111111111'::uuid,
        'user.a@example.test',
        '{"provider":"email","providers":["email"]}'::jsonb,
        '{}'::jsonb,
        'authenticated',
        'authenticated',
        now(),
        now()
    ),
    (
        '22222222-2222-4222-8222-222222222222'::uuid,
        'user.b@example.test',
        '{"provider":"email","providers":["email"]}'::jsonb,
        '{}'::jsonb,
        'authenticated',
        'authenticated',
        now(),
        now()
    );

-- Seed one known job record for User A and one known job record for User B
INSERT INTO public.jobs (id, owner_id, title)
VALUES
    (
        'aaaa1111-1111-4111-8111-111111111111'::uuid,
        '11111111-1111-4111-8111-111111111111'::uuid,
        'User A Initial Job'
    ),
    (
        'bbbb2222-2222-4222-8222-222222222222'::uuid,
        '22222222-2222-4222-8222-222222222222'::uuid,
        'User B Initial Job'
    );

-- ============================================================================
-- Metadata & Privilege Assertions (Assertions 1 - 6)
-- ============================================================================

SELECT has_table(
    'public',
    'jobs',
    'public.jobs table exists'
);

SELECT ok(
    (
        SELECT c.relrowsecurity
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND c.relname = 'jobs'
    ),
    'RLS is enabled on public.jobs'
);

SELECT is(
    (
        SELECT count(*)::int
        FROM information_schema.role_table_grants
        WHERE table_schema = 'public'
          AND table_name = 'jobs'
          AND grantee = 'PUBLIC'
    ),
    0,
    'PUBLIC has no inherited table grants on public.jobs'
);

SELECT ok(
    has_table_privilege('authenticated', 'public.jobs', 'SELECT'),
    'authenticated role has SELECT privilege on public.jobs'
);

SELECT ok(
    has_table_privilege('authenticated', 'public.jobs', 'INSERT'),
    'authenticated role has INSERT privilege on public.jobs'
);

SELECT ok(
    NOT has_table_privilege('anon', 'public.jobs', 'SELECT'),
    'anon role does not have SELECT privilege on public.jobs'
);

-- ============================================================================
-- Scenario 1: User A reads the jobs list (Assertions 7 - 9)
-- ============================================================================

SELECT test_helpers.switch_to_authenticated('11111111-1111-4111-8111-111111111111'::uuid);

SELECT is(
    current_user::text,
    'authenticated',
    'Scenario 1: current role is authenticated for User A'
);

SELECT is(
    auth.uid(),
    '11111111-1111-4111-8111-111111111111'::uuid,
    'Scenario 1: auth.uid() matches User A UUID'
);

SELECT results_eq(
    $$SELECT id, owner_id, title FROM public.jobs ORDER BY id$$,
    $$VALUES (
        'aaaa1111-1111-4111-8111-111111111111'::uuid,
        '11111111-1111-4111-8111-111111111111'::uuid,
        'INTENTIONAL_MISMATCH_FOR_CI_CHECK'::text
    )$$,
    'Scenario 1: User A reads jobs and receives exact set of only their own record'
);

-- ============================================================================
-- Scenario 2: User B reads the jobs list (Assertions 10 - 12)
-- ============================================================================

SELECT test_helpers.switch_to_authenticated('22222222-2222-4222-8222-222222222222'::uuid);

SELECT is(
    current_user::text,
    'authenticated',
    'Scenario 2: current role is authenticated for User B'
);

SELECT is(
    auth.uid(),
    '22222222-2222-4222-8222-222222222222'::uuid,
    'Scenario 2: auth.uid() matches User B UUID'
);

SELECT results_eq(
    $$SELECT id, owner_id, title FROM public.jobs ORDER BY id$$,
    $$VALUES (
        'bbbb2222-2222-4222-8222-222222222222'::uuid,
        '22222222-2222-4222-8222-222222222222'::uuid,
        'User B Initial Job'::text
    )$$,
    'Scenario 2: User B reads jobs and receives exact set of only their own record'
);

-- ============================================================================
-- Scenario 3: User A queries User B's record by known ID (Assertions 13 - 16)
-- ============================================================================

-- First verify while authenticated as User B that User B can see this record by ID
SELECT results_eq(
    $$SELECT id, owner_id, title FROM public.jobs WHERE id = 'bbbb2222-2222-4222-8222-222222222222'::uuid$$,
    $$VALUES (
        'bbbb2222-2222-4222-8222-222222222222'::uuid,
        '22222222-2222-4222-8222-222222222222'::uuid,
        'User B Initial Job'::text
    )$$,
    'Scenario 3 precondition: User B can read their own record by known ID'
);

-- Switch to User A and query User B's record by its known ID
SELECT test_helpers.switch_to_authenticated('11111111-1111-4111-8111-111111111111'::uuid);

SELECT is(
    current_user::text,
    'authenticated',
    'Scenario 3: current role is authenticated for User A'
);

SELECT is(
    auth.uid(),
    '11111111-1111-4111-8111-111111111111'::uuid,
    'Scenario 3: auth.uid() matches User A UUID'
);

SELECT is_empty(
    $$SELECT id, owner_id, title FROM public.jobs WHERE id = 'bbbb2222-2222-4222-8222-222222222222'::uuid$$,
    'Scenario 3: User A querying User B record by known ID returns zero rows'
);

-- ============================================================================
-- Scenario 4: User A creates a record with their own owner_id (Assertions 17 - 20)
-- ============================================================================

SELECT test_helpers.switch_to_authenticated('11111111-1111-4111-8111-111111111111'::uuid);

SELECT is(
    current_user::text,
    'authenticated',
    'Scenario 4: current role is authenticated for User A'
);

SELECT is(
    auth.uid(),
    '11111111-1111-4111-8111-111111111111'::uuid,
    'Scenario 4: auth.uid() matches User A UUID'
);

SELECT lives_ok(
    $$INSERT INTO public.jobs (id, owner_id, title) VALUES (
        'aaaa3333-3333-4333-8333-333333333333'::uuid,
        '11111111-1111-4111-8111-111111111111'::uuid,
        'User A Second Job'
    )$$,
    'Scenario 4: User A inserts a record with their own owner_id'
);

SELECT results_eq(
    $$SELECT id, owner_id, title FROM public.jobs WHERE id = 'aaaa3333-3333-4333-8333-333333333333'::uuid$$,
    $$VALUES (
        'aaaa3333-3333-4333-8333-333333333333'::uuid,
        '11111111-1111-4111-8111-111111111111'::uuid,
        'User A Second Job'::text
    )$$,
    'Scenario 4: User A can read the newly created record'
);

-- ============================================================================
-- Scenario 5: User A creates a record with User B's owner_id (Assertions 21 - 24)
-- ============================================================================

SELECT test_helpers.switch_to_authenticated('11111111-1111-4111-8111-111111111111'::uuid);

SELECT is(
    current_user::text,
    'authenticated',
    'Scenario 5: current role is authenticated for User A'
);

SELECT is(
    auth.uid(),
    '11111111-1111-4111-8111-111111111111'::uuid,
    'Scenario 5: auth.uid() matches User A UUID'
);

SELECT throws_ok(
    $$INSERT INTO public.jobs (id, owner_id, title) VALUES (
        'bbbb4444-4444-4444-8444-444444444444'::uuid,
        '22222222-2222-4222-8222-222222222222'::uuid,
        'Unauthorized Job For User B'
    )$$,
    '42501',
    NULL,
    'Scenario 5: User A insert with User B owner_id is rejected with SQLSTATE 42501'
);

SELECT test_helpers.reset_to_privileged();

SELECT is(
    (
        SELECT count(*)::int
        FROM public.jobs
        WHERE id = 'bbbb4444-4444-4444-8444-444444444444'::uuid
    ),
    0,
    'Scenario 5: rejected row was not created in public.jobs'
);

-- ============================================================================
-- Scenario 6: anon executes SELECT on public.jobs (Assertions 25 - 27)
-- ============================================================================

SELECT test_helpers.switch_to_anon();

SELECT is(
    current_user::text,
    'anon',
    'Scenario 6: current role is anon'
);

SELECT is(
    auth.uid(),
    NULL::uuid,
    'Scenario 6: auth.uid() is NULL for anon'
);

SELECT throws_ok(
    $$SELECT id, owner_id, title FROM public.jobs$$,
    '42501',
    NULL,
    'Scenario 6: anon SELECT on public.jobs fails with SQLSTATE 42501 due to revoked SELECT privilege'
);

-- ============================================================================
-- Finish Plan & Rollback Transaction
-- ============================================================================

SELECT test_helpers.reset_to_privileged();
SELECT * FROM finish(true);

ROLLBACK;
