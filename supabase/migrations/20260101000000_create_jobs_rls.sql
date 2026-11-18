-- Migration: Create public.jobs table with Row Level Security (RLS) and explicit role grants

CREATE TABLE public.jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id UUID NOT NULL,
    title TEXT NOT NULL
);

-- Enable Row Level Security (and enforce it)
ALTER TABLE public.jobs ENABLE ROW LEVEL SECURITY;

-- Remove all default or PUBLIC-inherited privileges before granting explicit role permissions
REVOKE ALL ON TABLE public.jobs FROM PUBLIC;
REVOKE ALL ON TABLE public.jobs FROM anon;
REVOKE ALL ON TABLE public.jobs FROM authenticated;

-- Configure explicit role privileges:
-- authenticated has SELECT and INSERT; anon has no SELECT (and no other privileges)
GRANT USAGE ON SCHEMA public TO anon, authenticated;
GRANT SELECT, INSERT ON TABLE public.jobs TO authenticated;

-- RLS Policy: SELECT allows authenticated users to see only rows where owner_id equals auth.uid()
CREATE POLICY jobs_select_own ON public.jobs
    FOR SELECT
    TO authenticated
    USING (owner_id = auth.uid());

-- RLS Policy: INSERT verifies that the new row's owner_id equals auth.uid() via WITH CHECK
CREATE POLICY jobs_insert_own ON public.jobs
    FOR INSERT
    TO authenticated
    WITH CHECK (owner_id = auth.uid());
