# Supabase RLS Isolation & pgTAP Verification Demo

Minimal demonstration repository showing how PostgreSQL Row Level Security (RLS) isolates per-user records in Supabase (`public.jobs`) and how `pgTAP` tests automatically verify access control on every pull request in GitHub Actions.

## Access Control Model

The migration [`supabase/migrations/20260101000000_create_jobs_rls.sql`](supabase/migrations/20260101000000_create_jobs_rls.sql) defines:

- **Table `public.jobs`**:
  - `id UUID PRIMARY KEY DEFAULT gen_random_uuid()`
  - `owner_id UUID NOT NULL`
  - `title TEXT NOT NULL`
- **Row Level Security**: Enabled on `public.jobs`.
- **Explicit Role Grants**:
  - All default and `PUBLIC`-inherited privileges on `public.jobs` are revoked (`REVOKE ALL ON TABLE public.jobs FROM PUBLIC, anon, authenticated`).
  - `authenticated` is explicitly granted `SELECT` and `INSERT`.
  - `anon` has no `SELECT` or other privileges on `public.jobs`.
- **RLS Policies**:
  - `jobs_select_own`: `FOR SELECT TO authenticated USING (owner_id = auth.uid())`
  - `jobs_insert_own`: `FOR INSERT TO authenticated WITH CHECK (owner_id = auth.uid())`

## Tested Scenarios (`supabase/tests/database/jobs_rls.test.sql`)

All fixtures (fictional Users A and B and their initial job records) and role/JWT helper functions are created inside a single isolated transaction and rolled back at the end of the suite (`BEGIN` ... `SELECT * FROM finish(true)` ... `ROLLBACK`). The suite sets the database role and JWT claims directly to test PostgreSQL policies for each user. Before each scenario, the test explicitly switches roles and JWT claims and asserts both `current_user` and `auth.uid()`:

| Scenario | Action | Expected Outcome |
|---|---|---|
| Metadata & Grants | Inspect table RLS state and grants for `PUBLIC`, `authenticated`, and `anon` | RLS is enabled; `PUBLIC` and `anon` have no grants; `authenticated` has `SELECT` and `INSERT`. |
| 1 | User A reads `public.jobs` | Receives the exact set containing only User A's own record. |
| 2 | User B reads `public.jobs` | Receives the exact set containing only User B's own record. |
| 3 | User A queries User B's record by known ID | Returns zero rows, even though User B can read that record by ID. |
| 4 | User A inserts a record with User A's `owner_id` | Insert succeeds under role `authenticated`, and User A can read the new record. |
| 5 | User A inserts a record with User B's `owner_id` | Rejected by `WITH CHECK` policy with `SQLSTATE 42501` under the same `authenticated` role; row is not created. |
| 6 | Role `anon` executes `SELECT` on `public.jobs` | Rejected with `SQLSTATE 42501` because `SELECT` privilege is revoked from `anon`. |

## Prerequisites

- **Docker** (Docker Engine or Docker Desktop running locally)
- **Supabase CLI**: pinned version **`2.122.0`**
- **Git**

## Reproducing Locally from a Clean Checkout

```bash
# 1. Clone the repository and enter the directory
git clone https://github.com/Pepelatzdev/example-pgtap.git
cd example-pgtap

# 2. Verify Supabase CLI version (2.122.0)
supabase --version

# 3. Start local Supabase stack (redirect stdout to avoid printing local keys/connection strings)
supabase start > /dev/null

# 4. Reset database to a clean state and apply migrations
supabase db reset --no-seed

# 5. Execute the pgTAP test suite (outputs jobs_rls.test.sql, 1..27 plan, all 27 assertions, and Result: PASS)
supabase test db --debug

# 6. Stop local Supabase stack and remove containers
supabase stop --no-backup
```
