# Renovation Control — SaaS starter with team administration

This version adds an owner-only Team screen for inviting staff, changing roles, cancelling pending invitations, and removing access.

## 1. Create/update Supabase
Create a Supabase project and run `supabase.sql` in SQL Editor. If you already ran an older version, run this complete file so the new tables, policies and RPC functions are installed.

## 2. Configure frontend
Copy `.env.example` to `.env` and add your Supabase URL and anon key.

## 3. Install/run
npm install
npm run dev

## 4. Deploy the invitation function
The invitation endpoint uses the Supabase service-role key server-side, never in the browser.

Install Supabase CLI and link the project, then:

supabase functions deploy invite-user --no-verify-jwt
supabase secrets set SUPABASE_SERVICE_ROLE_KEY=YOUR_SERVICE_ROLE_KEY

`SUPABASE_URL` is normally provided automatically to Edge Functions. Do not put the service-role key in `.env` for the frontend.

## Team features
Owners can:
- Invite a user by email
- Choose Project Manager, Site Manager, Purchasing, Tradesperson, or Customer
- See current members
- Change a member's role
- Remove a member's access
- See and cancel pending invitations

Security:
- Team navigation is owner-only.
- Membership changes are performed through SECURITY DEFINER RPCs that verify the authenticated user is an owner.
- The owner role cannot be assigned, changed, or removed from the Team screen.
- Company data remains isolated by Supabase Row Level Security.
- Invitation email delivery uses Supabase Auth's `inviteUserByEmail` from an Edge Function so the service-role key never reaches the browser.

## Invitation flow
Owner -> Team -> Invite -> Edge Function creates invitation + sends Supabase invite -> invited user accepts -> signup trigger matches the pending invitation email -> membership is created in the existing company with the selected role.

## Still needed for production
- Custom branded email templates/domain
- Password reset UX
- Customer-specific project policies
- Audit log / immutable admin history
- Stripe billing
- AI API integration
- File/photo storage
- Automated tests
- Production deployment and domain

## Project-level access

Owners can use **Team → Project access** to assign individual projects to non-owner users. Assigned users can only read/update project-linked requests, tasks, and materials for projects they are assigned to. Owners retain access to every company project.

Run the updated `supabase.sql` after the previous schema. It adds `project_members`, RLS policies, and owner-only RPCs for assigning/removing project access. Role changes automatically sync the assignment's stored role.
