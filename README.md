# linktree

A self-hosted, subscription-free link-in-bio page for **linktree.abhinavkuchhal.com**.

- Plain `index.html`, no build step. Deploys as a static site on Vercel.
- Links, social icons and profile live in **Supabase** (`links`, `profile` tables).
- Hidden admin panel: click the `© Abhinav Kuchhal` footer or open `/#admin`, enter the password,
  then add / edit / hide / reorder / delete links, edit the profile, or change the password.
- Icons: each link uses its `icon_url`, or falls back to the site's favicon automatically.
- Palette and VCR font match [abhinavkuchhal.com](https://abhinavkuchhal.com).
  Drop `VCR_OSD_MONO.ttf` into `fonts/` to use the exact font (falls back to VT323).

## Security model
The page ships only the Supabase **publishable** key, which can read active links but not write.
Every write calls a Postgres function that checks the admin password against a bcrypt hash in a
private schema. See `supabase/schema.sql`.
