# skidpaster.xyz

Static site (no backend) for GitHub Pages.

| URL | Shows |
| --- | --- |
| `skidpaster.xyz/` | Landing page with live menu previews |
| `skidpaster.xyz/Zany/menu.html` | Zany menu, rendered |
| `skidpaster.xyz/Zany/menu.lua` | Zany Lua source as plain text |
| `skidpaster.xyz/Rynz/menu.html` / `menu.lua` | Same for Rynz |

## Deploy on GitHub Pages

1. Push everything in this folder to the root of a GitHub repo (keep `CNAME` and `.nojekyll`).
2. Repo → **Settings → Pages** → Source: *Deploy from a branch* → Branch `main`, folder `/ (root)` → Save.
3. Custom domain: `skidpaster.xyz` (already set by the `CNAME` file) → tick **Enforce HTTPS** once available.
4. DNS at your domain registrar:
   - `A` records for `@`: `185.199.108.153`, `185.199.109.153`, `185.199.110.153`, `185.199.111.153`
   - `CNAME` for `www`: `<your-github-username>.github.io`

## Add a new menu

1. Create a folder, e.g. `NewMenu/`, with `menu.html` and `menu.lua`.
2. Add `{ id: 'NewMenu', tabs: '…' }` to the `MENUS` list in `index.html`.

Folder names are case-sensitive on GitHub Pages: `/Zany/` works, `/zany/` does not.
