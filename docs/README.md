# TimeboardApp Website

This folder contains a static website intended to be deployed at `timeboardapp.com`.

It is designed to be hosted as-is (no build step):

- `index.html` is the landing page.
- `docs/` contains documentation pages.
- `assets/` contains CSS/JS/images.

Deployment options:

1) GitHub Pages
- Publish the `web/` folder as the Pages root (or copy its contents to the Pages root).
- If you use a custom domain, keep the `CNAME` file.

2) Any static host
- Upload the contents of this folder.
- Configure the host to serve `index.html` for `/`.

If you prefer hosting the docs inside the application, you can also copy the HTML into a directory served by your reverse proxy.
