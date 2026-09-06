# scripts

Screenshot handling for writeups.

## Where images live

Each writeup is a page bundle: a folder holding `index.md` and the images it
references.

```
content/offensive/some-box/
  index.md
  login-form.png      ->  ![Login form](login-form.png)
```

Filename-only references. No `/images/...` paths, no `static/` - anything in
`static/` is copied to the published site verbatim, which is the behavior this
setup exists to avoid.

## Adding a screenshot

Capture to the staging area outside the repo, redact it there, then:

```
scripts/add-screenshot.sh ~/website-in-progress/screenshots-raw/some-box/shot.png some-box login-form.png
```

That copies the file into the bundle and strips its metadata. It prints the
markdown line to paste.

## What protects what

| Layer | Covers |
|---|---|
| `layouts/_markup/render-image.html` | Resizes to 1400px and re-encodes, so the published file carries no EXIF |
| `cascade.build.publishResources` in `hugo.yaml` | Only processed variants reach `public/` - full-resolution originals stay in the repo, off the site |
| `scripts/check-screenshots.sh` (pre-commit) | Blocks GPS/serial/author metadata, raw captures, and files over 2 MB |
| `.gitignore` | Keeps `_raw/` paths out by accident-proofing |

Run `scripts/install-hooks.sh` once per clone to enable the pre-commit check.

None of this makes a published image private. Everything the site renders is
fetchable by anyone with the URL. The controls above are about what is *in* the
image and what stays out of git history - redaction is still a manual step
before the screenshot enters the repo.
