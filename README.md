# Keyxor

Personal portfolio and security write-ups, built with Hugo and PaperMod.

## Setup

Use **Hugo Extended 0.165.0**, matching the deployment workflow, and Git.
Screenshot scripts also require Bash and ExifTool (`libimage-exiftool-perl`
on Debian/Ubuntu).

```bash
git clone --recurse-submodules https://github.com/Keyxor/Keyxor.github.io.git
cd Keyxor.github.io
hugo version
```

For an existing clone, initialize the pinned theme revision:

```bash
git submodule update --init --recursive
```

Install the screenshot pre-commit check once per clone:

```bash
scripts/install-hooks.sh
```

If another pre-commit hook already exists, the installer prints the line to
add to it. See [screenshot handling](scripts/README.md) for capture, redaction,
metadata stripping, and page-bundle conventions.

## Preview and build

```bash
hugo server
```

Open the local URL printed by Hugo. To include unpublished drafts:

```bash
hugo server --buildDrafts
```

Build the production output with:

```bash
hugo --gc --minify
```

The generated `public/` and `resources/_gen/` directories are ignored by Git.

## Add a write-up

Use an explicit archetype for the nested content paths:

```bash
hugo new content --kind writeups work/writeups/offensive/box-name/index.md
hugo new content --kind speedrun work/writeups/speedrun/box-name/index.md
```

Each page bundle holds `index.md` and its images. Fill in the title, summary,
tags, date, and content; remove the example image reference until an image is
available. New pages start with `draft: true`. Set it to `false` only when the
article is ready to publish.

Offensive write-ups are the current publishing priority. Detection and
remediation companions can remain drafts until later; link them from the
published article once they are available.

## Layout and theme maintenance

- `content/`: biography, section hubs, and articles.
- `hugo.yaml`: site settings, navigation, taxonomies, and publishing defaults.
- `layouts/`: homepage, section cards, image hook, callouts, and theme overrides.
- `assets/css/extended/custom.css`: palette and component styling.
- `static/`: favicon assets and web manifest, copied directly to the output.
- `themes/PaperMod/`: pinned Git submodule; keep site changes outside it.

Three compatibility overrides were copied from PaperMod revision
`d3768854d00ad003b0a8dbdba254ce9224377a01`:
`layouts/baseof.html`, `layouts/rss.xml`, and
`layouts/_partials/templates/opengraph.html`. They replace deprecated
`LanguageDirection` and `LanguageCode` properties with `Direction` and
`Locale`. When updating the theme, compare these copies with upstream and
remove them once upstream provides the equivalent fixes.

## Deployment and indexing

[GitHub Actions](.github/workflows/hugo.yaml) builds and deploys to GitHub
Pages on pushes to `main`, or through a manual workflow run. It checks out the
theme submodule and full Git history, builds without drafts, and uploads
`public/`. The full history supports Git-derived modification dates.

**The site is not ready for indexing.** Keep the `robotsNoIndex` cascade in
`hugo.yaml` and the disallow rule in `layouts/robots.txt` until launch. These
settings are separate from whether an individual article is a draft.
Keep `cascade.build.publishResources: false` when eventually changing the
indexing settings; it controls publication of original bundle resources.

## Checks

```bash
hugo --minify --panicOnWarning
python3 -B -m unittest discover -s tests -v
```

The screenshot regression tests require ExifTool and use temporary Git
repositories to check staged files independently of working-tree changes.
