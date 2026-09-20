# Tatami artwork

Three related green designs connect the tatami mat with folding tatami gusoku
armour. The guardian is used at the top of the repository README.

| File | Use |
|---|---|
| `tatami-mark.png` | Large standalone kanji mark |
| `tatami-face.png` | Large friendly kanji character |
| `tatami-guardian.png` | Large waving folding-armour mascot |
| `tatami-{mark,face,guardian}-512.png` | Smaller 512-pixel exports for documentation |
| `favicon-master.png` | Simplified guardian head on a cream tile |
| `favicon-{16,32,48,64,180,192,512}.png` | Square icon exports at the named pixel dimensions |
| `favicon.ico` | Multi-resolution icon containing 16, 32 and 48-pixel images |
| `concept-sheet.png` | Approved three-concept board, retained as a design reference |

The three large figures and favicon master are 1254 × 1254 RGBA PNGs.
The standalone figures have transparent backgrounds. The favicon has a cream
tile with transparent outer corners so its dark strokes remain visible on
both light and dark browser themes. These are raster assets, not SVG/vector
masters. The standalone assets were generated from the approved concept sheet;
they are not pixel-identical crops of that sheet.

## Design rule

Keep the defining kanji strokes intact. In the face and guardian, the upper
田 has one complete outer frame and uninterrupted horizontal and vertical
cross-strokes. Eyes sit in the upper quadrants. Do not cut the vertical stroke
short to insert a mouth, replace the grid with spectacles, or merge the lower
quadrants. The guardian uses the same geometry at favicon scale.

The palette is fresh green, deep forest outlines, warm straw trim and cream.
The illustrations include subtle tonal variation; the generation prompts give
the original approximate colour direction rather than a strict spot-colour
specification. Preserve the shared proportions and colours when making variants.

## README placement

From the root README:

```html
<p align="center">
  <img src="assets/branding/tatami-guardian-512.png" width="256" height="256" alt="Tatami: a friendly green folding-armour guardian whose head preserves the complete 田 cross in 畳.">
</p>
```

Use a repository-relative path so GitHub resolves the image on the current
branch. A local filesystem or ChatGPT download URL does not belong in the README.

## Future website use

When these files are served under `/assets/branding/`, a website may use:

```html
<link rel="icon" href="/assets/branding/favicon.ico" sizes="16x16 32x32 48x48">
<link rel="icon" type="image/png" sizes="32x32" href="/assets/branding/favicon-32.png">
<link rel="apple-touch-icon" sizes="180x180" href="/assets/branding/favicon-180.png">
```

A GitHub repository README cannot change GitHub's own browser-tab favicon.
The assets are ready for a
project website or application that controls its HTML head.

## Rebuild and provenance

Run `sh assets/branding/export.sh` from the repository root. It requires
ImageMagick (`magick` or `convert`) and regenerates only the size/format exports.
It never replaces the large source artwork or modifies the approved design.

The artwork was created with the built-in OpenAI image-generation tool from the
user-approved Tatami concepts, including a dedicated revision to restore the
complete 田 cross. The asset-generation prompts are retained in `PROMPTS.md`.
Size and ICO conversions use ImageMagick. The repository's root LICENSE applies
to these included assets; no third-party logo or stock artwork was incorporated.
