#!/bin/sh
# Mechanical size and file-format exports; no source artwork is redrawn.
set -eu
cd "$(dirname "$0")"

if command -v magick >/dev/null 2>&1; then
    imagemagick=magick
elif command -v convert >/dev/null 2>&1; then
    imagemagick=convert
else
    echo 'ImageMagick (magick or convert) is required.' >&2
    exit 1
fi

for variant in mark face guardian; do
    "$imagemagick" "tatami-$variant.png" -filter Lanczos -resize 512x512 \
        -strip "tatami-$variant-512.png"
done

for size in 16 32 48 64 180 192 512; do
    "$imagemagick" favicon-master.png -filter Lanczos -resize "${size}x${size}" \
        -strip "favicon-$size.png"
done

"$imagemagick" favicon-16.png favicon-32.png favicon-48.png favicon.ico
