#!/bin/bash
# Generate index.html from markdown sources using pandoc
# Note: This is a simplified version without the dynamic help output from the fosr binary.
# For the full version with help text, see the pages job in .gitlab-ci.yml.

set -e

# Check for pandoc
if ! command -v pandoc &> /dev/null; then
    echo "Error: pandoc is not installed."
    exit 1
fi

cd "$(dirname "$0")"

pandoc intro.md compile.md config_doc.md other_software.md schema.md lib.md roadmap.md usecases.md analysis.md limitations.md refs.md \
    -o index.html \
    --template template.html \
    --include-after-body footer.html \
    --standalone \
    --toc \
    --toc-depth 1

echo "Generated public/index.html"
