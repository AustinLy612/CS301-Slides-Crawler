# CS301 Slides Crawler

Automatically discovers and downloads PDF files from given web pages, then merges them into a single PDF. Supports Cookie-based auth, Bearer tokens, and generic form login — ideal for course pages that require authentication.

## Features
- Auth support:
  - Provide browser `Cookie` directly (strongly recommended).
  - Generic form login with customizable field names and hidden input extraction.
- Robust PDF discovery:
  - Finds `.pdf` links in `a`, `iframe`, `embed`, and `object` tags; normalizes relative links to absolute.
- Smart sorting and deduplication:
  - Deduplicates across multiple input pages.
  - Sorts primarily by numeric parts in filenames (ascending), then natural order for non-numeric names.
- Progress and resiliency:
  - Download progress via `tqdm`.
  - Error handling for timeouts and network issues.
- Merge and cleanup:
  - Uses `pypdf` to merge all downloaded PDFs.
  - Automatically removes individual PDFs after merging (can be disabled by editing the script).

## Requirements
- Python 3.8+ (recommended 3.12)
- Install dependencies:

```bash
pip install requests beautifulsoup4 tqdm pypdf
```

## Quick Start
- Cookie-based login (most common):

```bash
python .\download_and_merge_pdfs.py --cookie-header "<paste your full Cookie value here>"
```

After starting, the script prompts you to paste target page URLs — one per line — then submit a blank line to finish.

The merged PDF file will be saved in the same folder as "merged.pdf", and downloaded individual PDF files will be automatically delated after merging succssfully.
