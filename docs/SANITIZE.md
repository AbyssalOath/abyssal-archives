# Metadata stripping

Status: **stub, off by default.** `STRIP_METADATA=false`, and the stripper
registry in `src/sanitize.rs` contains **no implementations**. Every file is
stored **byte-for-byte** as it was uploaded or imported. The admin Files page
says so.

## Never for ISOs, disk images or binaries

Disk images (`.iso`, `.img`, `.qcow2`, ...), archives (`.zip`, `.tar.xz`, ...),
packages and executables are **never** modified, whatever a stripper claims to
support. `sanitize::is_never_modified` checks this before any stripper is
consulted, and files without an extension or sent as
`application/octet-stream` are treated the same way. Reasons:

- **Upstream checksums and signatures must keep matching.** People verify
  downloads against the SHA-256 / GPG signature published by the original
  project. Changing even one byte makes every such check fail, and to a careful
  user a modified ISO is indistinguishable from a tampered one.
- **Boot structures are fragile.** Hybrid ISOs carry El Torito boot records,
  MBR/GPT partition tables and isohybrid layouts at fixed offsets. A
  "metadata" rewrite can make an image unbootable.
- **There is nothing to strip.** Binary formats have no EXIF-style personal
  metadata worth removing, and the cost of a mistake is high.

## What may be stripped later

Only formats that commonly leak personal data and are safe to rewrite:

- **Images** (JPEG, PNG, WebP, TIFF): EXIF (GPS location, camera serials,
  timestamps), XMP, IPTC, embedded thumbnails.
- **PDF**: document info dictionary (author, creator tool, dates), XMP
  metadata.

## How it fits the pipeline

```
upload / import  ->  strip (only if STRIP_METADATA=true AND a stripper supports it)
                 ->  hash + size (SHA-256 and SHA-512, one pass, on the OUTPUT)
                 ->  store
```

Hashes and size are always computed on the bytes actually stored, so the
published checksums describe what visitors download. For uploads that will be
stripped, the upload is first spooled to a temporary file. Imports write the
stripped copy next to the source (a hidden `.strip-*` file) and remove the
original once the stripped copy is stored.

## Writing a stripper

Implement `MetadataStripper`:

```rust
pub trait MetadataStripper: Send + Sync {
    fn name(&self) -> &'static str;
    fn supports(&self, filename: &str, mime: Option<&str>) -> bool;
    fn strip(&self, input_path: &Path, output_path: &Path) -> Result<(), SanitizeError>;
}
```

- `supports` should match narrowly (extension **and** content sniffing,
  e.g. JPEG magic bytes), and never claim formats it does not fully understand.
- `strip` reads `input_path` and writes a new file to `output_path`. It must
  never modify the input, and must fail rather than write a partial output.
- Prefer well-tested pure-Rust crates (e.g. image container rewriters that drop
  metadata segments without re-encoding pixels) over shelling out to
  `exiftool`/`qpdf`. If external tools are used, run them with fixed arguments
  and a timeout.
- Register it in `StripperRegistry::new()` and add tests showing the output
  differs only in metadata.
