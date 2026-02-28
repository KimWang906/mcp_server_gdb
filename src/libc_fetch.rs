/// Automatic libc/ld download and sysroot construction for QEMU user-mode.
///
/// # V1 scope
/// - Downloads `libc6` from Ubuntu Packages index (noble → jammy → focal).
/// - Extracts `libc.so.6` and `ld-linux-*.so.*` into a temporary sysroot.
/// - QEMU `-L <sysroot>` handles the path rewrite; patchelf is not required.
/// - Only libc + ld are extracted; other shared libs (libstdc++, libgcc_s)
///   are NOT supported in V1.  Document this limitation.
/// - Checksums are NOT verified in V1.
///
/// # Caching
/// Downloaded .deb files are cached under
/// `$XDG_CACHE_HOME/mcp-gdb/libc/<arch>/<glibc_version>/`.

use std::io::Read;
use std::path::{Path, PathBuf};

use tempfile::TempDir;
use tracing::{debug, info};

use crate::error::{AppError, AppResult};
use crate::qemu::ElfInfo;

// ─── Ubuntu arch mapping (private) ───────────────────────────────────────────

/// Map ELF e_machine/endianness to the Ubuntu package architecture name.
fn ubuntu_arch(elf_info: &ElfInfo) -> Option<&'static str> {
    match elf_info.e_machine {
        3 => Some("i386"),
        8 if !elf_info.big_endian => Some("mipsel"),
        8 => Some("mips"),
        20 => Some("powerpc"),
        21 if !elf_info.big_endian => Some("ppc64el"),
        21 => Some("ppc64"),
        22 => Some("s390x"),
        40 if !elf_info.big_endian => Some("armhf"),
        40 => None, // armeb not in Ubuntu repos
        62 => Some("amd64"),
        183 => Some("arm64"),
        243 if elf_info.ei_class == 2 => Some("riscv64"),
        _ => None,
    }
}

// ─── Public API ───────────────────────────────────────────────────────────────

/// Result of a successful libc extraction.
pub struct LibcFetchResult {
    /// Root of the constructed sysroot; pass to `qemu-<arch> -L <sysroot>`.
    pub sysroot: PathBuf,
    /// Owns the `TempDir`; dropping this value removes the temporary files.
    pub _work_dir: TempDir,
}

/// Download (or use cached) Ubuntu libc6 and construct a minimal sysroot.
pub async fn extract_sysroot(binary: &Path, elf: &ElfInfo) -> AppResult<LibcFetchResult> {
    let ubuntu_arch = ubuntu_arch(elf).ok_or_else(|| {
        AppError::invalid_argument(
            "libc_fetch",
            format!("No Ubuntu package arch for e_machine 0x{:04x}", elf.e_machine),
        )
    })?;

    // Read the binary to scan for GLIBC_x.y version requirements.
    let binary_data = std::fs::read(binary)?;
    let (glibc_major, glibc_minor) = find_min_glibc_version(&binary_data).unwrap_or((2, 17));
    let glibc_version_str = format!("{}.{}", glibc_major, glibc_minor);
    info!(
        arch = ubuntu_arch,
        glibc = glibc_version_str,
        "libc_fetch: determined minimum GLIBC requirement"
    );

    // Prepare the cache directory.
    let cache_dir = get_cache_dir(ubuntu_arch, &glibc_version_str);
    std::fs::create_dir_all(&cache_dir)?;

    // Try Ubuntu releases in preference order until we find a suitable one.
    let releases = ["noble", "jammy", "focal"];
    let mut deb_bytes: Option<Vec<u8>> = None;
    let mut selected_pkg_version = String::new();

    for release in &releases {
        let is_ports = is_ports_arch(ubuntu_arch);
        let mirror_base = if is_ports {
            "https://ports.ubuntu.com/ubuntu-ports"
        } else {
            "https://deb.ubuntu.com/ubuntu"
        };

        match fetch_libc6_deb(mirror_base, release, ubuntu_arch, glibc_major, glibc_minor, &cache_dir).await {
            Ok((bytes, version)) => {
                deb_bytes = Some(bytes);
                selected_pkg_version = version;
                info!(release, pkg_version = selected_pkg_version, "libc_fetch: found package");
                break;
            }
            Err(e) => {
                debug!(release, error = %e, "libc_fetch: skipping release");
                continue;
            }
        }
    }

    let deb_bytes = deb_bytes.ok_or_else(|| {
        AppError::io(
            "libc_fetch",
            format!(
                "Could not find libc6 for arch={} glibc>={}.{} in noble/jammy/focal",
                ubuntu_arch, glibc_major, glibc_minor
            ),
        )
    })?;

    // Extract libc.so.6 and ld-linux-*.so.* from the .deb.
    let work_dir = TempDir::new().map_err(|e| {
        AppError::io("libc_fetch", format!("Failed to create temp dir: {}", e))
    })?;
    let sysroot = work_dir.path().join("sysroot");
    std::fs::create_dir_all(&sysroot)?;

    extract_libc_from_deb(&deb_bytes, ubuntu_arch, &sysroot)?;
    info!(sysroot = %sysroot.display(), pkg_version = selected_pkg_version, "libc_fetch: sysroot ready");

    Ok(LibcFetchResult { sysroot, _work_dir: work_dir })
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

/// Whether this arch is served from ports.ubuntu.com instead of deb.ubuntu.com.
fn is_ports_arch(ubuntu_arch: &str) -> bool {
    !matches!(ubuntu_arch, "amd64" | "i386")
}

/// XDG-aware cache path for downloaded debs.
fn get_cache_dir(arch: &str, version: &str) -> PathBuf {
    let base = std::env::var("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            std::env::var("HOME")
                .map(|h| PathBuf::from(h).join(".cache"))
                .unwrap_or_else(|_| PathBuf::from("/tmp/.mcp-gdb-cache"))
        });
    base.join("mcp-gdb").join("libc").join(arch).join(version)
}

/// Scan raw binary bytes for GLIBC_x.y version strings and return the maximum.
fn find_min_glibc_version(data: &[u8]) -> Option<(u32, u32)> {
    let prefix = b"GLIBC_";
    let mut max: Option<(u32, u32)> = None;
    let mut i = 0;
    while i + prefix.len() < data.len() {
        if data[i..].starts_with(prefix) {
            let rest = &data[i + prefix.len()..];
            // Find the end of the version string (non-digit, non-dot).
            let end = rest
                .iter()
                .position(|&b| b != b'.' && !b.is_ascii_digit())
                .unwrap_or(rest.len());
            if let Ok(s) = std::str::from_utf8(&rest[..end]) {
                if let Some((maj, min)) = parse_version_pair(s) {
                    max = Some(match max {
                        None => (maj, min),
                        Some((m, n)) => {
                            if maj > m || (maj == m && min > n) {
                                (maj, min)
                            } else {
                                (m, n)
                            }
                        }
                    });
                }
            }
        }
        i += 1;
    }
    max
}

fn parse_version_pair(s: &str) -> Option<(u32, u32)> {
    let mut parts = s.splitn(2, '.');
    let major = parts.next()?.parse::<u32>().ok()?;
    let minor = parts.next()?.parse::<u32>().ok()?;
    Some((major, minor))
}

/// Upstream glibc version from a Ubuntu package version string like "2.39-0ubuntu8.3".
fn upstream_glibc_from_pkg(pkg_version: &str) -> Option<(u32, u32)> {
    let upstream = pkg_version.split('-').next()?;
    parse_version_pair(upstream)
}

/// Download the libc6 .deb for `release`/`ubuntu_arch` that satisfies the
/// minimum glibc requirement, using the Packages index.
///
/// Returns `(deb_bytes, pkg_version_string)`.
async fn fetch_libc6_deb(
    mirror_base: &str,
    release: &str,
    ubuntu_arch: &str,
    min_glibc_major: u32,
    min_glibc_minor: u32,
    cache_dir: &Path,
) -> AppResult<(Vec<u8>, String)> {
    // Check cache first.
    let cache_deb = cache_dir.join(format!("{}-{}.deb", release, ubuntu_arch));
    let cache_ver = cache_dir.join(format!("{}-{}.version", release, ubuntu_arch));
    if cache_deb.exists() && cache_ver.exists() {
        if let Ok(version) = std::fs::read_to_string(&cache_ver) {
            let version = version.trim().to_string();
            if let Some((maj, min)) = upstream_glibc_from_pkg(&version) {
                if maj > min_glibc_major || (maj == min_glibc_major && min >= min_glibc_minor) {
                    let bytes = std::fs::read(&cache_deb)?;
                    debug!(cache = %cache_deb.display(), "libc_fetch: cache hit");
                    return Ok((bytes, version));
                }
            }
        }
    }

    // Fetch and parse the Packages index.
    let packages_url = format!(
        "{}/dists/{}/main/binary-{}/Packages",
        mirror_base, release, ubuntu_arch
    );
    debug!(url = packages_url, "libc_fetch: fetching Packages index");

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| AppError::io("libc_fetch", format!("reqwest build: {}", e)))?;

    let packages_text = client
        .get(&packages_url)
        .send()
        .await
        .map_err(|e| AppError::io("libc_fetch", format!("Packages fetch failed: {}", e)))?
        .text()
        .await
        .map_err(|e| AppError::io("libc_fetch", format!("Packages read failed: {}", e)))?;

    // Parse the Packages index to find libc6 with a suitable version.
    let (pkg_version, filename) =
        parse_packages_index(&packages_text, min_glibc_major, min_glibc_minor)?;

    // Download the .deb.
    let deb_url = format!("{}/{}", mirror_base, filename);
    debug!(url = deb_url, "libc_fetch: downloading deb");

    let deb_bytes = client
        .get(&deb_url)
        .send()
        .await
        .map_err(|e| AppError::io("libc_fetch", format!("deb download failed: {}", e)))?
        .bytes()
        .await
        .map_err(|e| AppError::io("libc_fetch", format!("deb read failed: {}", e)))?
        .to_vec();

    // Cache for future use.
    let _ = std::fs::write(&cache_deb, &deb_bytes);
    let _ = std::fs::write(&cache_ver, &pkg_version);

    Ok((deb_bytes, pkg_version))
}

/// Parse a Debian `Packages` file and return `(version, filename)` for the
/// `libc6` package whose upstream glibc version meets the minimum requirement.
fn parse_packages_index(
    text: &str,
    min_major: u32,
    min_minor: u32,
) -> AppResult<(String, String)> {
    let mut in_libc6 = false;
    let mut pkg_version = String::new();
    let mut filename = String::new();

    for line in text.lines() {
        if line.starts_with("Package: ") {
            // Reset state for every new stanza.
            let pkg = line["Package: ".len()..].trim();
            in_libc6 = pkg == "libc6";
            if !in_libc6 {
                pkg_version.clear();
                filename.clear();
            }
        }
        if !in_libc6 {
            continue;
        }
        if line.starts_with("Version: ") {
            pkg_version = line["Version: ".len()..].trim().to_string();
        } else if line.starts_with("Filename: ") {
            filename = line["Filename: ".len()..].trim().to_string();
        }
        // A blank line ends the stanza — check if this libc6 stanza is suitable.
        if line.is_empty() && in_libc6 && !pkg_version.is_empty() && !filename.is_empty() {
            if let Some((maj, min)) = upstream_glibc_from_pkg(&pkg_version) {
                if maj > min_major || (maj == min_major && min >= min_minor) {
                    return Ok((pkg_version, filename));
                }
            }
            // Reset and keep looking (there might be multiple libc6 stanzas).
            pkg_version.clear();
            filename.clear();
        }
    }

    // Check the final stanza (no trailing blank line).
    if in_libc6 && !pkg_version.is_empty() && !filename.is_empty() {
        if let Some((maj, min)) = upstream_glibc_from_pkg(&pkg_version) {
            if maj > min_major || (maj == min_major && min >= min_minor) {
                return Ok((pkg_version, filename));
            }
        }
    }

    Err(AppError::io(
        "libc_fetch",
        format!(
            "No libc6 package found satisfying GLIBC >= {}.{}",
            min_major, min_minor
        ),
    ))
}

/// Extract `libc.so.6` and `ld-linux-*.so.*` from the .deb into `sysroot`.
///
/// .deb is an `ar` archive containing `data.tar.{xz,gz,zst}`.
/// We unpack that tarball and fish out the two files we need, placing them
/// under `sysroot/lib/<multiarch-tuple>/`.
fn extract_libc_from_deb(deb_bytes: &[u8], ubuntu_arch: &str, sysroot: &Path) -> AppResult<()> {
    use std::io::Cursor;

    let cursor = Cursor::new(deb_bytes);
    let mut ar = ar::Archive::new(cursor);

    while let Some(entry) = ar.next_entry() {
        let entry = entry.map_err(|e| {
            AppError::io("libc_fetch.extract", format!("ar read error: {}", e))
        })?;
        let name = std::str::from_utf8(entry.header().identifier())
            .unwrap_or("")
            .to_string();

        if name.starts_with("data.tar") {
            let data = read_all_entry(entry)?;
            return extract_from_data_tar(&data, &name, ubuntu_arch, sysroot);
        }
    }

    Err(AppError::io("libc_fetch.extract", "data.tar.* not found in .deb"))
}

fn read_all_entry<R: Read>(mut entry: ar::Entry<R>) -> AppResult<Vec<u8>> {
    let mut buf = Vec::new();
    entry.read_to_end(&mut buf).map_err(|e| {
        AppError::io("libc_fetch.extract", format!("ar entry read: {}", e))
    })?;
    Ok(buf)
}

fn extract_from_data_tar(
    data: &[u8],
    name: &str,
    ubuntu_arch: &str,
    sysroot: &Path,
) -> AppResult<()> {
    use std::io::Cursor;

    // Decompress based on extension.
    let decompressed: Vec<u8> = if name.ends_with(".xz") {
        let mut decoder = xz2::read::XzDecoder::new(Cursor::new(data));
        let mut out = Vec::new();
        decoder.read_to_end(&mut out).map_err(|e| {
            AppError::io("libc_fetch.extract", format!("xz decompress: {}", e))
        })?;
        out
    } else if name.ends_with(".gz") {
        let mut decoder = flate2::read::GzDecoder::new(Cursor::new(data));
        let mut out = Vec::new();
        decoder.read_to_end(&mut out).map_err(|e| {
            AppError::io("libc_fetch.extract", format!("gz decompress: {}", e))
        })?;
        out
    } else if name.ends_with(".zst") {
        let mut decoder = zstd::Decoder::new(Cursor::new(data)).map_err(|e| {
            AppError::io("libc_fetch.extract", format!("zstd decoder create: {}", e))
        })?;
        let mut out = Vec::new();
        decoder.read_to_end(&mut out).map_err(|e| {
            AppError::io("libc_fetch.extract", format!("zstd decompress: {}", e))
        })?;
        out
    } else {
        return Err(AppError::io(
            "libc_fetch.extract",
            format!("Unknown data.tar compression: {}", name),
        ));
    };

    // Parse the inner tar archive.
    let mut archive = tar::Archive::new(Cursor::new(&decompressed));
    let mut found_any = false;

    for entry in archive.entries().map_err(|e| {
        AppError::io("libc_fetch.extract", format!("tar entries: {}", e))
    })? {
        let mut entry = entry.map_err(|e| {
            AppError::io("libc_fetch.extract", format!("tar entry: {}", e))
        })?;

        let path = entry.path().map_err(|e| {
            AppError::io("libc_fetch.extract", format!("tar path: {}", e))
        })?;
        let path_str = path.to_string_lossy();

        // We want ./lib/<tuple>/libc.so.6 and ./lib/<tuple>/ld-linux-*.so.*
        let is_libc = path_str.contains("/libc.so.6") || path_str.contains("/libc-");
        let is_ld = path_str.contains("/ld-linux") || path_str.contains("/ld-") && path_str.contains(".so");

        if !is_libc && !is_ld {
            continue;
        }

        // Determine the destination filename.
        let file_name = path.file_name().map(|f| f.to_os_string());
        let file_name = match file_name {
            Some(f) => f,
            None => continue,
        };

        // Place under sysroot/lib/<multiarch>/
        let multiarch = ubuntu_arch_to_multiarch(ubuntu_arch);
        let dest_dir = sysroot.join("lib").join(multiarch);
        std::fs::create_dir_all(&dest_dir)?;
        let dest_path = dest_dir.join(&file_name);

        let mut content = Vec::new();
        entry.read_to_end(&mut content).map_err(|e| {
            AppError::io("libc_fetch.extract", format!("tar file read: {}", e))
        })?;

        std::fs::write(&dest_path, &content)?;
        debug!(dest = %dest_path.display(), "libc_fetch: extracted");
        found_any = true;
    }

    if !found_any {
        return Err(AppError::io(
            "libc_fetch.extract",
            format!("No libc.so.6 or ld-* found in {} for arch {}", name, ubuntu_arch),
        ));
    }

    Ok(())
}

/// Map Ubuntu architecture name to GNU multiarch tuple for lib directory layout.
fn ubuntu_arch_to_multiarch(ubuntu_arch: &str) -> &'static str {
    match ubuntu_arch {
        "amd64" => "x86_64-linux-gnu",
        "i386" => "i386-linux-gnu",
        "arm64" => "aarch64-linux-gnu",
        "armhf" => "arm-linux-gnueabihf",
        "armel" => "arm-linux-gnueabi",
        "mipsel" => "mipsel-linux-gnu",
        "mips" => "mips-linux-gnu",
        "mips64el" => "mips64el-linux-gnuabi64",
        "powerpc" => "powerpc-linux-gnu",
        "ppc64el" => "powerpc64le-linux-gnu",
        "ppc64" => "powerpc64-linux-gnu",
        "s390x" => "s390x-linux-gnu",
        "riscv64" => "riscv64-linux-gnu",
        _ => "unknown",
    }
}
