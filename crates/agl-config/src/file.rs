//! Loading and atomically saving the configuration file.

use std::path::{Path, PathBuf};

use crate::model::Config;

/// A configuration load or save failure.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The file could not be read or written.
    #[error("config i/o at {path}: {source}")]
    Io {
        /// The path involved.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },

    /// The YAML could not be parsed into the schema.
    #[error("parsing config: {0}")]
    Parse(#[from] serde_yaml_ng::Error),

    /// The config could not be rendered back to YAML.
    #[error("rendering config: {0}")]
    Render(#[from] crate::yaml::ser::Error),

    /// The schema version is newer than this build understands.
    #[error("config schema version {found} is newer than supported version {supported}")]
    SchemaTooNew {
        /// The version in the file.
        found: u32,
        /// The newest version this build supports.
        supported: u32,
    },
}

/// Parses a configuration document from YAML text.
pub fn from_str(s: &str) -> Result<Config, Error> {
    let cfg: Config = serde_yaml_ng::from_str(s)?;
    if cfg.schema_version > agl_core::SCHEMA_VERSION {
        return Err(Error::SchemaTooNew {
            found: cfg.schema_version,
            supported: agl_core::SCHEMA_VERSION,
        });
    }

    Ok(cfg)
}

/// Renders a configuration document to YAML text in upstream's style.
pub fn to_string(cfg: &Config) -> Result<String, Error> {
    Ok(crate::yaml::to_string(cfg)?)
}

/// Reads and parses the configuration file at `path`.
pub fn load(path: &Path) -> Result<Config, Error> {
    let text = std::fs::read_to_string(path).map_err(|source| Error::Io {
        path: path.to_path_buf(),
        source,
    })?;

    from_str(&text)
}

/// Writes `cfg` to `path` atomically: render to a sibling temporary file, then
/// rename over the target so a crash cannot leave a half-written config.
pub fn save(path: &Path, cfg: &Config) -> Result<(), Error> {
    let text = to_string(cfg)?;
    let dir = path.parent().unwrap_or(Path::new("."));
    let tmp = dir.join(format!(
        ".{}.tmp",
        path.file_name().and_then(|s| s.to_str()).unwrap_or("AdGuardHome.yaml")
    ));

    let io = |source| Error::Io { path: path.to_path_buf(), source };

    std::fs::create_dir_all(dir).map_err(io)?;
    std::fs::write(&tmp, text.as_bytes()).map_err(io)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Upstream uses 0o600 for the config file.
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600)).map_err(io)?;
    }

    std::fs::rename(&tmp, path).map_err(io)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The config a real AdGuard Home v0.107.79 wrote, captured verbatim.
    const REFERENCE: &str = include_str!("../../../tests/fixtures/config/reference-v34.yaml");

    #[test]
    fn reproduces_the_reference_config_byte_for_byte() {
        let cfg = from_str(REFERENCE).expect("reference config must parse");
        let rendered = to_string(&cfg).expect("must render");

        if rendered != REFERENCE {
            // Show the first difference rather than two 200-line blobs.
            for (i, (a, b)) in rendered.lines().zip(REFERENCE.lines()).enumerate() {
                assert_eq!(a, b, "line {} differs", i + 1);
            }
            assert_eq!(
                rendered.lines().count(),
                REFERENCE.lines().count(),
                "line counts differ"
            );
            panic!("rendered output differs from the reference");
        }
    }

    #[test]
    fn round_trips_through_parse_and_render() {
        let cfg = from_str(REFERENCE).unwrap();
        let once = to_string(&cfg).unwrap();
        let twice = to_string(&from_str(&once).unwrap()).unwrap();
        assert_eq!(once, twice, "rendering must be idempotent");
    }

    #[test]
    fn rejects_a_future_schema() {
        let newer = REFERENCE.replace("schema_version: 34", "schema_version: 999");
        assert!(matches!(from_str(&newer), Err(Error::SchemaTooNew { found: 999, .. })));
    }

    #[test]
    fn parses_a_minimal_config_using_defaults() {
        let cfg = from_str("schema_version: 34\n").unwrap();
        assert_eq!(cfg.dns.port, 53);
        assert_eq!(cfg.auth_attempts, 5);
        assert!(cfg.filtering.protection_enabled);
        assert_eq!(cfg.filtering.max_http_size.bytes(), 256 * 1024 * 1024);
    }

    #[test]
    fn save_then_load_is_lossless() {
        let dir = std::env::temp_dir().join(format!("agl-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("AdGuardHome.yaml");

        let cfg = from_str(REFERENCE).unwrap();
        save(&p, &cfg).unwrap();
        let back = load(&p).unwrap();

        assert_eq!(to_string(&back).unwrap(), to_string(&cfg).unwrap());
        std::fs::remove_dir_all(&dir).ok();
    }
}
