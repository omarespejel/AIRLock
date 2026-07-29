//! Private randomized temporary directories for replay infrastructure.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use rand::RngCore;

const CREATE_ATTEMPTS: usize = 64;

pub(crate) struct PrivateTempDir {
    path: PathBuf,
}

impl PrivateTempDir {
    pub(crate) fn create_in(parent: &Path, prefix: &str) -> io::Result<Self> {
        for _ in 0..CREATE_ATTEMPTS {
            let mut random = [0_u8; 16];
            rand::rngs::OsRng
                .try_fill_bytes(&mut random)
                .map_err(|error| io::Error::other(format!("OS randomness unavailable: {error}")))?;
            let suffix = random
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let path = parent.join(format!("{prefix}{suffix}"));
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            match builder.create(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "random temporary-directory names collided repeatedly",
        ))
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for PrivateTempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn randomized_directories_are_distinct_and_private() {
        let parent = std::env::temp_dir();
        let first = PrivateTempDir::create_in(&parent, ".airlock-temp-").expect("first temp dir");
        let second = PrivateTempDir::create_in(&parent, ".airlock-temp-").expect("second temp dir");
        assert_ne!(first.path(), second.path());
        assert!(first.path().is_dir());
        assert!(second.path().is_dir());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(first.path())
                .expect("temp metadata")
                .permissions()
                .mode();
            assert_eq!(mode & 0o077, 0);
        }
    }
}
