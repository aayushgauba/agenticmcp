use super::{MAX_FILE, McpResult, Proposal, filename};
use std::{
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
};

#[cfg(target_os = "linux")]
use rustix::fs::{self, AtFlags, FlockOperation, Mode, OFlags};

/// An open directory capability and an exclusive advisory lock. Path resolution
/// for reads/writes remains relative to this descriptor, never a caller's path.
pub(super) struct DataDir {
    pub path: PathBuf,
    #[cfg(target_os = "linux")]
    directory: File,
}

impl DataDir {
    #[cfg(target_os = "linux")]
    pub fn open(path: &Path) -> McpResult<Self> {
        use std::os::unix::fs::MetadataExt;
        let directory = File::from(fs::open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        let metadata = directory.metadata()?;
        if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o077 != 0 {
            return Err(
                "data directory must be owned by the service account with mode 0700".into(),
            );
        }
        fs::flock(&directory, FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| "another service instance is using this data directory")?;
        Ok(Self {
            path: path.canonicalize()?,
            directory,
        })
    }

    #[cfg(not(target_os = "linux"))]
    pub fn open(_path: &Path) -> McpResult<Self> {
        Err("durable MCP execution currently requires Linux".into())
    }

    #[cfg(target_os = "linux")]
    fn file(&self, name: &str) -> McpResult<File> {
        use std::os::unix::fs::MetadataExt;
        filename(name)?;
        let file = File::from(fs::openat(
            &self.directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.mode() & 0o022 != 0
            || metadata.uid() != rustix::process::geteuid().as_raw()
        {
            return Err(
                "target must be a service-owned regular file, not linked or writable by others"
                    .into(),
            );
        }
        Ok(file)
    }

    #[cfg(target_os = "linux")]
    pub fn read(&self, name: &str) -> McpResult<Vec<u8>> {
        let mut bytes = Vec::new();
        self.file(name)?
            .take(MAX_FILE as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_FILE {
            return Err("file exceeds size limit".into());
        }
        Ok(bytes)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn read(&self, _name: &str) -> McpResult<Vec<u8>> {
        Err("Linux required".into())
    }

    #[cfg(target_os = "linux")]
    pub fn replace(&self, proposal: &Proposal) -> McpResult<()> {
        use std::os::unix::fs::PermissionsExt;
        let name = format!(".ajwt-{}.tmp", crate::crypto::id());
        let outcome = (|| -> McpResult<()> {
            let mode = self.file(&proposal.path)?.metadata()?.permissions().mode() & 0o777;
            let mut temp = File::from(fs::openat(
                &self.directory,
                &name,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )?);
            temp.write_all(proposal.replacement.as_bytes())?;
            temp.set_permissions(std::fs::Permissions::from_mode(mode))?;
            temp.sync_all()?;
            if crate::crypto::hash(&self.read(&proposal.path)?) != proposal.before_sha256 {
                return Err("file changed during execution".into());
            }
            fs::renameat(&self.directory, &name, &self.directory, &proposal.path)?;
            self.directory.sync_all()?;
            Ok(())
        })();
        if outcome.is_err() {
            let _ = fs::unlinkat(&self.directory, &name, AtFlags::empty());
        }
        outcome
    }

    #[cfg(not(target_os = "linux"))]
    pub fn replace(&self, _proposal: &Proposal) -> McpResult<()> {
        Err("Linux required".into())
    }
}
