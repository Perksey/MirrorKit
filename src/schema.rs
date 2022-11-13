use tokio::io::AsyncBufReadExt;

/// Encapsulates a single repository in the repository list file.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Repo {
    /// The source repo URL.
    pub src: String,

    /// The destination repo URL.
    pub dst: String,

    /// Do we need to send an update to the remote? Not used on rx.
    pub status: TxStatus,

    /// Named references. Not used on rx side.
    pub refs: std::collections::HashMap<String, RefKind>,

    /// - **Tx**: The Git SHAs that have been sent to the remote. Used in calculation of delta bundles.
    /// - **Rx**: The manifest SHAs that have been received (for anti-replay).
    pub shas: std::collections::HashSet<String>,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub enum TxStatus {
    UpToDate,
    FullTxNeeded(std::collections::HashSet<String>),
    DeltaTxNeeded(std::collections::HashSet<String>),
}

impl Default for TxStatus {
    fn default() -> Self {
        Self::UpToDate
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct Bundle {
    pub filename: String,
    pub uuid: uuid::Uuid,
    pub src: String,
    pub dst: String,
    pub added: std::collections::HashMap<String, Ref>,
    pub modified: std::collections::HashMap<String, Ref>,
    pub removed: std::collections::HashMap<String, RefKind>,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct Ref {
    pub sha: String,
    pub kind: RefKind,
}

#[derive(
    serde::Serialize, serde::Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug,
)]
pub enum RefKind {
    Branch,
    Tag,
}

impl Repo {
    pub async fn prune(&mut self, clone_dir: &std::path::PathBuf) -> anyhow::Result<()> {
        let mut hash_set = std::collections::HashSet::<String>::new();
        for ref_name in self.refs.keys() {
            for item in get_branch_shas(clone_dir, ref_name).await? {
                hash_set.insert(item);
            }
        }
        self.shas = hash_set;
        Ok(())
    }

    pub async fn get_bundle(
        &mut self,
        clone_dir: &std::path::PathBuf,
        branches: &[String],
        all_refs: &[(RefKind, String)],
    ) -> anyhow::Result<Bundle> {
        let uuid = uuid::Uuid::new_v4();
        let mut added = std::collections::HashMap::<String, Ref>::new();
        let mut modified = std::collections::HashMap::<String, Ref>::new();
        let mut removed = std::collections::HashMap::<String, RefKind>::new();
        for branch in branches {
            let (kind, _) = all_refs
                .iter()
                .find(|x| &x.1 == branch)
                .expect("attempted to include a branch in a bundle that does not exist");
            let sha_out = tokio::process::Command::new("git")
                .arg("rev-parse")
                .arg(branch)
                .current_dir(clone_dir)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::inherit())
                .output()
                .await?;
            if !sha_out.status.success() {
                anyhow::bail!("Failed to get branch sha");
            }
            let sha = String::from_utf8(sha_out.stdout)?.trim().to_string();
            let bundle_name = branch.strip_prefix("origin/").unwrap_or(branch).to_string();
            if let Some(known_kind) = self.refs.get_mut(branch) {
                if known_kind != kind {
                    // add as a deletion to delete the old kind first
                    removed.insert(bundle_name.clone(), *known_kind);

                    // now add it as an added
                    added.insert(bundle_name, Ref { sha, kind: *kind });

                    *known_kind = *kind;
                } else {
                    // it's in our refs and the refs we're sending to them
                    modified.insert(bundle_name, Ref { sha, kind: *kind });
                }
            } else {
                added.insert(bundle_name.clone(), Ref { sha, kind: *kind });
                self.refs.insert(branch.clone(), *kind);
            }
        }

        self.refs.retain(|name, kind| {
            if all_refs.iter().any(|rpair| &rpair.1 == name) {
                true
            } else {
                removed.insert(
                    name.strip_prefix("origin/").unwrap_or(name).to_string(),
                    *kind,
                );
                false
            }
        });

        Ok(Bundle {
            filename: format!("{}.bundle", uuid),
            uuid,
            src: self.src.clone(),
            dst: self.dst.clone(),
            added,
            modified,
            removed,
        })
    }

    pub async fn get_delta(
        &self,
        clone_dir: &std::path::PathBuf,
        branch: &str,
    ) -> anyhow::Result<String> {
        let shas = get_branch_shas(clone_dir, branch).await?;
        for sha in shas {
            if self.shas.contains(&sha) {
                log::debug!("They have {}, using this as a delta to {}", sha, branch);
                return Ok(format!("{}..{}", sha, branch));
            }
        }
        Ok(branch.to_string())
    }
}

pub async fn get_branch_shas(
    clone_dir: &std::path::PathBuf,
    ref_name: &str,
) -> anyhow::Result<Vec<String>> {
    let mut ret = Vec::new();
    log::debug!("Getting shas on {}", ref_name);
    let out = tokio::process::Command::new("git")
        .arg("log")
        .arg("--format=format:%H")
        .arg(ref_name)
        .current_dir(clone_dir)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .output()
        .await?;
    if !out.status.success() {
        anyhow::bail!("git log failed");
    }
    let mut buf_reader = tokio::io::BufReader::new(out.stdout.as_slice());
    let mut line = String::new();
    while buf_reader.read_line(&mut line).await? != 0 {
        log::trace!("{}: {}", ref_name, line);
        ret.push(line.trim().trim_matches('\"').to_string());
        line.clear();
    }
    Ok(ret)
}

pub async fn get_all_refs(
    clone_dir: &std::path::PathBuf,
) -> anyhow::Result<Vec<(RefKind, String)>> {
    let mut branches = Vec::new();
    for (kind, arg) in [(RefKind::Branch, "branch"), (RefKind::Tag, "tag")] {
        let out = tokio::process::Command::new("git")
            .arg(arg)
            .arg("--format=\"%(refname:short)\"")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .current_dir(clone_dir)
            .output()
            .await?;
        if !out.status.success() {
            anyhow::bail!("git branch failed");
        }

        let mut buf_reader = tokio::io::BufReader::new(out.stdout.as_slice());
        let mut line = String::new();
        while buf_reader.read_line(&mut line).await? != 0 {
            log::trace!("{:?}: {}", clone_dir, line);
            branches.push((kind, line.trim().trim_matches('\"').to_string()));
            line.clear();
        }
    }
    Ok(branches)
}
