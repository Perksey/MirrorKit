use clap::Parser;
use hex::ToHex;
use notify::Watcher;
use sha1::Digest;

mod cli;
pub mod schema;

#[rocket::post("/gitlab", data = "<data>")]
async fn webhook(
    data: rocket::serde::json::Json<gitlab::webhooks::WebHook>,
    list: &rocket::State<std::path::PathBuf>,
) -> Result<(), rocket::response::status::Custom<()>> {
    webhook_inner(data, list).await.map_err(|err| {
        log::error!(
            "Error in handling webhook: {}",
            anyhow::format_err!("{}", err)
        );
        rocket::response::status::Custom(rocket::http::Status::InternalServerError, ())
    })
}

async fn webhook_inner(
    data: rocket::serde::json::Json<gitlab::webhooks::WebHook>,
    list: &rocket::State<std::path::PathBuf>,
) -> anyhow::Result<()> {
    if let gitlab::webhooks::WebHook::Push(push_data) = data.0 {
        let repos: std::collections::HashMap<String, schema::Repo> =
            serde_json::from_slice(&tokio::fs::read(&**list).await?)?;
        if let Some((name, _)) = repos.into_iter().find(|(x, y)| {
            y.src.trim_matches('/') == push_data.project.git_http_url.trim_matches('/')
                || y.src.trim_matches('/') == push_data.project.git_ssh_url.trim_matches('/')
                || y.src.trim_matches('/') == push_data.project.web_url.trim_matches('/')
        }) {
            let branch = push_data
                .ref_
                .strip_prefix("refs/heads/")
                .unwrap_or_else(|| {
                    push_data
                        .ref_
                        .strip_prefix("refs/tags/")
                        .unwrap_or(&push_data.ref_)
                });
            tx_repo(list, name, vec![branch.to_string()], false).await?;
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = cli::Commands::parse();
    simple_logger::init_with_env()?;
    match args {
        cli::Commands::TxServer {
            mut list,
            export,
            work,
        } => {
            if !list.is_file() {
                println!("--list path must exist and be a path to a JSON file.");
                println!("To create this file, use the add/remove commands.");
                anyhow::bail!("File not found: --list");
            }

            list = list.canonicalize()?;

            if !export.is_dir() {
                println!("--export path must exist and be a path to a directory.");
                anyhow::bail!("Dir not found: --export");
            }

            if !work.is_dir() {
                println!("--work path must exist and be a path to a directory.");
                anyhow::bail!("Dir not found: --work");
            }

            log::info!("Attempting to read repos list...");
            let mut repos: std::collections::HashMap<String, schema::Repo> =
                serde_json::from_slice(&tokio::fs::read(&list).await?)?;

            log::info!("Performing initial processing...");
            if process_repos(&mut repos, &export, &work).await? {
                tokio::fs::write(&list, serde_json::to_vec_pretty(&repos)?).await?;
            }

            let (_watcher, rx) = start_file_watcher(list.clone());

            let list_cloned = list.clone();
            tokio::spawn(async move { tx_server(&list_cloned, &export, &work, rx).await });
            log::info!("Ready to start.");

            let _ = rocket::build()
                .manage(list)
                .mount("/", rocket::routes![webhook])
                .launch()
                .await?;
        }
        cli::Commands::RxServer { list, import, work } => {
            if !import.is_dir() {
                println!("--export path must exist and be a path to a directory.");
                anyhow::bail!("Dir not found: --export");
            }

            if !work.is_dir() {
                println!("--work path must exist and be a path to a directory.");
                anyhow::bail!("Dir not found: --work");
            }

            let mut repos: std::collections::HashMap<String, schema::Repo> = if list.exists() {
                log::info!("Attempting to read repos list...");
                serde_json::from_slice(&tokio::fs::read(&list).await?)?
            } else {
                std::collections::HashMap::new()
            };

            log::info!("Performing initial processing...");
            if process_bundles(&mut repos, &import, &work).await? {
                tokio::fs::write(&list, serde_json::to_vec_pretty(&repos)?).await?;
            }

            let (_watcher, rx) = start_file_watcher(import.canonicalize()?);

            log::info!("Ready to go.");
            rx_server(&list, &import, &work, rx).await;
        }
        cli::Commands::Add {
            list,
            name,
            source,
            destination,
        } => {
            let mut repos: std::collections::HashMap<String, schema::Repo> = if list.exists() {
                serde_json::from_slice(&tokio::fs::read(&list).await?)?
            } else {
                std::collections::HashMap::new()
            };
            repos.insert(
                name,
                schema::Repo {
                    src: source,
                    dst: destination,
                    status: schema::TxStatus::FullTxNeeded(std::default::Default::default()),
                    refs: std::collections::HashMap::new(),
                    shas: std::collections::HashSet::new(),
                },
            );
            tokio::fs::write(&list, serde_json::to_vec_pretty(&repos)?).await?;
        }
        cli::Commands::Remove { list, names } => {
            let mut repos: std::collections::HashMap<String, schema::Repo> = if list.exists() {
                serde_json::from_slice(&tokio::fs::read(&list).await?)?
            } else {
                std::collections::HashMap::new()
            };
            repos.retain(|k, _| !names.contains(k));
            tokio::fs::write(&list, serde_json::to_vec_pretty(&repos)?).await?;
        }
        cli::Commands::Tx {
            list,
            name,
            branches,
            full,
        } => {
            tx_repo(&list, name, branches, full).await?;
        }
    }
    Ok(())
}

async fn tx_repo(
    list: &std::path::PathBuf,
    name: String,
    branches: Vec<String>,
    full: bool,
) -> anyhow::Result<()> {
    let mut repos: std::collections::HashMap<String, schema::Repo> =
        serde_json::from_slice(&tokio::fs::read(list).await?)?;
    for (rname, repo) in &mut repos {
        if rname == &name {
            repo.status = match std::mem::take(&mut repo.status) {
                schema::TxStatus::UpToDate => {
                    if full {
                        schema::TxStatus::FullTxNeeded(branches.into_iter().collect())
                    } else {
                        schema::TxStatus::DeltaTxNeeded(branches.into_iter().collect())
                    }
                }
                schema::TxStatus::DeltaTxNeeded(mut already_branches) => {
                    already_branches.extend(branches);
                    if full {
                        schema::TxStatus::FullTxNeeded(already_branches)
                    } else {
                        schema::TxStatus::DeltaTxNeeded(already_branches)
                    }
                }
                schema::TxStatus::FullTxNeeded(mut already_branches) => {
                    already_branches.extend(branches);
                    schema::TxStatus::FullTxNeeded(already_branches)
                }
            };

            break;
        }
    }
    tokio::fs::write(&list, serde_json::to_vec_pretty(&repos)?).await?;
    Ok(())
}

fn start_file_watcher(
    path: std::path::PathBuf,
) -> (
    notify::RecommendedWatcher,
    tokio::sync::mpsc::Receiver<Vec<std::path::PathBuf>>,
) {
    let (tx, rx) = tokio::sync::mpsc::channel(10);
    let mut watcher =
        notify::recommended_watcher(move |event_opt: Result<notify::Event, notify::Error>| {
            log::trace!("Watcher event: {:?}", event_opt);
            match event_opt {
                Ok(event) => {
                    if event.kind.is_modify() || event.kind.is_create() {
                        match tx.blocking_send(event.paths) {
                            Ok(_) => log::debug!("Sent to listener."),
                            Err(err) => {
                                log::error!(
                                    "Failed to notify server of file system event: {:?}",
                                    err
                                )
                            }
                        }
                    }
                }
                Err(err) => log::error!("File system watcher error: {:?}", err),
            }
        })
        .expect("failed to create watcher");
    log::debug!("starting file watcher on \"{:?}\"", path);
    watcher
        .watch(&path, notify::RecursiveMode::Recursive)
        .expect("failed to wtach");
    (watcher, rx)
}

async fn process_repos(
    repos: &mut std::collections::HashMap<String, schema::Repo>,
    export: &std::path::PathBuf,
    work: &std::path::PathBuf,
) -> anyhow::Result<bool> {
    let mut any_tx = false;
    for (name, repo) in repos {
        match &repo.status {
            schema::TxStatus::UpToDate => log::debug!("\"{}\" up to date.", name),
            schema::TxStatus::FullTxNeeded(req_branches)
            | schema::TxStatus::DeltaTxNeeded(req_branches) => {
                log::info!("Processing \"{}\"...", name);

                let clone_path = work.join(name);
                clone_repo(&clone_path, repo, true).await?;

                let all_refs = schema::get_all_refs(&clone_path).await?;
                log::trace!("All refs: {:?}", all_refs);
                let mut branches = Vec::new();
                for (kind, rname) in &all_refs {
                    if req_branches.is_empty()
                        || kind == &schema::RefKind::Branch && req_branches.contains(rname)
                        || req_branches.contains(rname)
                    {
                        log::trace!("{}", rname);
                        branches.push(rname.clone());
                    }
                }

                let mut cmd = tokio::process::Command::new("git");
                cmd.arg("bundle")
                    .arg("create")
                    .arg(work.canonicalize()?.join(".bundle"))
                    .stderr(std::process::Stdio::inherit())
                    .stdout(std::process::Stdio::inherit())
                    .current_dir(&clone_path);

                let out = if let schema::TxStatus::FullTxNeeded(_) = &repo.status {
                    cmd.args(&branches);
                    log::debug!("Executing full {:?}", cmd);
                    cmd.output().await?
                } else {
                    let mut delta_strs = Vec::new();
                    for branch in &branches {
                        delta_strs.push(repo.get_delta(&clone_path, branch).await?);
                    }
                    cmd.args(delta_strs);
                    log::debug!("Executing delta {:?}", cmd);
                    cmd.output().await?
                };

                if !out.status.success() {
                    log::warn!(
                        "Failed to create bundle, assuming this is because there is no delta."
                    );
                    repo.status = schema::TxStatus::UpToDate;
                    continue;
                }

                let bundle = repo.get_bundle(&clone_path, &branches, &all_refs).await?;
                repo.prune(&clone_path).await?;
                repo.status = schema::TxStatus::UpToDate;

                any_tx = true;
                tokio::fs::rename(work.join(".bundle"), export.join(&bundle.filename)).await?;
                tokio::fs::write(
                    export.join(format!("{}.gitmanifest.json", bundle.uuid)),
                    serde_json::to_vec_pretty(&bundle)?,
                )
                .await?;
            }
        }
    }
    Ok(any_tx)
}

pub async fn process_bundles(
    repos: &mut std::collections::HashMap<String, schema::Repo>,
    import: &std::path::PathBuf,
    work: &std::path::PathBuf,
) -> anyhow::Result<bool> {
    log::info!("Processing bundles...");
    let mut any_rx = false;
    for bundle_opt in std::fs::read_dir(import)? {
        if let Ok(bundle) = bundle_opt {
            log::debug!("Checking \"{:?}\"", bundle.file_name());
            if !bundle
                .file_name()
                .to_string_lossy()
                .ends_with(".gitmanifest.json")
            {
                continue;
            }
            let path = bundle.path();
            if !path.is_file() {
                continue;
            }
            if repos
                .iter()
                .any(|(_, repo)| repo.shas.contains(&*path.as_os_str().to_string_lossy()))
            {
                log::debug!(
                    "File name \"{:?}\" has been processed before, not looking further.",
                    path
                );
                continue;
            }
            log::debug!("Reading {:?}...", path);
            let bundle: schema::Bundle = serde_json::from_slice(&tokio::fs::read(&path).await?)?;
            let bundle_file = path
                .parent()
                .ok_or_else(|| anyhow::anyhow!("gitmanifest should have parent path"))?
                .join(&bundle.filename);
            if !bundle_file.exists() {
                log::warn!("Bundle file doesn't exist, skipping this bundle.");
                continue;
            }
            // Anti-replay checks
            if repos
                .iter()
                .any(|(_, repo)| repo.shas.contains(&bundle.uuid.to_string()))
            {
                log::debug!(
                    "UUID of \"{:?}\" has been processed before, not looking further.",
                    path
                );
                continue;
            }
            // Convert back to a string before getting a sha so we can eliminate any differences in pretty printing etc.
            let sha_input = serde_json::to_vec(&bundle)?;
            let mut hasher = sha1::Sha1::new();
            hasher.update(&sha_input);
            let digest = hasher.finalize();
            if repos
                .iter()
                .any(|(_, repo)| repo.shas.contains(&digest.encode_hex::<String>()))
            {
                log::debug!(
                    "SHA of \"{:?}\" has been processed before, not looking further.",
                    path
                );
                continue;
            }
            // Bundle is good, let's process it.
            // Convert the destination repo URL to something we can store on a file system (as we don't know the
            // "friendly name" on the rx side)
            let mut hasher = sha1::Sha1::new();
            hasher.update(&bundle.dst);
            let key = hex::encode(hasher.finalize());
            // Get or create the repo in our "database"
            let repo = repos.entry(key.clone()).or_insert(schema::Repo {
                src: bundle.src.clone(),
                dst: bundle.dst.clone(),
                status: schema::TxStatus::UpToDate, // not used by rx
                refs: std::collections::HashMap::new(),
                shas: std::collections::HashSet::new(),
            });
            // Clone the destination repo
            let clone_path = work.join(key);
            clone_repo(&clone_path, repo, false).await?;
            // Unbundle the... bundle
            process_bundle(&clone_path, &bundle_file, &bundle).await?;
            repo.shas.insert(digest.encode_hex::<String>());
            repo.shas.insert(bundle.uuid.to_string());
            repo.shas
                .insert(path.as_os_str().to_string_lossy().to_string());
            any_rx = true;
        } else {
            log::error!("Failed to read bundle: {:?}", bundle_opt);
        }
    }
    Ok(any_rx)
}

async fn process_bundle(
    clone_path: &std::path::PathBuf,
    bundle_path: &std::path::PathBuf,
    bundle: &schema::Bundle,
) -> anyhow::Result<()> {
    // Unbundle
    let mut cmd = tokio::process::Command::new("git");
    cmd.arg("bundle")
        .arg("unbundle")
        .arg(bundle_path.canonicalize()?)
        .current_dir(clone_path);
    log::debug!("Executing command: {:?}", cmd);
    anyhow::ensure!(cmd.output().await?.status.success());

    for (name, kind) in &bundle.removed {
        let ref_name = match kind {
            schema::RefKind::Branch => format!(":refs/tags/{}", name),
            schema::RefKind::Tag => format!(":refs/heads/{}", name),
        };

        let out = tokio::process::Command::new("git")
            .arg("push")
            .arg("-d")
            .arg("origin")
            .arg(ref_name)
            .current_dir(clone_path)
            .output()
            .await?;
        anyhow::ensure!(out.status.success());
    }

    for (name, ref_data) in bundle.added.iter().chain(bundle.modified.iter()) {
        let push_ref = match ref_data.kind {
            schema::RefKind::Branch => format!("{}:refs/heads/{}", ref_data.sha, name),
            schema::RefKind::Tag => format!("{}:refs/tags/{}", ref_data.sha, name),
        };

        let out = tokio::process::Command::new("git")
            .arg("push")
            .arg("-f")
            .arg("origin")
            .arg(push_ref)
            .current_dir(clone_path)
            .output()
            .await?;
        anyhow::ensure!(out.status.success());
    }
    Ok(())
}

async fn tx_server(
    list: &std::path::PathBuf,
    export: &std::path::PathBuf,
    work: &std::path::PathBuf,
    mut rx: tokio::sync::mpsc::Receiver<Vec<std::path::PathBuf>>,
) {
    let mut changed = true;
    let mut attempts = 0;
    loop {
        if changed {
            match tx_process_once(list, export, work).await {
                Ok(()) => {
                    changed = false;
                    attempts = 0
                }
                Err(err) => {
                    if attempts >= 10 && work.exists() {
                        log::warn!("Deleting cache in an attempt to fix the issue...");
                        std::fs::remove_dir_all(work).expect("failed to delete cache");
                    } else if attempts > 15 {
                        panic!(
                            "Failed to process repos: {}",
                            anyhow::format_err!("{:?}", err)
                        );
                    }

                    log::error!(
                        "Failed to process changed config, will retry in 1 second: {:?}",
                        err
                    );

                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    attempts += 1;
                }
            }
        } else {
            changed = rx.recv().await.is_some();
            if !changed {
                // hung up
                panic!("file watcher hung up");
            }
        }
    }
}

async fn rx_server(
    list: &std::path::PathBuf,
    import: &std::path::PathBuf,
    work: &std::path::PathBuf,
    mut rx: tokio::sync::mpsc::Receiver<Vec<std::path::PathBuf>>,
) {
    let mut changed = true;
    let mut attempts = 0;
    loop {
        if changed {
            match rx_process_once(list, import, work).await {
                Ok(()) => {
                    changed = false;
                    attempts = 0
                }
                Err(err) => {
                    if attempts >= 10 && work.exists() {
                        log::warn!("Deleting cache in an attempt to fix the issue...");
                        std::fs::remove_dir_all(work).expect("failed to delete cache");
                    } else if attempts > 15 {
                        panic!(
                            "Failed to process bundles: {}",
                            anyhow::format_err!("{:?}", err)
                        );
                    }

                    log::error!(
                        "Failed to process bundle, will retry in 1 second: {:?}",
                        err
                    );

                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    attempts += 1;
                }
            }
        } else if let Some(path) = rx.recv().await {
            changed = path.iter().any(|x| {
                x.to_str()
                    .map_or(false, |x| x.ends_with(".gitmanifest.json"))
            });
        } else {
            // hung up
            panic!("file watcher hung up");
        }
    }
}

async fn tx_process_once(
    list: &std::path::PathBuf,
    export: &std::path::PathBuf,
    work: &std::path::PathBuf,
) -> anyhow::Result<()> {
    let mut repos = serde_json::from_slice(&tokio::fs::read(list).await?)?;
    if process_repos(&mut repos, export, work).await? {
        tokio::fs::write(list, serde_json::to_vec_pretty(&repos)?).await?;
    }
    Ok(())
}

async fn rx_process_once(
    list: &std::path::PathBuf,
    import: &std::path::PathBuf,
    work: &std::path::PathBuf,
) -> anyhow::Result<()> {
    let mut repos: std::collections::HashMap<String, schema::Repo> = if list.exists() {
        log::info!("Attempting to read repos list...");
        serde_json::from_slice(&tokio::fs::read(&list).await?)?
    } else {
        std::collections::HashMap::new()
    };
    if process_bundles(&mut repos, import, work).await? {
        tokio::fs::write(list, serde_json::to_vec_pretty(&repos)?).await?;
    }
    Ok(())
}

async fn clone_repo(
    clone_path: &std::path::PathBuf,
    repo: &schema::Repo,
    src: bool,
) -> anyhow::Result<()> {
    if clone_path.is_dir() && !repo.shas.is_empty() {
        let out = tokio::process::Command::new("git")
            .arg("fetch")
            .arg("--tags")
            .arg("origin")
            .arg("+refs/remotes/origin/*:reads/heads/*")
            .current_dir(clone_path)
            .output()
            .await?;
        if !out.status.success() {
            anyhow::bail!("fetch failed!");
        }
    } else {
        if clone_path.is_file() {
            tokio::fs::remove_file(&clone_path).await?;
        } else if clone_path.is_dir() {
            // If we have no shas in our JSON repo, that means the folder might reflect an old (now deleted)
            // repo with the same name
            tokio::fs::remove_dir_all(&clone_path).await?;
        }
        let out = tokio::process::Command::new("git")
            .arg("clone")
            .arg("--bare")
            .arg(if src { &repo.src } else { &repo.dst })
            .arg(clone_path)
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .output()
            .await?;
        if !out.status.success() {
            anyhow::bail!("clone failed!");
        }
    }
    Ok(())
}
