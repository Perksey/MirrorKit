#[derive(clap::Parser)]
pub enum Commands {
    /// Runs the bundle creator server (sender or tx server) intended to run on the non-airgapped network.
    TxServer {
        /// A JSON file containing repos to mirror. Recommend using the add/remove commands to create/update this file.
        list: std::path::PathBuf,

        /// Directory to export bundles and manifests into.
        export: std::path::PathBuf,

        /// Work directory - used to store bare repos.
        work: std::path::PathBuf,
    },

    /// Runs the bundle importer server (receiver or rx server) intended to run on the airgapped network.
    RxServer {
        /// A JSON file containing repos to mirror. Recommend using the add/remove commands to create/update this file.
        list: std::path::PathBuf,

        /// Directory to import bundles and manifests from.
        import: std::path::PathBuf,

        /// Work directory - used to store bare repos.
        work: std::path::PathBuf,
    },

    /// Adds a repo to the repo list.
    Add {
        /// A JSON file containing repos to mirror. If this doesn't exist, this command will create it.
        list: std::path::PathBuf,

        /// A friendly name for the repo.
        name: String,

        /// The URL of the repo to add on the non-airgapped side.
        source: String,

        /// The URL of the repo to add on the airgapped side.
        destination: String,
    },

    /// Removes a repo from the repo list.
    Remove {
        /// A JSON file containing repos to mirror.
        list: std::path::PathBuf,

        /// The repo names to remove.
        names: Vec<String>,
    },

    /// Instructs the mirror server to send a bundle. Useful if the remote misses a bundle.
    Tx {
        /// A JSON file containing repos to mirror.
        list: std::path::PathBuf,

        /// The name of the repo to send.
        name: String,

        /// The branch names to include in the delta bundle. If no branch names are provided, a full bundle is sent to
        /// the remote regardless of the full option.
        branches: Vec<String>,

        /// Whether to send the entire history of the given branches in the bundle.
        #[arg(long, short, action)]
        full: bool,
    },
}
