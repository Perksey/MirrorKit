<h1 align="center">MirrorKit</h1>
<div align="center">

<!-- TODO badges -->

</div>

<div>

MirrorKit provides a GitLab webhook for automatically mirroring a Git repo to an airgapped network using `git bundle`. It is not uncommon for these types of networks to have one-way data diodes, and this has been built specifically for that. 

MirrorKit involves two components:
- **Webhook Server**: Listens for GitLab webhooks, and creates git bundles for the repository changes. For new repositories, the entire repo is included in the bundle. For commits thereafter, a minimal "delta" bundle is created.
- **Airgapped Server**: Listens for bundles in a specific directory, and pushes the commits contained in the bundle back up to the mirror destination (e.g. an airgapped Git server).

How it works:
```bash
git branch -r --format="%(refname:short)"  # Get all branches
# Compare with stored in 
```


</div>

