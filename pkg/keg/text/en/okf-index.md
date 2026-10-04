write the OKF index.md and log.md from the dex

The {{aka}} command writes `index.md` (every node by id, with title and description, under `okf_version: "0.2"`) and `log.md` (the dex changes grouped by day, newest first) at the root of the keg. Writing them opts the keg in to OKF upkeep: from then on every change to the dex rewrites both files.
