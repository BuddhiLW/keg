make the keg an Open Knowledge Format (OKF) bundle

The {{aka}} command makes a keg readable as an Open Knowledge Format (OKF) v0.2 bundle (https://github.com/GoogleCloudPlatform/open-knowledge-format). OKF is a directory of markdown files with YAML front matter, which a keg already is. The gap is small: OKF needs a `type` key in the front matter of every markdown file, and it reads `tags`, `generated` and `status` from front matter too.

A keg becomes an OKF bundle in three steps:

    keg okf check        # list the files that do not conform
    keg okf fix write    # add the missing OKF keys
    keg okf index        # write index.md and log.md, and opt in

After {{cmd "index"}}, the keg keeps itself conformant: every create, edit, import or delete completes the front matter of the changed node and rewrites `index.md` and `log.md` from the dex. A keg without an `index.md` declaring `okf_version` is never changed.

Mapping from KEG to OKF:

* a node `N/README.md` is a concept with id `N/README` and `type: Note`
* the first `# heading` is the `title` when the front matter has none
* `dex/tags` becomes `tags`
* `generated` is `{by: ACTOR, at: TIME}`: ACTOR is `human:LOGIN` or `KEG_OKF_ACTOR`, TIME is the `published` date or the last dex change
* `draft: true` becomes `status: draft`
* `dex/*.md` get `type: KEG Index`
* sealed nodes are never opened or changed
