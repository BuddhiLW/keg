fail if any markdown file does not conform to OKF

The {{aka}} command exits non-zero, listing each file and its problem, when a markdown file in the keg does not conform to OKF v0.2: a concept without front matter, with front matter that is not YAML, or without a `type`; an `index.md` with front matter other than `okf_version` at the root; a `log.md` heading that is not a `YYYY-MM-DD` date. Sealed nodes are named as such: they are encrypted and cannot carry front matter.
