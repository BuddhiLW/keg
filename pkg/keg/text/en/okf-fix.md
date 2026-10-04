add the OKF front matter keys each file lacks

The {{aka}} command lists, for every markdown file of the keg, the OKF keys it would add: `type`, `title`, `tags`, `generated` and `status`. Nothing is written unless `write` is passed. Keys already present are never changed and the body is never touched, so a second run adds nothing. Sealed nodes and front matter that is not valid YAML are skipped and named, not guessed at. Review the result with `git diff` before publishing.
