fail if a node that must be sealed is stored in the clear

The {{aka}} command exits non-zero, naming the nodes, when a node carries a tag listed under `seal.topics` or `seal.topic-recipients` but is not sealed. The same check runs before every publish. It is suitable as a git pre-commit hook: `keg seal check`.
