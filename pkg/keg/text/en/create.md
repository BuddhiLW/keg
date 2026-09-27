create and edit content node

The {{aka}} command creates a new content node directory and `README.md` file and opens it for editing (see {{cmd "edit"}} command). The new node is then added to the index (`dex`) and the keg changes are published.

If the file is empty, no new node is created.

If the `sample` parameter is passed then an initial node `README.md` file will contain a sample rather than an empty file which can be modified and contains reminders about how to create KEGML content.

If the `sealed` parameter is passed the node is written sealed from the start (see {{cmd "seal"}}): the editor opens a private copy outside the keg and only the encrypted result is stored. Any further arguments become the node's public hint (its title in the index).
