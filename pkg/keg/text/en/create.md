create and edit content node

The {{aka}} command creates a new content node directory and `README.md` file and opens it for editing (see {{cmd "edit"}} command). The new node is then added to the index (`dex`) and the keg changes are published.

If the file is empty, no new node is created.

If the `sample` parameter is passed then an initial node `README.md` file will contain a sample rather than an empty file which can be modified and contains reminders about how to create KEGML content.

If the `encrypt` parameter (or its older name `sealed`) is passed the node is written sealed from the start (see {{cmd "seal"}}): the editor opens a private copy outside the keg and only the encrypted result is stored. Words that are not options become the node's public hint (its title in the index). Without options the keg's `seal:` policy picks the recipients. These options change that for this node:

    --to FPR|FILE      encrypt to this full fingerprint, or to the one
                       written in FILE (repeatable)
    --key FILE         encrypt to the public key in FILE, without
                       importing it into any keyring (repeatable)
    --homedir DIR      use the gpg keyring in DIR for this command
    --show-recipients  write recipient key ids into the ciphertext

`--to` and `--key` name the only recipients. The editor opens with a `seal: [FPR, ...]` front matter directive naming them. That directive is stored inside the ciphertext, so later edits and rekeys keep the same recipients; delete it to fall back to the policy. An edit that leaves only the directive creates nothing. Name your own key as well if you want to read the node yourself.

A `--key` file must hold one public key. A secret key file is refused: export its public half with `gpg --export`, or point `--homedir` at the keyring that holds it. For later edits to find a key that is not in your keyring, list its file under `seal: key-files:` in the `keg` file (or `KEG_SEAL_KEY_FILES`). To decrypt, gpg needs the secret key: set `seal: gpg: homedir:` or `KEG_SEAL_GPG_HOMEDIR` to the keyring that holds it.

    keg create encrypt --key ~/mnt/1/vault-private.pub.gpg a public hint
    keg create encrypt --homedir ~/mnt/1/gnupg-vault --to ~/mnt/1/vault-private.fpr
    KEG_SEAL_GPG_HOMEDIR=~/mnt/1/gnupg-vault keg view last
