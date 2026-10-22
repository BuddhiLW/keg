create a node encrypted from the start

The {{aka}} command creates a new content node that is sealed from the start (see {{cmd "seal"}}): the editor opens a private copy outside the keg and only the encrypted result is stored. If the copy is left empty the node is not created.

Without parameters, and at a terminal, {{aka}} asks for the public hint and the recipients; a blank answer keeps the default. Otherwise these parameters come first, and the first other word starts the public hint (the node's title in the index, so never the secret):

    to FPR|FILE       encrypt to this full fingerprint, or to the one
                      written in FILE (repeatable)
    key FILE          encrypt to the public key in FILE, without
                      importing it into any keyring (repeatable)
    homedir DIR       use only the gpg keyring in DIR for this command
    show-recipients   write recipient key ids into the ciphertext

With no recipients the keg's `seal:` policy picks them, and with no policy the node is sealed to the own key of your first keyring (set once with `keg set keyrings DIR[,DIR...]`, see {{cmd "seal"}}). `to` and `key` name the only recipients instead: the editor opens with a `seal: [FPR, ...]` front matter directive naming them. The directive is stored inside the ciphertext, so later edits and rekeys keep the same recipients; delete it to fall back to the policy. An edit that leaves only the directive creates nothing. Name your own key too if you want to read the node yourself.

A `key` file must hold one public key. A secret key file is refused: export its public half with `gpg --export`, or point `homedir` at the keyring that holds it. For later edits to find a key that is not in your keyring, list its file under `seal: key-files:` in the `keg` file (or `KEG_SEAL_KEY_FILES`). To decrypt, gpg needs the secret key: list the keyring that holds it in `keg set keyrings`, and {{cmd "edit"}} and {{cmd "view"}} find it.

    keg set keyrings ~/mnt/1/gnupg-vault,~/.gnupg
    keg create encrypt
    keg create encrypt key ~/mnt/1/vault-private.pub.gpg a public hint
    keg view last

`sealed` is an older name for this command.
