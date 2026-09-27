encrypt a node so it can live in git unreadable

The {{aka}} command encrypts a content node `README.md` in place with OpenPGP (`gpg`) so it can be committed and pushed, even to a public repo, without anyone but its recipients reading it. The node keeps its directory and its `README.md`; only the content changes to a sealed envelope:

    #hive/sealed 1
    hint: optional public title
    -----BEGIN PGP MESSAGE-----
    ...

The envelope is byte-identical to the one hive memory uses, so a sealed node can be ingested into hive without ever being opened. Anything after the node identifier is the *hint*: it becomes the node's title in the index (`dex`), so it must not carry the secret. Without a hint the title is `🔒 sealed`.

A node can be sealed to several keys at once (multi-key). Recipients come from the `seal:` section of the `keg` file:

    seal:
      recipients:            # every sealed node, unless a tag below maps it
        - 0123...ABCD        # full fingerprints only
        - 4567...EF01
      topic-recipients:      # a tag is its own compartment: INSTEAD of recipients
        diary:
          - 0123...ABCD
      topics: [private]      # nodes with these tags may never be published in the clear
      show-recipients: false # default: key ids are hidden in the ciphertext
      gpg:
        bin: gpg
        homedir: ""

Environment overrides: `KEG_SEAL_RECIPIENTS` (comma list), `KEG_SEAL_TOPIC_RECIPIENTS` (`tag=FPR,...`), `KEG_SEALED_TOPICS`, `KEG_SEAL_GPG_BIN`, `KEG_SEAL_GPG_HOMEDIR`. With no recipients at all the node is sealed to your own default key.

Once sealed, {{cmd "edit"}} decrypts into a private, short-lived copy outside the keg and seals the result back; {{cmd "view"}} decrypts in memory. Plaintext is never written inside the keg. Publishing refuses to push when a node carrying a tag listed in `topics` or `topic-recipients` is stored in the clear (see {{cmd "check"}}).

A note can also ask to be sealed itself, so a plain note can become secret later. Add a directive to its front matter:

    ---
    seal: true                # or a list: seal: [0123...ABCD, 4567...EF01]
    seal-hint: public title   # optional
    ---

Before anything is published (and on {{cmd "apply"}}), every plaintext node carrying `seal: true` or a fingerprint list is sealed in place and its index title replaced by the hint. `true` follows the keg policy (default recipients or the tag's compartment); a fingerprint list names the only recipients and overrides the policy. The directive travels inside the ciphertext, so later edits keep the same recipients and hint. A directive that cannot be understood (a short key id, an empty list, broken YAML) stops the publish rather than guessing. {{cmd "check"}} also fails while any such note is still in the clear.
