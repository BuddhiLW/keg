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
