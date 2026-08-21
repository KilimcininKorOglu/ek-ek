# Old config examples

One directory per schema version, holding real documents written by that
schema. A migration test loads a document from here and checks that the steps
bring it forward correctly.

Every new schema adds a directory and at least one document. Without a real
old document, a migration step is only tested against what the current model
already produces, which is the one case that needs no migration.

`legacy-extra-field.json` carries a field the current model does not accept.
It exists to keep migration honest: steps run on the stored document, not on
the parsed model, and this document cannot be parsed by the current model at
all.
