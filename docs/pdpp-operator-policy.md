# PDPP operator policy: no AI training on held owner data

Applies to: every deployment of this Personal Server that runs the PDPP
Authorization Server (`packages/server/src/routes/pdpp-auth.ts`, mounted at
`/pdpp/v1`) or the PDPP Resource Server
(`packages/server/src/pdpp/records-bootstrap.ts`, mounted at `/v1`).

## Statement

The operator of this Personal Server does not use owner data that it holds in
the PDPP Authorization Server role or the PDPP Resource Server role for AI
training. The only exception is data the operator receives as a client under a
grant that carries the AI training processing permission
(`https://pdpp.dev/processing/ai_training`) issued to the operator as a client.

"AI training" has the meaning in PDPP Core v0.1.0 §6 "AI training": using data
to fit or select the learned parameters or stored examples of a machine-learning
model, including fine-tuning, distillation, reinforcement learning and model
selection by evaluation.

This build supports no processing permission
(`SUPPORTED_PROCESSING_PERMISSIONS` is empty in
`packages/core/src/pdpp/public-validation.ts`). No grant this server issues can
therefore carry the AI training permission, and the exception above cannot
arise.

## Data the policy covers

- Authorization Server role: grants, consent evidence, review digests,
  authorization codes, token and refresh-family digests, retained source
  declarations, revocation dispositions (`<storageRoot>/pdpp-auth.db`,
  `<storageRoot>/pdpp-declarations.db`), and pending consent sessions in
  memory.
- Resource Server role: stored records, record versions, blobs and change
  history that the Resource Server serves under grants and owner tokens.

## Spec references

- PDPP Core v0.1.0 §9 Authorization Server conformance, item 38: "Its operator
  does not use owner data held in the AS role for AI training, except under a
  training grant issued to it as a client."
- PDPP Core v0.1.0 §9 Resource Server conformance, item 29 (the same duty for
  the RS role).
- PDPP Core v0.1.0 §6 "AI training": "An operator of an AS or RS MUST NOT use
  owner data that it holds in that role for AI training, except under a
  training grant issued to it as a client."

## Scope and limits

This is a policy statement about operator conduct. Code cannot enforce it, and
this repository cannot verify it for a given deployment. A deployment that
changes this policy must not claim PDPP Core v0.1.0 AS item 38 or RS item 29.
