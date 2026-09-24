# Silent Payments test vectors

Vectors published by the BIPs themselves, so a mistake shared with any one
implementation still shows up.

## `bip374_generate_proof_vectors.csv`, `bip374_verify_proof_vectors.csv`

`bip-0374/test_vectors_generate_proof.csv` and
`bip-0374/test_vectors_verify_proof.csv` from bitcoin/bips, with only their line
endings changed from CRLF to LF: 11 proof
generation cases (8 successes and 3 failures) and 17 verification cases (8 that
hold and 9 that must not).

Each row carries its own generator point, which is why
`silent_payments.dleq_prove` and `dleq_verify` take one; every device path uses
secp256k1's own G.

## `bip352_sending_vectors.json`

The **sending** half of `bip-0352/send_and_receive_test_vectors.json`, each case
kept verbatim under its own comment. The receiving half is what
`BIP352_RECEIVING` in `tests/test_silent_payments.py` already covers, and dropping
it here keeps a 412 KB file down to 73 KB.

A case's `expected.outputs` is a list of complete output sets, not one set: BIP-352
lets a sender order the recipients sharing a scan key as it likes, so the computed
set must equal exactly one of them. BIP-375 is what narrows the choice.
