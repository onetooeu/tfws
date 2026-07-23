# Federated transparency

Events are canonical, signed, hash-linked and inserted into Merkle trees. Logs publish signed
checkpoints. Clients require policy-defined witness quorum and gossip checkpoints to detect
split views. During partitions, clients retain the last trusted checkpoint and report freshness
honestly.
