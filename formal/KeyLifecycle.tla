---------------------------- MODULE KeyLifecycle ----------------------------
EXTENDS Naturals, Sequences
CONSTANT MaxEpoch
VARIABLES epoch, active, revoked
Init == /\ epoch = 1 /\ active = {1} /\ revoked = {}
Rotate == /\ epoch < MaxEpoch /\ epoch' = epoch + 1 /\ active' = {epoch + 1} /\ revoked' = revoked
Revoke == /\ active # {} /\ revoked' = revoked \cup active /\ active' = {} /\ UNCHANGED epoch
Next == Rotate \/ Revoke
NoRevokedActive == active \cap revoked = {}
EpochMonotonic == epoch >= 1
Spec == Init /\ [][Next]_<<epoch,active,revoked>>
=============================================================================
