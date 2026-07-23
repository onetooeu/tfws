--------------------------- MODULE AgentAuthority ---------------------------
EXTENDS FiniteSets
CONSTANT Actions, Forbidden
VARIABLE executed, safeMode
Init == /\ executed = {} /\ safeMode = FALSE
Execute(a) == /\ a \in Actions \ Forbidden /\ ~safeMode /\ executed' = executed \cup {a} /\ UNCHANGED safeMode
Stop == /\ safeMode' = TRUE /\ UNCHANGED executed
Next == Stop \/ \E a \in Actions: Execute(a)
ForbiddenNeverExecutes == executed \cap Forbidden = {}
Spec == Init /\ [][Next]_<<executed,safeMode>>
=============================================================================
