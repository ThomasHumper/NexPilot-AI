namespace NexPilot

/-- Severity levels emitted by NexPilot's static-analysis rules. -/
inductive Severity where
  | low
  | medium
  | high
  | critical
  deriving DecidableEq, Repr

/-- A finding is a reportable observation, not necessarily a confirmed vulnerability. -/
structure Finding where
  ruleId : String
  severity : Severity
  line : Nat
  message : String
  deriving Repr

/-- A minimal representation of a rule result. -/
structure RuleResult where
  triggered : Bool
  finding : Finding
  deriving Repr

end NexPilot
