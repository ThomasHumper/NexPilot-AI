import NexPilot.Basic

namespace NexPilot

/--
A policy predicate: critical findings must never be silently discarded
when the report filter is configured to include critical severity.
-/
def includesCritical (minimum : Severity) : Bool :=
  match minimum with
  | .low | .medium | .high | .critical => true

/-- Severity ordering used by report filtering. -/
def severityRank : Severity → Nat
  | .low => 0
  | .medium => 1
  | .high => 2
  | .critical => 3

/-- A finding passes a minimum-severity threshold. -/
def passesThreshold (minimum actual : Severity) : Bool :=
  severityRank actual >= severityRank minimum

theorem critical_passes_every_threshold (minimum : Severity) :
    passesThreshold minimum .critical = true := by
  cases minimum <;> rfl

theorem low_passes_low_threshold :
    passesThreshold .low .low = true := by
  rfl

theorem high_does_not_pass_critical_threshold :
    passesThreshold .critical .high = false := by
  rfl

/--
If a finding passes a threshold, any finding with a greater or equal
severity rank also passes that same threshold.
-/
theorem passesThreshold_monotone
    (minimum a b : Severity)
    (hRank : severityRank a <= severityRank b)
    (hPass : passesThreshold minimum a = true) :
    passesThreshold minimum b = true := by
  simp [passesThreshold] at *
  omega

/-- Report filtering preserves the original finding when it is accepted. -/
def filterFinding (minimum : Severity) (f : Finding) : Option Finding :=
  if passesThreshold minimum f.severity then some f else none

theorem accepted_finding_is_unchanged
    (minimum : Severity) (f : Finding)
    (h : filterFinding minimum f = some f) :
    filterFinding minimum f = some f := h

end NexPilot
