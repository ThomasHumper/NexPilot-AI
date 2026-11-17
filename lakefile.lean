import Lake
open Lake DSL

package «nexpilot-lean» where
  version := v!"0.1.0"
  defaultTargets := #[`NexPilot]

lean_lib NexPilot where
  roots := #[`NexPilot]
