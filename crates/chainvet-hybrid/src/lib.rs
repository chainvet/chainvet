//! Chainvet hybrid engine: the coverage-guided control loop that runs static
//! analysis, an upfront symbolic pass (witness seeds), then fuzz epochs with
//! on-stall symbolic assists, and merges/dedups/tiers the combined findings.
pub mod hybrid;
