pub mod coverage;
pub mod finding;
pub mod report;
pub mod witness;

// Public API re-exports. Callers may not yet use these paths internally,
// but they form the stable surface for the results module.
#[allow(unused_imports)]
pub use coverage::{CoverageReport, CoverageTracker};
#[allow(unused_imports)]
pub use finding::{Confidence, SeFinding, SeVulnKind};
#[allow(unused_imports)]
pub use witness::Witness;
