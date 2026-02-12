//! Output formatter trait.

use crate::report::ExportReport;
use bugs::bug::Bug;

/// Trait for output formatters.
pub trait OutputFormatter {
    /// Format the analysis report.
    fn format(&self, report: &ExportReport) -> String;

    /// Get the file extension for this format.
    fn extension(&self) -> &'static str;

    /// Get the content type for this format.
    fn content_type(&self) -> &'static str;
}

/// Format a location for display.
pub fn format_location(bug: &Bug) -> String {
    format!("<unknown>:{}:{}", bug.loc.start_line, bug.loc.start_col,)
}
