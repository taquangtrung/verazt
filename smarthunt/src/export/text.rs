//! Text output formatter.

use crate::export::formatter::OutputFormatter;
use crate::report::ExportReport;

/// Plain text output formatter.
#[derive(Debug, Default)]
pub struct TextFormatter;

impl TextFormatter {
    pub fn new() -> Self {
        Self
    }
}

impl OutputFormatter for TextFormatter {
    fn format(&self, report: &ExportReport) -> String {
        let mut output = String::new();

        output.push_str(&format!(
            "SmartHunt Analysis Report\n\
             =========================\n\n\
             Files analyzed: {}\n\
             Duration: {:.2}s\n\n",
            report.files_analyzed.len(),
            report.duration.as_secs_f64()
        ));

        output.push_str(&format!(
            "Summary:\n\
             - Critical: {}\n\
             - High: {}\n\
             - Medium: {}\n\
             - Low: {}\n\
             - Info: {}\n\
             - Total: {}\n\n",
            report.stats.bugs_by_severity.critical,
            report.stats.bugs_by_severity.high,
            report.stats.bugs_by_severity.medium,
            report.stats.bugs_by_severity.low,
            report.stats.bugs_by_severity.info,
            report.total_bugs(),
        ));

        if report.bugs.is_empty() {
            output.push_str("✅ No issues found!\n");
        } else {
            output.push_str("Findings:\n");
            output.push_str("---------\n\n");

            for (i, bug) in report.bugs.iter().enumerate() {
                output.push_str(&format!("{}. [{}] {}\n", i + 1, bug.risk_level, bug.name));

                output.push_str(&format!(
                    "   Location: {}:{}\n",
                    bug.loc.start_line, bug.loc.start_col
                ));

                if let Some(desc) = &bug.description {
                    output.push_str(&format!("   {}\n", desc));
                }

                output.push('\n');
            }
        }

        output
    }

    fn extension(&self) -> &'static str {
        "txt"
    }

    fn content_type(&self) -> &'static str {
        "text/plain"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_text_formatter() {
        let report = ExportReport::new(vec![], vec![], Duration::from_secs(1));
        let formatter = TextFormatter::new();
        let output = formatter.format(&report);
        assert!(output.contains("SmartHunt Analysis Report"));
        assert!(output.contains("No issues found"));
    }
}
