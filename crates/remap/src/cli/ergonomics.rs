use crate::diagnostic::Diagnostic;

pub(super) fn set_target(matches: &clap::ArgMatches) -> Result<String, Diagnostic> {
    let moved = matches.get_one::<String>("moved-to");
    let until = matches.get_one::<String>("until").map(String::as_str);
    if until.is_some() && moved.is_none() {
        return Err(Diagnostic::invalid_target(
            "--until requires --moved-to".to_owned(),
        ));
    }
    moved.map_or_else(
        || super::required_string(matches, super::TARGET),
        |name| {
            remap_core::MovedTarget::new(name, until)
                .map(|target| target.to_string())
                .map_err(|error| Diagnostic::invalid_target(error.to_string()))
        },
    )
}
