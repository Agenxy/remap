#[cfg(target_os = "linux")]
use std::ffi::CString;

#[cfg(target_os = "linux")]
use nix::unistd::{Gid, Uid, User, initgroups, setgid, setuid};
use remap_protocol::Diagnostic;

#[cfg(target_os = "linux")]
#[derive(Debug)]
pub(crate) struct ResolvedUser {
    name: CString,
    uid: Uid,
    gid: Gid,
}

#[cfg(target_os = "macos")]
#[derive(Debug)]
pub(crate) struct ResolvedUser;

#[cfg(target_os = "linux")]
pub(crate) fn resolve(user_name: &str) -> Result<ResolvedUser, Diagnostic> {
    if !Uid::effective().is_root() {
        return Err(privilege_error(
            "the privileged network bootstrap must start as root",
            "run the installed system service or use the documented sudo bootstrap",
        ));
    }
    validate_user_name(user_name)?;
    let user = User::from_name(user_name)
        .map_err(|_error| account_lookup_error())?
        .ok_or_else(account_lookup_error)?;
    if user.uid.is_root() {
        return Err(privilege_error(
            "Remap refuses to serve network traffic as root",
            "configure a real non-root runtime account",
        ));
    }
    let name = CString::new(user.name).map_err(|_error| account_lookup_error())?;
    Ok(ResolvedUser {
        name,
        uid: user.uid,
        gid: user.gid,
    })
}

#[cfg(target_os = "macos")]
pub(crate) fn resolve(_user_name: &str) -> Result<ResolvedUser, Diagnostic> {
    Err(privilege_error(
        "macOS network listeners must be provided by launchd socket activation",
        "repair or reinstall the native Remap launchd service",
    ))
}

#[cfg(target_os = "linux")]
pub(crate) fn discard(user: &ResolvedUser) -> Result<(), Diagnostic> {
    initgroups(&user.name, user.gid).map_err(|_error| transition_error())?;
    setgid(user.gid).map_err(|_error| transition_error())?;
    setuid(user.uid).map_err(|_error| transition_error())?;
    if Uid::effective() != user.uid || Uid::current() != user.uid || Uid::effective().is_root() {
        return Err(transition_error());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub(crate) fn discard(_user: &ResolvedUser) -> Result<(), Diagnostic> {
    Err(transition_error())
}

#[cfg(target_os = "linux")]
fn validate_user_name(user_name: &str) -> Result<(), Diagnostic> {
    if user_name.is_empty() || user_name.len() > 255 || user_name.chars().any(char::is_control) {
        return Err(privilege_error(
            "the declared runtime account name is invalid",
            "repair the root-owned Remap service configuration before retrying",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn account_lookup_error() -> Diagnostic {
    privilege_error(
        "the declared non-root runtime account could not be resolved",
        "repair the root-owned Remap service configuration before retrying",
    )
}

fn transition_error() -> Diagnostic {
    privilege_error(
        "Remap could not establish the declared unprivileged runtime identity",
        "the process has stopped; inspect the native service identity before retrying",
    )
}

fn privilege_error(message: &str, hint: &str) -> Diagnostic {
    Diagnostic::new(
        "E_PRIVILEGE_TRANSITION",
        message,
        Some(hint.to_owned()),
        false,
    )
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    use nix::unistd::Uid;

    #[cfg(target_os = "linux")]
    #[test]
    fn ordinary_users_cannot_enter_the_privileged_bootstrap() {
        if Uid::effective().is_root() {
            return;
        }
        let error = super::resolve("root").err();
        assert!(error.is_some_and(|diagnostic| diagnostic.code == "E_PRIVILEGE_TRANSITION"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_requires_socket_activation_instead_of_root_groups() {
        let error = super::resolve("any-user").err();
        assert!(error.is_some_and(|diagnostic| {
            diagnostic.message.contains("launchd socket activation")
        }));
    }
}
