//! Dropping privilege, once the parts that need it are done.

/// Give up root, if this process has it.
///
/// Binding port 25 needs privilege and nothing else here does. A mail server
/// that keeps root after binding is a mail server where every parser bug is a
/// root bug — and the parsers are reachable by anyone on the internet.
///
/// # Ordering
///
/// Called after the listeners are bound and before any connection is served.
/// Earlier and the bind fails; later and there is a window where a message is
/// being parsed as root.
///
/// # Under systemd this is already done
///
/// The packaged unit runs as `User=pigeon` with `AmbientCapabilities=
/// CAP_NET_BIND_SERVICE`, so the process never has root to drop. This exists
/// for the other ways people run daemons — by hand, in a container started as
/// root, from an init script — where the alternative is serving the internet as
/// uid 0.
#[cfg(unix)]
pub fn drop_privilege(user: Option<&str>) -> Result<(), String> {
    // SAFETY: `getuid` reads a process attribute and cannot fail.
    if unsafe { libc::getuid() } != 0 {
        return Ok(());
    }

    let Some(user) = user else {
        return Err("running as root with no `user` configured.\n\
             Binding port 25 needs privilege; serving mail does not, and a parser bug \n\
             reachable by anyone on the internet should not be a root bug. Set `user` \n\
             in the configuration, or run under the packaged systemd unit."
            .into());
    };

    let name = std::ffi::CString::new(user).map_err(|e| e.to_string())?;
    // SAFETY: `getpwnam` takes a NUL-terminated name and returns a pointer into
    // static storage or null; the null case is handled below and nothing here
    // outlives the call.
    let entry = unsafe { libc::getpwnam(name.as_ptr()) };
    if entry.is_null() {
        return Err(format!("no user named {user}"));
    }
    // SAFETY: non-null, and `passwd` is fully initialised by `getpwnam`.
    let (uid, gid) = unsafe { ((*entry).pw_uid, (*entry).pw_gid) };

    if uid == 0 {
        return Err(format!("{user} is root, so there is nothing to drop"));
    }

    // Groups first, then the group, then the user. Any other order leaves
    // privilege behind: setting the uid first removes the ability to change
    // groups at all, which is the classic way this is got wrong.
    // SAFETY: each call is checked, and none of them borrows anything.
    unsafe {
        if libc::setgroups(0, std::ptr::null()) != 0 {
            return Err(format!(
                "cannot clear supplementary groups: {}",
                std::io::Error::last_os_error()
            ));
        }
        if libc::setgid(gid) != 0 {
            return Err(format!(
                "cannot become group {gid}: {}",
                std::io::Error::last_os_error()
            ));
        }
        if libc::setuid(uid) != 0 {
            return Err(format!(
                "cannot become {user}: {}",
                std::io::Error::last_os_error()
            ));
        }

        // Verified rather than assumed. `setuid` returning zero is not the same
        // as privilege being gone on every platform this might run on, and a
        // daemon that believes it dropped root while holding it is worse than
        // one that never tried.
        if libc::setuid(0) == 0 {
            return Err("privilege was not dropped: this process can still become root".into());
        }
    }

    tracing::info!(%user, "dropped privilege");
    Ok(())
}

#[cfg(not(unix))]
pub fn drop_privilege(_user: Option<&str>) -> Result<(), String> {
    Ok(())
}
