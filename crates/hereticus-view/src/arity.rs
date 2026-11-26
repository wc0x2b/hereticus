//! How many arguments a callee reads, where the code that calls it does
//! not say.
//!
//! A call passes its arguments in registers, and the code before it can
//! set a register for another use. So the high IL takes the count of a
//! callee from its prototype, where this table holds it, or from the code
//! of the callee, where the binary holds it.

/// How many arguments a callee reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Arity {
    /// Exactly this many.
    Exact(usize),
    /// This many, and more that a format names, as `printf` reads.
    AtLeast(usize),
}

impl Arity {
    /// How many arguments a call shows, where the code before it sets the
    /// first `set`, and the convention passes `most` in registers.
    pub(crate) fn shown(self, set: usize, most: usize) -> usize {
        let count = match self {
            Self::Exact(count) => count,
            Self::AtLeast(count) => count.max(set),
        };
        count.min(most)
    }
}

use Arity::{AtLeast, Exact};

/// The arguments of functions of the C library and of the Linux kernel, by
/// their prototypes.
const KNOWN: &[(&str, Arity)] = &[
    // Texts.
    ("strlen", Exact(1)),
    ("strnlen", Exact(2)),
    ("strcmp", Exact(2)),
    ("strncmp", Exact(3)),
    ("strcasecmp", Exact(2)),
    ("strncasecmp", Exact(3)),
    ("strchr", Exact(2)),
    ("strrchr", Exact(2)),
    ("strstr", Exact(2)),
    ("strcpy", Exact(2)),
    ("strncpy", Exact(3)),
    ("strcat", Exact(2)),
    ("strncat", Exact(3)),
    ("strdup", Exact(1)),
    ("strndup", Exact(2)),
    ("strtol", Exact(3)),
    ("strtoul", Exact(3)),
    ("strtoll", Exact(3)),
    ("strtoull", Exact(3)),
    ("atoi", Exact(1)),
    ("memcpy", Exact(3)),
    ("memmove", Exact(3)),
    ("memset", Exact(3)),
    ("memcmp", Exact(3)),
    ("memchr", Exact(3)),
    // Formats.
    ("printf", AtLeast(1)),
    ("fprintf", AtLeast(2)),
    ("sprintf", AtLeast(2)),
    ("snprintf", AtLeast(3)),
    ("sscanf", AtLeast(2)),
    ("syslog", AtLeast(2)),
    ("err", AtLeast(2)),
    ("errx", AtLeast(2)),
    ("warn", AtLeast(1)),
    ("warnx", AtLeast(1)),
    ("printk", AtLeast(1)),
    ("_printk", AtLeast(1)),
    // Memory.
    ("malloc", Exact(1)),
    ("calloc", Exact(2)),
    ("realloc", Exact(2)),
    ("free", Exact(1)),
    // Processes and users.
    ("exit", Exact(1)),
    ("_exit", Exact(1)),
    ("abort", Exact(0)),
    ("fork", Exact(0)),
    ("getpid", Exact(0)),
    ("getuid", Exact(0)),
    ("geteuid", Exact(0)),
    ("getgid", Exact(0)),
    ("getegid", Exact(0)),
    ("setuid", Exact(1)),
    ("setgid", Exact(1)),
    ("setresuid", Exact(3)),
    ("setresgid", Exact(3)),
    ("initgroups", Exact(2)),
    ("getpwnam", Exact(1)),
    ("getgrnam", Exact(1)),
    ("umask", Exact(1)),
    ("getenv", Exact(1)),
    ("setenv", Exact(3)),
    ("sleep", Exact(1)),
    ("usleep", Exact(1)),
    ("__errno_location", Exact(0)),
    ("__stack_chk_fail", Exact(0)),
    // Files and sockets.
    ("open", AtLeast(2)),
    ("ioctl", AtLeast(2)),
    ("fcntl", AtLeast(2)),
    ("close", Exact(1)),
    ("read", Exact(3)),
    ("write", Exact(3)),
    ("unlink", Exact(1)),
    ("chmod", Exact(2)),
    ("fopen", Exact(2)),
    ("fclose", Exact(1)),
    ("fgets", Exact(3)),
    ("fputs", Exact(2)),
    ("fread", Exact(4)),
    ("fwrite", Exact(4)),
    ("socket", Exact(3)),
    ("connect", Exact(3)),
    ("bind", Exact(3)),
    ("listen", Exact(2)),
    ("accept", Exact(3)),
    ("send", Exact(4)),
    ("recv", Exact(4)),
    ("sendto", Exact(6)),
    ("recvfrom", Exact(6)),
    ("poll", Exact(3)),
    ("select", Exact(5)),
    // The Linux kernel.
    ("capable", Exact(1)),
    ("kfree", Exact(1)),
    ("copy_to_user", Exact(3)),
    ("copy_from_user", Exact(3)),
    ("__raw_copy_to_user", Exact(3)),
    ("__raw_copy_from_user", Exact(3)),
];

/// The arguments that the function `name` reads, by its prototype, where
/// the table holds it.
pub(crate) fn known(name: &str) -> Option<Arity> {
    KNOWN.iter().find(|(known, _)| *known == name).map(|&(_, arity)| arity)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_count_is_its_own_or_at_least_the_one_set() {
        assert_eq!(Exact(2).shown(4, 8), 2, "the code sets more for another use");
        assert_eq!(Exact(3).shown(1, 8), 3, "the code set the rest before");
        assert_eq!(AtLeast(2).shown(4, 8), 4, "a format reads more");
        assert_eq!(AtLeast(2).shown(1, 8), 2);
        assert_eq!(Exact(6).shown(0, 4), 4, "no more than the registers");
    }

    #[test]
    fn each_name_is_known_once() {
        let mut names: Vec<&str> = KNOWN.iter().map(|(name, _)| *name).collect();
        names.sort_unstable();
        let count = names.len();
        names.dedup();
        assert_eq!(names.len(), count);
        assert_eq!(known("strcmp"), Some(Exact(2)));
        assert_eq!(known("printf"), Some(AtLeast(1)));
        assert_eq!(known("sub_1234"), None);
    }
}
