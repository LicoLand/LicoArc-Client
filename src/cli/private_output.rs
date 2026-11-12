//! Private write-boundary guard: command destinations that receive endpoint
//! state, credentials, spool contents or received plaintext must resolve
//! outside every Git checkout, including ignored directories. Read-only
//! inputs are never inspected.

use std::io;
use std::path::{Path, PathBuf};

use super::Options;

pub(super) fn validate(command: &str, options: &Options) -> Result<(), String> {
    validate_with(command, options, |path| std::path::absolute(path))
}

fn validate_with(
    command: &str,
    options: &Options,
    absolute: impl Fn(&Path) -> io::Result<PathBuf>,
) -> Result<(), String> {
    let names: &[&str] = match command {
        "enroll" => &["credentials"],
        "receive" => &["spool"],
        "init" | "finish" | "record-send" => &["dir"],
        "offer" | "begin" | "accept" | "dispatch" => &["dir", "out"],
        "record-read" => &["dir", "spool", "out"],
        _ => &[],
    };
    for name in names {
        let Some(value) = options.optional(name) else {
            continue;
        };
        if *name == "out" && value == "-" && matches!(command, "offer" | "begin" | "accept") {
            continue;
        }
        let unknown = || format!("--{name}: cannot verify private output location");
        let path = absolute(Path::new(value)).map_err(|_| unknown())?;
        if inside_checkout(&path).map_err(|_| unknown())? {
            return Err(format!(
                "--{name}: private output must be outside a Git checkout"
            ));
        }
    }
    Ok(())
}

fn inside_checkout(path: &Path) -> io::Result<bool> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "private output is not absolute",
        ));
    }
    if has_checkout_ancestor(path)? {
        return Ok(true);
    }
    let mut probe = path;
    loop {
        match std::fs::canonicalize(probe) {
            Ok(resolved) => return has_checkout_ancestor(&resolved),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                // A dangling link or an object that changed during resolution
                // is not evidence that this is a new outside path.
                match std::fs::symlink_metadata(probe) {
                    Ok(_) => return Err(error),
                    Err(missing) if missing.kind() == io::ErrorKind::NotFound => {}
                    Err(other) => return Err(other),
                }
                probe = probe.parent().ok_or(error)?;
            }
            Err(error) => return Err(error),
        }
    }
}

fn has_checkout_ancestor(path: &Path) -> io::Result<bool> {
    for ancestor in path.ancestors() {
        match std::fs::symlink_metadata(ancestor.join(".git")) {
            Ok(_) => return Ok(true),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                ) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::{Path, PathBuf, validate_with};
    use crate::cli::{Options, run};

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            let mut suffix = [0_u8; 8];
            getrandom::fill(&mut suffix).expect("scratch entropy");
            let root = std::env::temp_dir().join(format!(
                "licoarc-private-output-{tag}-{:016x}",
                u64::from_ne_bytes(suffix),
            ));
            std::fs::create_dir(&root).expect("fresh scratch root");
            Self(root)
        }

        fn repo(&self) -> PathBuf {
            self.0.join("repo")
        }

        fn external(&self) -> PathBuf {
            self.0.join("external")
        }

        fn make_repo(&self) -> PathBuf {
            let repo = self.repo();
            std::fs::create_dir(&repo).expect("repo dir");
            std::fs::create_dir(repo.join(".git")).expect("checkout marker");
            std::fs::write(repo.join(".gitignore"), "dev/\n").expect("repo ignore");
            repo
        }

        fn make_gitfile_repo(&self) -> PathBuf {
            let repo = self.0.join("gitfile-repo");
            std::fs::create_dir(&repo).expect("gitfile repo dir");
            std::fs::write(repo.join(".git"), "gitdir: elsewhere\n").expect("checkout marker file");
            repo
        }

        fn make_external(&self) -> PathBuf {
            let external = self.external();
            std::fs::create_dir(&external).expect("external dir");
            external
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn options(pairs: &[(&str, &str)]) -> Options {
        let mut arguments = Vec::new();
        for (name, value) in pairs {
            arguments.push(format!("--{name}"));
            arguments.push((*value).to_owned());
        }
        Options::parse(&arguments).expect("test options parse")
    }

    fn argv(command: &str, pairs: &[(&str, &Path)]) -> Vec<String> {
        let mut arguments = vec!["licoarc-client".to_owned(), command.to_owned()];
        for (name, value) in pairs {
            arguments.push(format!("--{name}"));
            arguments.push(
                value
                    .as_os_str()
                    .to_str()
                    .expect("utf-8 test path")
                    .to_owned(),
            );
        }
        arguments
    }

    fn run_cli(arguments: &[String]) -> (i32, Vec<u8>, Vec<u8>) {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let exit = run(arguments, &mut out, &mut err);
        (exit.0, out, err)
    }

    #[test]
    fn run_rejects_checkout_local_private_output_before_any_work() {
        let scratch = Scratch::new("run");
        let repo = scratch.make_repo();
        let external = scratch.make_external();
        let dev_endpoint = repo.join("dev").join("endpoint");
        let endpoint = repo.join("endpoint");
        let credentials = repo.join("arbitrary.json");
        let spool = repo.join("messages");
        let artifact = repo.join("artifact");
        let outside_dir = external.join("dir");
        let outside_out = external.join("out");

        let cases: Vec<(&str, Vec<String>, PathBuf)> = vec![
            (
                "init --dir under ignored dev/",
                argv("init", &[("dir", &dev_endpoint)]),
                dev_endpoint.clone(),
            ),
            (
                "enroll --credentials",
                argv("enroll", &[("credentials", &credentials)]),
                credentials.clone(),
            ),
            (
                "receive --spool",
                argv("receive", &[("spool", &spool)]),
                spool.clone(),
            ),
            (
                "record-read --spool",
                argv(
                    "record-read",
                    &[
                        ("dir", &outside_dir),
                        ("spool", &spool),
                        ("out", &outside_out),
                    ],
                ),
                spool.clone(),
            ),
            (
                "offer --out",
                argv("offer", &[("dir", &outside_dir), ("out", &artifact)]),
                artifact.clone(),
            ),
            (
                "begin --out",
                argv("begin", &[("dir", &outside_dir), ("out", &artifact)]),
                artifact.clone(),
            ),
            (
                "accept --out",
                argv("accept", &[("dir", &outside_dir), ("out", &artifact)]),
                artifact.clone(),
            ),
            (
                "dispatch --out",
                argv("dispatch", &[("dir", &outside_dir), ("out", &artifact)]),
                artifact.clone(),
            ),
            (
                "finish --dir",
                argv("finish", &[("dir", &endpoint)]),
                endpoint.clone(),
            ),
            (
                "record-send --dir",
                argv("record-send", &[("dir", &endpoint)]),
                endpoint.clone(),
            ),
        ];
        for (label, arguments, target) in cases {
            let (code, out, err) = run_cli(&arguments);
            assert_eq!(code, 1, "{label}");
            assert!(
                out.is_empty(),
                "{label}: rejected command must not emit output"
            );
            let message = String::from_utf8(err).expect("utf-8 error");
            assert!(
                message.contains("private output must be outside a Git checkout"),
                "{label}: {message}"
            );
            assert!(!target.exists(), "{label}: target must not be created");
        }
        assert!(
            !outside_dir.exists(),
            "refusal must not create sibling dirs"
        );
        assert!(
            !outside_out.exists(),
            "refusal must not create sibling files"
        );
    }

    #[test]
    fn validate_accepts_external_destinations() {
        let scratch = Scratch::new("external");
        let external = scratch.make_external();
        let base = external.clone();
        let absolute = move |path: &Path| Ok(base.join(path));

        let missing = options(&[("dir", "nested/deep/endpoint")]);
        validate_with("init", &missing, &absolute).expect("missing nested external dir");

        let existing = external.join("existing.txt");
        std::fs::write(&existing, b"fixture").expect("existing external file");
        let present = options(&[("dir", "."), ("out", "existing.txt")]);
        validate_with("offer", &present, &absolute).expect("existing external file");
    }

    #[test]
    fn validate_recognizes_a_git_file_checkout_marker() {
        let scratch = Scratch::new("gitfile");
        let repo = scratch.make_gitfile_repo();
        let options = options(&[("dir", "endpoint")]);
        let error = validate_with("init", &options, |path| Ok(repo.join(path)))
            .expect_err("gitfile checkout must be refused");
        assert!(error.contains("private output must be outside a Git checkout"));
    }

    #[test]
    fn read_only_inputs_are_never_resolved() {
        let scratch = Scratch::new("readonly");
        let repo = scratch.make_repo();
        let dir = repo.join("endpoint").to_string_lossy().into_owned();
        let file = repo.join("message.txt").to_string_lossy().into_owned();
        let credentials = repo.join("credentials.json").to_string_lossy().into_owned();
        let options = options(&[
            ("dir", dir.as_str()),
            ("file", file.as_str()),
            ("credentials", credentials.as_str()),
            ("handle", "fixture-handle"),
        ]);
        for command in ["send", "handle"] {
            validate_with(command, &options, |_| -> std::io::Result<PathBuf> {
                panic!("read-only inputs must not be resolved")
            })
            .expect("read-only inputs stay outside the write boundary");
        }
    }

    #[test]
    fn stdout_dash_is_only_stdout_where_the_command_allows_it() {
        let scratch = Scratch::new("dash");
        let repo = scratch.make_repo();
        let external = scratch.make_external();
        let dir = external.join("dir").to_string_lossy().into_owned();
        for command in ["offer", "begin", "accept"] {
            let options = options(&[("dir", dir.as_str()), ("out", "-")]);
            validate_with(command, &options, |path| Ok(repo.join(path)))
                .unwrap_or_else(|error| panic!("{command} --out - must pass: {error}"));
        }
        for command in ["dispatch", "record-read"] {
            let options = options(&[("dir", dir.as_str()), ("out", "-")]);
            let error = validate_with(command, &options, |path| Ok(repo.join(path)))
                .expect_err("{command} --out - names a directory, not stdout");
            assert!(
                error.contains("private output must be outside a Git checkout"),
                "{command}: {error}"
            );
        }
    }

    #[test]
    fn lexical_parent_traversal_cannot_escape_a_checkout() {
        let scratch = Scratch::new("traversal");
        let repo = scratch.make_repo();
        let external = scratch.make_external();
        let sneaky = repo.join("..").join("external").join("artifact");
        let dir = external.to_string_lossy().into_owned();
        let out = sneaky.to_string_lossy().into_owned();
        let options = options(&[("dir", dir.as_str()), ("out", out.as_str())]);
        let error = validate_with("offer", &options, |path| Ok(path.to_path_buf()))
            .expect_err("repo/../external must stay refused");
        assert!(error.contains("private output must be outside a Git checkout"));
        assert!(!external.join("artifact").exists());
    }

    #[cfg(unix)]
    mod unix {
        use super::*;

        #[test]
        fn symlinks_cannot_redirect_private_output_into_a_checkout() {
            let scratch = Scratch::new("symlink");
            let repo = scratch.make_repo();
            let external = scratch.make_external();
            let inside = repo.join("endpoint");
            std::fs::create_dir(&inside).expect("repo endpoint dir");

            let inward = external.join("inward");
            std::os::unix::fs::symlink(&inside, &inward).expect("symlink into checkout");
            let missing_child = inward.join("child");
            let child = missing_child.to_string_lossy().into_owned();
            let parsed = options(&[("dir", child.as_str())]);
            let error = validate_with("init", &parsed, |path| Ok(path.to_path_buf()))
                .expect_err("resolved checkout ancestor must refuse");
            assert!(error.contains("private output must be outside a Git checkout"));
            assert!(!missing_child.exists());

            let dangling = external.join("dangling");
            std::os::unix::fs::symlink(external.join("ghost"), &dangling)
                .expect("dangling symlink");
            let dangling_child = dangling.join("child").to_string_lossy().into_owned();
            let parsed = options(&[("dir", dangling_child.as_str())]);
            let error = validate_with("init", &parsed, |path| Ok(path.to_path_buf()))
                .expect_err("dangling symlink is a verification error");
            assert!(error.contains("cannot verify private output location"));

            let outward = repo.join("outward");
            std::os::unix::fs::symlink(&external, &outward).expect("symlink out of checkout");
            let outward_child = outward.join("child").to_string_lossy().into_owned();
            let parsed = options(&[("dir", outward_child.as_str())]);
            let error = validate_with("init", &parsed, |path| Ok(path.to_path_buf()))
                .expect_err("lexical checkout ancestor must refuse");
            assert!(error.contains("private output must be outside a Git checkout"));
            assert!(!outward.join("child").exists());
        }
    }
}
