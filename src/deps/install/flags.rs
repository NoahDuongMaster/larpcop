//! Flags that take a separate value, per tool: their value is not a package.

pub(super) const NPM_FLAGS: &[&str] = &[
    "--registry",
    "--prefix",
    "-w",
    "--workspace",
    "--tag",
    "--cache",
    "--userconfig",
    "--omit",
    "--include",
];
pub(super) const PNPM_FLAGS: &[&str] =
    &["--filter", "-F", "--dir", "-C", "--registry", "--store-dir"];
pub(super) const YARN_FLAGS: &[&str] = &["--cwd", "--registry"];
pub(super) const BUN_FLAGS: &[&str] = &[
    "--cwd",
    "--registry",
    "-c",
    "--config",
    "--cache-dir",
    "--backend",
];
pub(super) const PIP_FLAGS: &[&str] = &[
    "-r",
    "--requirement",
    "-c",
    "--constraint",
    "-e",
    "--editable",
    "-i",
    "--index-url",
    "--extra-index-url",
    "-f",
    "--find-links",
    "-t",
    "--target",
    "--prefix",
    "--root",
    "--python",
    "-p",
    "--group",
    "--optional",
    "--extra",
    "--platform",
    "--python-version",
    "-P",
    "--upgrade-package",
];
pub(super) const GEM_FLAGS: &[&str] = &["-v", "--version", "--source", "--group", "--require"];
pub(super) const DOTNET_FLAGS: &[&str] =
    &["-v", "--version", "-f", "--framework", "-s", "--source"];
pub(super) const CARGO_FLAGS: &[&str] = &[
    "--git",
    "--path",
    "-p",
    "--package",
    "-F",
    "--features",
    "--rename",
    "--registry",
    "--branch",
    "--tag",
    "--rev",
    "--manifest-path",
    "--target",
];

pub(super) const NPX_FLAGS: &[&str] = &[
    "-p",
    "--package",
    "-c",
    "--call",
    "--registry",
    "--cache",
    "-w",
    "--workspace",
];
pub(super) const UVX_FLAGS: &[&str] = &[
    "--from",
    "--with",
    "-w",
    "--python",
    "-p",
    "--index",
    "--index-url",
    "--extra-index-url",
    "--exclude-newer",
];
pub(super) const PIPX_FLAGS: &[&str] = &[
    "--spec",
    "--python",
    "--pip-args",
    "--suffix",
    "--index-url",
];
pub(super) const CARGO_INSTALL_FLAGS: &[&str] = &[
    "--version",
    "--vers",
    "--git",
    "--path",
    "--branch",
    "--tag",
    "--rev",
    "--root",
    "--registry",
    "--index",
    "-F",
    "--features",
    "--target",
    "--bin",
    "--example",
    "-j",
    "--jobs",
    "--profile",
];
pub(super) const GO_FLAGS: &[&str] = &["-o", "-tags", "-ldflags", "-gcflags", "-mod", "-modfile"];
