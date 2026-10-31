use super::*;

fn names(cmd: &str) -> Vec<String> {
    requests(cmd)
        .into_iter()
        .map(|r| {
            format!(
                "{}:{}",
                r.eco,
                r.name.unwrap_or_else(|| format!("<{}>", r.spec))
            )
        })
        .collect()
}

#[test]
fn finds_package_installs() {
    assert_eq!(
        names("npm i -D left-pad@1.3.0 @types/node"),
        ["npm:left-pad", "npm:@types/node"]
    );
    assert_eq!(
        names("cd web && pnpm --version; pnpm add --filter app zod"),
        ["npm:zod"]
    );
    assert_eq!(names("CI=1 yarn add pad@npm:left-pad@^1"), ["npm:left-pad"]);
    assert_eq!(
        names("npm install github:acme/x ./local"),
        ["npm:<github:acme/x>", "npm:<./local>"]
    );
    assert_eq!(
        names("python3 -m pip install 'Requests[socks]>=2' -r req.txt"),
        ["pypi:requests"]
    );
    assert_eq!(
        names("uv add --group dev Pytest && poetry add django"),
        ["pypi:pytest", "pypi:django"]
    );
    assert_eq!(names("cargo add serde@1 -F derive"), ["cargo:serde"]);
    assert_eq!(
        names("go get github.com/spf13/cobra@v1.8.1 ./..."),
        ["go:github.com/spf13/cobra"]
    );
    // Regression (live Claude Code run): `2>&1` was read as a package.
    assert_eq!(
        names("npm view slugify version 2>&1 | head && npm install slugify 2>&1 | tail -5"),
        ["npm:slugify"]
    );
    assert_eq!(names("npm i zod > install.log 2>/dev/null"), ["npm:zod"]);
    assert_eq!(
        names("gem install rack -v 2.2.3 && bundle add Nokogiri"),
        ["rubygems:rack", "rubygems:Nokogiri"]
    );
    assert_eq!(
        names("dotnet add src/App.csproj package Newtonsoft.Json --version 12.0.1"),
        ["nuget:newtonsoft.json"]
    );
    assert_eq!(
        names("composer require Guzzlehttp/Guzzle:7.4.0"),
        ["composer:guzzlehttp/guzzle"]
    );
    assert_eq!(
        names("npm i zod & pnpm add yup &> log"),
        ["npm:zod", "npm:yup"]
    );
    for cmd in [
        "npm install",
        "npm ci",
        "pnpm install --frozen-lockfile",
        "yarn",
        "npm test",
        "cargo build",
    ] {
        assert!(requests(cmd).is_empty(), "{cmd}");
    }
}

#[test]
fn tool_runners_and_versions() {
    let got = |cmd: &str| -> Vec<String> {
        requests(cmd)
            .into_iter()
            .map(|r| {
                format!(
                    "{} {}:{}@{}",
                    r.via,
                    r.eco,
                    r.name.unwrap_or_default(),
                    r.version.unwrap_or_default()
                )
            })
            .collect()
    };
    assert_eq!(
        got("npx --yes create-vite@5.2.0 app --template react"),
        ["npx npm:create-vite@5.2.0"]
    );
    assert_eq!(got("npx -p typescript tsc --init"), ["npx npm:typescript@"]);
    assert_eq!(
        got("pnpm dlx prettier --write ."),
        ["pnpm dlx npm:prettier@"]
    );
    assert_eq!(got("uvx -p 3.12 ruff@0.6.0 check"), ["uvx pypi:ruff@0.6.0"]);
    assert_eq!(
        got("uvx --from 'black==24.1.0' black ."),
        ["uvx pypi:black@24.1.0"]
    );
    assert_eq!(
        got("pipx run --spec httpie http GET x"),
        ["pipx pypi:httpie@"]
    );
    assert_eq!(
        got("cargo install ripgrep --version 14.1.0 --locked"),
        ["cargo install cargo:ripgrep@14.1.0"]
    );
    assert_eq!(
        got("go install golang.org/x/tools/gopls@v0.16.1"),
        ["go install go:golang.org/x/tools/gopls@v0.16.1"]
    );
    assert_eq!(
        got("gem install rack -v 2.2.3"),
        ["gem install rubygems:rack@2.2.3"]
    );
    // `-v` is verbose for pip, not a version.
    assert_eq!(
        got("pip install -v requests"),
        ["pip install pypi:requests@"]
    );
}
