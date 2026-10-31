//! Lockfiles (and exact-version manifests) of RubyGems, NuGet, Maven/Gradle and
//! Composer. Maven has no lockfile: `pom.xml` versions are exact, so its direct
//! dependencies are checked; `gradle.lockfile` covers the whole Gradle graph.

use super::super::ecosystem::{Ecosystem, Pinned};
use anyhow::{Result, anyhow};
use serde::Deserialize;
use std::collections::BTreeMap;

/// Bundler: `GEM` sections from rubygems.org; specs are indented four spaces,
/// `name (version[-platform])`. GIT and PATH sections are not registry gems.
pub(super) fn gemfile_lock(content: &str) -> Vec<Pinned> {
    let mut out = Vec::new();
    let (mut gem, mut public) = (false, false);
    for line in content.lines() {
        if !line.starts_with(' ') {
            gem = line.trim() == "GEM";
            public = false;
            continue;
        }
        if let Some(remote) = line.trim().strip_prefix("remote:") {
            public = remote.trim().trim_end_matches('/') == "https://rubygems.org";
            continue;
        }
        let spec = line.strip_prefix("    ").filter(|s| !s.starts_with(' '));
        if let (true, true, Some((name, rest))) =
            (gem, public, spec.and_then(|s| s.split_once(" (")))
        {
            let version = rest.trim_end_matches(')').split('-').next().unwrap_or("");
            out.push(Pinned::new(Ecosystem::RubyGems, name, version));
        }
    }
    out
}

#[derive(Deserialize)]
struct NugetLock {
    #[serde(default)]
    dependencies: BTreeMap<String, BTreeMap<String, NugetEntry>>,
}

#[derive(Deserialize)]
struct NugetEntry {
    #[serde(rename = "type")]
    kind: String,
    resolved: Option<String>,
}

/// NuGet `packages.lock.json`: per target framework; `Project` entries are local.
pub(super) fn nuget_lock(content: &str) -> Result<Vec<Pinned>> {
    let lock: NugetLock = serde_json::from_str(content)?;
    Ok(lock
        .dependencies
        .values()
        .flatten()
        .filter(|(_, e)| e.kind != "Project")
        .filter_map(|(name, e)| Some(Pinned::new(Ecosystem::NuGet, name, e.resolved.as_deref()?)))
        .collect())
}

/// `group:artifact:version=configurations`, one per line.
pub(super) fn gradle_lock(content: &str) -> Vec<Pinned> {
    content
        .lines()
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| l.split('=').next())
        .filter_map(|coord| {
            let mut p = coord.trim().split(':');
            let (g, a, v) = (p.next()?, p.next()?, p.next()?);
            Some(Pinned::new(Ecosystem::Maven, &format!("{g}:{a}"), v))
        })
        .collect()
}

#[derive(Deserialize)]
struct ComposerLock {
    #[serde(default)]
    packages: Vec<ComposerPackage>,
    #[serde(default, rename = "packages-dev")]
    dev: Vec<ComposerPackage>,
}

#[derive(Deserialize)]
struct ComposerPackage {
    name: String,
    version: String,
    dist: Option<ComposerDist>,
}

#[derive(Deserialize)]
struct ComposerDist {
    #[serde(rename = "type")]
    kind: String,
}

/// `composer.lock`: tagged releases; `dev-*` branches and path repositories are not.
pub(super) fn composer_lock(content: &str) -> Result<Vec<Pinned>> {
    let lock: ComposerLock = serde_json::from_str(content)?;
    Ok(lock
        .packages
        .iter()
        .chain(&lock.dev)
        .filter(|p| {
            !p.version.starts_with("dev-") && p.dist.as_ref().is_none_or(|d| d.kind != "path")
        })
        .map(|p| {
            Pinned::new(
                Ecosystem::Packagist,
                &p.name,
                p.version.trim_start_matches('v'),
            )
        })
        .collect())
}

/// `pom.xml` dependencies with a literal version (properties are skipped).
pub(super) fn pom(content: &str) -> Result<Vec<Pinned>> {
    let doc = roxmltree::Document::parse(content).map_err(|e| anyhow!("{e}"))?;
    Ok(doc
        .descendants()
        .filter(|n| n.has_tag_name("dependency"))
        .filter_map(|d| {
            let (g, a, v) = (
                child(d, "groupId")?,
                child(d, "artifactId")?,
                child(d, "version")?,
            );
            (!v.contains("${") && !v.starts_with(['[', '(']))
                .then(|| Pinned::new(Ecosystem::Maven, &format!("{g}:{a}"), v))
        })
        .collect())
}

fn child<'a>(n: roxmltree::Node<'a, '_>, tag: &str) -> Option<&'a str> {
    n.children()
        .find(|c| c.has_tag_name(tag))
        .and_then(|c| c.text())
        .map(str::trim)
}

/// `*.csproj` `<PackageReference Include="X" Version="1.2.3" />` (NuGet resolves
/// the lowest matching version, so a plain version is what gets installed).
pub(super) fn csproj(content: &str) -> Result<Vec<Pinned>> {
    let doc = roxmltree::Document::parse(content).map_err(|e| anyhow!("{e}"))?;
    Ok(doc
        .descendants()
        .filter(|n| n.has_tag_name("PackageReference"))
        .filter_map(|r| {
            let name = r.attribute("Include")?;
            let version = r
                .attribute("Version")
                .or_else(|| r.children().find(|c| c.has_tag_name("Version"))?.text())?
                .trim();
            (!version.starts_with(['[', '(', '$']) && !version.contains('*'))
                .then(|| Pinned::new(Ecosystem::NuGet, name, version))
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pins(v: Vec<Pinned>) -> Vec<String> {
        v.iter().map(|p| format!("{}:{p}", p.eco)).collect()
    }

    #[test]
    fn bundler_nuget_gradle_composer_maven() {
        // Bundler 1.16 output, plus a GIT source and a platform-specific gem.
        let gemfile = "GIT\n  remote: https://github.com/x/y.git\n  revision: abc\n  specs:\n    y (0.1.0)\n\n\
GEM\n  remote: https://rubygems.org/\n  specs:\n    mini_portile2 (2.8.9)\n    nokogiri (1.13.10-arm64-darwin)\n      racc (~> 1.4)\n    rack (2.2.3)\n\n\
PLATFORMS\n  ruby\n\nDEPENDENCIES\n  rack (= 2.2.3)\n";
        assert_eq!(
            pins(gemfile_lock(gemfile)),
            [
                "rubygems:mini_portile2@2.8.9",
                "rubygems:nokogiri@1.13.10",
                "rubygems:rack@2.2.3"
            ]
        );
        let nuget = r#"{"version": 1, "dependencies": {"net8.0": {
            "Newtonsoft.Json": {"type": "Direct", "requested": "[13.0.1, )", "resolved": "13.0.1"},
            "System.Text.Json": {"type": "Transitive", "resolved": "8.0.0"},
            "MyLib": {"type": "Project"}}}}"#;
        assert_eq!(
            pins(nuget_lock(nuget).unwrap()),
            [
                "nuget:newtonsoft.json@13.0.1",
                "nuget:system.text.json@8.0.0"
            ]
        );
        let gradle = "# This is a Gradle generated file\ncom.squareup.okio:okio:3.6.0=compileClasspath,runtimeClasspath\nempty=annotationProcessor\n";
        assert_eq!(
            pins(gradle_lock(gradle)),
            ["maven:com.squareup.okio:okio@3.6.0"]
        );
        let composer = r#"{"packages": [
            {"name": "guzzlehttp/guzzle", "version": "7.4.0", "dist": {"type": "zip"}},
            {"name": "acme/local", "version": "dev-main", "dist": {"type": "path"}}],
          "packages-dev": [{"name": "phpunit/phpunit", "version": "v11.0.0"}]}"#;
        assert_eq!(
            pins(composer_lock(composer).unwrap()),
            [
                "composer:guzzlehttp/guzzle@7.4.0",
                "composer:phpunit/phpunit@11.0.0"
            ]
        );
        let pom_xml = "<project><dependencies>\
<dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>2.14.1</version></dependency>\
<dependency><groupId>a</groupId><artifactId>b</artifactId><version>${b.version}</version></dependency>\
</dependencies></project>";
        assert_eq!(
            pins(pom(pom_xml).unwrap()),
            ["maven:org.apache.logging.log4j:log4j-core@2.14.1"]
        );
        let project = r#"<Project Sdk="Microsoft.NET.Sdk"><ItemGroup>
            <PackageReference Include="Newtonsoft.Json" Version="12.0.1" />
            <PackageReference Include="Serilog"><Version>3.1.1</Version></PackageReference>
            <PackageReference Include="Floating" Version="1.*" />
        </ItemGroup></Project>"#;
        assert_eq!(
            pins(csproj(project).unwrap()),
            ["nuget:newtonsoft.json@12.0.1", "nuget:serilog@3.1.1"]
        );
    }
}
