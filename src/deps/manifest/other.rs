//! Manifests of RubyGems (Gemfile), Composer (composer.json), NuGet (*.csproj),
//! Maven (pom.xml) and Gradle (build.gradle[.kts], libs.versions.toml).

use super::Direct;
use crate::deps::ecosystem::Ecosystem;
use anyhow::{Result, anyhow};
use regex::Regex;
use std::sync::LazyLock;

/// `gem "name"`, except gems from a path or git source.
pub(super) fn gemfile(content: &str) -> Direct {
    static GEM: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r#"^\s*gem\s+["']([^"']+)["']"#).expect("static regex"));
    content
        .lines()
        .filter(|l| !l.contains("path:") && !l.contains("git:") && !l.contains("github:"))
        .filter_map(|l| GEM.captures(l))
        .map(|c| (Ecosystem::RubyGems, c[1].to_string()))
        .collect()
}

/// `require` / `require-dev` packages (`vendor/name`; not `php` or `ext-*`).
pub(super) fn composer_json(content: &str) -> Result<Direct> {
    let doc: serde_json::Value = serde_json::from_str(content)?;
    Ok(["require", "require-dev"]
        .iter()
        .filter_map(|k| doc[k].as_object())
        .flat_map(|m| m.keys())
        .filter(|name| name.contains('/'))
        .map(|name| (Ecosystem::Packagist, Ecosystem::Packagist.normalize(name)))
        .collect())
}

pub(super) fn csproj(content: &str) -> Result<Direct> {
    let doc = roxmltree::Document::parse(content).map_err(|e| anyhow!("{e}"))?;
    Ok(doc
        .descendants()
        .filter(|n| n.has_tag_name("PackageReference"))
        .filter_map(|r| r.attribute("Include"))
        .map(|name| (Ecosystem::NuGet, Ecosystem::NuGet.normalize(name)))
        .collect())
}

pub(super) fn pom(content: &str) -> Result<Direct> {
    let doc = roxmltree::Document::parse(content).map_err(|e| anyhow!("{e}"))?;
    let text = |n: roxmltree::Node, tag: &str| -> Option<String> {
        let t = n.children().find(|c| c.has_tag_name(tag))?.text()?;
        Some(t.trim().to_string())
    };
    Ok(doc
        .descendants()
        .filter(|n| n.has_tag_name("dependency"))
        .filter_map(|d| {
            Some((
                Ecosystem::Maven,
                format!("{}:{}", text(d, "groupId")?, text(d, "artifactId")?),
            ))
        })
        .collect())
}

/// `implementation("group:artifact:1.0")` and the other dependency configurations.
pub(super) fn gradle(content: &str) -> Direct {
    static DEP: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r#"\b(?:implementation|api|compileOnly|runtimeOnly|testImplementation|testRuntimeOnly|testCompileOnly|annotationProcessor|kapt|ksp|classpath)\s*\(?\s*["']([\w.\-]+):([\w.\-]+)(?::[^"']*)?["']"#,
        )
        .expect("static regex")
    });
    DEP.captures_iter(content)
        .map(|c| (Ecosystem::Maven, format!("{}:{}", &c[1], &c[2])))
        .collect()
}

/// Gradle version catalog `[libraries]`: `"g:a:v"`, `{ module = "g:a" }` or
/// `{ group = "g", name = "a" }`.
pub(super) fn version_catalog(content: &str) -> Result<Direct> {
    let doc: toml::Table = toml::from_str(content)?;
    let libraries = doc.get("libraries").and_then(|l| l.as_table());
    Ok(libraries
        .into_iter()
        .flatten()
        .filter_map(|(_, lib)| {
            let coord = match lib {
                toml::Value::String(s) => s.rsplitn(2, ':').last()?.to_string(),
                toml::Value::Table(t) => match (t.get("module"), t.get("group"), t.get("name")) {
                    (Some(m), _, _) => m.as_str()?.to_string(),
                    (None, Some(g), Some(n)) => format!("{}:{}", g.as_str()?, n.as_str()?),
                    _ => return None,
                },
                _ => return None,
            };
            Some((Ecosystem::Maven, coord))
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(d: Direct) -> Vec<String> {
        d.into_iter().map(|(e, n)| format!("{e}:{n}")).collect()
    }

    #[test]
    fn other_ecosystems() {
        let gemfile = "source 'https://rubygems.org'\ngem 'rails', '~> 7.1'\ngem \"pg\"\ngem 'mine', path: '../mine'\n";
        assert_eq!(
            names(super::gemfile(gemfile)),
            ["rubygems:pg", "rubygems:rails"]
        );
        let composer = r#"{"require": {"php": "^8.2", "ext-json": "*", "Monolog/Monolog": "^3"}, "require-dev": {"phpunit/phpunit": "^11"}}"#;
        assert_eq!(
            names(composer_json(composer).unwrap()),
            ["composer:monolog/monolog", "composer:phpunit/phpunit"]
        );
        let csproj = r#"<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup></Project>"#;
        assert_eq!(
            names(super::csproj(csproj).unwrap()),
            ["nuget:newtonsoft.json"]
        );
        let pom = "<project><dependencies><dependency><groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId><version>2.0.13</version></dependency></dependencies></project>";
        assert_eq!(
            names(super::pom(pom).unwrap()),
            ["maven:org.slf4j:slf4j-api"]
        );
        let gradle = "dependencies {\n  implementation(\"com.squareup.okhttp3:okhttp:4.12.0\")\n  testImplementation 'junit:junit:4.13.2'\n}\n";
        assert_eq!(
            names(super::gradle(gradle)),
            ["maven:com.squareup.okhttp3:okhttp", "maven:junit:junit"]
        );
        let catalog = "[libraries]\nguava = \"com.google.guava:guava:33.0.0-jre\"\nktor = { module = \"io.ktor:ktor-client-core\", version.ref = \"ktor\" }\nslf4j = { group = \"org.slf4j\", name = \"slf4j-api\", version = \"2.0.13\" }\n";
        assert_eq!(
            names(version_catalog(catalog).unwrap()),
            [
                "maven:com.google.guava:guava",
                "maven:io.ktor:ktor-client-core",
                "maven:org.slf4j:slf4j-api"
            ]
        );
    }
}
