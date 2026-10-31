//! Taint in Ruby shapes: Rails scopes, paren-less calls, implicit returns,
//! `unless`, autoloaded constants, and a parameter named like a source.

use super::tests_calls::{found, guarded};

#[test]
fn ruby_rails_shapes() {
    let dir = tempfile::tempdir().unwrap();
    let models = dir.path().join("app/models");
    let controllers = dir.path().join("app/controllers");
    std::fs::create_dir_all(&models).unwrap();
    std::fs::create_dir_all(&controllers).unwrap();
    std::fs::write(
        models.join("report.rb"),
        "\
class Report < ApplicationRecord
  scope :by_col, ->(col) { Db.exec(\"SELECT #{col} FROM reports\") }
end
",
    )
    .unwrap();
    std::fs::write(
        controllers.join("reports_controller.rb"),
        "\
class ReportsController < ApplicationController
  def a
    Report.by_col(chosen)
  end

  def b
    name = params[:name]
    return head(400) unless ALLOWED.include?(name)
    Db.exec(name)
  end

  def c
    name = params[:name]
    Db.exec(name) unless ALLOWED.include?(name)
  end

  def d(*params)
    Db.exec(params.first)
  end

  private

  def chosen
    params[:col]
  end
end
",
    )
    .unwrap();
    let r = guarded(
        "Ruby",
        dir.path(),
        &["params"],
        &["Db.exec($X)"],
        &[],
        &["$L.include?($X)"],
    );
    let lines: Vec<usize> = found(&r, dir.path(), "app/controllers/reports_controller.rb")
        .iter()
        .map(|(l, _)| *l)
        .collect();
    // a: `chosen` returns params implicitly and the scope interpolates it;
    // c: runs only when the check fails. b is guarded; d's `params` is its own.
    assert_eq!(lines, [3, 14]);
}
