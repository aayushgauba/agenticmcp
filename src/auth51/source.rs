use super::*;
use rustpython_parser::{
    Parse,
    ast::{self, Constant, Expr, Ranged, Stmt},
};
use rustpython_unparser::{Unparser, transformer::Transformer};

pub(crate) fn dedent(source: &str) -> String {
    let lines: Vec<String> = source
        .split_inclusive('\n')
        .map(|line| {
            let text = line.strip_suffix('\n').unwrap_or(line);
            if text.chars().all(|c| c == ' ' || c == '\t') {
                if line.ends_with('\n') {
                    "\n".into()
                } else {
                    String::new()
                }
            } else {
                line.into()
            }
        })
        .collect();
    let mut margin: Option<String> = None;
    for line in &lines {
        if line.is_empty() || line == "\n" {
            continue;
        }
        let indent: String = line
            .chars()
            .take_while(|c| *c == ' ' || *c == '\t')
            .collect();
        margin = Some(match margin {
            None => indent,
            Some(old) => old
                .chars()
                .zip(indent.chars())
                .take_while(|(a, b)| a == b)
                .map(|(a, _)| a)
                .collect(),
        });
    }
    let margin = margin.unwrap_or_default();
    lines
        .iter()
        .map(|line| line.strip_prefix(&margin).unwrap_or(line))
        .collect()
}

fn remove_docstring(body: &mut Vec<Stmt>) {
    if body.first().is_some_and(|s|matches!(s,Stmt::Expr(e) if matches!(e.value.as_ref(),Expr::Constant(c) if matches!(c.value,Constant::Str(_))))) {
        body.remove(0);
        if body.is_empty(){body.push(Stmt::Pass(ast::StmtPass {range:Default::default()}));}
    }
}
struct Strip;
impl Transformer for Strip {
    fn visit_stmt(&mut self, mut stmt: Stmt) -> Option<Stmt> {
        match &mut stmt {
            Stmt::FunctionDef(n) => remove_docstring(&mut n.body),
            Stmt::AsyncFunctionDef(n) => remove_docstring(&mut n.body),
            Stmt::ClassDef(n) => remove_docstring(&mut n.body),
            _ => {}
        }
        self.generic_visit_stmt(stmt)
    }
}

/// Auth51's dedent -> Python AST -> strip docstrings -> unparse pipeline,
/// executed entirely in Rust. Invalid Python retains its dedented source.
pub fn normalize_python_source(source: &str) -> Result<String> {
    let source = dedent(source);
    let Ok(mut body) = ast::Suite::parse(&source, "<identity>") else {
        return Ok(source);
    };
    remove_docstring(&mut body);
    let mut strip = Strip;
    let body = strip.visit_stmt_vec(body);
    let mut unparser = Unparser::new();
    for statement in &body {
        unparser.unparse_stmt(statement);
    }
    // CPython inserts a blank line before each definition, including nested
    // definitions. Locate these through the AST, never through text patterns
    // that could accidentally modify a multiline string literal.
    struct Definitions(Vec<usize>, Vec<(usize, usize)>);
    impl Transformer for Definitions {
        fn visit_stmt(&mut self, stmt: Stmt) -> Option<Stmt> {
            let decorators = match &stmt {
                Stmt::FunctionDef(n) => Some(&n.decorator_list),
                Stmt::AsyncFunctionDef(n) => Some(&n.decorator_list),
                Stmt::ClassDef(n) => Some(&n.decorator_list),
                _ => None,
            };
            if let Some(decorators) = decorators {
                self.0.push(
                    decorators
                        .first()
                        .map(|d| usize::from(d.range().start()).saturating_sub(1))
                        .unwrap_or(usize::from(stmt.range().start())),
                );
            }
            self.generic_visit_stmt(stmt)
        }
        fn visit_expr(&mut self, expr: Expr) -> Option<Expr> {
            if matches!(expr, Expr::JoinedStr(_)) {
                self.1.push((
                    usize::from(expr.range().start()),
                    usize::from(expr.range().end()),
                ));
            }
            self.generic_visit_expr(expr)
        }
    }
    let mut definitions = Definitions(vec![], vec![]);
    if let Ok(body) = ast::Suite::parse(&unparser.source, "<normalized>") {
        definitions.visit_stmt_vec(body);
    }
    let mut starts: Vec<_> = definitions
        .0
        .into_iter()
        .map(|offset| unparser.source[..offset].rfind('\n').map_or(0, |n| n + 1))
        .filter(|n| *n > 0)
        .collect();
    starts.sort_unstable();
    starts.dedup();
    let mut edits: Vec<_> = starts
        .into_iter()
        .map(|n| (n, n, "\n".to_string()))
        .collect();
    for (start, end) in definitions.1 {
        let text = &unparser.source[start..end];
        if text.starts_with("f\"")
            && text.ends_with('"')
            && !text.contains('\'')
            && !text.contains("\\\"")
        {
            edits.push((start, end, format!("f'{}'", &text[2..text.len() - 1])));
        }
    }
    edits.sort_by_key(|e| std::cmp::Reverse(e.0));
    for (start, end, text) in edits {
        unparser.source.replace_range(start..end, &text);
    }
    Ok(unparser.source.trim_matches('\n').to_string())
}
