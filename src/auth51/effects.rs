use super::*;
use rustpython_parser::{
    Parse,
    ast::{self, Constant, Expr, Stmt},
};
use rustpython_unparser::transformer::Transformer;
use serde_json::json;
use std::collections::{BTreeMap, VecDeque};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Effect {
    pub kind: String,
    pub r#ref: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub tier: Option<String>,
    pub provenance: String,
    pub confidence: f64,
    #[serde(default)]
    pub detail: Option<String>,
}
fn effect(kind: &str, reference: &str, confidence: f64, detail: &str) -> Effect {
    Effect {
        kind: kind.into(),
        r#ref: reference.into(),
        name: None,
        tier: None,
        provenance: "static".into(),
        confidence,
        detail: Some(detail.into()),
    }
}
fn recognizers() -> &'static Value {
    static DATA: std::sync::OnceLock<Value> = std::sync::OnceLock::new();
    DATA.get_or_init(|| {
        serde_json::from_str(include_str!("recognizers.json")).expect("recognizer snapshot")
    })
}
enum Node {
    Stmt(Stmt),
    Expr(Expr),
    Keyword(ast::Keyword),
    Arguments(ast::Arguments),
    Arg(ast::Arg),
    Comprehension(ast::Comprehension),
    Handler(ast::ExceptHandler),
    Case(ast::MatchCase),
}
#[derive(Default)]
struct Walk {
    queue: VecDeque<Node>,
}
impl Transformer for Walk {
    fn visit_stmt(&mut self, n: Stmt) -> Option<Stmt> {
        self.queue.push_back(Node::Stmt(n.clone()));
        Some(n)
    }
    fn visit_expr(&mut self, n: Expr) -> Option<Expr> {
        self.queue.push_back(Node::Expr(n.clone()));
        Some(n)
    }
    fn visit_keyword(&mut self, n: ast::Keyword) -> Option<ast::Keyword> {
        self.queue.push_back(Node::Keyword(n.clone()));
        Some(n)
    }
    fn visit_arguments(&mut self, n: ast::Arguments) -> ast::Arguments {
        self.queue.push_back(Node::Arguments(n.clone()));
        n
    }
    fn visit_arg(&mut self, n: ast::Arg) -> Option<ast::Arg> {
        self.queue.push_back(Node::Arg(n.clone()));
        Some(n)
    }
    fn visit_comprehension(&mut self, n: ast::Comprehension) -> Option<ast::Comprehension> {
        self.queue.push_back(Node::Comprehension(n.clone()));
        Some(n)
    }
    fn visit_except_handler(&mut self, n: ast::ExceptHandler) -> Option<ast::ExceptHandler> {
        self.queue.push_back(Node::Handler(n.clone()));
        Some(n)
    }
    fn visit_match_case(&mut self, n: ast::MatchCase) -> Option<ast::MatchCase> {
        self.queue.push_back(Node::Case(n.clone()));
        Some(n)
    }
}
fn dotted(expr: &Expr, bindings: &BTreeMap<String, String>) -> Option<String> {
    match expr {
        Expr::Name(n) => Some(
            bindings
                .get(n.id.as_str())
                .cloned()
                .unwrap_or_else(|| n.id.to_string()),
        ),
        Expr::Attribute(n) => Some(format!("{}.{}", dotted(&n.value, bindings)?, n.attr)),
        _ => None,
    }
}
fn string(expr: &Expr) -> Option<&str> {
    if let Expr::Constant(n) = expr {
        if let Constant::Str(s) = &n.value {
            return Some(s);
        }
    }
    None
}
fn str_arg(call: &ast::ExprCall, index: usize) -> Option<&str> {
    call.args.get(index).and_then(string)
}
fn recognize(call: &ast::ExprCall, bindings: &BTreeMap<String, String>) -> Option<Effect> {
    let data = recognizers();
    let Some(path) = dotted(&call.func, bindings) else {
        return if matches!(call.func.as_ref(),Expr::Call(c) if matches!(c.func.as_ref(),Expr::Name(n) if n.id.as_str()=="getattr"))
        {
            Some(effect(
                "unknown",
                "getattr-dispatch",
                0.6,
                "dynamic getattr(...) dispatch",
            ))
        } else {
            None
        };
    };
    let leaf = path.rsplit('.').next().unwrap_or("");
    let head = path.split('.').next().unwrap_or("");
    let contains = |key: &str, s: &str| {
        data[key]
            .as_array()
            .is_some_and(|a| a.iter().any(|v| v == s))
    };
    if contains("dynamic", &path) || contains("dynamic", leaf) {
        return Some(effect(
            "unknown",
            &path,
            0.7,
            &format!("dynamic code execution: {path}"),
        ));
    }
    if let Some(fixed) = data["http"].get(&path) {
        let method = fixed
            .as_str()
            .or_else(|| str_arg(call, 0))
            .unwrap_or("get")
            .to_lowercase();
        let url = str_arg(call, usize::from(fixed.is_null()));
        let mut e = effect(
            "egress",
            url.filter(|s| !s.is_empty()).unwrap_or(&path),
            0.8,
            format!("{path} {} {}", method.to_uppercase(), url.unwrap_or("")).trim(),
        );
        e.tier = Some(
            data["http_tiers"][&method]
                .as_str()
                .unwrap_or("WRITE")
                .into(),
        );
        return Some(e);
    }
    if let Some(sdk) = data["sdk"].get(&path) {
        let mut e = effect("resource_op", &format!("sdk:{path}"), 0.8, &path);
        e.name = sdk[1].as_str().map(str::to_string);
        return Some(e);
    }
    if contains("sdk_roots", head) && path.contains('.') {
        let mut e = effect("resource_op", &format!("sdk:{path}"), 0.6, &path);
        e.name = Some(leaf.into());
        return Some(e);
    }
    if let Some(reference) = data["stdlib"][&path].as_str() {
        return Some(effect("local_side_effect", reference, 0.85, &path));
    }
    if path == "open" {
        let mode = str_arg(call, 1).filter(|s| !s.is_empty()).or_else(|| {
            call.keywords
                .iter()
                .find(|k| k.arg.as_ref().is_some_and(|a| a.as_str() == "mode"))
                .and_then(|k| string(&k.value))
        });
        if mode.is_some_and(|s| s.chars().any(|c| "wax+".contains(c))) {
            return Some(effect(
                "local_side_effect",
                "fs.write",
                0.7,
                &format!("open(mode={})", mode.unwrap_or("")),
            ));
        }
    }
    if leaf == "execute" {
        if let Some(sql) = str_arg(call, 0) {
            if regex::Regex::new(r"(?i)\bdrop\b")
                .expect("constant")
                .is_match(sql)
            {
                return Some(effect("local_side_effect", "db.drop", 0.75, "SQL DROP"));
            }
            if regex::Regex::new(r"(?i)\b(delete|truncate)\b")
                .expect("constant")
                .is_match(sql)
            {
                return Some(effect(
                    "local_side_effect",
                    "db.delete",
                    0.75,
                    "SQL DELETE/TRUNCATE",
                ));
            }
        }
    }
    None
}
/// Static Python analysis using a Rust AST. Source is never executed.
pub fn analyze_source(source: &str) -> Vec<Effect> {
    let Ok(body) = ast::Suite::parse(&super::source::dedent(source), "<tool>") else {
        return vec![effect(
            "unknown",
            "unparseable",
            0.5,
            "source did not parse",
        )];
    };
    let mut walk = Walk::default();
    for s in body {
        walk.queue.push_back(Node::Stmt(s));
    }
    let mut calls = vec![];
    let mut bindings = BTreeMap::new();
    while let Some(node) = walk.queue.pop_front() {
        match node {
            Node::Stmt(s) => {
                match &s {
                    Stmt::Import(n) => {
                        for a in &n.names {
                            let head = a.name.as_str().split('.').next().unwrap_or("");
                            bindings.insert(
                                a.asname.as_ref().map_or(head, |s| s.as_str()).into(),
                                if a.asname.is_some() {
                                    a.name.to_string()
                                } else {
                                    head.into()
                                },
                            );
                        }
                    }
                    Stmt::ImportFrom(n) => {
                        for a in &n.names {
                            let module = n.module.as_ref().map_or("", |s| s.as_str());
                            bindings.insert(
                                a.asname.as_ref().unwrap_or(&a.name).to_string(),
                                if module.is_empty() {
                                    a.name.to_string()
                                } else {
                                    format!("{module}.{}", a.name)
                                },
                            );
                        }
                    }
                    _ => {}
                }
                walk.generic_visit_stmt(s);
            }
            Node::Expr(e) => {
                if let Expr::Call(c) = &e {
                    calls.push(c.clone());
                }
                walk.generic_visit_expr(e);
            }
            Node::Keyword(n) => {
                walk.generic_visit_keyword(n);
            }
            Node::Arguments(n) => {
                walk.generic_visit_arguments(n);
            }
            Node::Arg(n) => {
                walk.generic_visit_arg(n);
            }
            Node::Comprehension(n) => {
                walk.generic_visit_comprehension(n);
            }
            Node::Handler(n) => {
                walk.generic_visit_except_handler(n);
            }
            Node::Case(n) => {
                walk.generic_visit_match_case(n);
            }
        }
    }
    let mut effects: Vec<Effect> = vec![];
    for call in calls {
        if let Some(e) = recognize(&call, &bindings) {
            if let Some(old) = effects.iter_mut().find(|old| {
                old.kind == e.kind
                    && old.r#ref == e.r#ref
                    && old.name == e.name
                    && old.tier == e.tier
            }) {
                if e.confidence > old.confidence {
                    *old = e;
                }
            } else {
                effects.push(e);
            }
        }
    }
    effects
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct EvidenceBundle {
    #[serde(default)]
    pub effects: Vec<Effect>,
    #[serde(default)]
    pub attested_tiers: BTreeMap<String, String>,
    #[serde(default)]
    pub downstream_tiers: BTreeMap<String, String>,
    #[serde(default)]
    pub override_tier: Option<String>,
    #[serde(default)]
    pub nominal_name: String,
    #[serde(default)]
    pub nominal_tags: Vec<String>,
    #[serde(default)]
    pub nominal_risk: String,
}
pub fn resolve_consequence(bundle: &EvidenceBundle, policy: &TierPolicy) -> Result<Value> {
    let known = |tier: &str| policy.tiers.iter().any(|t| t.name == tier);
    if let Some(t) = bundle
        .override_tier
        .as_ref()
        .filter(|t| !t.is_empty() && known(t))
    {
        return Ok(
            json!({"tier":t,"effects":[],"driver":null,"basis":"override","provisional":false,"override_applied":true}),
        );
    }
    if bundle.effects.is_empty() {
        return Ok(
            json!({"tier":policy.classify(&bundle.nominal_name,&bundle.nominal_tags,&bundle.nominal_risk)?,"effects":[],"driver":null,"basis":if bundle.nominal_name.is_empty(){"empty-default"}else{"nominal"},"provisional":true,"override_applied":false}),
        );
    }
    let mut per = vec![];
    let mut driver = None;
    let mut highest = i64::MIN;
    for e in &bundle.effects {
        let mut tier = e.tier.clone().filter(|t| !t.is_empty() && known(t));
        if tier.is_none() {
            tier = match e.kind.as_str() {
                "downstream_tool" => bundle.downstream_tiers.get(&e.r#ref).cloned(),
                "resource_op" | "egress" => bundle
                    .attested_tiers
                    .get(&e.r#ref)
                    .filter(|t| !t.is_empty())
                    .cloned(),
                "local_side_effect" => recognizers()["local_tiers"][&e.r#ref]
                    .as_str()
                    .filter(|t| known(t))
                    .map(str::to_string),
                _ => None,
            };
            if tier.is_none()
                && matches!(
                    e.kind.as_str(),
                    "resource_op" | "egress" | "local_side_effect"
                )
            {
                if let Some(name) = e.name.as_ref().filter(|s| !s.is_empty()) {
                    tier = Some(policy.classify(name, &[], "")?);
                }
            }
        }
        let used_floor = tier.is_none();
        let tier = tier.unwrap_or_else(|| policy.unknown_floor.clone());
        let rank = policy
            .tiers
            .iter()
            .find(|t| t.name == tier)
            .map_or(-1, |t| t.rank);
        let ec = json!({"effect":e,"tier":tier,"used_floor":used_floor});
        if driver.is_none() || rank > highest {
            highest = rank;
            driver = Some(ec.clone());
        }
        per.push(ec);
    }
    let driver = driver.expect("nonempty effects");
    Ok(
        json!({"tier":driver["tier"],"effects":per,"provisional":driver["used_floor"]==true||driver["effect"]["provenance"]=="nominal","driver":driver,"basis":"effects","override_applied":false}),
    )
}
