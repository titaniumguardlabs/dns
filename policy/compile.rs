use crate::policy::schema::{
    BoolExpr, DimensionType, EvaluationMode, ExprNode, PolicyDocument, Predicate, Rule, RuleSet,
};
use chrono::{DateTime, Utc};
use regex::Regex;
use std::cmp::Reverse;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone)]
pub struct CompiledPolicy {
    pub document: PolicyDocument,
    pub ordered_rules: Vec<CompiledRuleRef>,
    pub qname_exact: HashMap<String, Vec<usize>>,
    pub qname_suffix: Vec<(String, usize)>,
    pub qtype_map: HashMap<String, Vec<usize>>,
    pub cidr_rules: Vec<(CidrBlock, usize)>,
    pub compiled_regexes: HashMap<String, Regex>,
}

#[derive(Debug, Clone)]
pub struct CompiledRuleRef {
    pub rule_set_id: String,
    pub rule_index: usize,
    pub specificity: i64,
    pub updated_at_ts: i64,
}

#[derive(Debug, Clone)]
pub struct CidrBlock {
    pub network: IpAddr,
    pub prefix: u8,
}

pub fn compile_policy(document: PolicyDocument) -> Result<CompiledPolicy, String> {
    validate_document(&document)?;

    let order = ordered_rule_sets(&document)?;
    let mut ordered_rules = Vec::new();

    for rule_set in order {
        if !rule_set.enabled {
            continue;
        }
        for (idx, rule) in rule_set.rules.iter().enumerate() {
            if !rule.enabled {
                continue;
            }
            let specificity = compute_specificity(&rule.when);
            let updated_at_ts = DateTime::parse_from_rfc3339(&rule.provenance.updated_at)
                .map(|d| d.with_timezone(&Utc).timestamp())
                .unwrap_or(0);
            ordered_rules.push(CompiledRuleRef {
                rule_set_id: rule_set.id.clone(),
                rule_index: idx,
                specificity,
                updated_at_ts,
            });
        }
    }

    ordered_rules.sort_by_key(|entry| {
        let rule = find_rule(&document.rule_sets, &entry.rule_set_id, entry.rule_index)
            .expect("rule must exist");
        (
            Reverse(rule.priority),
            Reverse(entry.specificity),
            Reverse(entry.updated_at_ts),
            rule.id.clone(),
        )
    });

    let mut compiled = CompiledPolicy {
        document,
        ordered_rules,
        qname_exact: HashMap::new(),
        qname_suffix: Vec::new(),
        qtype_map: HashMap::new(),
        cidr_rules: Vec::new(),
        compiled_regexes: HashMap::new(),
    };

    compiled.compiled_regexes = build_regex_index(&compiled)?;
    build_indices(&mut compiled);
    Ok(compiled)
}

fn validate_document(document: &PolicyDocument) -> Result<(), String> {
    if document.evaluation.mode != EvaluationMode::Ordered {
        return Err("evaluation.mode must be ORDERED".to_string());
    }

    let mut rule_set_ids = HashSet::new();
    for rule_set in &document.rule_sets {
        if !rule_set_ids.insert(rule_set.id.clone()) {
            return Err(format!("duplicate rule_set id: {}", rule_set.id));
        }
        let mut rule_ids = HashSet::new();
        for rule in &rule_set.rules {
            if !rule_ids.insert(rule.id.clone()) {
                return Err(format!("duplicate rule id in {}: {}", rule_set.id, rule.id));
            }
            validate_expr(document, &rule.when)?;
        }
    }

    for id in &document.evaluation.merge_rule_sets {
        if !rule_set_ids.contains(id) {
            return Err(format!(
                "merge_rule_sets references unknown rule_set id: {id}"
            ));
        }
    }

    Ok(())
}

fn validate_expr(document: &PolicyDocument, expr: &BoolExpr) -> Result<(), String> {
    for node in expr
        .all
        .iter()
        .chain(expr.any.iter())
        .chain(expr.not.iter())
    {
        match node {
            ExprNode::Nested(n) => validate_expr(document, n)?,
            ExprNode::Predicate(p) => validate_predicate(document, p)?,
        }
    }
    Ok(())
}

fn validate_predicate(document: &PolicyDocument, predicate: &Predicate) -> Result<(), String> {
    let dim_type = if let Some(dim) = document.dimensions.get(&predicate.field) {
        dim.value_type.clone()
    } else if predicate.field.starts_with("req.headers.")
        || predicate.field.starts_with("req.query.")
    {
        DimensionType::StringOrNull
    } else {
        return Err(format!("unknown dimension field: {}", predicate.field));
    };

    let op = document
        .operators
        .get(&predicate.op)
        .ok_or_else(|| format!("unknown operator: {}", predicate.op))?;

    if !op.applicable_types.contains(&dim_type)
        && !(predicate.field.starts_with("req.headers.")
            || predicate.field.starts_with("req.query."))
    {
        return Err(format!(
            "operator {} is not applicable to type {:?} for field {}",
            predicate.op, dim_type, predicate.field
        ));
    }

    if (predicate.op == "EXISTS" || predicate.op == "NOT_EXISTS") && !predicate.value.is_null() {
        return Err(format!(
            "operator {} must not specify a non-null value for field {}",
            predicate.op, predicate.field
        ));
    }

    Ok(())
}

fn ordered_rule_sets(document: &PolicyDocument) -> Result<Vec<&RuleSet>, String> {
    if document.evaluation.merge_rule_sets.is_empty() {
        return Ok(document.rule_sets.iter().collect());
    }

    let mut map: BTreeMap<&str, &RuleSet> = BTreeMap::new();
    for rs in &document.rule_sets {
        map.insert(rs.id.as_str(), rs);
    }

    let mut ordered = Vec::new();
    for id in &document.evaluation.merge_rule_sets {
        let rs = map
            .get(id.as_str())
            .copied()
            .ok_or_else(|| format!("unknown rule_set in merge_rule_sets: {id}"))?;
        ordered.push(rs);
    }
    Ok(ordered)
}

fn find_rule<'a>(rule_sets: &'a [RuleSet], rule_set_id: &str, index: usize) -> Option<&'a Rule> {
    let rs = rule_sets.iter().find(|rs| rs.id == rule_set_id)?;
    rs.rules.get(index)
}

pub fn compute_specificity(expr: &BoolExpr) -> i64 {
    let mut score = 0;
    for node in &expr.all {
        score += node_score(node);
    }
    for node in &expr.any {
        score += node_score(node);
    }
    for node in &expr.not {
        score += node_score(node) + 5;
    }
    score
}

fn node_score(node: &ExprNode) -> i64 {
    match node {
        ExprNode::Nested(expr) => compute_specificity(expr),
        ExprNode::Predicate(p) => {
            let mut score = 10;
            if p.field == "client.auth.user" && p.op == "EQ" {
                score += 100;
            } else if p.field == "client.auth.groups" && (p.op == "IN_SET" || p.op == "CONTAINS") {
                score += 60;
            } else if p.field == "dns.qname" && p.op == "EQ" {
                score += 80;
            } else if p.field == "dns.qname" && (p.op == "ENDS_WITH" || p.op == "STARTS_WITH") {
                score += 40;
            } else if p.op == "IN_CIDR" {
                score += 50;
            } else if p.op == "IN" || p.op == "NOT_IN" {
                score += 20;
            }
            score
        }
    }
}

fn build_indices(compiled: &mut CompiledPolicy) {
    for (compiled_idx, entry) in compiled.ordered_rules.iter().enumerate() {
        let Some(rule) = find_rule(
            &compiled.document.rule_sets,
            &entry.rule_set_id,
            entry.rule_index,
        ) else {
            continue;
        };
        index_expr(
            rule,
            &rule.when,
            compiled_idx,
            &mut compiled.qname_exact,
            &mut compiled.qname_suffix,
            &mut compiled.qtype_map,
            &mut compiled.cidr_rules,
        );
    }
}

fn build_regex_index(compiled: &CompiledPolicy) -> Result<HashMap<String, Regex>, String> {
    let mut out = HashMap::new();
    for entry in &compiled.ordered_rules {
        let Some(rule) = find_rule(
            &compiled.document.rule_sets,
            &entry.rule_set_id,
            entry.rule_index,
        ) else {
            continue;
        };
        collect_regexes(&rule.when, &mut out)?;
    }
    Ok(out)
}

fn collect_regexes(expr: &BoolExpr, out: &mut HashMap<String, Regex>) -> Result<(), String> {
    for node in expr
        .all
        .iter()
        .chain(expr.any.iter())
        .chain(expr.not.iter())
    {
        match node {
            ExprNode::Nested(inner) => collect_regexes(inner, out)?,
            ExprNode::Predicate(predicate) => {
                if predicate.op != "MATCHES_REGEX" {
                    continue;
                }
                let pattern = predicate.value.as_str().ok_or_else(|| {
                    format!(
                        "MATCHES_REGEX requires a string value for field {}",
                        predicate.field
                    )
                })?;
                if out.contains_key(pattern) {
                    continue;
                }
                let compiled = Regex::new(pattern)
                    .map_err(|err| format!("invalid regex pattern '{pattern}': {err}"))?;
                out.insert(pattern.to_string(), compiled);
            }
        }
    }
    Ok(())
}

fn index_expr(
    rule: &Rule,
    expr: &BoolExpr,
    compiled_idx: usize,
    qname_exact: &mut HashMap<String, Vec<usize>>,
    qname_suffix: &mut Vec<(String, usize)>,
    qtype_map: &mut HashMap<String, Vec<usize>>,
    cidr_rules: &mut Vec<(CidrBlock, usize)>,
) {
    for node in expr
        .all
        .iter()
        .chain(expr.any.iter())
        .chain(expr.not.iter())
    {
        match node {
            ExprNode::Nested(inner) => index_expr(
                rule,
                inner,
                compiled_idx,
                qname_exact,
                qname_suffix,
                qtype_map,
                cidr_rules,
            ),
            ExprNode::Predicate(p) => {
                if p.field == "dns.qname" && p.op == "EQ" {
                    if let Some(qname) = p.value.as_str() {
                        qname_exact
                            .entry(qname.to_ascii_lowercase())
                            .or_default()
                            .push(compiled_idx);
                    }
                }
                if p.field == "dns.qname" && p.op == "ENDS_WITH" {
                    if let Some(suffix) = p.value.as_str() {
                        qname_suffix.push((suffix.to_ascii_lowercase(), compiled_idx));
                    }
                }
                if p.field == "dns.qtype" {
                    if p.op == "EQ" {
                        if let Some(qtype) = p.value.as_str() {
                            qtype_map
                                .entry(qtype.to_ascii_uppercase())
                                .or_default()
                                .push(compiled_idx);
                        }
                    } else if p.op == "IN" {
                        if let Some(qtypes) = p.value.as_array() {
                            for qtype in qtypes.iter().filter_map(|v| v.as_str()) {
                                qtype_map
                                    .entry(qtype.to_ascii_uppercase())
                                    .or_default()
                                    .push(compiled_idx);
                            }
                        }
                    }
                }
                if p.op == "IN_CIDR"
                    && (p.field == "client.ip" || p.field == "dest.ip")
                    && p.value.is_array()
                {
                    for cidr in p.value.as_array().into_iter().flatten() {
                        if let Some(text) = cidr.as_str() {
                            if let Some(parsed) = parse_cidr(text) {
                                cidr_rules.push((parsed, compiled_idx));
                            }
                        }
                    }
                }
            }
        }
    }

    let _ = rule;
}

pub fn parse_cidr(text: &str) -> Option<CidrBlock> {
    let (ip, prefix) = text.split_once('/')?;
    let network: IpAddr = ip.parse().ok()?;
    let prefix: u8 = prefix.parse().ok()?;

    let max = match network {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if prefix > max {
        return None;
    }

    Some(CidrBlock { network, prefix })
}

pub fn ip_in_cidr(ip: IpAddr, cidr: &CidrBlock) -> bool {
    match (ip, cidr.network) {
        (IpAddr::V4(ip), IpAddr::V4(net)) => match_ipv4(ip, net, cidr.prefix),
        (IpAddr::V6(ip), IpAddr::V6(net)) => match_ipv6(ip, net, cidr.prefix),
        _ => false,
    }
}

fn match_ipv4(ip: Ipv4Addr, net: Ipv4Addr, prefix: u8) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    (u32::from(ip) & mask) == (u32::from(net) & mask)
}

fn match_ipv6(ip: Ipv6Addr, net: Ipv6Addr, prefix: u8) -> bool {
    let ip = u128::from_be_bytes(ip.octets());
    let net = u128::from_be_bytes(net.octets());
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    (ip & mask) == (net & mask)
}

#[cfg(test)]
mod tests {
    use super::{compile_policy, ip_in_cidr, parse_cidr};
    use crate::policy::schema::PolicyDocument;
    use serde_json::json;
    use std::net::IpAddr;

    #[test]
    fn cidr_parser_and_match_work() {
        let cidr = parse_cidr("10.0.0.0/8").expect("cidr should parse");
        assert!(ip_in_cidr("10.1.2.3".parse::<IpAddr>().expect("ip"), &cidr));
        assert!(!ip_in_cidr(
            "11.1.2.3".parse::<IpAddr>().expect("ip"),
            &cidr
        ));
    }

    #[test]
    fn compile_rejects_unknown_dimension() {
        let doc: PolicyDocument = serde_json::from_value(json!({
          "version":"1.0.0",
          "defaults":{"action":"ALLOW","log_level":"info","fail_closed":false},
          "evaluation":{"mode":"ORDERED","first_match_wins":true,"tie_breakers":[],"merge_rule_sets":[]},
          "dimensions":{"dns.qname":{"type":"string","source_stage":"REQUEST","description":""}},
          "operators":{"EQ":{"applicable_types":["string"],"value_schema":{"type":"string"},"semantics":""}},
          "schemas":{},"evaluation_semantics":{},"specificity":{},"examples":{},"explain_trace":{},"implementation_notes":{},
          "rule_sets":[{"id":"global","scope":"GLOBAL","enabled":true,"rules":[{"id":"rule_1","enabled":true,"priority":1,"description":"","when":{"all":[{"field":"dns.unknown","op":"EQ","value":"x"}]},"action":{"type":"DENY","deny":{"reason":"blocked","status_code":403,"body":"blocked"}},"provenance":{"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z","created_by":"test"}}]}]
        }))
        .expect("document");

        let err = compile_policy(doc).expect_err("unknown field should fail");
        assert!(err.contains("unknown dimension field: dns.unknown"));
    }

    #[test]
    fn compile_orders_rules_deterministically() {
        let doc: PolicyDocument = serde_json::from_value(json!({
          "version":"1.0.0",
          "defaults":{"action":"ALLOW","log_level":"info","fail_closed":false},
          "evaluation":{"mode":"ORDERED","first_match_wins":true,"tie_breakers":[],"merge_rule_sets":[]},
          "dimensions":{"dns.qname":{"type":"string","source_stage":"REQUEST","description":""}},
          "operators":{"EQ":{"applicable_types":["string"],"value_schema":{"type":"string"},"semantics":""}},
          "schemas":{},"evaluation_semantics":{},"specificity":{},"examples":{},"explain_trace":{},"implementation_notes":{},
          "rule_sets":[{"id":"global","scope":"GLOBAL","enabled":true,"rules":[
            {"id":"rule_low","enabled":true,"priority":10,"description":"","when":{"all":[{"field":"dns.qname","op":"EQ","value":"a.example."}]},"action":{"type":"DENY","deny":{"reason":"blocked","status_code":403,"body":"blocked"}},"provenance":{"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z","created_by":"test"}},
            {"id":"rule_high","enabled":true,"priority":20,"description":"","when":{"all":[{"field":"dns.qname","op":"EQ","value":"a.example."}]},"action":{"type":"DENY","deny":{"reason":"blocked","status_code":403,"body":"blocked"}},"provenance":{"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-02T00:00:00Z","created_by":"test"}}
          ]}]
        }))
        .expect("document");

        let compiled = compile_policy(doc).expect("compile");
        assert_eq!(compiled.ordered_rules.len(), 2);
        assert_eq!(compiled.ordered_rules[0].rule_index, 1);
        assert_eq!(compiled.ordered_rules[1].rule_index, 0);
    }

    #[test]
    fn compile_rejects_invalid_regex_pattern() {
        let doc: PolicyDocument = serde_json::from_value(json!({
          "version":"1.0.0",
          "defaults":{"action":"ALLOW","log_level":"info","fail_closed":false},
          "evaluation":{"mode":"ORDERED","first_match_wins":true,"tie_breakers":[],"merge_rule_sets":[]},
          "dimensions":{"dns.qname":{"type":"string","source_stage":"REQUEST","description":""}},
          "operators":{"MATCHES_REGEX":{"applicable_types":["string"],"value_schema":{"type":"string"},"semantics":""}},
          "schemas":{},"evaluation_semantics":{},"specificity":{},"examples":{},"explain_trace":{},"implementation_notes":{},
          "rule_sets":[{"id":"global","scope":"GLOBAL","enabled":true,"rules":[
            {"id":"rule_bad_regex","enabled":true,"priority":10,"description":"","when":{"all":[{"field":"dns.qname","op":"MATCHES_REGEX","value":"["}]},"action":{"type":"DENY","deny":{"reason":"blocked","status_code":403,"body":"blocked"}},"provenance":{"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z","created_by":"test"}}
          ]}]
        }))
        .expect("document");

        let err = compile_policy(doc).expect_err("compile should fail");
        assert!(err.contains("invalid regex pattern"), "unexpected: {err}");
    }
}
