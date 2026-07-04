use crate::policy::compile::{CompiledPolicy, ip_in_cidr, parse_cidr};
use crate::policy::facts::RuntimeFacts;
use crate::policy::schema::{ActionType, BoolExpr, ExprNode, Predicate, RuleSet, RuleSetScope};
use crate::policy::trace::{EvaluatedRule, ExplainTrace};
use serde_json::Value;
use std::collections::HashSet;
use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct EvalResult {
    pub decision: ActionType,
    pub matched_rule_id: Option<String>,
    pub matched_rule_set_id: Option<String>,
    pub reason: String,
    pub trace: ExplainTrace,
}

pub fn evaluate_policy(
    compiled: &CompiledPolicy,
    facts: &RuntimeFacts,
    max_trace_facts: usize,
) -> EvalResult {
    let candidate_positions = shortlist_candidates(compiled, facts);
    let mut trace = ExplainTrace::new();

    for idx in candidate_positions {
        let Some(rule_ref) = compiled.ordered_rules.get(idx) else {
            continue;
        };
        let Some(rule_set) = compiled
            .document
            .rule_sets
            .iter()
            .find(|rs| rs.id == rule_ref.rule_set_id)
        else {
            continue;
        };

        if !rule_set_applies(rule_set, facts) {
            trace.evaluated.push(EvaluatedRule {
                rule_id: format!("{}::<selector-miss>", rule_set.id),
                matched: false,
                short_circuit_reason: Some("rule_set selectors did not match".to_string()),
            });
            continue;
        }

        let Some(rule) = rule_set.rules.get(rule_ref.rule_index) else {
            continue;
        };

        let matched = eval_expr(&rule.when, facts, compiled);
        trace.evaluated.push(EvaluatedRule {
            rule_id: rule.id.clone(),
            matched,
            short_circuit_reason: if matched {
                Some("first_match_wins".to_string())
            } else {
                Some("predicate_mismatch".to_string())
            },
        });

        if matched {
            let deny = rule.action.deny.as_ref();
            trace.extracted_facts = Some(facts.snapshot(max_trace_facts));
            return EvalResult {
                decision: rule.action.action_type.clone(),
                matched_rule_id: Some(rule.id.clone()),
                matched_rule_set_id: Some(rule_set.id.clone()),
                reason: deny
                    .map(|d| d.reason.clone())
                    .unwrap_or_else(|| format!("matched {}", rule.id)),
                trace,
            };
        }
    }

    trace.extracted_facts = Some(facts.snapshot(max_trace_facts));
    let default = &compiled.document.defaults.action;
    EvalResult {
        decision: default.clone(),
        matched_rule_id: None,
        matched_rule_set_id: None,
        reason: "no rule matched; default action".to_string(),
        trace,
    }
}

fn shortlist_candidates(compiled: &CompiledPolicy, facts: &RuntimeFacts) -> Vec<usize> {
    let mut candidates = HashSet::new();

    if let Some(qname) = facts.get("dns.qname").and_then(|v| v.as_str()) {
        let qname = qname.to_ascii_lowercase();
        if let Some(list) = compiled.qname_exact.get(&qname) {
            for idx in list {
                candidates.insert(*idx);
            }
        }
        for (suffix, idx) in &compiled.qname_suffix {
            if qname.ends_with(suffix) {
                candidates.insert(*idx);
            }
        }
    }

    if let Some(qtype) = facts.get("dns.qtype").and_then(|v| v.as_str()) {
        if let Some(list) = compiled.qtype_map.get(&qtype.to_ascii_uppercase()) {
            for idx in list {
                candidates.insert(*idx);
            }
        }
    }

    if let Some(ip) = facts
        .get("client.ip")
        .and_then(|v| v.as_str())
        .and_then(|v| v.parse::<IpAddr>().ok())
    {
        for (cidr, idx) in &compiled.cidr_rules {
            if ip_in_cidr(ip, cidr) {
                candidates.insert(*idx);
            }
        }
    }

    if candidates.is_empty() {
        return (0..compiled.ordered_rules.len()).collect();
    }

    let mut out: Vec<_> = candidates.into_iter().collect();
    out.sort_unstable();
    out
}

fn rule_set_applies(rule_set: &RuleSet, facts: &RuntimeFacts) -> bool {
    if !rule_set.enabled {
        return false;
    }

    match rule_set.scope {
        RuleSetScope::Global => true,
        RuleSetScope::Org => match_selector(rule_set, facts, "org_id", "client.auth.org"),
        RuleSetScope::Team => match_selector(rule_set, facts, "team", "client.auth.team"),
        RuleSetScope::User => match_selector(rule_set, facts, "user", "client.auth.user"),
        RuleSetScope::Custom => {
            if let Some(selectors) = rule_set.selectors.as_ref() {
                let mut ok = true;
                if selectors.org_id.is_some() {
                    ok &= match_selector(rule_set, facts, "org_id", "client.auth.org");
                }
                if selectors.team.is_some() {
                    ok &= match_selector(rule_set, facts, "team", "client.auth.team");
                }
                if selectors.user.is_some() {
                    ok &= match_selector(rule_set, facts, "user", "client.auth.user");
                }
                ok
            } else {
                true
            }
        }
    }
}

fn match_selector(
    rule_set: &RuleSet,
    facts: &RuntimeFacts,
    selector_field: &str,
    fact_field: &str,
) -> bool {
    let expected = match selector_field {
        "org_id" => rule_set.selectors.as_ref().and_then(|s| s.org_id.as_ref()),
        "team" => rule_set.selectors.as_ref().and_then(|s| s.team.as_ref()),
        "user" => rule_set.selectors.as_ref().and_then(|s| s.user.as_ref()),
        _ => None,
    };

    let Some(expected) = expected else {
        return true;
    };

    facts
        .get(fact_field)
        .and_then(|v| v.as_str())
        .map(|actual| actual == expected)
        .unwrap_or(false)
}

fn eval_expr(expr: &BoolExpr, facts: &RuntimeFacts, compiled: &CompiledPolicy) -> bool {
    let all_ok = expr.all.iter().all(|n| eval_node(n, facts, compiled));
    let any_ok = if expr.any.is_empty() {
        true
    } else {
        expr.any.iter().any(|n| eval_node(n, facts, compiled))
    };
    let not_ok = expr.not.iter().all(|n| !eval_node(n, facts, compiled));

    all_ok && any_ok && not_ok
}

fn eval_node(node: &ExprNode, facts: &RuntimeFacts, compiled: &CompiledPolicy) -> bool {
    match node {
        ExprNode::Nested(inner) => eval_expr(inner, facts, compiled),
        ExprNode::Predicate(predicate) => eval_predicate(predicate, facts, compiled),
    }
}

fn eval_predicate(predicate: &Predicate, facts: &RuntimeFacts, compiled: &CompiledPolicy) -> bool {
    let field_value = lookup_value(&predicate.field, facts);

    match predicate.op.as_str() {
        "EXISTS" => field_value.is_some(),
        "NOT_EXISTS" => field_value.is_none(),
        "EQ" => value_eq(field_value, Some(&predicate.value)),
        "NEQ" => !value_eq(field_value, Some(&predicate.value)),
        "IN" => in_array(field_value, &predicate.value),
        "NOT_IN" => !in_array(field_value, &predicate.value),
        "IN_SET" => in_set(field_value, &predicate.value),
        "CONTAINS" => contains_op(field_value, &predicate.value),
        "STARTS_WITH" => starts_with(field_value, &predicate.value),
        "ENDS_WITH" => ends_with(field_value, &predicate.value),
        "MATCHES_REGEX" => matches_regex(field_value, &predicate.value, compiled),
        "LT" => numeric_compare(field_value, &predicate.value, |a, b| a < b),
        "LTE" => numeric_compare(field_value, &predicate.value, |a, b| a <= b),
        "GT" => numeric_compare(field_value, &predicate.value, |a, b| a > b),
        "GTE" => numeric_compare(field_value, &predicate.value, |a, b| a >= b),
        "BETWEEN" => between(field_value, &predicate.value),
        "IN_CIDR" => in_cidr(field_value, &predicate.value),
        "NOT_IN_CIDR" => !in_cidr(field_value, &predicate.value),
        _ => false,
    }
}

fn lookup_value<'a>(field: &str, facts: &'a RuntimeFacts) -> Option<&'a Value> {
    if let Some(v) = facts.get(field) {
        return Some(v);
    }

    if let Some(rest) = field.strip_prefix("req.headers.") {
        return facts
            .get("req.headers")
            .and_then(|m| m.as_object())
            .and_then(|m| m.get(&rest.to_ascii_lowercase()));
    }
    if let Some(rest) = field.strip_prefix("req.query.") {
        return facts
            .get("req.query")
            .and_then(|m| m.as_object())
            .and_then(|m| m.get(rest));
    }

    None
}

fn value_eq(a: Option<&Value>, b: Option<&Value>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

fn in_array(actual: Option<&Value>, expected: &Value) -> bool {
    let Some(actual) = actual else {
        return false;
    };
    expected
        .as_array()
        .map(|arr| arr.iter().any(|v| v == actual))
        .unwrap_or(false)
}

fn in_set(actual: Option<&Value>, expected: &Value) -> bool {
    let Some(actual) = actual else {
        return false;
    };
    let Some(actual_array) = actual.as_array() else {
        return false;
    };
    let Some(expected_array) = expected.as_array() else {
        return false;
    };
    actual_array
        .iter()
        .any(|v| expected_array.iter().any(|expected| expected == v))
}

fn contains_op(actual: Option<&Value>, expected: &Value) -> bool {
    match (actual.and_then(|v| v.as_str()), expected.as_str()) {
        (Some(actual), Some(expected)) => actual.contains(expected),
        _ => false,
    }
}

fn starts_with(actual: Option<&Value>, expected: &Value) -> bool {
    match (actual.and_then(|v| v.as_str()), expected.as_str()) {
        (Some(actual), Some(expected)) => actual.starts_with(expected),
        _ => false,
    }
}

fn ends_with(actual: Option<&Value>, expected: &Value) -> bool {
    match (actual.and_then(|v| v.as_str()), expected.as_str()) {
        (Some(actual), Some(expected)) => actual.ends_with(expected),
        _ => false,
    }
}

fn matches_regex(actual: Option<&Value>, expected: &Value, compiled: &CompiledPolicy) -> bool {
    let Some(actual) = actual.and_then(|v| v.as_str()) else {
        return false;
    };
    let Some(pattern) = expected.as_str() else {
        return false;
    };

    compiled
        .compiled_regexes
        .get(pattern)
        .map(|re| re.is_match(actual))
        .unwrap_or(false)
}

fn numeric_compare(actual: Option<&Value>, expected: &Value, cmp: fn(f64, f64) -> bool) -> bool {
    let Some(left) = actual.and_then(value_to_f64) else {
        return false;
    };
    let Some(right) = value_to_f64(expected) else {
        return false;
    };
    cmp(left, right)
}

fn value_to_f64(v: &Value) -> Option<f64> {
    if let Some(i) = v.as_i64() {
        return Some(i as f64);
    }
    if let Some(u) = v.as_u64() {
        return Some(u as f64);
    }
    v.as_f64()
}

fn between(actual: Option<&Value>, expected: &Value) -> bool {
    let Some(actual) = actual.and_then(value_to_f64) else {
        return false;
    };
    let Some(arr) = expected.as_array() else {
        return false;
    };
    if arr.len() != 2 {
        return false;
    }
    let Some(min) = value_to_f64(&arr[0]) else {
        return false;
    };
    let Some(max) = value_to_f64(&arr[1]) else {
        return false;
    };
    actual >= min && actual <= max
}

fn in_cidr(actual: Option<&Value>, expected: &Value) -> bool {
    let Some(ip) = actual
        .and_then(|v| v.as_str())
        .and_then(|v| v.parse::<IpAddr>().ok())
    else {
        return false;
    };
    let Some(arr) = expected.as_array() else {
        return false;
    };
    arr.iter().any(|entry| {
        entry
            .as_str()
            .and_then(parse_cidr)
            .map(|cidr| ip_in_cidr(ip, &cidr))
            .unwrap_or(false)
    })
}

#[cfg(test)]
mod tests {
    use super::evaluate_policy;
    use crate::policy::compile::compile_policy;
    use crate::policy::facts::RuntimeFacts;
    use crate::policy::schema::{ActionType, PolicyDocument};
    use serde_json::json;
    use std::collections::HashMap;

    #[test]
    fn policy_uses_default_when_no_rule_matches() {
        let doc: PolicyDocument = serde_json::from_value(json!({
          "version":"1.0.0",
          "defaults":{"action":"DENY","log_level":"info","fail_closed":true},
          "evaluation":{"mode":"ORDERED","first_match_wins":true,"tie_breakers":[],"merge_rule_sets":[]},
          "dimensions":{"req.method":{"type":"string","source_stage":"REQUEST","description":""}},
          "operators":{"EQ":{"applicable_types":["string"],"value_schema":{"type":"string"},"semantics":""}},
          "schemas":{},"evaluation_semantics":{},"specificity":{},"examples":{},"explain_trace":{},"implementation_notes":{},
          "rule_sets":[{"id":"global","scope":"GLOBAL","enabled":true,"rules":[{"id":"allow_get","enabled":true,"priority":10,"description":"","when":{"all":[{"field":"req.method","op":"EQ","value":"GET"}]},"action":{"type":"ALLOW"},"provenance":{"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z","created_by":"test"}}]}]
        })).expect("document");

        let compiled = compile_policy(doc).expect("compile");
        let facts = RuntimeFacts {
            fields: HashMap::new(),
        };
        let result = evaluate_policy(&compiled, &facts, 8);
        assert_eq!(format!("{:?}", result.decision), "Deny");
    }

    #[test]
    fn first_match_wins_returns_highest_priority_match() {
        let doc: PolicyDocument = serde_json::from_value(json!({
          "version":"1.0.0",
          "defaults":{"action":"ALLOW","log_level":"info","fail_closed":false},
          "evaluation":{"mode":"ORDERED","first_match_wins":true,"tie_breakers":[],"merge_rule_sets":[]},
          "dimensions":{
            "dns.qname":{"type":"string","source_stage":"REQUEST","description":""},
            "dns.qtype":{"type":"string","source_stage":"REQUEST","description":""}
          },
          "operators":{"EQ":{"applicable_types":["string"],"value_schema":{"type":"string"},"semantics":""}},
          "schemas":{},"evaluation_semantics":{},"specificity":{},"examples":{},"explain_trace":{},"implementation_notes":{},
          "rule_sets":[{"id":"global","scope":"GLOBAL","enabled":true,"rules":[
            {"id":"deny_general","enabled":true,"priority":10,"description":"","when":{"all":[{"field":"dns.qname","op":"EQ","value":"blocked.example."}]},"action":{"type":"DENY","deny":{"reason":"general","status_code":403,"body":"blocked"}},"provenance":{"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z","created_by":"test"}},
            {"id":"allow_override","enabled":true,"priority":20,"description":"","when":{"all":[{"field":"dns.qname","op":"EQ","value":"blocked.example."},{"field":"dns.qtype","op":"EQ","value":"A"}]},"action":{"type":"ALLOW"},"provenance":{"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z","created_by":"test"}}
          ]}]
        }))
        .expect("document");

        let compiled = compile_policy(doc).expect("compile");
        let mut fields = HashMap::new();
        fields.insert("dns.qname".to_string(), json!("blocked.example."));
        fields.insert("dns.qtype".to_string(), json!("A"));

        let result = evaluate_policy(&compiled, &RuntimeFacts { fields }, 8);
        assert_eq!(result.decision, ActionType::Allow);
        assert_eq!(result.matched_rule_id.as_deref(), Some("allow_override"));
    }
}
