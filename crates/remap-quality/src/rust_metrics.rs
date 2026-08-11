use std::path::Path;

use proc_macro2::Span;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{
    BinOp, Block, ExprBinary, ExprForLoop, ExprIf, ExprLet, ExprLoop, ExprMatch, ExprWhile,
    ImplItemFn, ItemEnum, ItemFn, ItemImpl, ItemStruct, ItemTrait, Signature, TraitItemFn,
};

use crate::limits::{
    MAX_COMPLEXITY, MAX_FUNCTION_LINES, MAX_NESTING, MAX_PARAMETERS, MAX_TYPE_LINES,
};
use crate::model::{Rule, Violation};

pub(crate) fn analyze(path: &Path, source: &str) -> Result<Vec<Violation>, String> {
    let syntax = syn::parse_file(source).map_err(|error| {
        let start = error.span().start();
        format!(
            "cannot parse {} at {}:{}: {error}",
            path.display(),
            start.line,
            start.column + 1
        )
    })?;
    let mut analyzer = RustAnalyzer {
        path,
        violations: Vec::new(),
    };
    analyzer.visit_file(&syntax);
    Ok(analyzer.violations)
}

struct RustAnalyzer<'path> {
    path: &'path Path,
    violations: Vec<Violation>,
}

impl RustAnalyzer<'_> {
    fn check_function(&mut self, name: &str, signature: &Signature, block: &Block, span: Span) {
        self.check_span(Rule::FunctionLines, name, span, MAX_FUNCTION_LINES);
        self.check_value(
            Rule::Parameters,
            name,
            signature.span(),
            signature.inputs.len(),
            MAX_PARAMETERS,
        );

        let mut flow = FlowMetrics::new();
        flow.visit_block(block);
        self.check_value(
            Rule::Complexity,
            name,
            signature.span(),
            flow.complexity,
            MAX_COMPLEXITY,
        );
        self.check_value(
            Rule::Nesting,
            name,
            signature.span(),
            flow.maximum_nesting,
            MAX_NESTING,
        );
    }

    fn check_signature(&mut self, name: &str, signature: &Signature, span: Span) {
        self.check_span(Rule::FunctionLines, name, span, MAX_FUNCTION_LINES);
        self.check_value(
            Rule::Parameters,
            name,
            signature.span(),
            signature.inputs.len(),
            MAX_PARAMETERS,
        );
    }

    fn check_span(&mut self, rule: Rule, name: &str, span: Span, maximum: usize) {
        self.check_value(rule, name, span, span_lines(span), maximum);
    }

    fn check_value(&mut self, rule: Rule, name: &str, span: Span, actual: usize, maximum: usize) {
        if actual > maximum {
            self.violations.push(Violation {
                rule,
                path: self.path.to_path_buf(),
                line: span.start().line,
                symbol: Some(name.to_owned()),
                actual,
                maximum,
            });
        }
    }
}

impl<'syntax> Visit<'syntax> for RustAnalyzer<'_> {
    fn visit_item_fn(&mut self, node: &'syntax ItemFn) {
        self.check_function(
            &node.sig.ident.to_string(),
            &node.sig,
            &node.block,
            node.span(),
        );
        visit::visit_item_fn(self, node);
    }

    fn visit_impl_item_fn(&mut self, node: &'syntax ImplItemFn) {
        self.check_function(
            &node.sig.ident.to_string(),
            &node.sig,
            &node.block,
            node.span(),
        );
        visit::visit_impl_item_fn(self, node);
    }

    fn visit_trait_item_fn(&mut self, node: &'syntax TraitItemFn) {
        if let Some(block) = &node.default {
            self.check_function(&node.sig.ident.to_string(), &node.sig, block, node.span());
        } else {
            self.check_signature(&node.sig.ident.to_string(), &node.sig, node.span());
        }
        visit::visit_trait_item_fn(self, node);
    }

    fn visit_item_struct(&mut self, node: &'syntax ItemStruct) {
        self.check_span(
            Rule::TypeLines,
            &node.ident.to_string(),
            node.span(),
            MAX_TYPE_LINES,
        );
        visit::visit_item_struct(self, node);
    }

    fn visit_item_enum(&mut self, node: &'syntax ItemEnum) {
        self.check_span(
            Rule::TypeLines,
            &node.ident.to_string(),
            node.span(),
            MAX_TYPE_LINES,
        );
        visit::visit_item_enum(self, node);
    }

    fn visit_item_trait(&mut self, node: &'syntax ItemTrait) {
        self.check_span(
            Rule::TypeLines,
            &node.ident.to_string(),
            node.span(),
            MAX_TYPE_LINES,
        );
        visit::visit_item_trait(self, node);
    }

    fn visit_item_impl(&mut self, node: &'syntax ItemImpl) {
        self.check_span(Rule::TypeLines, "impl", node.span(), MAX_TYPE_LINES);
        visit::visit_item_impl(self, node);
    }
}

struct FlowMetrics {
    complexity: usize,
    current_nesting: usize,
    maximum_nesting: usize,
}

impl FlowMetrics {
    const fn new() -> Self {
        Self {
            complexity: 1,
            current_nesting: 0,
            maximum_nesting: 0,
        }
    }

    fn enter_control_flow(&mut self) {
        self.current_nesting += 1;
        self.maximum_nesting = self.maximum_nesting.max(self.current_nesting);
    }

    fn leave_control_flow(&mut self) {
        self.current_nesting = self.current_nesting.saturating_sub(1);
    }
}

impl<'syntax> Visit<'syntax> for FlowMetrics {
    fn visit_expr_if(&mut self, node: &'syntax ExprIf) {
        self.complexity += 1;
        self.enter_control_flow();
        visit::visit_expr_if(self, node);
        self.leave_control_flow();
    }

    fn visit_expr_for_loop(&mut self, node: &'syntax ExprForLoop) {
        self.complexity += 1;
        self.enter_control_flow();
        visit::visit_expr_for_loop(self, node);
        self.leave_control_flow();
    }

    fn visit_expr_while(&mut self, node: &'syntax ExprWhile) {
        self.complexity += 1;
        self.enter_control_flow();
        visit::visit_expr_while(self, node);
        self.leave_control_flow();
    }

    fn visit_expr_loop(&mut self, node: &'syntax ExprLoop) {
        self.complexity += 1;
        self.enter_control_flow();
        visit::visit_expr_loop(self, node);
        self.leave_control_flow();
    }

    fn visit_expr_match(&mut self, node: &'syntax ExprMatch) {
        self.complexity += node.arms.len().saturating_sub(1);
        self.enter_control_flow();
        visit::visit_expr_match(self, node);
        self.leave_control_flow();
    }

    fn visit_expr_binary(&mut self, node: &'syntax ExprBinary) {
        if matches!(node.op, BinOp::And(_) | BinOp::Or(_)) {
            self.complexity += 1;
        }
        visit::visit_expr_binary(self, node);
    }

    fn visit_expr_let(&mut self, node: &'syntax ExprLet) {
        self.complexity += 1;
        visit::visit_expr_let(self, node);
    }
}

fn span_lines(span: Span) -> usize {
    span.end().line.saturating_sub(span.start().line) + 1
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::path::Path;

    use super::analyze;
    use crate::limits::{MAX_COMPLEXITY, MAX_FUNCTION_LINES, MAX_NESTING, MAX_TYPE_LINES};
    use crate::model::Rule;

    fn contains_rule(source: &str, rule: Rule) -> Result<bool, String> {
        analyze(Path::new("fixture.rs"), source)
            .map(|violations| violations.iter().any(|violation| violation.rule == rule))
    }

    #[test]
    fn reports_parameter_limit() -> Result<(), Box<dyn Error>> {
        let source = "fn crowded(a:u8,b:u8,c:u8,d:u8,e:u8,f:u8,g:u8,h:u8,i:u8) {}";
        let violations = analyze(Path::new("fixture.rs"), source)?;
        assert!(
            violations
                .iter()
                .any(|violation| violation.rule == Rule::Parameters)
        );
        Ok(())
    }

    #[test]
    fn counts_branching_complexity() -> Result<(), Box<dyn Error>> {
        let source = "fn branch(a: bool, b: bool) { if a && b { } else if a { } }";
        let violations = analyze(Path::new("fixture.rs"), source)?;
        assert!(violations.is_empty());
        Ok(())
    }

    #[test]
    fn reports_function_line_limit() -> Result<(), Box<dyn Error>> {
        let body = "let _value = 1;\n".repeat(MAX_FUNCTION_LINES);
        let source = format!("fn long() {{\n{body}}}");
        assert!(contains_rule(&source, Rule::FunctionLines)?);
        Ok(())
    }

    #[test]
    fn reports_type_line_limit() -> Result<(), Box<dyn Error>> {
        let spacing = "\n".repeat(MAX_TYPE_LINES);
        let source = format!("struct Large {{{spacing}value: u8\n}}");
        assert!(contains_rule(&source, Rule::TypeLines)?);
        Ok(())
    }

    #[test]
    fn reports_complexity_limit() -> Result<(), Box<dyn Error>> {
        let branches = "if true {}\n".repeat(MAX_COMPLEXITY);
        let source = format!("fn complex() {{\n{branches}}}");
        assert!(contains_rule(&source, Rule::Complexity)?);
        Ok(())
    }

    #[test]
    fn reports_nesting_limit() -> Result<(), Box<dyn Error>> {
        let openings = "if true {\n".repeat(MAX_NESTING + 1);
        let closings = "}\n".repeat(MAX_NESTING + 1);
        let source = format!("fn nested() {{\n{openings}{closings}}}");
        assert!(contains_rule(&source, Rule::Nesting)?);
        Ok(())
    }
}
