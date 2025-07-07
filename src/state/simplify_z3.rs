use z3::{
    ast::{Ast, Dynamic, BV},
    Config, Context, DeclKind, SatResult, Solver,
};

/// Is the given Z3 expression a big number (constant)?
fn is_bnum<'ctx>(expr: &impl Ast<'ctx>) -> bool {
    let Ok(decl) = expr.safe_decl() else {
        return false;
    };
    if decl.kind() != DeclKind::BNUM {
        return false;
    }
    assert!(expr.children().is_empty());
    true
}

/// Is the given Z3 expression an If-Then-Else construction?
fn is_ite<'ctx>(expr: &impl Ast<'ctx>) -> bool {
    let Ok(decl) = expr.safe_decl() else {
        return false;
    };
    decl.kind() == DeclKind::ITE
}

/// Retrieve the constant boolean from a Z3 expression
fn get_constant_bool<'ctx>(expr: &impl Ast<'ctx>) -> Option<bool> {
    let Ok(decl) = expr.safe_decl() else {
        return None;
    };
    match decl.kind() {
        DeclKind::FALSE => Some(false),
        DeclKind::TRUE => Some(true),
        _ => None,
    }
}

/// Simplify a Z3 Dynamic AST in a similar way as
/// https://theory.stanford.edu/~nikolaj/programmingz3.html#sec-subterm-simplification
pub fn simplify_dynamic<'ctx>(expr: &Dynamic<'ctx>) -> Dynamic<'ctx> {
    let Ok(decl) = expr.safe_decl() else {
        // I don't know how this can happen
        todo!();
        // return expr.to_owned()
    };
    let children: Vec<Dynamic<'ctx>> = expr
        .children()
        .iter()
        .map(|x| simplify_dynamic(x))
        .collect();
    if children.is_empty() {
        // There is no sub-expression
        return expr.to_owned();
    }
    // println!("> simpl {:?} {:?}", decl.kind(), children);
    match decl.kind() {
        DeclKind::EQ => {
            let [left, right] = children
                .clone()
                .try_into()
                .expect("Unexpected arguments of EQ");
            if is_ite(&left) && is_bnum(&right) {
                // Transform ITE(cond, t, f) == r into ITE(cond, t == r, f == r)
                let [cond, val_true, val_false] = left.children().try_into().unwrap();
                let cond = cond.as_bool().unwrap();
                let new_val_true = simplify_dynamic(&(val_true._eq(&right)).simplify().into());
                let new_val_false = simplify_dynamic(&(val_false._eq(&right)).simplify().into());
                let new_expr = simplify_dynamic(&cond.ite(&new_val_true, &new_val_false));
                // println!("  => {new_expr}");
                return new_expr;
            }
        }
        DeclKind::ITE => {
            // If-then-else
            let [cond, val_true, val_false] = children.clone().try_into().unwrap();
            if let Some(bool_val_true) = get_constant_bool(&val_true) {
                if let Some(bool_val_false) = get_constant_bool(&val_false) {
                    // Transform ITE(cond, true or false, true or false) into a simpler expression
                    let new_expr = match (bool_val_true, bool_val_false) {
                        (false, false) => val_true,
                        (false, true) => {
                            let cond = cond.as_bool().unwrap();
                            simplify_dynamic(&cond.not().simplify().into())
                        }
                        (true, false) => cond,
                        (true, true) => val_true,
                    };
                    // println!("  => {new_expr}");
                    return new_expr;
                }
            }
        }
        _ => {}
    }
    // Complex conversion of children, cf. https://github.com/prove-rs/z3.rs/issues/351
    decl.apply(
        &children
            .iter()
            .map(|x| x as &dyn Ast<'ctx>)
            .collect::<Vec<_>>(),
    )
}

/// Simplify a Z3 Dynamic AST and prove the result is equivalent to the given expression
pub fn simplify_dynamic_proven<'ctx>(expr: &Dynamic<'ctx>) -> Dynamic<'ctx> {
    let simplified = simplify_dynamic(expr);

    // Prove expr == simplified
    let solver = Solver::new(expr.get_ctx());
    solver.assert(&expr._eq(&simplified).not());
    assert_eq!(solver.check(), SatResult::Unsat);
    return simplified;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simplify_constraint() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let bit_0 = BV::from_u64(&ctx, 0, 1);
        let bit_1 = BV::from_u64(&ctx, 1, 1);
        let u8_0 = BV::from_u64(&ctx, 0, 8);
        let u8_1 = BV::from_u64(&ctx, 1, 8);
        let u64_0 = BV::from_u64(&ctx, 0, 64);
        let x = BV::new_const(&ctx, "x", 64);

        // Test simplifying (ite (= (ite (= indices_len_R9!259 #x0000000000000000) #x01 #x00) #x00) #b1 #b0)
        let expr = x
            ._eq(&u64_0)
            .ite(&u8_1, &u8_0)
            ._eq(&u8_0)
            .ite(&bit_1, &bit_0);
        println!("expr: {expr}");
        assert_eq!(
            expr.to_string(),
            "(ite (= (ite (= x #x0000000000000000) #x01 #x00) #x00) #b1 #b0)"
        );

        let expr_simpl = expr.simplify();
        println!("simplified: {expr_simpl}");
        assert_eq!(expr.to_string(), expr_simpl.to_string()); // No change

        let expr_simpl = simplify_dynamic(&expr.clone().into()).as_bv().unwrap();
        println!("simplified2: {expr_simpl}");
        assert_eq!(
            expr_simpl.to_string(),
            "(ite (not (= x #x0000000000000000)) #b1 #b0)"
        );

        // Prove expr == expr_simpl
        let solver = Solver::new(&ctx);
        solver.assert(&expr._eq(&expr_simpl).not());
        assert_eq!(solver.check(), SatResult::Unsat);

        // Use simplify_dynamic_proven directly
        let expr_simpl2 = simplify_dynamic_proven(&expr.clone().into())
            .as_bv()
            .unwrap();
        assert_eq!(expr_simpl, expr_simpl2);
    }
}
