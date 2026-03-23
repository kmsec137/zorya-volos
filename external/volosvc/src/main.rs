use volosvc::{VectorClock};

fn main() {
    let mut node_a = VectorClock::new("A");
    let mut node_b = VectorClock::new("B");

    node_a.tick(); // A: {A:1}
    node_b.tick(); // B: {B:1}

    println!("Are they concurrent? {:?}", node_a.partial_cmp(&node_b).is_none());

    node_a.merge(&node_b); // A receives from B. A: {A:2, B:1}
    println!("A after merge: {:?}", node_a);
}
