use std::collections::HashMap;
use std::cmp::Ordering;
use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub struct VolosVC {
    pub node_id: String,
    pub clocks: HashMap<String, u64>,
}

impl VolosVC {
    /// Create a new clock for a specific node
    pub fn new(node_id: &str) -> Self {
        let mut clocks = HashMap::new();
        clocks.insert(node_id.to_string(), 0);
        Self {
            node_id: node_id.to_string(),
            clocks,
        }
    }

    /// Increment the local clock (used for local events or before sending)
    pub fn tick(&mut self) {
        let count = self.clocks.entry(self.node_id.clone()).or_insert(0);
        *count += 1;
    }
   pub fn tick_at(&mut self, node_id: &str) {
        let count = self.clocks.entry(node_id.to_string()).or_insert(0); //it will insert a node id if the node is wrong!! need to have a more stable failove state here
        *count += 1;
    }

    /// Merge another clock into this one (used on receive)
    pub fn merge(&mut self, other: &VolosVC) {
        for (node, &timestamp) in &other.clocks {
            let local_timestamp = self.clocks.entry(node.clone()).or_insert(0);
            *local_timestamp = (*local_timestamp).max(timestamp);
        }
        self.tick();
    }

    /// Compare two clocks to determine causality
    pub fn partial_cmp(&self, other: &VolosVC) -> Option<Ordering> {
        let mut greater = false;
        let mut less = false;

        // Get all unique keys from both clocks
        let all_keys: std::collections::HashSet<_> = self.clocks.keys()
            .chain(other.clocks.keys())
            .collect();

        for key in all_keys {
            let v1 = self.clocks.get(key).unwrap_or(&0);
            let v2 = other.clocks.get(key).unwrap_or(&0);

            if v1 > v2 { greater = true; }
            if v1 < v2 { less = true; }
        }

        match (greater, less) {
            (true, false) => Some(Ordering::Greater),
            (false, true) => Some(Ordering::Less),
            (false, false) => Some(Ordering::Equal),
            (true, true) => None, // Concurrent events
        }
    }
}


impl fmt::Display for VolosVC {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Collect and sort keys so the output is always in the same order
        let mut entries: Vec<_> = self.clocks.iter().collect();
        entries.sort_by_key(|&(node, _)| node);

        // Format each entry as "Node:Value"
        let clock_strings: Vec<String> = entries
            .iter()
            .map(|(node, count)| format!("\"{}\":\"{}\"", node, count))
            .collect();

        // Write the final string to the formatter
        write!(
            f,
            "VolosVC {{ node_id: \"{}\", clocks:[ {} ] }}",
            self.node_id,
            clock_strings.join(", ")
        )
    }
}
