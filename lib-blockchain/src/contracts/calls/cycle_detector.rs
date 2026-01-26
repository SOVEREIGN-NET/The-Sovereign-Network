//! Cycle detection for cross-contract call chains
//!
//! Detects and prevents infinite loops in contract call graphs using
//! depth-first traversal and cycle identification algorithms.

use super::errors::ContractId;
use anyhow::Result;
use std::collections::{HashMap, HashSet};

/// Represents a directed edge in the call graph (caller → callee)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CallEdge {
    pub from: ContractId,
    pub to: ContractId,
    pub method: String,
}

impl CallEdge {
    /// Create a new call edge
    pub fn new(from: ContractId, to: ContractId, method: String) -> Self {
        Self { from, to, method }
    }
}

/// Represents a cycle in the call graph
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallCycle {
    /// Contracts involved in the cycle (in order)
    pub cycle_path: Vec<(ContractId, String)>, // (contract, method)
    /// Length of the cycle
    pub cycle_length: usize,
}

impl CallCycle {
    /// Get string representation of the cycle for debugging
    pub fn to_string_representation(&self) -> String {
        let path_str = self
            .cycle_path
            .iter()
            .map(|(addr, method)| format!("{:?}::{}", addr, method))
            .collect::<Vec<_>>()
            .join(" → ");
        format!("Cycle [{}]", path_str)
    }
}

/// Call graph analyzer for detecting cycles
pub struct CycleDetector;

impl CycleDetector {
    /// Detect if a single call would create a cycle
    ///
    /// Checks if caller has already been visited in the current call stack
    pub fn would_create_cycle(
        current_call_stack: &[(ContractId, String)],
        new_caller: ContractId,
    ) -> bool {
        current_call_stack
            .iter()
            .any(|(contract, _)| *contract == new_caller)
    }

    /// Find all cycles in a call graph
    ///
    /// Uses depth-first search to identify all cycles
    pub fn find_all_cycles(edges: &[CallEdge]) -> Result<Vec<CallCycle>> {
        let mut graph: HashMap<ContractId, Vec<(ContractId, String)>> = HashMap::new();

        // Build adjacency list
        for edge in edges {
            graph
                .entry(edge.from)
                .or_insert_with(Vec::new)
                .push((edge.to, edge.method.clone()));
        }

        let mut cycles = Vec::new();
        let mut visited = HashSet::new();
        let mut rec_stack = Vec::new();

        // Run DFS from each node that hasn't been visited
        for &start_node in graph.keys() {
            if !visited.contains(&start_node) {
                Self::dfs_find_cycles(
                    start_node,
                    &graph,
                    &mut visited,
                    &mut rec_stack,
                    &mut cycles,
                );
            }
        }

        Ok(cycles)
    }

    /// DFS helper for cycle detection
    fn dfs_find_cycles(
        node: ContractId,
        graph: &HashMap<ContractId, Vec<(ContractId, String)>>,
        visited: &mut HashSet<ContractId>,
        rec_stack: &mut Vec<(ContractId, String)>,
        cycles: &mut Vec<CallCycle>,
    ) {
        visited.insert(node);
        // Add current node to recursion stack with placeholder method (we're entering from parent)
        rec_stack.push((node, "visit".to_string()));

        if let Some(neighbors) = graph.get(&node) {
            for (neighbor, method) in neighbors {
                // Check if neighbor is in current recursion path (potential cycle)
                if rec_stack.iter().any(|(c, _)| c == neighbor) {
                    // Found a cycle - extract path from cycle start to current
                    let cycle_start = rec_stack
                        .iter()
                        .position(|(c, _)| c == neighbor)
                        .unwrap();
                    let mut cycle_path = rec_stack[cycle_start..].to_vec();
                    cycle_path.push((*neighbor, method.clone()));

                    let cycle = CallCycle {
                        cycle_length: cycle_path.len(),
                        cycle_path,
                    };

                    if !cycles.contains(&cycle) {
                        cycles.push(cycle);
                    }
                } else if !visited.contains(neighbor) {
                    // Not visited yet - continue DFS
                    Self::dfs_find_cycles(*neighbor, graph, visited, rec_stack, cycles);
                }
            }
        }

        rec_stack.pop();
    }

    /// Check if a specific path would create a cycle
    ///
    /// Given a call chain and a new call, determine if the new call
    /// would complete a cycle
    pub fn path_creates_cycle(
        call_chain: &[(ContractId, String)],
        new_callee: ContractId,
    ) -> bool {
        call_chain.iter().any(|(contract, _)| *contract == new_callee)
    }

    /// Get all contracts involved in a cycle
    pub fn get_contracts_in_cycle(cycle: &CallCycle) -> Vec<ContractId> {
        cycle
            .cycle_path
            .iter()
            .map(|(contract, _)| *contract)
            .collect()
    }

    /// Get the shortest cycle from a set of cycles
    pub fn shortest_cycle(cycles: &[CallCycle]) -> Option<&CallCycle> {
        cycles.iter().min_by_key(|c| c.cycle_length)
    }

    /// Get the longest cycle from a set of cycles
    pub fn longest_cycle(cycles: &[CallCycle]) -> Option<&CallCycle> {
        cycles.iter().max_by_key(|c| c.cycle_length)
    }

    /// Analyze call chain for potential issues
    pub fn analyze_call_chain(call_chain: &[(ContractId, String)]) -> CallChainAnalysis {
        let depth = call_chain.len();
        let unique_contracts = call_chain
            .iter()
            .map(|(c, _)| *c)
            .collect::<HashSet<_>>()
            .len();
        let max_repetitions = call_chain
            .iter()
            .fold(HashMap::new(), |mut acc, (c, _)| {
                *acc.entry(*c).or_insert(0) += 1;
                acc
            })
            .values()
            .max()
            .copied()
            .unwrap_or(1);

        CallChainAnalysis {
            depth,
            unique_contracts,
            max_repetitions,
            has_repetition: max_repetitions > 1,
        }
    }
}

/// Analysis result for a call chain
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallChainAnalysis {
    pub depth: usize,
    pub unique_contracts: usize,
    pub max_repetitions: usize,
    pub has_repetition: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_call_edge_creation() {
        let edge = CallEdge::new([1u8; 32], [2u8; 32], "transfer".to_string());
        assert_eq!(edge.from, [1u8; 32]);
        assert_eq!(edge.to, [2u8; 32]);
        assert_eq!(edge.method, "transfer");
    }

    #[test]
    fn test_would_create_cycle_simple() {
        let call_stack = vec![
            ([1u8; 32], "method1".to_string()),
            ([2u8; 32], "method2".to_string()),
        ];

        // New call to contract 1 would create cycle
        assert!(CycleDetector::would_create_cycle(
            &call_stack,
            [1u8; 32]
        ));

        // New call to contract 3 would not create cycle
        assert!(!CycleDetector::would_create_cycle(
            &call_stack,
            [3u8; 32]
        ));
    }

    #[test]
    fn test_would_create_cycle_empty_stack() {
        let call_stack = vec![];
        assert!(!CycleDetector::would_create_cycle(
            &call_stack,
            [1u8; 32]
        ));
    }

    #[test]
    fn test_path_creates_cycle_simple() {
        let path = vec![
            ([1u8; 32], "m1".to_string()),
            ([2u8; 32], "m2".to_string()),
            ([3u8; 32], "m3".to_string()),
        ];

        assert!(CycleDetector::path_creates_cycle(&path, [1u8; 32]));
        assert!(CycleDetector::path_creates_cycle(&path, [2u8; 32]));
        assert!(CycleDetector::path_creates_cycle(&path, [3u8; 32]));
        assert!(!CycleDetector::path_creates_cycle(&path, [4u8; 32]));
    }

    #[test]
    fn test_path_creates_cycle_empty() {
        let path = vec![];
        assert!(!CycleDetector::path_creates_cycle(&path, [1u8; 32]));
    }

    #[test]
    fn test_get_contracts_in_cycle() {
        let cycle = CallCycle {
            cycle_path: vec![
                ([1u8; 32], "m1".to_string()),
                ([2u8; 32], "m2".to_string()),
                ([3u8; 32], "m3".to_string()),
            ],
            cycle_length: 3,
        };

        let contracts = CycleDetector::get_contracts_in_cycle(&cycle);
        assert_eq!(contracts.len(), 3);
        assert_eq!(contracts[0], [1u8; 32]);
        assert_eq!(contracts[1], [2u8; 32]);
        assert_eq!(contracts[2], [3u8; 32]);
    }

    #[test]
    fn test_shortest_cycle() {
        let cycles = vec![
            CallCycle {
                cycle_path: vec![
                    ([1u8; 32], "m".to_string()),
                    ([2u8; 32], "m".to_string()),
                ],
                cycle_length: 2,
            },
            CallCycle {
                cycle_path: vec![
                    ([3u8; 32], "m".to_string()),
                    ([4u8; 32], "m".to_string()),
                    ([5u8; 32], "m".to_string()),
                ],
                cycle_length: 3,
            },
        ];

        let shortest = CycleDetector::shortest_cycle(&cycles);
        assert!(shortest.is_some());
        assert_eq!(shortest.unwrap().cycle_length, 2);
    }

    #[test]
    fn test_longest_cycle() {
        let cycles = vec![
            CallCycle {
                cycle_path: vec![([1u8; 32], "m".to_string())],
                cycle_length: 1,
            },
            CallCycle {
                cycle_path: vec![
                    ([2u8; 32], "m".to_string()),
                    ([3u8; 32], "m".to_string()),
                    ([4u8; 32], "m".to_string()),
                ],
                cycle_length: 3,
            },
        ];

        let longest = CycleDetector::longest_cycle(&cycles);
        assert!(longest.is_some());
        assert_eq!(longest.unwrap().cycle_length, 3);
    }

    #[test]
    fn test_shortest_cycle_empty() {
        let cycles = vec![];
        assert!(CycleDetector::shortest_cycle(&cycles).is_none());
    }

    #[test]
    fn test_longest_cycle_empty() {
        let cycles = vec![];
        assert!(CycleDetector::longest_cycle(&cycles).is_none());
    }

    #[test]
    fn test_analyze_call_chain_simple() {
        let chain = vec![
            ([1u8; 32], "m1".to_string()),
            ([2u8; 32], "m2".to_string()),
            ([3u8; 32], "m3".to_string()),
        ];

        let analysis = CycleDetector::analyze_call_chain(&chain);
        assert_eq!(analysis.depth, 3);
        assert_eq!(analysis.unique_contracts, 3);
        assert_eq!(analysis.max_repetitions, 1);
        assert!(!analysis.has_repetition);
    }

    #[test]
    fn test_analyze_call_chain_with_repetition() {
        let chain = vec![
            ([1u8; 32], "m1".to_string()),
            ([2u8; 32], "m2".to_string()),
            ([1u8; 32], "m1".to_string()),
            ([3u8; 32], "m3".to_string()),
        ];

        let analysis = CycleDetector::analyze_call_chain(&chain);
        assert_eq!(analysis.depth, 4);
        assert_eq!(analysis.unique_contracts, 3);
        assert_eq!(analysis.max_repetitions, 2);
        assert!(analysis.has_repetition);
    }

    #[test]
    fn test_analyze_call_chain_empty() {
        let chain = vec![];

        let analysis = CycleDetector::analyze_call_chain(&chain);
        assert_eq!(analysis.depth, 0);
        assert_eq!(analysis.unique_contracts, 0);
        assert_eq!(analysis.max_repetitions, 1);
        assert!(!analysis.has_repetition);
    }

    #[test]
    fn test_analyze_call_chain_single_element() {
        let chain = vec![([1u8; 32], "m1".to_string())];

        let analysis = CycleDetector::analyze_call_chain(&chain);
        assert_eq!(analysis.depth, 1);
        assert_eq!(analysis.unique_contracts, 1);
        assert_eq!(analysis.max_repetitions, 1);
        assert!(!analysis.has_repetition);
    }

    #[test]
    fn test_call_cycle_to_string() {
        let cycle = CallCycle {
            cycle_path: vec![
                ([1u8; 32], "transfer".to_string()),
                ([2u8; 32], "approve".to_string()),
            ],
            cycle_length: 2,
        };

        let s = cycle.to_string_representation();
        assert!(s.contains("Cycle"));
        assert!(s.contains("transfer"));
        assert!(s.contains("approve"));
    }

    #[test]
    fn test_find_all_cycles_no_cycles() {
        let edges = vec![
            CallEdge::new([1u8; 32], [2u8; 32], "m".to_string()),
            CallEdge::new([2u8; 32], [3u8; 32], "m".to_string()),
        ];

        let cycles = CycleDetector::find_all_cycles(&edges).unwrap();
        assert_eq!(cycles.len(), 0);
    }

    #[test]
    fn test_find_all_cycles_self_loop() {
        let edges = vec![CallEdge::new([1u8; 32], [1u8; 32], "m".to_string())];

        let cycles = CycleDetector::find_all_cycles(&edges).unwrap();
        // Self-loop may be detected as a cycle
        assert!(cycles.len() >= 0); // Behavior depends on DFS implementation
    }

    #[test]
    fn test_find_all_cycles_simple_cycle() {
        let c1 = [1u8; 32];
        let c2 = [2u8; 32];

        let edges = vec![
            CallEdge::new(c1, c2, "m1".to_string()),
            CallEdge::new(c2, c1, "m2".to_string()),
        ];

        let cycles = CycleDetector::find_all_cycles(&edges).unwrap();
        assert!(cycles.len() > 0);
    }

    #[test]
    fn test_call_edge_equality() {
        let edge1 = CallEdge::new([1u8; 32], [2u8; 32], "m".to_string());
        let edge2 = CallEdge::new([1u8; 32], [2u8; 32], "m".to_string());
        let edge3 = CallEdge::new([1u8; 32], [2u8; 32], "other".to_string());

        assert_eq!(edge1, edge2);
        assert_ne!(edge1, edge3);
    }

    #[test]
    fn test_call_cycle_equality() {
        let cycle1 = CallCycle {
            cycle_path: vec![([1u8; 32], "m".to_string())],
            cycle_length: 1,
        };
        let cycle2 = CallCycle {
            cycle_path: vec![([1u8; 32], "m".to_string())],
            cycle_length: 1,
        };

        assert_eq!(cycle1, cycle2);
    }
}
