#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Root {
    pub(crate) hash: [u8; 32],
    pub(crate) mutated: bool,
}

pub(crate) fn root(mut hashes: Vec<[u8; 32]>) -> Root {
    let mut mutated = false;
    while let [.., last] = *hashes
        && hashes.len() > 1
    {
        let (pairs, _) = hashes.as_chunks::<2>();
        mutated |= pairs.iter().any(|[left, right]| left == right);
        if hashes.len() % 2 == 1 {
            hashes.push(last);
        }
        let (pairs, rest) = hashes.as_chunks::<2>();
        assert!(rest.is_empty());
        hashes = pairs
            .iter()
            .map(|[left, right]| {
                bitcoin_hashes::sha256d::Hash::hash(&[*left, *right].concat()).to_byte_array()
            })
            .collect();
    }
    Root {
        hash: hashes.first().copied().unwrap_or([0; 32]),
        mutated,
    }
}

#[cfg(test)]
mod tests {
    fn parent(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
        bitcoin_hashes::sha256d::Hash::hash(&[left, right].concat()).to_byte_array()
    }

    #[test]
    fn root_of_no_hashes_is_zero() {
        assert_eq!(
            super::root(Vec::new()),
            super::Root {
                hash: [0; 32],
                mutated: false
            }
        );
    }

    #[test]
    fn root_of_one_hash_is_the_hash() {
        assert_eq!(super::root(vec![[0xaa; 32]]).hash, [0xaa; 32]);
    }

    #[test]
    fn odd_level_pairs_its_last_hash_with_itself() {
        let [a, b, c] = [[0xaa; 32], [0xbb; 32], [0xcc; 32]];
        let root = super::root(vec![a, b, c]);
        assert_eq!(root.hash, parent(parent(a, b), parent(c, c)));
        assert!(!root.mutated);
    }

    #[test]
    fn odd_level_above_an_odd_level_pairs_its_last_hash_with_itself() {
        let [a, b, c, d, e] = [[0xaa; 32], [0xbb; 32], [0xcc; 32], [0xdd; 32], [0xee; 32]];
        let ee = parent(e, e);
        assert_eq!(
            super::root(vec![a, b, c, d, e]).hash,
            parent(parent(parent(a, b), parent(c, d)), parent(ee, ee))
        );
    }

    #[test]
    fn duplicate_of_the_odd_last_hash_gives_the_same_root_but_is_mutated() {
        let [a, b, c] = [[0xaa; 32], [0xbb; 32], [0xcc; 32]];
        let root = super::root(vec![a, b, c, c]);
        assert_eq!(root.hash, super::root(vec![a, b, c]).hash);
        assert!(root.mutated);
    }

    #[test]
    fn equal_pair_on_an_upper_level_is_mutated() {
        let [a, b] = [[0xaa; 32], [0xbb; 32]];
        let root = super::root(vec![a, b, a, b]);
        assert_eq!(root.hash, parent(parent(a, b), parent(a, b)));
        assert!(root.mutated);
    }

    #[test]
    fn equal_hashes_in_different_pairs_are_not_mutated() {
        let [a, b] = [[0xaa; 32], [0xbb; 32]];
        assert!(!super::root(vec![a, b, b, a]).mutated);
    }
}
