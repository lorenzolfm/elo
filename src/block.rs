use crate::serialize::{Decode, Encode};

pub(crate) const BLOCK_HEADER_SIZE: usize = 80;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BlockHeader {
    pub(crate) version: i32,
    pub(crate) prev: bitcoin_hashes::sha256d::Hash,
    pub(crate) merkle_root: [u8; 32],
    pub(crate) time: u32,
    pub(crate) bits: u32,
    pub(crate) nonce: u32,
}

impl BlockHeader {
    pub(crate) fn hash(&self) -> bitcoin_hashes::sha256d::Hash {
        let mut bytes = Vec::with_capacity(BLOCK_HEADER_SIZE);
        self.encode(&mut bytes);
        bitcoin_hashes::sha256d::Hash::hash(&bytes)
    }
}

impl Encode for BlockHeader {
    fn encode(&self, out: &mut Vec<u8>) {
        let length_before = out.len();
        self.version.encode(out);
        self.prev.encode(out);
        self.merkle_root.encode(out);
        self.time.encode(out);
        self.bits.encode(out);
        self.nonce.encode(out);
        assert_eq!(out.len() - length_before, BLOCK_HEADER_SIZE);
    }
}

impl Decode for BlockHeader {
    fn decode(input: &mut &[u8]) -> Result<Self, crate::serialize::Error> {
        let length_before = input.len();
        let header = Self {
            version: i32::decode(input)?,
            prev: Decode::decode(input)?,
            merkle_root: Decode::decode(input)?,
            time: u32::decode(input)?,
            bits: u32::decode(input)?,
            nonce: u32::decode(input)?,
        };
        assert_eq!(length_before - input.len(), BLOCK_HEADER_SIZE);
        Ok(header)
    }
}

const WITNESS_COMMITMENT_HEADER: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];

const TRANSACTION_SIZE_MUTATED: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Block {
    pub(crate) header: BlockHeader,
    pub(crate) transactions: Vec<crate::transaction::Transaction>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Unmutated(Block);

impl Unmutated {
    pub(crate) fn transactions_count(&self) -> usize {
        self.0.transactions.len()
    }
}

const _: () = assert!(size_of::<crate::transaction::Transaction>() <= 64);
const _: () = assert!(size_of::<crate::transaction::TxIn>() <= 96);
const _: () = assert!(size_of::<crate::transaction::TxOut>() <= 32);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MutationError {
    MerkleRoot,
    DuplicateTransactions,
    TransactionOf64Bytes,
    WitnessReservedValue,
    WitnessMerkleRoot,
    UnexpectedWitness,
}

impl Block {
    pub(crate) fn check_mutation(
        self,
        position: crate::chain::Position,
    ) -> Result<Unmutated, MutationError> {
        assert_eq!(self.header.hash(), position.hash());
        let root = self.merkle_root();
        if root.hash != self.header.merkle_root {
            return Err(MutationError::MerkleRoot);
        }
        if root.mutated {
            return Err(MutationError::DuplicateTransactions);
        }

        let Some((coinbase, coinbase_input, rest)) = self
            .transactions
            .split_first()
            .and_then(|(first, rest)| Some((first, first.coinbase_input()?, rest)))
        else {
            return if self
                .transactions
                .iter()
                .any(|transaction| transaction.size_without_witness() == TRANSACTION_SIZE_MUTATED)
            {
                Err(MutationError::TransactionOf64Bytes)
            } else {
                Ok(Unmutated(self))
            };
        };

        let commitment = if position.height() >= position.network().segwit_height() {
            witness_commitment(coinbase)
        } else {
            None
        };
        if let Some(commitment) = commitment {
            let reserved_value = coinbase_input
                .witness
                .reserved_value()
                .ok_or(MutationError::WitnessReservedValue)?;
            let witness_root = witness_merkle_root(rest);
            let committed =
                bitcoin_hashes::sha256d::Hash::hash([witness_root, reserved_value].as_flattened());
            return if committed.as_byte_array() == commitment {
                Ok(Unmutated(self))
            } else {
                Err(MutationError::WitnessMerkleRoot)
            };
        }

        if self
            .transactions
            .iter()
            .any(crate::transaction::Transaction::has_witness)
        {
            return Err(MutationError::UnexpectedWitness);
        }
        Ok(Unmutated(self))
    }

    fn merkle_root(&self) -> crate::merkle::Root {
        crate::merkle::root(
            self.transactions
                .iter()
                .map(|transaction| transaction.txid().to_byte_array())
                .collect(),
        )
    }
}

fn witness_merkle_root(after_coinbase: &[crate::transaction::Transaction]) -> [u8; 32] {
    let coinbase_wtxid = [0; 32];
    let wtxids = after_coinbase
        .iter()
        .map(|transaction| transaction.wtxid().to_byte_array());
    crate::merkle::root(std::iter::once(coinbase_wtxid).chain(wtxids).collect()).hash
}

fn witness_commitment(coinbase: &crate::transaction::Transaction) -> Option<&[u8; 32]> {
    coinbase.outputs().iter().rev().find_map(|output| {
        output
            .script_pubkey
            .strip_prefix(&WITNESS_COMMITMENT_HEADER)?
            .first_chunk()
    })
}

impl Encode for Block {
    fn encode(&self, out: &mut Vec<u8>) {
        self.header.encode(out);
        crate::transaction::write_vector(out, &self.transactions);
    }
}

impl Decode for Block {
    fn decode(input: &mut &[u8]) -> Result<Self, crate::serialize::Error> {
        Ok(Self {
            header: BlockHeader::decode(input)?,
            transactions: crate::transaction::read_vector(input)?,
        })
    }
}

impl std::fmt::Display for MutationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MutationError::MerkleRoot => {
                write!(
                    f,
                    "the merkle root of the transactions is not the one in the header"
                )
            }
            MutationError::DuplicateTransactions => {
                write!(f, "the transactions repeat a part of the merkle tree")
            }
            MutationError::TransactionOf64Bytes => {
                write!(
                    f,
                    "the first transaction is not a coinbase, and a transaction has 64 bytes"
                )
            }
            MutationError::WitnessReservedValue => {
                write!(f, "the coinbase witness is not one item of 32 bytes")
            }
            MutationError::WitnessMerkleRoot => {
                write!(f, "the witness merkle root is not the one in the coinbase")
            }
            MutationError::UnexpectedWitness => {
                write!(
                    f,
                    "a transaction has a witness, but the coinbase has no witness commitment"
                )
            }
        }
    }
}

impl std::error::Error for MutationError {}

#[cfg(fuzzing)]
#[cfg_attr(false, mutants::skip)]
pub(crate) mod fuzz {
    use crate::serialize::{Decode, Encode};

    const NETWORKS: [crate::chainparams::Network; 4] = [
        crate::chainparams::Network::Mainnet,
        crate::chainparams::Network::Testnet4,
        crate::chainparams::Network::Signet,
        crate::chainparams::Network::Regtest,
    ];

    pub fn block(data: &[u8]) {
        let mut input = data;
        let Ok(block) = super::Block::decode(&mut input) else {
            return;
        };
        let mut encoded = Vec::new();
        block.encode(&mut encoded);
        assert_eq!(encoded, data[..data.len() - input.len()]);
        for transaction in &block.transactions {
            assert_eq!(
                transaction.txid() == transaction.wtxid(),
                !transaction.has_witness()
            );
        }

        let mut rooted = block.clone();
        rooted.header.merkle_root = block.merkle_root().hash;
        for network in NETWORKS {
            for height in [0, network.segwit_height()] {
                let check = |block: &super::Block| {
                    let position =
                        crate::chain::Position::new(network, height, block.header.hash());
                    block.clone().check_mutation(position).map(|_| ())
                };
                let rooted_result = check(&rooted);
                assert_ne!(rooted_result, Err(super::MutationError::MerkleRoot));
                assert_eq!(
                    check(&block),
                    if block.header.merkle_root == rooted.header.merkle_root {
                        rooted_result
                    } else {
                        Err(super::MutationError::MerkleRoot)
                    }
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::serialize::{Decode, Encode};

    #[test]
    fn header_decodes_prev_in_wire_order() {
        let payload = crate::fixtures::headers_payload();
        let (count, mut input) = payload.split_first().unwrap();
        assert_eq!(*count, 2);
        let header = super::BlockHeader::decode(&mut input).unwrap();

        assert_eq!(
            header.prev,
            crate::fixtures::hash_from_display_hex(
                "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
            )
        );
    }

    fn block_103() -> super::Block {
        crate::fixtures::block(crate::fixtures::REGTEST_BLOCK_103)
    }

    fn with_merkle_root(mut block: super::Block) -> super::Block {
        block.header.merkle_root = block.merkle_root().hash;
        block
    }

    fn witness(bytes: &[u8]) -> crate::transaction::Witness {
        crate::transaction::Witness::decode(&mut &bytes[..]).unwrap()
    }

    const REGTEST: crate::chainparams::Network = crate::chainparams::Network::Regtest;

    fn check(
        block: super::Block,
        network: crate::chainparams::Network,
        height: usize,
    ) -> Result<(), super::MutationError> {
        let position = crate::chain::Position::new(network, height, block.header.hash());
        let unmutated = block.clone().check_mutation(position)?;
        assert_eq!(unmutated, super::Unmutated(block));
        Ok(())
    }

    fn changed(
        transaction: &crate::transaction::Transaction,
        change: impl FnOnce(&mut Vec<crate::transaction::TxIn>, &mut Vec<crate::transaction::TxOut>),
    ) -> crate::transaction::Transaction {
        let mut inputs = transaction.inputs().to_vec();
        let mut outputs = transaction.outputs().to_vec();
        change(&mut inputs, &mut outputs);
        crate::transaction::Transaction::new(
            transaction.version,
            inputs,
            outputs,
            transaction.lock_time,
        )
        .unwrap()
    }

    #[test]
    #[should_panic]
    fn position_of_another_block_is_refused() {
        let position = crate::chain::Position::new(REGTEST, 0, REGTEST.genesis().hash());
        let _ = block_103().check_mutation(position);
    }

    #[test]
    fn block_round_trips_with_the_txids_and_hash_of_core() {
        let block = block_103();
        let mut encoded = Vec::new();
        block.encode(&mut encoded);
        assert_eq!(
            encoded,
            crate::fixtures::hex(crate::fixtures::REGTEST_BLOCK_103)
        );

        assert_eq!(
            block.header.hash(),
            crate::fixtures::hash_from_display_hex(
                "2e1b26f32330298af67653f3e37c35937b07ebf828864abeb68456eef3acdc31"
            )
        );
        let txids: Vec<_> = block.transactions.iter().map(|t| t.txid()).collect();
        assert_eq!(
            txids,
            [
                "efce6cee0fd4dd9f3542a8e7b1cbac943d87d22383a6a0ab358025cb2ad85927",
                "85cd22b7b5402a07a3b0cb8e4e5ea71a315e5a3c6b519cd03cf586c8b40a87f2",
                "a041d4b35c28a2577a728ae1f7300ec3cd7d35e0fcba70850a2e7ce223942176",
            ]
            .map(crate::fixtures::hash_from_display_hex)
        );
        let witnesses: Vec<_> = block.transactions.iter().map(|t| t.has_witness()).collect();
        assert_eq!(witnesses, [true, true, false]);
    }

    #[test]
    fn block_needs_each_transaction() {
        let bytes = crate::fixtures::hex(crate::fixtures::REGTEST_BLOCK_103);
        let mut input = &bytes[..bytes.len() - 1];
        assert_eq!(
            super::Block::decode(&mut input),
            Err(crate::serialize::Error::UnexpectedEnd)
        );
    }

    #[test]
    fn core_blocks_are_not_mutated() {
        let block = block_103();
        let position = crate::chain::Position::new(REGTEST, 103, block.header.hash());
        assert_eq!(
            block.check_mutation(position).unwrap().transactions_count(),
            3
        );
        let genesis = crate::fixtures::block(crate::fixtures::REGTEST_GENESIS_BLOCK);
        assert_eq!(genesis.header, REGTEST.genesis());
        let position = crate::chain::Position::new(REGTEST, 0, genesis.header.hash());
        assert_eq!(
            genesis
                .check_mutation(position)
                .unwrap()
                .transactions_count(),
            1
        );
    }

    #[test]
    fn other_merkle_root_in_the_header_is_bad_txnmrklroot() {
        let mut block = block_103();
        block.header.merkle_root[0] ^= 1;
        assert_eq!(
            check(block, REGTEST, 103),
            Err(super::MutationError::MerkleRoot)
        );
    }

    #[test]
    fn duplicate_last_transaction_is_bad_txns_duplicate() {
        let mut block = block_103();
        let last = block.transactions[2].clone();
        block.transactions.push(last);
        assert_eq!(
            check(block, REGTEST, 103),
            Err(super::MutationError::DuplicateTransactions)
        );
    }

    #[test]
    fn other_witness_is_bad_witness_merkle_match() {
        let mut block = block_103();
        block.transactions[1] = changed(&block.transactions[1], |inputs, _| {
            inputs[0].witness = witness(&[0x01, 0x01, 0xbb]);
        });
        assert_eq!(
            check(block, REGTEST, 103),
            Err(super::MutationError::WitnessMerkleRoot)
        );
    }

    #[test]
    fn coinbase_witness_other_than_one_item_of_32_bytes_is_bad_witness_nonce_size() {
        let short = [&[0x01, 0x1f][..], &[0; 31]].concat();
        let two = [&[0x02, 0x20][..], &[0; 32], &[0x00]].concat();
        for coinbase_witness in [short, two] {
            let mut block = block_103();
            block.transactions[0] = changed(&block.transactions[0], |inputs, _| {
                inputs[0].witness = witness(&coinbase_witness);
            });
            assert_eq!(
                check(block, REGTEST, 103),
                Err(super::MutationError::WitnessReservedValue)
            );
        }
    }

    #[test]
    fn witness_with_no_commitment_is_unexpected_witness() {
        let mut block = block_103();
        let mut commitment = None;
        block.transactions[0] = changed(&block.transactions[0], |_, outputs| {
            commitment = outputs.pop();
        });
        let commitment = commitment.unwrap();
        assert_eq!(
            commitment.script_pubkey[..6],
            super::WITNESS_COMMITMENT_HEADER
        );
        assert_eq!(
            check(with_merkle_root(block), REGTEST, 103),
            Err(super::MutationError::UnexpectedWitness)
        );
    }

    #[test]
    fn commitment_is_the_last_output_that_has_its_header() {
        let mut block = block_103();
        let mut other = block.transactions[0].outputs()[1].clone();
        other.script_pubkey[6] ^= 1;
        block.transactions[0] = changed(&block.transactions[0], |_, outputs| {
            outputs.push(other.clone());
        });
        assert_eq!(
            check(with_merkle_root(block.clone()), REGTEST, 103),
            Err(super::MutationError::WitnessMerkleRoot)
        );

        other.script_pubkey.truncate(37);
        block.transactions[0] = changed(&block.transactions[0], |_, outputs| {
            *outputs.last_mut().unwrap() = other;
        });
        assert_eq!(check(with_merkle_root(block), REGTEST, 103), Ok(()));
    }

    #[test]
    fn witness_before_segwit_is_unexpected_witness() {
        let mainnet = crate::chainparams::Network::Mainnet;
        assert_eq!(check(block_103(), mainnet, 481_824), Ok(()));
        assert_eq!(
            check(block_103(), mainnet, 481_823),
            Err(super::MutationError::UnexpectedWitness)
        );
    }

    fn transaction_of(size: usize) -> crate::transaction::Transaction {
        let size_empty_script = 60;
        let transaction = crate::transaction::Transaction::new(
            1,
            vec![crate::transaction::TxIn {
                previous_output: crate::transaction::OutPoint {
                    txid: bitcoin_hashes::sha256d::Hash::from_byte_array([0xaa; 32]),
                    vout: 0,
                },
                script_sig: Vec::new(),
                sequence: 0,
                witness: crate::transaction::Witness::default(),
            }],
            vec![crate::transaction::TxOut {
                value: 0,
                script_pubkey: vec![0x51; size - size_empty_script],
            }],
            0,
        )
        .unwrap();
        assert_eq!(transaction.size_without_witness(), size);
        transaction
    }

    #[test]
    fn no_coinbase_and_a_transaction_of_64_bytes_is_mutated() {
        let block = |size| {
            with_merkle_root(super::Block {
                header: REGTEST.genesis(),
                transactions: vec![transaction_of(size)],
            })
        };
        assert_eq!(
            check(block(64), REGTEST, 1),
            Err(super::MutationError::TransactionOf64Bytes)
        );
        assert_eq!(check(block(65), REGTEST, 1), Ok(()));
    }

    #[test]
    fn coinbase_first_and_a_transaction_of_64_bytes_is_not_mutated() {
        let mut block = crate::fixtures::block(crate::fixtures::REGTEST_GENESIS_BLOCK);
        block.transactions.push(transaction_of(64));
        assert_eq!(check(with_merkle_root(block), REGTEST, 1), Ok(()));
    }

    #[test]
    fn no_transactions_with_a_zero_merkle_root_is_not_mutated() {
        let block = super::Block {
            header: super::BlockHeader {
                merkle_root: [0; 32],
                ..REGTEST.genesis()
            },
            transactions: Vec::new(),
        };
        assert_eq!(check(block, REGTEST, 1), Ok(()));
    }

    #[test]
    fn header_requires_nonce() {
        let payload = crate::fixtures::headers_payload();
        let (_, headers) = payload.split_first().unwrap();
        let mut input = &headers[..super::BLOCK_HEADER_SIZE - size_of::<u32>()];
        assert_eq!(
            super::BlockHeader::decode(&mut input),
            Err(crate::serialize::Error::UnexpectedEnd)
        );
    }
}
