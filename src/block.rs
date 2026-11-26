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

pub(crate) const SIGOPS_COST_MAX: usize = 80_000;

const LEGACY_SIGOPS_MAX: usize = SIGOPS_COST_MAX / crate::transaction::WITNESS_SCALE_FACTOR;

const _: () =
    assert!(LEGACY_SIGOPS_MAX * crate::transaction::WITNESS_SCALE_FACTOR == SIGOPS_COST_MAX);

const BLOCK_TRANSACTIONS_COUNT_MAX: usize = (crate::transaction::BLOCK_BASE_SIZE_MAX
    - BLOCK_HEADER_SIZE)
    / <crate::transaction::Transaction as crate::transaction::SizeMin>::SIZE_MIN;

const _: () = assert!(
    BLOCK_TRANSACTIONS_COUNT_MAX
        * <crate::transaction::Transaction as crate::transaction::SizeMin>::SIZE_MIN
        <= crate::transaction::BLOCK_BASE_SIZE_MAX - BLOCK_HEADER_SIZE
);
const _: () = assert!(
    (BLOCK_TRANSACTIONS_COUNT_MAX + 1)
        * <crate::transaction::Transaction as crate::transaction::SizeMin>::SIZE_MIN
        > crate::transaction::BLOCK_BASE_SIZE_MAX - BLOCK_HEADER_SIZE
);

const BIP34_HEIGHT_BYTES_MAX: usize = 1 + size_of::<usize>() + 1;

const _: () = assert!(crate::transaction::OP_PUSHDATA1 == 0x4c);
const _: () = assert!(BIP34_HEIGHT_BYTES_MAX <= 0x4c);

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Transactions {
    pub(crate) first: crate::transaction::Transaction,
    pub(crate) rest: Vec<crate::transaction::Transaction>,
}

fn transactions_base_size<'a>(
    count: usize,
    transactions: impl Iterator<Item = &'a crate::transaction::Transaction>,
) -> usize {
    let transactions_size: usize = transactions
        .map(crate::transaction::Transaction::size_without_witness)
        .sum();
    let size = BLOCK_HEADER_SIZE + crate::serialize::compact_size_length(count) + transactions_size;
    assert!(
        size >= BLOCK_HEADER_SIZE
            + count * <crate::transaction::Transaction as crate::transaction::SizeMin>::SIZE_MIN
    );
    assert!(size > BLOCK_HEADER_SIZE);
    size
}

fn transactions_witness_bytes<'a>(
    transactions: impl Iterator<Item = &'a crate::transaction::Transaction>,
) -> usize {
    let size: usize = transactions
        .map(crate::transaction::Transaction::witness_bytes)
        .sum();
    assert!(matches!(size, 0 | 4..));
    size
}

impl Transactions {
    fn len(&self) -> usize {
        1 + self.rest.len()
    }

    fn iter(&self) -> impl Iterator<Item = &crate::transaction::Transaction> {
        std::iter::once(&self.first).chain(&self.rest)
    }

    #[cfg(any(test, fuzzing))]
    fn block_base_size(&self) -> usize {
        transactions_base_size(self.len(), self.iter())
    }

    #[cfg(any(test, fuzzing))]
    fn witness_bytes(&self) -> usize {
        transactions_witness_bytes(self.iter())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct HashedTransactions {
    first: crate::transaction::HashedTransaction,
    rest: Vec<crate::transaction::HashedTransaction>,
}

impl HashedTransactions {
    fn from_transactions(transactions: Transactions) -> HashedTransactions {
        HashedTransactions {
            first: crate::transaction::HashedTransaction::new(transactions.first),
            rest: transactions
                .rest
                .into_iter()
                .map(crate::transaction::HashedTransaction::new)
                .collect(),
        }
    }

    fn len(&self) -> usize {
        1 + self.rest.len()
    }

    fn iter(&self) -> impl Iterator<Item = &crate::transaction::Transaction> {
        std::iter::once(self.first.transaction()).chain(
            self.rest
                .iter()
                .map(crate::transaction::HashedTransaction::transaction),
        )
    }

    fn merkle_root(&self) -> crate::merkle::Root {
        let txids = std::iter::once(self.first.txid().to_byte_array())
            .chain(self.rest.iter().map(|tx| tx.txid().to_byte_array()))
            .collect();
        crate::merkle::root(txids)
    }

    fn block_base_size(&self) -> usize {
        transactions_base_size(self.len(), self.iter())
    }

    fn witness_bytes(&self) -> usize {
        transactions_witness_bytes(self.iter())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Block {
    pub(crate) header: BlockHeader,
    pub(crate) transactions: Option<Transactions>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Unmutated {
    position: crate::chain::Position,
    header: BlockHeader,
    transactions: Option<HashedTransactions>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Checked {
    header: BlockHeader,
    coinbase: crate::transaction::CheckedCoinbase,
    rest: Vec<crate::transaction::CheckedRegularTransaction>,
}

impl Checked {
    fn header(&self) -> BlockHeader {
        self.header
    }

    fn coinbase(&self) -> &crate::transaction::CheckedCoinbase {
        &self.coinbase
    }

    fn rest(&self) -> &[crate::transaction::CheckedRegularTransaction] {
        assert!(self.rest.len() < BLOCK_TRANSACTIONS_COUNT_MAX);
        &self.rest
    }

    pub(crate) fn transactions_count(&self) -> std::num::NonZeroUsize {
        assert!(self.rest.len() < BLOCK_TRANSACTIONS_COUNT_MAX);
        std::num::NonZeroUsize::MIN.saturating_add(self.rest.len())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MatchedHeader {
    position: crate::chain::BlockPosition,
    header: BlockHeader,
}

impl MatchedHeader {
    pub(crate) fn new(
        position: crate::chain::BlockPosition,
        header: BlockHeader,
    ) -> Option<MatchedHeader> {
        (header.hash() == position.hash() && header.time > position.prev_median_time_past())
            .then_some(MatchedHeader { position, header })
    }

    pub(crate) fn position(&self) -> crate::chain::BlockPosition {
        self.position
    }

    pub(crate) fn decode_body(
        self,
        input: &mut &[u8],
    ) -> Result<DownloadedBlock, crate::serialize::Error> {
        Ok(DownloadedBlock {
            position: self.position,
            block: Block::decode_body(self.header, input)?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DownloadedBlock {
    position: crate::chain::BlockPosition,
    block: Block,
}

impl DownloadedBlock {
    pub(crate) fn check(self) -> Result<CheckedBlock, CheckError> {
        let checked = Unmutated::check_mutation(self.block, self.position.position())
            .map_err(CheckError::Mutated)?
            .check_consensus()
            .map_err(CheckError::Invalid)?;
        assert_eq!(checked.header().hash(), self.position.hash());
        assert!(checked.header().time > self.position.prev_median_time_past());
        Ok(CheckedBlock {
            position: self.position,
            checked,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CheckedBlock {
    position: crate::chain::BlockPosition,
    checked: Checked,
}

impl CheckedBlock {
    #[cfg(any(test, fuzzing))]
    pub(crate) fn from_checked(
        position: crate::chain::BlockPosition,
        checked: Checked,
    ) -> Option<CheckedBlock> {
        (checked.header.hash() == position.hash()
            && checked.header.time > position.prev_median_time_past())
        .then_some(CheckedBlock { position, checked })
    }

    pub(crate) fn position(&self) -> crate::chain::BlockPosition {
        self.position
    }

    pub(crate) fn height(&self) -> std::num::NonZeroUsize {
        self.position.height()
    }

    pub(crate) fn header(&self) -> BlockHeader {
        self.checked.header()
    }

    pub(crate) fn coinbase(&self) -> &crate::transaction::CheckedCoinbase {
        self.checked.coinbase()
    }

    pub(crate) fn rest(&self) -> &[crate::transaction::CheckedRegularTransaction] {
        self.checked.rest()
    }

    pub(crate) fn transactions_count(&self) -> std::num::NonZeroUsize {
        self.checked.transactions_count()
    }
}

#[cfg(any(test, fuzzing))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PositionedBlock {
    position: crate::chain::Position,
    block: Block,
}

#[cfg(any(test, fuzzing))]
impl PositionedBlock {
    pub(crate) fn new(block: Block, position: crate::chain::Position) -> Option<PositionedBlock> {
        let time_valid = match position {
            crate::chain::Position::Block(block_position) => {
                block.header.time > block_position.prev_median_time_past()
            }
            crate::chain::Position::Genesis { .. } => true,
        };
        (block.header.hash() == position.hash() && time_valid)
            .then_some(PositionedBlock { position, block })
    }

    pub(crate) fn check(self) -> Result<Checked, CheckError> {
        Unmutated::check_mutation(self.block, self.position)
            .map_err(CheckError::Mutated)?
            .check_consensus()
            .map_err(CheckError::Invalid)
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockError {
    Empty,
    BaseSizeTooLarge,
    CoinbaseMissing,
    MultipleCoinbases,
    Transaction(crate::transaction::TransactionError),
    SigOpsTooMany,
    NonFinalTransaction,
    CoinbaseHeight,
    WeightTooLarge,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckError {
    Mutated(MutationError),
    Invalid(BlockError),
}

fn weight_from_base(base: usize, witness: usize) -> usize {
    assert!(base > BLOCK_HEADER_SIZE);
    assert!(matches!(witness, 0 | 4..));
    let total = base.saturating_add(witness);
    assert!(total >= base);
    let weight = base
        .saturating_mul(crate::transaction::WITNESS_SCALE_FACTOR - 1)
        .saturating_add(total);
    assert!(weight >= base.saturating_mul(crate::transaction::WITNESS_SCALE_FACTOR));
    assert!(weight >= total);
    weight
}

impl Block {
    fn decode_body(
        header: BlockHeader,
        input: &mut &[u8],
    ) -> Result<Self, crate::serialize::Error> {
        let count = crate::serialize::read_compact_size(input)?;
        let transactions = match count.checked_sub(1) {
            None => None,
            Some(rest_count) => {
                let first = crate::transaction::read_item(input)?;
                let rest = crate::transaction::read_items(input, rest_count)?;
                Some(Transactions { first, rest })
            }
        };
        Ok(Self {
            header,
            transactions,
        })
    }

    #[cfg(any(test, fuzzing))]
    fn transactions_iter(&self) -> impl Iterator<Item = &crate::transaction::Transaction> {
        self.transactions.iter().flat_map(Transactions::iter)
    }

    #[cfg(any(test, fuzzing))]
    fn size_without_witness(&self) -> usize {
        self.transactions
            .as_ref()
            .map_or(BLOCK_HEADER_SIZE + 1, Transactions::block_base_size)
    }

    #[cfg(any(test, fuzzing))]
    fn witness_bytes(&self) -> usize {
        self.transactions
            .as_ref()
            .map_or(0, Transactions::witness_bytes)
    }

    #[cfg(any(test, fuzzing))]
    fn size_with_witness(&self) -> usize {
        let base = self.size_without_witness();
        let witness = self.witness_bytes();
        let size = base + witness;
        assert!(size >= base);
        size
    }

    #[cfg(any(test, fuzzing))]
    fn weight(&self) -> usize {
        weight_from_base(self.size_without_witness(), self.witness_bytes())
    }

    #[cfg(any(test, fuzzing))]
    fn merkle_root(&self) -> crate::merkle::Root {
        crate::merkle::root(
            self.transactions_iter()
                .map(|transaction| transaction.txid().to_byte_array())
                .collect(),
        )
    }
}

impl Unmutated {
    fn check_mutation(
        block: Block,
        position: crate::chain::Position,
    ) -> Result<Unmutated, MutationError> {
        let Block {
            header,
            transactions,
        } = block;
        assert_eq!(header.hash(), position.hash());
        match position {
            crate::chain::Position::Block(block_position) => {
                assert!(header.time > block_position.prev_median_time_past());
            }
            #[cfg(any(test, fuzzing))]
            crate::chain::Position::Genesis { .. } => {}
        }
        let transactions = transactions.map(HashedTransactions::from_transactions);
        let root = match &transactions {
            Some(transactions) => transactions.merkle_root(),
            None => crate::merkle::root(Vec::new()),
        };
        if root.hash != header.merkle_root {
            return Err(MutationError::MerkleRoot);
        }
        if root.mutated {
            return Err(MutationError::DuplicateTransactions);
        }

        let Some(transactions) = transactions else {
            return Ok(Unmutated {
                position,
                header,
                transactions: None,
            });
        };
        let Some(coinbase_input) = transactions.first.transaction().coinbase_input() else {
            return if transactions
                .iter()
                .any(|transaction| transaction.size_without_witness() == TRANSACTION_SIZE_MUTATED)
            {
                Err(MutationError::TransactionOf64Bytes)
            } else {
                Ok(Unmutated {
                    position,
                    header,
                    transactions: Some(transactions),
                })
            };
        };

        let commitment = if position.height() >= position.network().segwit_height() {
            witness_commitment(transactions.first.transaction())
        } else {
            None
        };
        if let Some(commitment) = commitment {
            let reserved_value = coinbase_input
                .witness
                .reserved_value()
                .ok_or(MutationError::WitnessReservedValue)?;
            let witness_root = witness_merkle_root(
                transactions
                    .rest
                    .iter()
                    .map(crate::transaction::HashedTransaction::transaction),
            );
            let committed =
                bitcoin_hashes::sha256d::Hash::hash([witness_root, reserved_value].as_flattened());
            return if committed.as_byte_array() == commitment {
                Ok(Unmutated {
                    position,
                    header,
                    transactions: Some(transactions),
                })
            } else {
                Err(MutationError::WitnessMerkleRoot)
            };
        }

        if transactions
            .iter()
            .any(crate::transaction::Transaction::has_witness)
        {
            return Err(MutationError::UnexpectedWitness);
        }
        Ok(Unmutated {
            position,
            header,
            transactions: Some(transactions),
        })
    }

    fn check_consensus(self) -> Result<Checked, BlockError> {
        assert_eq!(self.header.hash(), self.position.hash());
        let Some(transactions) = self.transactions else {
            return Err(BlockError::Empty);
        };
        let base_size = transactions.block_base_size();
        if base_size > crate::transaction::BLOCK_BASE_SIZE_MAX {
            return Err(BlockError::BaseSizeTooLarge);
        }
        assert!(transactions.len() <= BLOCK_TRANSACTIONS_COUNT_MAX);
        let witness_bytes = transactions.witness_bytes();
        if transactions.first.transaction().coinbase_input().is_none() {
            return Err(BlockError::CoinbaseMissing);
        }
        if transactions
            .rest
            .iter()
            .any(|transaction| transaction.transaction().coinbase_input().is_some())
        {
            return Err(BlockError::MultipleCoinbases);
        }

        let network = self.position.network();
        let (height, lock_time_cutoff, bip34_height) = match self.position {
            crate::chain::Position::Block(block) => {
                assert!(self.header.time > block.prev_median_time_past());
                let lock_time_cutoff = if block.height() >= network.csv_height() {
                    block.prev_median_time_past()
                } else {
                    self.header.time
                };
                let bip34_height =
                    (block.height() >= network.bip34_height()).then_some(block.height());
                (block.height().get(), lock_time_cutoff, bip34_height)
            }
            #[cfg(any(test, fuzzing))]
            crate::chain::Position::Genesis { .. } => (0, self.header.time, None),
        };

        let mut seen_outpoints = std::collections::HashSet::new();
        let coinbase = transactions
            .first
            .into_checked_coinbase()
            .map_err(BlockError::Transaction)?;
        let mut sigops = coinbase.legacy_sigop_count();
        let mut all_final = coinbase.is_final(height, lock_time_cutoff);
        let mut rest = Vec::with_capacity(transactions.rest.len());
        for transaction in transactions.rest {
            let checked = transaction
                .into_checked_regular(&mut seen_outpoints)
                .map_err(BlockError::Transaction)?;
            sigops = sigops.saturating_add(checked.legacy_sigop_count());
            if !checked.is_final(height, lock_time_cutoff) {
                all_final = false;
            }
            rest.push(checked);
        }
        if sigops > LEGACY_SIGOPS_MAX {
            return Err(BlockError::SigOpsTooMany);
        }
        if !all_final {
            return Err(BlockError::NonFinalTransaction);
        }
        if let Some(bip34_height) = bip34_height {
            let expected = encode_bip34_height(bip34_height);
            if !coinbase.script_sig().starts_with(expected.as_slice()) {
                return Err(BlockError::CoinbaseHeight);
            }
        }
        if weight_from_base(base_size, witness_bytes) > crate::transaction::BLOCK_WEIGHT_MAX {
            return Err(BlockError::WeightTooLarge);
        }
        Ok(Checked {
            header: self.header,
            coinbase,
            rest,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Bip34Height {
    bytes: [u8; BIP34_HEIGHT_BYTES_MAX],
    length: usize,
}

impl Bip34Height {
    pub(crate) fn as_slice(&self) -> &[u8] {
        assert!(self.length >= 1);
        assert!(self.length <= BIP34_HEIGHT_BYTES_MAX);
        &self.bytes[..self.length]
    }
}

pub(crate) fn encode_bip34_height(height: std::num::NonZeroUsize) -> Bip34Height {
    let mut out = [0; BIP34_HEIGHT_BYTES_MAX];
    let value = height.get();
    if value <= 16 {
        let opcode =
            crate::transaction::OP_1_OFFSET + u8::try_from(value).expect("value is at most 16");
        assert!(opcode > crate::transaction::OP_1_OFFSET);
        assert!(opcode <= crate::transaction::OP_1_OFFSET + 16);
        out[0] = opcode;
        return Bip34Height {
            bytes: out,
            length: 1,
        };
    }
    let payload = &mut out[1..];
    let mut remaining = value;
    let mut payload_length = 0;
    for _ in 0..size_of::<usize>() {
        if remaining == 0 {
            break;
        }
        payload[payload_length] = remaining.to_le_bytes()[0];
        payload_length += 1;
        remaining >>= 8;
    }
    assert_eq!(remaining, 0);
    assert!(payload_length >= 1);
    assert!(payload_length <= size_of::<usize>());
    if payload[payload_length - 1] & 0x80 != 0 {
        payload[payload_length] = 0;
        payload_length += 1;
    }
    assert_eq!(payload[payload_length - 1] & 0x80, 0);
    assert!(payload[payload_length - 1] != 0 || payload[payload_length - 2] & 0x80 != 0);
    out[0] = u8::try_from(payload_length).expect("encoded usize fits in a direct script push");
    assert!(out[0] < crate::transaction::OP_PUSHDATA1);
    let total = 1 + payload_length;
    assert!(total >= 2);
    assert!(total <= BIP34_HEIGHT_BYTES_MAX);
    assert_eq!(usize::from(out[0]) + 1, total);
    Bip34Height {
        bytes: out,
        length: total,
    }
}

fn witness_merkle_root<'a>(
    after_coinbase: impl IntoIterator<Item = &'a crate::transaction::Transaction>,
) -> [u8; 32] {
    let coinbase_wtxid = [0; 32];
    let wtxids = after_coinbase
        .into_iter()
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
        match &self.transactions {
            None => crate::serialize::write_compact_size(out, 0),
            Some(transactions) => {
                crate::serialize::write_compact_size(out, transactions.len());
                for transaction in transactions.iter() {
                    transaction.encode(out);
                }
            }
        }
    }
}

impl Decode for Block {
    fn decode(input: &mut &[u8]) -> Result<Self, crate::serialize::Error> {
        let header = BlockHeader::decode(input)?;
        Self::decode_body(header, input)
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

impl std::fmt::Display for BlockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlockError::Empty => write!(f, "the block has no transactions"),
            BlockError::BaseSizeTooLarge => {
                write!(
                    f,
                    "the block is larger than {} bytes without witness",
                    crate::transaction::BLOCK_BASE_SIZE_MAX
                )
            }
            BlockError::CoinbaseMissing => write!(f, "the first transaction is not a coinbase"),
            BlockError::MultipleCoinbases => write!(f, "more than one transaction is a coinbase"),
            BlockError::Transaction(error) => write!(f, "{error}"),
            BlockError::SigOpsTooMany => {
                write!(f, "the legacy sigop cost is above {SIGOPS_COST_MAX}")
            }
            BlockError::NonFinalTransaction => write!(f, "a transaction is not final"),
            BlockError::CoinbaseHeight => {
                write!(
                    f,
                    "the coinbase scriptSig does not start with the block height"
                )
            }
            BlockError::WeightTooLarge => {
                write!(
                    f,
                    "the block weight is above {}",
                    crate::transaction::BLOCK_WEIGHT_MAX
                )
            }
        }
    }
}

impl std::error::Error for BlockError {}

impl std::fmt::Display for CheckError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CheckError::Mutated(error) => write!(f, "{error}"),
            CheckError::Invalid(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for CheckError {}

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
        assert_eq!(block.size_with_witness(), encoded.len());
        assert_eq!(
            block.weight(),
            block
                .size_without_witness()
                .saturating_mul(crate::transaction::WITNESS_SCALE_FACTOR - 1)
                .saturating_add(encoded.len())
        );
        for transaction in block.transactions_iter() {
            assert_eq!(
                transaction.txid() == transaction.wtxid(),
                !transaction.has_witness()
            );
        }

        let mut rooted = block.clone();
        rooted.header.merkle_root = block.merkle_root().hash;
        let prev_median_time_past = block.header.time.saturating_sub(1);
        for network in NETWORKS {
            for height in [
                0,
                network.bip34_height().get(),
                network.csv_height().get(),
                network.segwit_height(),
            ] {
                let make_position = |block: &super::Block| match std::num::NonZeroUsize::new(height)
                {
                    Some(height) => {
                        crate::chain::Position::Block(crate::chain::BlockPosition::new(
                            network,
                            height,
                            block.header.hash(),
                            prev_median_time_past,
                        ))
                    }
                    None => crate::chain::Position::genesis(network, block.header.hash()),
                };
                let rooted_position = make_position(&rooted);
                let block_position = make_position(&block);
                let Some(rooted_positioned) =
                    super::PositionedBlock::new(rooted.clone(), rooted_position)
                else {
                    assert_eq!(block.header.time, 0);
                    assert_eq!(
                        super::PositionedBlock::new(block.clone(), block_position),
                        None
                    );
                    continue;
                };
                let rooted_result = rooted_positioned.check().map(|_| ());
                assert_ne!(
                    rooted_result,
                    Err(super::CheckError::Mutated(super::MutationError::MerkleRoot))
                );
                let block_result = super::PositionedBlock::new(block.clone(), block_position)
                    .expect("same header time and matching hash")
                    .check()
                    .map(|_| ());
                assert_eq!(
                    block_result,
                    if block.header.merkle_root == rooted.header.merkle_root {
                        rooted_result
                    } else {
                        Err(super::CheckError::Mutated(super::MutationError::MerkleRoot))
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

    fn position_at(
        block: &super::Block,
        network: crate::chainparams::Network,
        height: usize,
        prev_median_time_past: u32,
    ) -> crate::chain::Position {
        match std::num::NonZeroUsize::new(height) {
            Some(height) => crate::chain::Position::Block(crate::chain::BlockPosition::new(
                network,
                height,
                block.header.hash(),
                prev_median_time_past,
            )),
            None => crate::chain::Position::genesis(network, block.header.hash()),
        }
    }

    fn check(
        block: super::Block,
        network: crate::chainparams::Network,
        height: usize,
    ) -> Result<(), super::CheckError> {
        let prev_median_time_past = block.header.time.checked_sub(1).unwrap();
        check_with_median_time_past(block, network, height, prev_median_time_past)
    }

    fn check_with_median_time_past(
        block: super::Block,
        network: crate::chainparams::Network,
        height: usize,
        prev_median_time_past: u32,
    ) -> Result<(), super::CheckError> {
        let position = position_at(&block, network, height, prev_median_time_past);
        let checked = super::PositionedBlock::new(block.clone(), position)
            .unwrap()
            .check()?;
        let expected = block.transactions.unwrap();
        assert_eq!(checked.header(), block.header);
        assert_eq!(checked.coinbase().txid(), expected.first.txid());
        assert_eq!(
            checked.coinbase().script_sig(),
            expected.first.inputs()[0].script_sig.as_slice()
        );
        assert_eq!(
            checked.coinbase().outputs().len().get(),
            expected.first.outputs().len()
        );
        let rest_txids: Vec<_> = checked.rest().iter().map(|tx| tx.txid()).collect();
        let expected_txids: Vec<_> = expected.rest.iter().map(|tx| tx.txid()).collect();
        assert_eq!(rest_txids, expected_txids);
        Ok(())
    }

    fn with_commitment(mut block: super::Block) -> super::Block {
        let reserved_value = [0_u8; 32];
        let transactions = block.transactions.as_mut().unwrap();
        let witness_root = super::witness_merkle_root(&transactions.rest);
        let committed =
            bitcoin_hashes::sha256d::Hash::hash([witness_root, reserved_value].as_flattened());
        let mut script_pubkey = super::WITNESS_COMMITMENT_HEADER.to_vec();
        script_pubkey.extend_from_slice(committed.as_byte_array());
        let coinbase_witness = [&[0x01, 0x20][..], &reserved_value].concat();
        transactions.first = changed(&transactions.first, |inputs, outputs| {
            inputs[0].witness = witness(&coinbase_witness);
            outputs.retain(|output| {
                !output
                    .script_pubkey
                    .starts_with(&super::WITNESS_COMMITMENT_HEADER)
            });
            outputs.push(crate::transaction::TxOut {
                value: 0,
                script_pubkey,
            });
        });
        with_merkle_root(block)
    }

    fn valid_block_at(height: usize) -> super::Block {
        let mut script_sig = match std::num::NonZeroUsize::new(height) {
            Some(height) => super::encode_bip34_height(height).as_slice().to_vec(),
            None => Vec::new(),
        };
        if script_sig.len() < 2 {
            script_sig.resize(2, 0);
        }
        let coinbase = crate::transaction::Transaction::new(
            1,
            vec![crate::transaction::TxIn {
                previous_output: crate::transaction::OutPoint {
                    txid: bitcoin_hashes::sha256d::Hash::from_byte_array([0; 32]),
                    vout: u32::MAX,
                },
                script_sig,
                sequence: u32::MAX,
                witness: crate::transaction::Witness::default(),
            }],
            vec![crate::transaction::TxOut {
                value: 50_0000_0000,
                script_pubkey: Vec::new(),
            }],
            0,
        )
        .unwrap();
        with_merkle_root(super::Block {
            header: REGTEST.genesis(),
            transactions: Some(super::Transactions {
                first: coinbase,
                rest: Vec::new(),
            }),
        })
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
            transaction.lock_time_raw(),
        )
        .unwrap()
    }

    #[test]
    fn position_of_another_block_is_refused() {
        let block = block_103();
        let position = crate::chain::Position::genesis(REGTEST, REGTEST.genesis().hash());
        assert_eq!(super::PositionedBlock::new(block.clone(), position), None);
        let block_position = crate::chain::BlockPosition::new(
            REGTEST,
            std::num::NonZeroUsize::MIN,
            REGTEST.genesis().hash(),
            0,
        );
        assert_eq!(
            super::MatchedHeader::new(block_position, block.header),
            None
        );

        for invalid_time_past in [block.header.time, block.header.time + 1] {
            let bad_time = crate::chain::BlockPosition::new(
                REGTEST,
                std::num::NonZeroUsize::MIN,
                block.header.hash(),
                invalid_time_past,
            );
            assert_eq!(super::MatchedHeader::new(bad_time, block.header), None);
            assert_eq!(
                super::PositionedBlock::new(block.clone(), bad_time.position()),
                None
            );
        }
        let valid_time = crate::chain::BlockPosition::new(
            REGTEST,
            std::num::NonZeroUsize::MIN,
            block.header.hash(),
            block.header.time - 1,
        );
        assert!(super::MatchedHeader::new(valid_time, block.header).is_some());
        assert!(super::PositionedBlock::new(block, valid_time.position()).is_some());
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
        assert_eq!(block.size_with_witness(), encoded.len());

        assert_eq!(
            block.header.hash(),
            crate::fixtures::hash_from_display_hex(
                "2e1b26f32330298af67653f3e37c35937b07ebf828864abeb68456eef3acdc31"
            )
        );
        let txids: Vec<_> = block.transactions_iter().map(|t| t.txid()).collect();
        assert_eq!(
            txids,
            [
                "efce6cee0fd4dd9f3542a8e7b1cbac943d87d22383a6a0ab358025cb2ad85927",
                "85cd22b7b5402a07a3b0cb8e4e5ea71a315e5a3c6b519cd03cf586c8b40a87f2",
                "a041d4b35c28a2577a728ae1f7300ec3cd7d35e0fcba70850a2e7ce223942176",
            ]
            .map(crate::fixtures::hash_from_display_hex)
        );
        let witnesses: Vec<_> = block.transactions_iter().map(|t| t.has_witness()).collect();
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
    fn core_blocks_pass_all_checks() {
        let block = block_103();
        let position = position_at(&block, REGTEST, 103, block.header.time - 1);
        assert_eq!(
            super::PositionedBlock::new(block.clone(), position)
                .unwrap()
                .check()
                .unwrap()
                .transactions_count()
                .get(),
            3
        );
        let bytes = crate::fixtures::hex(crate::fixtures::REGTEST_BLOCK_103);
        let mut input = bytes.as_slice();
        let header = super::BlockHeader::decode(&mut input).unwrap();
        let height = std::num::NonZeroUsize::new(103).unwrap();
        let block_position =
            crate::chain::BlockPosition::new(REGTEST, height, header.hash(), header.time - 1);
        let checked_raw = super::PositionedBlock::new(block.clone(), block_position.position())
            .unwrap()
            .check()
            .unwrap();
        let wrong_hash = crate::chain::BlockPosition::new(
            REGTEST,
            height,
            REGTEST.genesis().hash(),
            header.time - 1,
        );
        let equal_time =
            crate::chain::BlockPosition::new(REGTEST, height, header.hash(), header.time);
        assert_eq!(
            super::CheckedBlock::from_checked(wrong_hash, checked_raw.clone()),
            None
        );
        assert_eq!(
            super::CheckedBlock::from_checked(equal_time, checked_raw),
            None
        );
        let matched = super::MatchedHeader::new(block_position, header).unwrap();
        assert_eq!(matched.position(), block_position);
        let checked = matched.decode_body(&mut input).unwrap().check().unwrap();
        assert_eq!(checked.height(), height);
        assert_eq!(checked.position().hash(), block.header.hash());
        assert_eq!(checked.transactions_count().get(), 3);

        let genesis = crate::fixtures::block(crate::fixtures::REGTEST_GENESIS_BLOCK);
        assert_eq!(genesis.header, REGTEST.genesis());
        let position = crate::chain::Position::genesis(REGTEST, genesis.header.hash());
        assert_eq!(
            super::PositionedBlock::new(genesis, position)
                .unwrap()
                .check()
                .unwrap()
                .transactions_count()
                .get(),
            1
        );
    }

    #[test]
    fn other_merkle_root_in_the_header_is_bad_txnmrklroot() {
        let mut block = block_103();
        block.header.merkle_root[0] ^= 1;
        assert_eq!(
            check(block, REGTEST, 103),
            Err(super::CheckError::Mutated(super::MutationError::MerkleRoot))
        );
    }

    #[test]
    fn duplicate_last_transaction_is_bad_txns_duplicate() {
        let mut block = block_103();
        let transactions = block.transactions.as_mut().unwrap();
        let last = transactions.rest[1].clone();
        transactions.rest.push(last);
        assert_eq!(
            check(block, REGTEST, 103),
            Err(super::CheckError::Mutated(
                super::MutationError::DuplicateTransactions
            ))
        );
    }

    #[test]
    fn other_witness_is_bad_witness_merkle_match() {
        let mut block = block_103();
        let transactions = block.transactions.as_mut().unwrap();
        transactions.rest[0] = changed(&transactions.rest[0], |inputs, _| {
            inputs[0].witness = witness(&[0x01, 0x01, 0xbb]);
        });
        assert_eq!(
            check(block, REGTEST, 103),
            Err(super::CheckError::Mutated(
                super::MutationError::WitnessMerkleRoot
            ))
        );
    }

    #[test]
    fn coinbase_witness_other_than_one_item_of_32_bytes_is_bad_witness_nonce_size() {
        let short = [&[0x01, 0x1f][..], &[0; 31]].concat();
        let two = [&[0x02, 0x20][..], &[0; 32], &[0x00]].concat();
        for coinbase_witness in [short, two] {
            let mut block = block_103();
            let transactions = block.transactions.as_mut().unwrap();
            transactions.first = changed(&transactions.first, |inputs, _| {
                inputs[0].witness = witness(&coinbase_witness);
            });
            assert_eq!(
                check(block, REGTEST, 103),
                Err(super::CheckError::Mutated(
                    super::MutationError::WitnessReservedValue
                ))
            );
        }
    }

    #[test]
    fn witness_with_no_commitment_is_unexpected_witness() {
        let mut block = block_103();
        let mut commitment = None;
        let transactions = block.transactions.as_mut().unwrap();
        transactions.first = changed(&transactions.first, |_, outputs| {
            commitment = outputs.pop();
        });
        let commitment = commitment.unwrap();
        assert_eq!(
            commitment.script_pubkey[..6],
            super::WITNESS_COMMITMENT_HEADER
        );
        assert_eq!(
            check(with_merkle_root(block), REGTEST, 103),
            Err(super::CheckError::Mutated(
                super::MutationError::UnexpectedWitness
            ))
        );
    }

    #[test]
    fn commitment_is_the_last_output_that_has_its_header() {
        let mut block = block_103();
        let mut other = block.transactions.as_ref().unwrap().first.outputs()[1].clone();
        other.script_pubkey[6] ^= 1;
        block.transactions.as_mut().unwrap().first =
            changed(&block.transactions.as_ref().unwrap().first, |_, outputs| {
                outputs.push(other.clone());
            });
        assert_eq!(
            check(with_merkle_root(block.clone()), REGTEST, 103),
            Err(super::CheckError::Mutated(
                super::MutationError::WitnessMerkleRoot
            ))
        );

        other.script_pubkey.truncate(37);
        block.transactions.as_mut().unwrap().first =
            changed(&block.transactions.as_ref().unwrap().first, |_, outputs| {
                *outputs.last_mut().unwrap() = other;
            });
        assert_eq!(check(with_merkle_root(block), REGTEST, 103), Ok(()));
    }

    #[test]
    fn witness_before_segwit_is_unexpected_witness() {
        let mainnet = crate::chainparams::Network::Mainnet;
        let mut block = block_103();
        let height_bytes =
            super::encode_bip34_height(std::num::NonZeroUsize::new(481_824).unwrap());
        let transactions = block.transactions.as_mut().unwrap();
        transactions.first = changed(&transactions.first, |inputs, _| {
            inputs[0].script_sig = height_bytes.as_slice().to_vec();
        });
        let block = with_merkle_root(block);
        assert_eq!(check(block.clone(), mainnet, 481_824), Ok(()));
        assert_eq!(
            check(block, mainnet, 481_823),
            Err(super::CheckError::Mutated(
                super::MutationError::UnexpectedWitness
            ))
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
                transactions: Some(super::Transactions {
                    first: transaction_of(size),
                    rest: Vec::new(),
                }),
            })
        };
        assert_eq!(
            check(block(64), REGTEST, 1),
            Err(super::CheckError::Mutated(
                super::MutationError::TransactionOf64Bytes
            ))
        );
        assert_eq!(
            check(block(65), REGTEST, 1),
            Err(super::CheckError::Invalid(
                super::BlockError::CoinbaseMissing
            ))
        );
    }

    #[test]
    fn coinbase_first_and_a_transaction_of_64_bytes_is_not_mutated() {
        let mut block = valid_block_at(1);
        block
            .transactions
            .as_mut()
            .unwrap()
            .rest
            .push(transaction_of(64));
        assert_eq!(check(with_merkle_root(block), REGTEST, 1), Ok(()));
    }

    #[test]
    fn no_transactions_with_a_zero_merkle_root_is_empty() {
        let block = super::Block {
            header: super::BlockHeader {
                merkle_root: [0; 32],
                ..REGTEST.genesis()
            },
            transactions: None,
        };
        let mut encoded = Vec::new();
        block.encode(&mut encoded);
        assert_eq!(block.size_without_witness(), encoded.len());
        assert_eq!(block.size_with_witness(), encoded.len());
        assert_eq!(
            block.weight(),
            encoded.len() * crate::transaction::WITNESS_SCALE_FACTOR
        );
        assert_eq!(
            super::Block::decode(&mut encoded.as_slice()),
            Ok(block.clone())
        );
        assert_eq!(
            check(block, REGTEST, 1),
            Err(super::CheckError::Invalid(super::BlockError::Empty))
        );
    }

    #[test]
    fn base_size_limit_rejects_above_one_million_bytes() {
        let make = |target_size: usize| {
            let mut block = valid_block_at(1);
            let overhead = block.size_without_witness();
            let filler = target_size - overhead - 60 - 4;
            let tx = crate::transaction::Transaction::new(
                1,
                vec![crate::transaction::TxIn {
                    previous_output: crate::transaction::OutPoint {
                        txid: bitcoin_hashes::sha256d::Hash::from_byte_array([0x11; 32]),
                        vout: 0,
                    },
                    script_sig: Vec::new(),
                    sequence: u32::MAX,
                    witness: crate::transaction::Witness::default(),
                }],
                vec![crate::transaction::TxOut {
                    value: 0,
                    script_pubkey: vec![0x51; filler],
                }],
                0,
            )
            .unwrap();
            block.transactions.as_mut().unwrap().rest.push(tx);
            let block = with_merkle_root(block);
            assert_eq!(block.size_without_witness(), target_size);
            block
        };
        assert_eq!(
            check(make(crate::transaction::BLOCK_BASE_SIZE_MAX), REGTEST, 1),
            Ok(())
        );
        assert_eq!(
            check(
                make(crate::transaction::BLOCK_BASE_SIZE_MAX + 1),
                REGTEST,
                1
            ),
            Err(super::CheckError::Invalid(
                super::BlockError::BaseSizeTooLarge
            ))
        );

        let make_many = |target_size: usize| {
            let mut block = valid_block_at(1);
            let rest = &mut block.transactions.as_mut().unwrap().rest;
            for vout in 0..251_u32 {
                rest.push(
                    crate::transaction::Transaction::new(
                        1,
                        vec![crate::transaction::TxIn {
                            previous_output: crate::transaction::OutPoint {
                                txid: bitcoin_hashes::sha256d::Hash::from_byte_array([0x22; 32]),
                                vout,
                            },
                            script_sig: Vec::new(),
                            sequence: u32::MAX,
                            witness: crate::transaction::Witness::default(),
                        }],
                        vec![crate::transaction::TxOut {
                            value: 0,
                            script_pubkey: Vec::new(),
                        }],
                        0,
                    )
                    .unwrap(),
                );
            }
            let overhead = block.size_without_witness() + 2;
            let filler = target_size - overhead - 60 - 4;
            let filler_tx = crate::transaction::Transaction::new(
                1,
                vec![crate::transaction::TxIn {
                    previous_output: crate::transaction::OutPoint {
                        txid: bitcoin_hashes::sha256d::Hash::from_byte_array([0x22; 32]),
                        vout: 251,
                    },
                    script_sig: Vec::new(),
                    sequence: u32::MAX,
                    witness: crate::transaction::Witness::default(),
                }],
                vec![crate::transaction::TxOut {
                    value: 0,
                    script_pubkey: vec![0x51; filler],
                }],
                0,
            )
            .unwrap();
            block.transactions.as_mut().unwrap().rest.push(filler_tx);
            let block = with_merkle_root(block);
            assert_eq!(block.size_without_witness(), target_size);
            block
        };
        assert_eq!(
            check(
                make_many(crate::transaction::BLOCK_BASE_SIZE_MAX),
                REGTEST,
                1
            ),
            Ok(())
        );
        assert_eq!(
            check(
                make_many(crate::transaction::BLOCK_BASE_SIZE_MAX + 1),
                REGTEST,
                1
            ),
            Err(super::CheckError::Invalid(
                super::BlockError::BaseSizeTooLarge
            ))
        );
    }

    #[test]
    fn second_coinbase_is_multiple_coinbases() {
        let mut block = valid_block_at(1);
        let transactions = block.transactions.as_mut().unwrap();
        let mut second = transactions.first.clone();
        second = changed(&second, |inputs, _| {
            inputs[0].script_sig.push(0x99);
        });
        transactions.rest.push(second);
        assert_eq!(
            check(with_merkle_root(block), REGTEST, 1),
            Err(super::CheckError::Invalid(
                super::BlockError::MultipleCoinbases
            ))
        );
    }

    #[test]
    fn transaction_check_error_propagates_as_block_error() {
        let mut block = valid_block_at(1);
        let transactions = block.transactions.as_mut().unwrap();
        transactions.first = changed(&transactions.first, |_, outputs| {
            outputs[0].value = -1;
        });
        assert_eq!(
            check(with_merkle_root(block), REGTEST, 1),
            Err(super::CheckError::Invalid(super::BlockError::Transaction(
                crate::transaction::TransactionError::OutputNegative
            )))
        );
    }

    #[test]
    fn legacy_sigop_limit_is_twenty_thousand() {
        let make = |extra_checksig: bool| {
            let mut block = valid_block_at(1);
            let mut script_pubkey = vec![0xae; super::LEGACY_SIGOPS_MAX / 20];
            if extra_checksig {
                script_pubkey.push(0xac);
            }
            block.transactions.as_mut().unwrap().rest.push(
                crate::transaction::Transaction::new(
                    1,
                    vec![crate::transaction::TxIn {
                        previous_output: crate::transaction::OutPoint {
                            txid: bitcoin_hashes::sha256d::Hash::from_byte_array([0x22; 32]),
                            vout: 0,
                        },
                        script_sig: Vec::new(),
                        sequence: u32::MAX,
                        witness: crate::transaction::Witness::default(),
                    }],
                    vec![crate::transaction::TxOut {
                        value: 0,
                        script_pubkey,
                    }],
                    0,
                )
                .unwrap(),
            );
            with_merkle_root(block)
        };
        assert_eq!(check(make(false), REGTEST, 1), Ok(()));
        assert_eq!(
            check(make(true), REGTEST, 1),
            Err(super::CheckError::Invalid(super::BlockError::SigOpsTooMany))
        );
    }

    #[test]
    fn finality_switches_from_header_time_to_prev_median_time_past_at_csv_height() {
        let mainnet = crate::chainparams::Network::Mainnet;
        let header_time = 600_000_010;
        let prev_median_time_past = 600_000_000;
        let make = |height: usize, lock_time: u32| {
            let mut block = valid_block_at(height);
            block.header.time = header_time;
            block.transactions.as_mut().unwrap().rest.push(
                crate::transaction::Transaction::new(
                    1,
                    vec![crate::transaction::TxIn {
                        previous_output: crate::transaction::OutPoint {
                            txid: bitcoin_hashes::sha256d::Hash::from_byte_array([0x33; 32]),
                            vout: 0,
                        },
                        script_sig: Vec::new(),
                        sequence: 0,
                        witness: crate::transaction::Witness::default(),
                    }],
                    vec![crate::transaction::TxOut {
                        value: 0,
                        script_pubkey: Vec::new(),
                    }],
                    lock_time,
                )
                .unwrap(),
            );
            with_merkle_root(block)
        };

        assert_eq!(
            check_with_median_time_past(
                make(419_327, 600_000_005),
                mainnet,
                419_327,
                prev_median_time_past
            ),
            Ok(())
        );
        assert_eq!(
            check_with_median_time_past(
                make(419_328, 600_000_005),
                mainnet,
                419_328,
                prev_median_time_past
            ),
            Err(super::CheckError::Invalid(
                super::BlockError::NonFinalTransaction
            ))
        );
        assert_eq!(
            check_with_median_time_past(
                make(419_329, 600_000_005),
                mainnet,
                419_329,
                prev_median_time_past
            ),
            Err(super::CheckError::Invalid(
                super::BlockError::NonFinalTransaction
            ))
        );
        assert_eq!(
            check_with_median_time_past(
                make(419_328, prev_median_time_past),
                mainnet,
                419_328,
                prev_median_time_past
            ),
            Err(super::CheckError::Invalid(
                super::BlockError::NonFinalTransaction
            ))
        );
        assert_eq!(
            check_with_median_time_past(
                make(419_328, prev_median_time_past - 1),
                mainnet,
                419_328,
                prev_median_time_past
            ),
            Ok(())
        );
        assert_eq!(
            check_with_median_time_past(
                make(419_328, 419_328),
                mainnet,
                419_328,
                prev_median_time_past
            ),
            Err(super::CheckError::Invalid(
                super::BlockError::NonFinalTransaction
            ))
        );
        assert_eq!(
            check_with_median_time_past(
                make(419_328, 419_327),
                mainnet,
                419_328,
                prev_median_time_past
            ),
            Ok(())
        );
        assert_eq!(
            check_with_median_time_past(make(0, header_time - 1), REGTEST, 0, 0),
            Ok(())
        );
        assert_eq!(
            check_with_median_time_past(make(0, header_time), REGTEST, 0, 0),
            Err(super::CheckError::Invalid(
                super::BlockError::NonFinalTransaction
            ))
        );
    }

    #[test]
    fn bip34_height_encoding_and_activation_match_core() {
        for (height, expected) in [
            (1_usize, &[0x51][..]),
            (16, &[0x60]),
            (17, &[0x01, 0x11]),
            (103, &[0x01, 0x67]),
            (127, &[0x01, 0x7f]),
            (128, &[0x02, 0x80, 0x00]),
            (255, &[0x02, 0xff, 0x00]),
            (256, &[0x02, 0x00, 0x01]),
            (32_767, &[0x02, 0xff, 0x7f]),
            (32_768, &[0x03, 0x00, 0x80, 0x00]),
            (227_931, &[0x03, 0x5b, 0x7a, 0x03]),
            (8_388_607, &[0x03, 0xff, 0xff, 0x7f]),
            (8_388_608, &[0x04, 0x00, 0x00, 0x80, 0x00]),
        ] {
            let encoded = super::encode_bip34_height(std::num::NonZeroUsize::new(height).unwrap());
            assert_eq!(encoded.as_slice(), expected, "{height}");
        }
        let max_encoded =
            super::encode_bip34_height(std::num::NonZeroUsize::new(usize::MAX).unwrap());
        assert_eq!(max_encoded.as_slice().len(), super::BIP34_HEIGHT_BYTES_MAX);
        assert_eq!(*max_encoded.as_slice().last().unwrap(), 0);

        let mainnet = crate::chainparams::Network::Mainnet;
        let wrong_script = |height: usize| {
            let mut block = valid_block_at(height);
            let transactions = block.transactions.as_mut().unwrap();
            transactions.first = changed(&transactions.first, |inputs, _| {
                inputs[0].script_sig = vec![0x01, 0x01];
            });
            with_merkle_root(block)
        };
        assert_eq!(check(wrong_script(227_930), mainnet, 227_930), Ok(()));
        assert_eq!(
            check(wrong_script(227_931), mainnet, 227_931),
            Err(super::CheckError::Invalid(
                super::BlockError::CoinbaseHeight
            ))
        );
        assert_eq!(check(valid_block_at(227_931), mainnet, 227_931), Ok(()));
        assert_eq!(
            check(wrong_script(1), REGTEST, 1),
            Err(super::CheckError::Invalid(
                super::BlockError::CoinbaseHeight
            ))
        );
        assert_eq!(
            check(wrong_script(2), REGTEST, 2),
            Err(super::CheckError::Invalid(
                super::BlockError::CoinbaseHeight
            ))
        );
        assert_eq!(check(valid_block_at(1), REGTEST, 1), Ok(()));
    }

    #[test]
    fn weight_limit_checks_after_witness_malleation() {
        let make = |witness_item_size: usize| {
            let mut block = valid_block_at(1);
            let mut witness_bytes = Vec::new();
            crate::serialize::write_compact_size(&mut witness_bytes, 1);
            crate::serialize::write_compact_size(&mut witness_bytes, witness_item_size);
            witness_bytes.resize(witness_bytes.len() + witness_item_size, 0xaa);
            let spend = crate::transaction::Transaction::new(
                1,
                vec![crate::transaction::TxIn {
                    previous_output: crate::transaction::OutPoint {
                        txid: bitcoin_hashes::sha256d::Hash::from_byte_array([0x44; 32]),
                        vout: 0,
                    },
                    script_sig: Vec::new(),
                    sequence: u32::MAX,
                    witness: witness(&witness_bytes),
                }],
                vec![crate::transaction::TxOut {
                    value: 0,
                    script_pubkey: vec![0x51; 999_000],
                }],
                0,
            )
            .unwrap();
            block.transactions.as_mut().unwrap().rest.push(spend);
            with_commitment(block)
        };

        let sample = make(1_000);
        assert!(sample.size_without_witness() <= crate::transaction::BLOCK_BASE_SIZE_MAX);
        assert!(sample.weight() < crate::transaction::BLOCK_WEIGHT_MAX);
        let extra = crate::transaction::BLOCK_WEIGHT_MAX - sample.weight();
        let at_limit = make(1_000 + extra);
        assert_eq!(at_limit.weight(), crate::transaction::BLOCK_WEIGHT_MAX);
        assert_eq!(check(at_limit.clone(), REGTEST, 1), Ok(()));

        let over_limit = make(1_000 + extra + 1);
        assert_eq!(
            over_limit.weight(),
            crate::transaction::BLOCK_WEIGHT_MAX + 1
        );
        assert_eq!(
            check(over_limit, REGTEST, 1),
            Err(super::CheckError::Invalid(
                super::BlockError::WeightTooLarge
            ))
        );

        let mut bloated_coinbase = at_limit.clone();
        let bad_coinbase_witness = [&[0x01, 0x21][..], &[0; 33]].concat();
        let transactions = bloated_coinbase.transactions.as_mut().unwrap();
        transactions.first = changed(&transactions.first, |inputs, _| {
            inputs[0].witness = witness(&bad_coinbase_witness);
        });
        assert!(bloated_coinbase.weight() > crate::transaction::BLOCK_WEIGHT_MAX);
        assert_eq!(
            check(bloated_coinbase, REGTEST, 1),
            Err(super::CheckError::Mutated(
                super::MutationError::WitnessReservedValue
            ))
        );

        let mut bloated_spend = at_limit;
        let mut bad_spend_witness = Vec::new();
        crate::serialize::write_compact_size(&mut bad_spend_witness, 1);
        crate::serialize::write_compact_size(&mut bad_spend_witness, 1_000 + extra + 1);
        bad_spend_witness.resize(bad_spend_witness.len() + 1_000 + extra + 1, 0xaa);
        let transactions = bloated_spend.transactions.as_mut().unwrap();
        transactions.rest[0] = changed(&transactions.rest[0], |inputs, _| {
            inputs[0].witness = witness(&bad_spend_witness);
        });
        assert!(bloated_spend.weight() > crate::transaction::BLOCK_WEIGHT_MAX);
        assert_eq!(
            check(bloated_spend, REGTEST, 1),
            Err(super::CheckError::Mutated(
                super::MutationError::WitnessMerkleRoot
            ))
        );
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
