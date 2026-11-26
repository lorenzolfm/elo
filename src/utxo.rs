const COINBASE_MATURITY_BLOCKS: usize = 100;

const BLOCK_SUBSIDY_INITIAL: i64 = 50 * crate::transaction::COIN;

const SUBSIDY_HALVINGS_MAX: u32 = 64;

const _: () = assert!(BLOCK_SUBSIDY_INITIAL == 5_000_000_000);
const _: () = assert!(BLOCK_SUBSIDY_INITIAL <= crate::transaction::MONEY_MAX);

const _: () = assert!(
    BLOCK_SUBSIDY_INITIAL
        * 2
        * (crate::chainparams::Network::Mainnet
            .subsidy_halving_interval()
            .get() as i64)
        <= crate::transaction::MONEY_MAX
);
const _: () = assert!(
    BLOCK_SUBSIDY_INITIAL
        * 2
        * (crate::chainparams::Network::Regtest
            .subsidy_halving_interval()
            .get() as i64)
        <= crate::transaction::MONEY_MAX
);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectError {
    DuplicateTxId,
    MissingInputs,
    PrematureCoinbaseSpend,
    InputsBelowOutputs,
    NonFinalSequence,
    SigOpsTooMany,
    CoinbaseAmount,
}

impl std::fmt::Display for ConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectError::DuplicateTxId => {
                write!(f, "a transaction overwrites an unspent transaction id")
            }
            ConnectError::MissingInputs => {
                write!(f, "a transaction input is missing or already spent")
            }
            ConnectError::PrematureCoinbaseSpend => {
                write!(
                    f,
                    "a transaction spends a coinbase output before {COINBASE_MATURITY_BLOCKS} confirmations"
                )
            }
            ConnectError::InputsBelowOutputs => {
                write!(f, "a transaction spends less than its outputs pay")
            }
            ConnectError::NonFinalSequence => {
                write!(f, "a transaction does not satisfy its relative lock-time")
            }
            ConnectError::SigOpsTooMany => {
                write!(
                    f,
                    "the block sigop cost is above {}",
                    crate::block::SIGOPS_COST_MAX
                )
            }
            ConnectError::CoinbaseAmount => {
                write!(f, "the coinbase pays more than the subsidy plus fees")
            }
        }
    }
}

impl std::error::Error for ConnectError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectedBlock {
    position: crate::chain::BlockPosition,
    transactions_count: std::num::NonZeroUsize,
}

impl ConnectedBlock {
    pub(crate) fn height(&self) -> std::num::NonZeroUsize {
        self.position.height()
    }

    #[cfg(any(test, fuzzing))]
    #[cfg_attr(false, mutants::skip)]
    pub(crate) fn hash(&self) -> bitcoin_hashes::sha256d::Hash {
        self.position.hash()
    }

    pub(crate) fn hash_display(&self) -> impl std::fmt::Display {
        self.position.hash_display()
    }

    pub(crate) fn transactions_count(&self) -> std::num::NonZeroUsize {
        self.transactions_count
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DisconnectTip {
    pub(crate) block_hash: bitcoin_hashes::sha256d::Hash,
    pub(crate) prev_hash: bitcoin_hashes::sha256d::Hash,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct UtxoSet {
    network: crate::chainparams::Network,
    coins: std::collections::HashMap<crate::transaction::OutPoint, Coin>,
    undo: Vec<BlockUndo>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Coin {
    output: crate::transaction::TxOut,
    height: std::num::NonZeroUsize,
    is_coinbase: bool,
}

const _: () = assert!(size_of::<Coin>() <= 48);

#[derive(Clone, Debug, PartialEq, Eq)]
struct BlockUndo {
    block_hash: bitcoin_hashes::sha256d::Hash,
    prev_hash: bitcoin_hashes::sha256d::Hash,
    created: Vec<crate::transaction::OutPoint>,
    spent: Vec<(crate::transaction::OutPoint, Coin)>,
    overwritten: Vec<(crate::transaction::OutPoint, Coin)>,
}

impl UtxoSet {
    pub(crate) fn new(network: crate::chainparams::Network) -> UtxoSet {
        UtxoSet {
            network,
            coins: std::collections::HashMap::new(),
            undo: Vec::new(),
        }
    }

    pub(crate) fn height(&self) -> usize {
        self.undo.len()
    }

    pub(crate) fn best_block(&self) -> bitcoin_hashes::sha256d::Hash {
        self.undo
            .last()
            .map_or_else(|| self.network.genesis().hash(), |undo| undo.block_hash)
    }

    pub(crate) fn connect_block(
        &mut self,
        block: crate::block::CheckedBlock,
        ancestor_median_time_past: impl Fn(usize) -> u32,
    ) -> Result<ConnectedBlock, ConnectError> {
        let position = block.position();
        assert_eq!(position.network(), self.network);
        let height = position.height();
        let prev_hash = self.best_block();
        assert_eq!(height.get(), self.height() + 1);
        assert_eq!(block.header().prev, prev_hash);
        assert_eq!(
            ancestor_median_time_past(height.get() - 1),
            position.prev_median_time_past()
        );

        let coinbase = block.coinbase();
        let rest = block.rest();
        assert_eq!(coinbase.inputs().len(), 1);
        assert!(coinbase.inputs()[0].previous_output.is_null());
        let coinbase_txid = coinbase.txid();

        let bip30_repeat = self.network.is_bip30_repeat(height, position.hash());
        if bip30_repeat {
            assert_eq!(self.network, crate::chainparams::Network::Mainnet);
        } else if has_unspent_output(&self.coins, coinbase_txid, coinbase.outputs().len()) {
            return Err(ConnectError::DuplicateTxId);
        }
        for transaction in rest {
            if has_unspent_output(&self.coins, transaction.txid(), transaction.outputs().len()) {
                return Err(ConnectError::DuplicateTxId);
            }
        }

        let enforce_bip68 = height >= self.network.csv_height();
        let mut sigops_cost = coinbase
            .legacy_sigop_count()
            .saturating_mul(crate::transaction::WITNESS_SCALE_FACTOR);
        assert!(sigops_cost <= crate::block::SIGOPS_COST_MAX);

        let mut overlay = Overlay::new(&self.coins);
        overlay.add_outputs(
            coinbase_txid,
            coinbase.outputs(),
            height,
            OutputKind::Coinbase {
                allow_overwrite: bip30_repeat,
            },
        );

        let mut fees: i64 = 0;
        for transaction in rest {
            let inputs = transaction.inputs();
            let mut spent_coins = Vec::with_capacity(inputs.len());
            for input in inputs {
                assert!(!input.previous_output.is_null());
                let coin = overlay
                    .get(&input.previous_output)
                    .ok_or(ConnectError::MissingInputs)?;
                spent_coins.push(coin);
            }

            let mut value_in: i64 = 0;
            for coin in &spent_coins {
                assert!(coin.height <= height);
                if coin.is_coinbase {
                    let age_blocks = height.get() - coin.height.get();
                    if age_blocks < COINBASE_MATURITY_BLOCKS {
                        return Err(ConnectError::PrematureCoinbaseSpend);
                    }
                }
                assert!(!coin.output.is_unspendable());
                assert!(coin.output.value >= 0);
                assert!(coin.output.value <= crate::transaction::MONEY_MAX);
                value_in += coin.output.value;
                assert!(value_in <= crate::transaction::MONEY_MAX);
            }

            let value_out = transaction.value_out();
            if value_in < value_out {
                return Err(ConnectError::InputsBelowOutputs);
            }
            let transaction_fee = value_in - value_out;
            assert!(transaction_fee >= 0);
            assert!(transaction_fee <= crate::transaction::MONEY_MAX);
            fees += transaction_fee;
            assert!(fees <= crate::transaction::MONEY_MAX);

            if enforce_bip68 {
                check_sequence_locks(
                    transaction,
                    &spent_coins,
                    height,
                    position.prev_median_time_past(),
                    &ancestor_median_time_past,
                )?;
            }

            sigops_cost = sigops_cost.saturating_add(
                transaction
                    .legacy_sigop_count()
                    .saturating_mul(crate::transaction::WITNESS_SCALE_FACTOR),
            );
            for (input, coin) in inputs.iter().zip(&spent_coins) {
                sigops_cost = sigops_cost.saturating_add(
                    crate::transaction::input_p2sh_and_witness_sigop_cost(input, &coin.output),
                );
            }
            if sigops_cost > crate::block::SIGOPS_COST_MAX {
                return Err(ConnectError::SigOpsTooMany);
            }

            drop(spent_coins);
            for input in inputs {
                overlay.spend(input.previous_output);
            }
            overlay.add_outputs(
                transaction.txid(),
                transaction.outputs(),
                height,
                OutputKind::Regular,
            );
        }

        assert!(sigops_cost <= crate::block::SIGOPS_COST_MAX);
        assert!(fees >= 0);
        let block_reward = block_subsidy(self.network, height) + fees;
        assert!(block_reward >= 0);
        assert!(block_reward <= crate::transaction::MONEY_MAX);
        if coinbase.value_out() > block_reward {
            return Err(ConnectError::CoinbaseAmount);
        }

        let block_hash = position.hash();
        let coins_len_before = self.coins.len();
        let changes = overlay.into_changes();
        let changes_len = changes.len();
        let mut created = Vec::new();
        let mut spent = Vec::new();
        let mut overwritten = Vec::new();
        for (outpoint, entry) in changes {
            match entry {
                OverlayEntry::Added(coin) => {
                    let previous = self.coins.insert(outpoint, coin);
                    assert!(previous.is_none());
                    created.push(outpoint);
                }
                OverlayEntry::Spent => {
                    let previous = self
                        .coins
                        .remove(&outpoint)
                        .expect("spent coin exists in base");
                    spent.push((outpoint, previous));
                }
                OverlayEntry::Overwritten(coin) => {
                    let previous = self
                        .coins
                        .insert(outpoint, coin)
                        .expect("overwritten coin exists in base");
                    overwritten.push((outpoint, previous));
                }
            }
        }
        assert_eq!(created.len() + spent.len() + overwritten.len(), changes_len);
        if !bip30_repeat {
            assert!(overwritten.is_empty());
        }
        assert_eq!(
            self.coins.len() + spent.len(),
            coins_len_before + created.len()
        );
        self.undo.push(BlockUndo {
            block_hash,
            prev_hash,
            created,
            spent,
            overwritten,
        });
        assert_eq!(self.height(), height.get());
        assert_eq!(self.best_block(), block_hash);

        Ok(ConnectedBlock {
            position,
            transactions_count: block.transactions_count(),
        })
    }

    pub(crate) fn disconnect_tip(&mut self, expected: DisconnectTip) {
        let height_before = self.height();
        let coins_len_before = self.coins.len();
        let undo = self.undo.pop().expect("connected block has undo");
        assert_eq!(undo.block_hash, expected.block_hash);
        assert_eq!(undo.prev_hash, expected.prev_hash);

        let created_count = undo.created.len();
        let spent_count = undo.spent.len();
        let restored_height_max = self.height();
        for outpoint in undo.created {
            let removed = self.coins.remove(&outpoint);
            assert!(removed.is_some());
        }
        for (outpoint, coin) in undo.spent {
            assert!(coin.height.get() <= restored_height_max);
            assert!(!coin.output.is_unspendable());
            assert!(coin.output.value >= 0);
            assert!(coin.output.value <= crate::transaction::MONEY_MAX);
            let previous = self.coins.insert(outpoint, coin);
            assert!(previous.is_none());
        }
        for (outpoint, coin) in undo.overwritten {
            assert!(coin.height.get() <= restored_height_max);
            assert!(!coin.output.is_unspendable());
            assert!(coin.output.value >= 0);
            assert!(coin.output.value <= crate::transaction::MONEY_MAX);
            let previous = self.coins.insert(outpoint, coin);
            assert!(previous.is_some());
        }

        assert_eq!(self.height(), height_before - 1);
        assert_eq!(
            self.coins.len() + created_count,
            coins_len_before + spent_count
        );
        assert_eq!(self.best_block(), expected.prev_hash);
    }
}

enum OutputKind {
    Coinbase { allow_overwrite: bool },
    Regular,
}

enum OverlayEntry {
    Added(Coin),
    Spent,
    Overwritten(Coin),
}

struct Overlay<'a> {
    base: &'a std::collections::HashMap<crate::transaction::OutPoint, Coin>,
    changes: std::collections::BTreeMap<crate::transaction::OutPoint, OverlayEntry>,
}

impl<'a> Overlay<'a> {
    fn new(base: &'a std::collections::HashMap<crate::transaction::OutPoint, Coin>) -> Overlay<'a> {
        Overlay {
            base,
            changes: std::collections::BTreeMap::new(),
        }
    }

    fn get(&self, outpoint: &crate::transaction::OutPoint) -> Option<&Coin> {
        let coin = match self.changes.get(outpoint) {
            Some(OverlayEntry::Added(coin) | OverlayEntry::Overwritten(coin)) => Some(coin),
            Some(OverlayEntry::Spent) => None,
            None => self.base.get(outpoint),
        };
        if let Some(coin) = coin {
            assert!(!coin.output.is_unspendable());
            assert!(coin.output.value >= 0);
            assert!(coin.output.value <= crate::transaction::MONEY_MAX);
        }
        coin
    }

    fn spend(&mut self, outpoint: crate::transaction::OutPoint) {
        match self.changes.remove(&outpoint) {
            Some(OverlayEntry::Added(_)) => {}
            Some(OverlayEntry::Overwritten(_)) => {
                panic!("attempted to spend a coinbase output from the same block")
            }
            Some(OverlayEntry::Spent) => panic!("attempted to spend an already spent coin"),
            None => {
                assert!(self.base.contains_key(&outpoint));
                self.changes.insert(outpoint, OverlayEntry::Spent);
            }
        }
    }

    fn add_outputs(
        &mut self,
        txid: bitcoin_hashes::sha256d::Hash,
        outputs: &[crate::transaction::TxOut],
        height: std::num::NonZeroUsize,
        kind: OutputKind,
    ) {
        assert!(!outputs.is_empty());
        assert!(outputs.len() <= crate::transaction::TX_OUTPUTS_COUNT_MAX);
        let (is_coinbase, allow_overwrite) = match kind {
            OutputKind::Coinbase { allow_overwrite } => (true, allow_overwrite),
            OutputKind::Regular => (false, false),
        };
        for (index, output) in outputs.iter().enumerate() {
            assert!(output.value >= 0);
            assert!(output.value <= crate::transaction::MONEY_MAX);
            if output.is_unspendable() {
                continue;
            }
            let outpoint = crate::transaction::OutPoint {
                txid,
                vout: u32::try_from(index).expect("outputs count fits in u32"),
            };
            assert!(!self.changes.contains_key(&outpoint));
            let coin = Coin {
                output: output.clone(),
                height,
                is_coinbase,
            };
            let entry = if self.base.contains_key(&outpoint) {
                assert!(allow_overwrite);
                OverlayEntry::Overwritten(coin)
            } else {
                OverlayEntry::Added(coin)
            };
            self.changes.insert(outpoint, entry);
        }
    }

    fn into_changes(
        self,
    ) -> std::collections::BTreeMap<crate::transaction::OutPoint, OverlayEntry> {
        self.changes
    }
}

fn has_unspent_output(
    coins: &std::collections::HashMap<crate::transaction::OutPoint, Coin>,
    txid: bitcoin_hashes::sha256d::Hash,
    outputs_count: usize,
) -> bool {
    assert!(outputs_count >= 1);
    assert!(outputs_count <= crate::transaction::TX_OUTPUTS_COUNT_MAX);
    (0..outputs_count).any(|index| {
        let outpoint = crate::transaction::OutPoint {
            txid,
            vout: u32::try_from(index).expect("outputs count fits in u32"),
        };
        coins.contains_key(&outpoint)
    })
}

fn block_subsidy(network: crate::chainparams::Network, height: std::num::NonZeroUsize) -> i64 {
    let interval = network.subsidy_halving_interval().get();
    let halvings = height.get() / interval;
    assert!(height.get() - halvings * interval < interval);
    let subsidy = match u32::try_from(halvings) {
        Ok(halvings) if halvings < SUBSIDY_HALVINGS_MAX => BLOCK_SUBSIDY_INITIAL >> halvings,
        _ => 0,
    };
    assert!(subsidy >= 0);
    assert!(subsidy <= BLOCK_SUBSIDY_INITIAL);
    subsidy
}

fn check_sequence_locks(
    transaction: &crate::transaction::CheckedTransaction,
    spent_coins: &[&Coin],
    block_height: std::num::NonZeroUsize,
    prev_median_time_past: u32,
    ancestor_median_time_past: &impl Fn(usize) -> u32,
) -> Result<(), ConnectError> {
    let inputs = transaction.inputs();
    assert_eq!(inputs.len(), spent_coins.len());
    if transaction.version() < 2 {
        return Ok(());
    }
    let block_height_value = block_height.get();
    let prev_median_time_past_seconds = u64::from(prev_median_time_past);
    for (input, coin) in inputs.iter().zip(spent_coins) {
        let coin_height = coin.height.get();
        assert!(coin_height <= block_height_value);
        match input.relative_lock_time() {
            crate::transaction::RelativeLockTime::Disabled => {}
            crate::transaction::RelativeLockTime::Blocks(blocks) => {
                if block_height_value - coin_height < usize::from(blocks) {
                    return Err(ConnectError::NonFinalSequence);
                }
            }
            crate::transaction::RelativeLockTime::Seconds(relative_seconds) => {
                let coin_median_time_past_seconds =
                    u64::from(ancestor_median_time_past(coin_height - 1));
                if prev_median_time_past_seconds < coin_median_time_past_seconds + relative_seconds
                {
                    return Err(ConnectError::NonFinalSequence);
                }
            }
        }
    }
    Ok(())
}

#[cfg(fuzzing)]
#[cfg_attr(false, mutants::skip)]
pub(crate) mod fuzz {
    use crate::serialize::Decode;

    const STEPS_MAX: usize = 64;

    const TRANSACTIONS_PER_BLOCK_MAX: usize = 4;

    pub fn utxo(data: &[u8]) {
        let mut cursor = data;
        let network = match next_byte(&mut cursor) % 4 {
            0 => crate::chainparams::Network::Regtest,
            1 => crate::chainparams::Network::Mainnet,
            2 => crate::chainparams::Network::Testnet4,
            _ => crate::chainparams::Network::Signet,
        };
        let genesis = network.genesis();
        let mut utxo = super::UtxoSet::new(network);
        let mut headers = vec![genesis];
        let mut median_times_past = vec![genesis.time];
        let mut snapshots: Vec<super::UtxoSet> = Vec::new();
        let mut tag: u32 = 0;

        for _ in 0..STEPS_MAX {
            if cursor.is_empty() {
                break;
            }
            let action = next_byte(&mut cursor);
            if action.is_multiple_of(5) {
                if let Some(expected) = snapshots.pop() {
                    let tip = headers.pop().expect("connected tip exists");
                    median_times_past.pop().expect("connected mtp exists");
                    let prev = headers.last().expect("parent header exists");
                    utxo.disconnect_tip(super::DisconnectTip {
                        block_hash: tip.hash(),
                        prev_hash: prev.hash(),
                    });
                    assert_eq!(utxo, expected);
                    assert_eq!(utxo.height(), headers.len() - 1);
                    assert_eq!(utxo.best_block(), prev.hash());
                }
                continue;
            }

            let height_usize = utxo.height() + 1;
            let height = std::num::NonZeroUsize::new(height_usize).expect("height is nonzero");
            let prev = *headers.last().expect("genesis exists");
            let prev_mtp = *median_times_past.last().expect("genesis mtp exists");
            let time_step = u32::from(next_byte(&mut cursor)) * 64 + 1;
            let Some(block_time) = prev_mtp.checked_add(time_step) else {
                break;
            };

            let mut existing: Vec<(crate::transaction::OutPoint, super::Coin)> = utxo
                .coins
                .iter()
                .map(|(outpoint, coin)| (*outpoint, coin.clone()))
                .collect();
            existing.sort_unstable_by_key(|(a, _)| *a);

            let tx_count = usize::from(next_byte(&mut cursor)) % (TRANSACTIONS_PER_BLOCK_MAX + 1);
            let mut rest = Vec::with_capacity(tx_count);
            let mut spent_in_block: std::collections::HashSet<crate::transaction::OutPoint> =
                std::collections::HashSet::new();
            let mut intra_block: Vec<(crate::transaction::OutPoint, i64, Vec<u8>)> = Vec::new();
            let mut expected_fees: i64 = 0;

            for _ in 0..tx_count {
                let version = match next_byte(&mut cursor) % 4 {
                    0 => 0,
                    1 => 1,
                    2 => 2,
                    _ => u32::MAX,
                };
                let source = next_byte(&mut cursor);
                let chosen: Option<(crate::transaction::OutPoint, i64, Vec<u8>)> =
                    if source.is_multiple_of(4) && !intra_block.is_empty() {
                        let index = usize::from(next_byte(&mut cursor)) % intra_block.len();
                        Some(intra_block[index].clone())
                    } else if source % 4 == 3 {
                        Some((
                            crate::transaction::OutPoint {
                                txid: bitcoin_hashes::sha256d::Hash::from_byte_array(
                                    [next_byte(&mut cursor); 32],
                                ),
                                vout: u32::from(next_byte(&mut cursor) % 4),
                            },
                            crate::transaction::COIN,
                            vec![0x51],
                        ))
                    } else if !existing.is_empty() {
                        let index = usize::from(next_byte(&mut cursor)) % existing.len();
                        let (outpoint, coin) = &existing[index];
                        Some((
                            *outpoint,
                            coin.output.value,
                            coin.output.script_pubkey.clone(),
                        ))
                    } else {
                        None
                    };
                let Some((outpoint, coin_value, prev_script)) = chosen else {
                    continue;
                };
                if outpoint.txid.as_byte_array() == &[0; 32] && outpoint.vout == u32::MAX {
                    continue;
                }
                if source % 8 != 7 && spent_in_block.contains(&outpoint) {
                    continue;
                }
                let sequence_mode = next_byte(&mut cursor);
                let sequence = match sequence_mode % 6 {
                    0 => u32::MAX,
                    1 => crate::transaction::SEQUENCE_LOCK_TIME_DISABLE_FLAG | 0xffff,
                    2 => u32::from(next_byte(&mut cursor) % 4),
                    3 => {
                        crate::transaction::SEQUENCE_LOCK_TIME_TYPE_FLAG
                            | u32::from(next_byte(&mut cursor) % 4)
                    }
                    4 => 0x0001_0000 | u32::from(next_byte(&mut cursor) % 4),
                    _ => 0,
                };
                let (script_sig, witness) = spending_witness_for(
                    &prev_script,
                    height_usize >= network.segwit_height(),
                    next_byte(&mut cursor),
                );
                let value_mode = next_byte(&mut cursor);
                let (out_value, fee) = match value_mode % 4 {
                    0 => (coin_value, 0),
                    1 => {
                        let fee = coin_value.min(i64::from(next_byte(&mut cursor)) * 1_000);
                        (coin_value - fee, fee)
                    }
                    2 => (0, coin_value),
                    _ => {
                        let over = (coin_value + 1).min(crate::transaction::MONEY_MAX);
                        (over, 0)
                    }
                };
                let out_script = output_script(next_byte(&mut cursor));
                let mut outputs = vec![crate::transaction::TxOut {
                    value: out_value,
                    script_pubkey: out_script,
                }];
                if next_byte(&mut cursor).is_multiple_of(4) {
                    outputs.push(crate::transaction::TxOut {
                        value: 0,
                        script_pubkey: vec![0x6a, 0x01, 0xaa],
                    });
                }
                let mut tx = crate::transaction::Transaction::new(
                    version,
                    vec![crate::transaction::TxIn {
                        previous_output: outpoint,
                        script_sig,
                        sequence,
                        witness,
                    }],
                    outputs,
                    0,
                )
                .expect("non-empty inputs and outputs");
                if tx.size_without_witness() == 64 {
                    let mut out = tx.outputs().to_vec();
                    out[0].script_pubkey.push(0x51);
                    tx = crate::transaction::Transaction::new(
                        version,
                        vec![crate::transaction::TxIn {
                            previous_output: outpoint,
                            script_sig: tx.inputs()[0].script_sig.clone(),
                            sequence,
                            witness: tx.inputs()[0].witness.clone(),
                        }],
                        out,
                        0,
                    )
                    .expect("non-empty inputs and outputs");
                }
                if !spent_in_block.contains(&outpoint) {
                    spent_in_block.insert(outpoint);
                    expected_fees = expected_fees.saturating_add(fee);
                    let txid = tx.txid();
                    for (vout, output) in tx.outputs().iter().enumerate() {
                        if !output.is_unspendable() {
                            intra_block.push((
                                crate::transaction::OutPoint {
                                    txid,
                                    vout: u32::try_from(vout).expect("vout fits in u32"),
                                },
                                output.value,
                                output.script_pubkey.clone(),
                            ));
                        }
                    }
                }
                rest.push(tx);
            }

            let subsidy = super::block_subsidy(network, height);
            let reward_limit = subsidy
                .saturating_add(expected_fees)
                .min(crate::transaction::MONEY_MAX);
            let coinbase_mode = next_byte(&mut cursor);
            let coinbase_value = match coinbase_mode % 4 {
                0 => reward_limit,
                1 => 0,
                2 => reward_limit / 2,
                _ => (reward_limit + 1).min(crate::transaction::MONEY_MAX),
            };
            let coinbase_script_sig =
                if height < network.bip34_height() && coinbase_mode & 0x80 != 0 {
                    vec![0x51, 0x51]
                } else {
                    tag = tag.wrapping_add(1);
                    let mut script_sig = crate::block::encode_bip34_height(height)
                        .as_slice()
                        .to_vec();
                    script_sig.extend_from_slice(&tag.to_le_bytes());
                    script_sig
                };
            let mut coinbase_outputs = vec![crate::transaction::TxOut {
                value: coinbase_value,
                script_pubkey: output_script(next_byte(&mut cursor)),
            }];
            let has_witness = rest
                .iter()
                .any(crate::transaction::Transaction::has_witness);
            let coinbase_witness = if has_witness && height_usize >= network.segwit_height() {
                let reserved = [0; 32];
                let wtxids = std::iter::once([0; 32])
                    .chain(rest.iter().map(|tx| tx.wtxid().to_byte_array()))
                    .collect();
                let witness_root = crate::merkle::root(wtxids).hash;
                let commitment =
                    bitcoin_hashes::sha256d::Hash::hash([witness_root, reserved].as_flattened());
                let mut script = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
                script.extend_from_slice(commitment.as_byte_array());
                coinbase_outputs.push(crate::transaction::TxOut {
                    value: 0,
                    script_pubkey: script,
                });
                let mut raw = vec![0x01, 0x20];
                raw.extend_from_slice(&reserved);
                crate::transaction::Witness::decode(&mut raw.as_slice()).expect("valid witness")
            } else {
                crate::transaction::Witness::default()
            };
            let coinbase = crate::transaction::Transaction::new(
                1,
                vec![crate::transaction::TxIn {
                    previous_output: crate::transaction::OutPoint {
                        txid: bitcoin_hashes::sha256d::Hash::from_byte_array([0; 32]),
                        vout: u32::MAX,
                    },
                    script_sig: coinbase_script_sig,
                    sequence: u32::MAX,
                    witness: coinbase_witness,
                }],
                coinbase_outputs,
                0,
            )
            .expect("valid coinbase");

            let txids = std::iter::once(coinbase.txid().to_byte_array())
                .chain(rest.iter().map(|tx| tx.txid().to_byte_array()))
                .collect();
            let merkle_root = crate::merkle::root(txids).hash;
            let header = crate::block::BlockHeader {
                version: 4,
                prev: prev.hash(),
                merkle_root,
                time: block_time,
                bits: genesis.bits,
                nonce: tag,
            };
            let block = crate::block::Block {
                header,
                transactions: Some(crate::block::Transactions {
                    first: coinbase,
                    rest,
                }),
            };
            let position =
                crate::chain::BlockPosition::new(network, height, header.hash(), prev_mtp);
            let Ok(checked) = crate::block::PositionedBlock::new(block, position.position())
                .expect("matching header and time")
                .check()
            else {
                continue;
            };
            let checked_block = crate::block::CheckedBlock::from_checked(position, checked)
                .expect("matching position");
            let before = utxo.clone();
            match utxo.connect_block(checked_block, |h| median_times_past[h]) {
                Err(_) => {
                    assert_eq!(utxo, before);
                }
                Ok(connected) => {
                    assert_eq!(connected.height(), height);
                    assert_eq!(connected.hash(), header.hash());
                    assert_eq!(utxo.height(), height_usize);
                    assert_eq!(utxo.best_block(), header.hash());
                    let mut roundtrip = utxo.clone();
                    roundtrip.disconnect_tip(super::DisconnectTip {
                        block_hash: header.hash(),
                        prev_hash: prev.hash(),
                    });
                    assert_eq!(roundtrip, before);
                    let total: i64 = utxo.coins.values().map(|coin| coin.output.value).sum();
                    assert!(total >= 0);
                    assert!(total < crate::transaction::MONEY_MAX);
                    snapshots.push(before);
                    headers.push(header);
                    median_times_past.push(median_time_past(&headers));
                }
            }
        }
    }

    fn next_byte(cursor: &mut &[u8]) -> u8 {
        match cursor.split_first() {
            Some((byte, rest)) => {
                *cursor = rest;
                *byte
            }
            None => 0,
        }
    }

    fn median_time_past(headers: &[crate::block::BlockHeader]) -> u32 {
        let start = headers.len().saturating_sub(11);
        let mut times: Vec<u32> = headers[start..].iter().map(|header| header.time).collect();
        times.sort_unstable();
        times[times.len() / 2]
    }

    fn output_script(selector: u8) -> Vec<u8> {
        match selector % 5 {
            0 => vec![0x51],
            1 => {
                let mut script = vec![0xa9, 20];
                script.extend_from_slice(&[0x11; 20]);
                script.push(0x87);
                script
            }
            2 => {
                let mut script = vec![0x00, 20];
                script.extend_from_slice(&[0x22; 20]);
                script
            }
            3 => {
                let mut script = vec![0x00, 32];
                script.extend_from_slice(&[0x33; 32]);
                script
            }
            _ => vec![0x6a, 0x02, 0xaa, 0xbb],
        }
    }

    fn spending_witness_for(
        prev_script: &[u8],
        allow_witness: bool,
        selector: u8,
    ) -> (Vec<u8>, crate::transaction::Witness) {
        if prev_script.len() == 23 && prev_script[0] == 0xa9 {
            if selector.is_multiple_of(2) {
                return (
                    vec![0x02, 0x52, 0xae],
                    crate::transaction::Witness::default(),
                );
            }
            let mut redeem = vec![0x00, 32];
            redeem.extend_from_slice(&[0x33; 32]);
            let mut script_sig = vec![u8::try_from(redeem.len()).expect("redeem fits in u8")];
            script_sig.extend_from_slice(&redeem);
            let witness = if allow_witness {
                crate::transaction::Witness::decode(&mut &[0x01, 0x02, 0x53, 0xae][..])
                    .expect("valid witness")
            } else {
                crate::transaction::Witness::default()
            };
            return (script_sig, witness);
        }
        if prev_script.len() == 34
            && prev_script[0] == 0x00
            && prev_script[1] == 32
            && allow_witness
        {
            let witness = crate::transaction::Witness::decode(&mut &[0x01, 0x02, 0x52, 0xae][..])
                .expect("valid witness");
            return (Vec::new(), witness);
        }
        (Vec::new(), crate::transaction::Witness::default())
    }
}

#[cfg(test)]
mod tests {
    use crate::serialize::Decode;

    fn nonzero(value: usize) -> std::num::NonZeroUsize {
        std::num::NonZeroUsize::new(value).unwrap()
    }

    fn witness_from(items: &[&[u8]]) -> crate::transaction::Witness {
        let mut bytes = Vec::new();
        crate::serialize::write_compact_size(&mut bytes, items.len());
        for item in items {
            crate::serialize::write_string(&mut bytes, item);
        }
        crate::transaction::Witness::decode(&mut bytes.as_slice()).unwrap()
    }

    fn p2sh_script() -> Vec<u8> {
        let mut script = vec![0xa9, 20];
        script.extend_from_slice(&[0x11; 20]);
        script.push(0x87);
        script
    }

    fn p2wpkh_script() -> Vec<u8> {
        let mut script = vec![0x00, 20];
        script.extend_from_slice(&[0x22; 20]);
        script
    }

    fn p2wsh_script() -> Vec<u8> {
        let mut script = vec![0x00, 32];
        script.extend_from_slice(&[0x33; 32]);
        script
    }

    fn coinbase_tx(
        network: crate::chainparams::Network,
        height: usize,
        tag: u32,
        outputs: Vec<crate::transaction::TxOut>,
    ) -> crate::transaction::Transaction {
        let mut script_sig = if height >= network.bip34_height().get() {
            crate::block::encode_bip34_height(nonzero(height))
                .as_slice()
                .to_vec()
        } else {
            Vec::new()
        };
        script_sig.extend_from_slice(&tag.to_le_bytes());
        if script_sig.len() < 2 {
            script_sig.resize(2, 0);
        }
        crate::transaction::Transaction::new(
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
            outputs,
            0,
        )
        .unwrap()
    }

    fn build_checked_block(
        network: crate::chainparams::Network,
        height: usize,
        prev: bitcoin_hashes::sha256d::Hash,
        prev_mtp: u32,
        mut coinbase: crate::transaction::Transaction,
        rest: Vec<crate::transaction::Transaction>,
    ) -> crate::block::CheckedBlock {
        if rest
            .iter()
            .any(crate::transaction::Transaction::has_witness)
            && height >= network.segwit_height()
        {
            let reserved = [0; 32];
            let wtxids = std::iter::once([0; 32])
                .chain(rest.iter().map(|tx| tx.wtxid().to_byte_array()))
                .collect();
            let witness_root = crate::merkle::root(wtxids).hash;
            let commitment =
                bitcoin_hashes::sha256d::Hash::hash([witness_root, reserved].as_flattened());
            let mut script = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
            script.extend_from_slice(commitment.as_byte_array());
            let mut outputs = coinbase.outputs().to_vec();
            outputs.push(crate::transaction::TxOut {
                value: 0,
                script_pubkey: script,
            });
            let mut input = coinbase.inputs()[0].clone();
            input.witness = witness_from(&[&reserved]);
            coinbase =
                crate::transaction::Transaction::new(coinbase.version, vec![input], outputs, 0)
                    .unwrap();
        }
        let txids = std::iter::once(coinbase.txid().to_byte_array())
            .chain(rest.iter().map(|tx| tx.txid().to_byte_array()))
            .collect();
        let merkle_root = crate::merkle::root(txids).hash;
        let header = crate::block::BlockHeader {
            version: 4,
            prev,
            merkle_root,
            time: prev_mtp + 1,
            bits: network.genesis().bits,
            nonce: 0,
        };
        let block = crate::block::Block {
            header,
            transactions: Some(crate::block::Transactions {
                first: coinbase,
                rest,
            }),
        };
        let position =
            crate::chain::BlockPosition::new(network, nonzero(height), header.hash(), prev_mtp);
        let checked = crate::block::PositionedBlock::new(block, position.position())
            .unwrap()
            .check()
            .unwrap();
        crate::block::CheckedBlock::from_checked(position, checked).unwrap()
    }

    fn utxo_at(
        network: crate::chainparams::Network,
        height: usize,
        best_block: bitcoin_hashes::sha256d::Hash,
        coins: Vec<(crate::transaction::OutPoint, super::Coin)>,
    ) -> super::UtxoSet {
        let undo = (0..height)
            .map(|_| super::BlockUndo {
                block_hash: best_block,
                prev_hash: best_block,
                created: Vec::new(),
                spent: Vec::new(),
                overwritten: Vec::new(),
            })
            .collect();
        super::UtxoSet {
            network,
            coins: coins.into_iter().collect(),
            undo,
        }
    }

    #[test]
    fn connect_error_display_covers_all_variants() {
        let messages = [
            (
                super::ConnectError::DuplicateTxId,
                "a transaction overwrites an unspent transaction id",
            ),
            (
                super::ConnectError::MissingInputs,
                "a transaction input is missing or already spent",
            ),
            (
                super::ConnectError::PrematureCoinbaseSpend,
                "a transaction spends a coinbase output before 100 confirmations",
            ),
            (
                super::ConnectError::InputsBelowOutputs,
                "a transaction spends less than its outputs pay",
            ),
            (
                super::ConnectError::NonFinalSequence,
                "a transaction does not satisfy its relative lock-time",
            ),
            (
                super::ConnectError::SigOpsTooMany,
                "the block sigop cost is above 80000",
            ),
            (
                super::ConnectError::CoinbaseAmount,
                "the coinbase pays more than the subsidy plus fees",
            ),
        ];
        for (error, expected) in messages {
            assert_eq!(error.to_string(), expected);
        }
    }

    #[test]
    fn block_subsidy_halves_on_schedule_and_reaches_zero() {
        for network in [
            crate::chainparams::Network::Mainnet,
            crate::chainparams::Network::Testnet4,
            crate::chainparams::Network::Signet,
        ] {
            assert_eq!(super::block_subsidy(network, nonzero(1)), 5_000_000_000);
            assert_eq!(
                super::block_subsidy(network, nonzero(209_999)),
                5_000_000_000
            );
            assert_eq!(
                super::block_subsidy(network, nonzero(210_000)),
                2_500_000_000
            );
            assert_eq!(
                super::block_subsidy(network, nonzero(420_000)),
                1_250_000_000
            );
            assert_eq!(super::block_subsidy(network, nonzero(210_000 * 32)), 1);
            assert_eq!(super::block_subsidy(network, nonzero(210_000 * 33)), 0);
            assert_eq!(super::block_subsidy(network, nonzero(210_000 * 63)), 0);
            assert_eq!(super::block_subsidy(network, nonzero(210_000 * 64)), 0);
            assert_eq!(super::block_subsidy(network, nonzero(usize::MAX)), 0);
        }

        let regtest = crate::chainparams::Network::Regtest;
        assert_eq!(super::block_subsidy(regtest, nonzero(1)), 5_000_000_000);
        assert_eq!(super::block_subsidy(regtest, nonzero(149)), 5_000_000_000);
        assert_eq!(super::block_subsidy(regtest, nonzero(150)), 2_500_000_000);
        assert_eq!(super::block_subsidy(regtest, nonzero(299)), 2_500_000_000);
        assert_eq!(super::block_subsidy(regtest, nonzero(300)), 1_250_000_000);
        assert_eq!(super::block_subsidy(regtest, nonzero(150 * 32)), 1);
        assert_eq!(super::block_subsidy(regtest, nonzero(150 * 33)), 0);
        assert_eq!(super::block_subsidy(regtest, nonzero(150 * 64)), 0);
        assert_eq!(super::block_subsidy(regtest, nonzero(usize::MAX)), 0);

        for (network, expected) in [
            (
                crate::chainparams::Network::Mainnet,
                2_099_999_997_690_000_i64,
            ),
            (crate::chainparams::Network::Regtest, 1_499_999_998_350_i64),
        ] {
            let interval = network.subsidy_halving_interval().get();
            let total: i64 = (0..super::SUBSIDY_HALVINGS_MAX)
                .map(|halving| {
                    let height = (usize::try_from(halving).unwrap() * interval).max(1);
                    super::block_subsidy(network, nonzero(height))
                        * i64::try_from(interval).unwrap()
                })
                .sum();
            assert_eq!(total, expected);
            assert!(total < crate::transaction::MONEY_MAX);
        }
    }

    #[test]
    fn coinbase_amount_enforces_subsidy_plus_multi_tx_fees_across_halving() {
        let regtest = crate::chainparams::Network::Regtest;
        let genesis = regtest.genesis();
        let mut utxo = super::UtxoSet::new(regtest);
        let prev_mtp = genesis.time;

        let over = build_checked_block(
            regtest,
            1,
            genesis.hash(),
            prev_mtp,
            coinbase_tx(
                regtest,
                1,
                1,
                vec![crate::transaction::TxOut {
                    value: 5_000_000_001,
                    script_pubkey: vec![0x51],
                }],
            ),
            Vec::new(),
        );
        let before = utxo.clone();
        assert_eq!(
            utxo.connect_block(over, |_| prev_mtp),
            Err(super::ConnectError::CoinbaseAmount)
        );
        assert_eq!(utxo, before);

        let exact = build_checked_block(
            regtest,
            1,
            genesis.hash(),
            prev_mtp,
            coinbase_tx(
                regtest,
                1,
                2,
                vec![crate::transaction::TxOut {
                    value: 5_000_000_000,
                    script_pubkey: vec![0x51],
                }],
            ),
            Vec::new(),
        );
        let connected = utxo.connect_block(exact, |_| prev_mtp).unwrap();
        assert_eq!(connected.height(), nonzero(1));
        assert_eq!(utxo.height(), 1);

        let burned = build_checked_block(
            regtest,
            2,
            utxo.best_block(),
            prev_mtp + 1,
            coinbase_tx(
                regtest,
                2,
                3,
                vec![crate::transaction::TxOut {
                    value: 0,
                    script_pubkey: vec![0x51],
                }],
            ),
            Vec::new(),
        );
        utxo.connect_block(burned, |_| prev_mtp + 1).unwrap();
        assert_eq!(utxo.height(), 2);

        let out_a = crate::transaction::OutPoint {
            txid: bitcoin_hashes::sha256d::Hash::from_byte_array([0xaa; 32]),
            vout: 0,
        };
        let out_b = crate::transaction::OutPoint {
            txid: bitcoin_hashes::sha256d::Hash::from_byte_array([0xbb; 32]),
            vout: 0,
        };
        let mut halving_utxo = utxo_at(
            regtest,
            149,
            genesis.hash(),
            vec![
                (
                    out_a,
                    super::Coin {
                        output: crate::transaction::TxOut {
                            value: 10,
                            script_pubkey: vec![0x51],
                        },
                        height: nonzero(10),
                        is_coinbase: false,
                    },
                ),
                (
                    out_b,
                    super::Coin {
                        output: crate::transaction::TxOut {
                            value: 20,
                            script_pubkey: vec![0x51],
                        },
                        height: nonzero(10),
                        is_coinbase: false,
                    },
                ),
            ],
        );
        let tx_a = crate::transaction::Transaction::new(
            1,
            vec![crate::transaction::TxIn {
                previous_output: out_a,
                script_sig: Vec::new(),
                sequence: u32::MAX,
                witness: crate::transaction::Witness::default(),
            }],
            vec![crate::transaction::TxOut {
                value: 7,
                script_pubkey: vec![0x51],
            }],
            0,
        )
        .unwrap();
        let tx_b = crate::transaction::Transaction::new(
            1,
            vec![crate::transaction::TxIn {
                previous_output: out_b,
                script_sig: Vec::new(),
                sequence: u32::MAX,
                witness: crate::transaction::Witness::default(),
            }],
            vec![crate::transaction::TxOut {
                value: 15,
                script_pubkey: vec![0x51],
            }],
            0,
        )
        .unwrap();

        let over_halving = build_checked_block(
            regtest,
            150,
            genesis.hash(),
            prev_mtp,
            coinbase_tx(
                regtest,
                150,
                1,
                vec![crate::transaction::TxOut {
                    value: 2_500_000_000 + 8 + 1,
                    script_pubkey: vec![0x51],
                }],
            ),
            vec![tx_a.clone(), tx_b.clone()],
        );
        let snap = halving_utxo.clone();
        assert_eq!(
            halving_utxo.connect_block(over_halving, |_| prev_mtp),
            Err(super::ConnectError::CoinbaseAmount)
        );
        assert_eq!(halving_utxo, snap);

        let exact_halving = build_checked_block(
            regtest,
            150,
            genesis.hash(),
            prev_mtp,
            coinbase_tx(
                regtest,
                150,
                2,
                vec![crate::transaction::TxOut {
                    value: 2_500_000_000 + 8,
                    script_pubkey: vec![0x51],
                }],
            ),
            vec![tx_a, tx_b],
        );
        halving_utxo
            .connect_block(exact_halving, |_| prev_mtp)
            .unwrap();
        assert_eq!(halving_utxo.height(), 150);
    }

    #[test]
    fn unspendable_outputs_are_omitted_and_max_size_output_is_spendable() {
        let regtest = crate::chainparams::Network::Regtest;
        let genesis = regtest.genesis();
        let mut utxo = super::UtxoSet::new(regtest);
        let prev_mtp = genesis.time;

        let coinbase = coinbase_tx(
            regtest,
            1,
            1,
            vec![
                crate::transaction::TxOut {
                    value: 100,
                    script_pubkey: vec![0x6a, 0x04, 1, 2, 3, 4],
                },
                crate::transaction::TxOut {
                    value: 200,
                    script_pubkey: vec![0x51; 10_001],
                },
                crate::transaction::TxOut {
                    value: 300,
                    script_pubkey: vec![0x51; 10_000],
                },
            ],
        );
        let coinbase_txid = coinbase.txid();
        let block = build_checked_block(regtest, 1, genesis.hash(), prev_mtp, coinbase, Vec::new());
        let block_hash = block.header().hash();
        let before = utxo.clone();
        utxo.connect_block(block, |_| prev_mtp).unwrap();
        assert_eq!(utxo.coins.len(), 1);
        assert!(!utxo.coins.contains_key(&crate::transaction::OutPoint {
            txid: coinbase_txid,
            vout: 0,
        }));
        assert!(!utxo.coins.contains_key(&crate::transaction::OutPoint {
            txid: coinbase_txid,
            vout: 1,
        }));
        assert!(utxo.coins.contains_key(&crate::transaction::OutPoint {
            txid: coinbase_txid,
            vout: 2,
        }));
        utxo.disconnect_tip(super::DisconnectTip {
            block_hash,
            prev_hash: genesis.hash(),
        });
        assert_eq!(utxo, before);
    }

    #[test]
    fn missing_inputs_intra_block_spend_and_double_spend_rollback() {
        let regtest = crate::chainparams::Network::Regtest;
        let genesis = regtest.genesis();
        let prev_mtp = genesis.time;

        let genesis_block = crate::fixtures::block(crate::fixtures::REGTEST_GENESIS_BLOCK);
        let genesis_coinbase_txid = genesis_block.transactions.unwrap().first.txid();
        let spend_genesis = crate::transaction::Transaction::new(
            1,
            vec![crate::transaction::TxIn {
                previous_output: crate::transaction::OutPoint {
                    txid: genesis_coinbase_txid,
                    vout: 0,
                },
                script_sig: Vec::new(),
                sequence: u32::MAX,
                witness: crate::transaction::Witness::default(),
            }],
            vec![crate::transaction::TxOut {
                value: 1,
                script_pubkey: vec![0x51],
            }],
            0,
        )
        .unwrap();
        let mut utxo = super::UtxoSet::new(regtest);
        let block = build_checked_block(
            regtest,
            1,
            genesis.hash(),
            prev_mtp,
            coinbase_tx(
                regtest,
                1,
                1,
                vec![crate::transaction::TxOut {
                    value: 0,
                    script_pubkey: vec![0x51],
                }],
            ),
            vec![spend_genesis],
        );
        let before = utxo.clone();
        assert_eq!(
            utxo.connect_block(block, |_| prev_mtp),
            Err(super::ConnectError::MissingInputs)
        );
        assert_eq!(utxo, before);

        let seed_out = crate::transaction::OutPoint {
            txid: bitcoin_hashes::sha256d::Hash::from_byte_array([0x12; 32]),
            vout: 0,
        };
        let mut utxo = utxo_at(
            regtest,
            1,
            genesis.hash(),
            vec![(
                seed_out,
                super::Coin {
                    output: crate::transaction::TxOut {
                        value: 1_000,
                        script_pubkey: vec![0x51],
                    },
                    height: nonzero(1),
                    is_coinbase: false,
                },
            )],
        );

        let parent = crate::transaction::Transaction::new(
            1,
            vec![crate::transaction::TxIn {
                previous_output: seed_out,
                script_sig: Vec::new(),
                sequence: u32::MAX,
                witness: crate::transaction::Witness::default(),
            }],
            vec![crate::transaction::TxOut {
                value: 900,
                script_pubkey: vec![0x51],
            }],
            0,
        )
        .unwrap();
        let child = crate::transaction::Transaction::new(
            1,
            vec![crate::transaction::TxIn {
                previous_output: crate::transaction::OutPoint {
                    txid: parent.txid(),
                    vout: 0,
                },
                script_sig: Vec::new(),
                sequence: u32::MAX,
                witness: crate::transaction::Witness::default(),
            }],
            vec![crate::transaction::TxOut {
                value: 800,
                script_pubkey: vec![0x51],
            }],
            0,
        )
        .unwrap();

        let wrong_order = build_checked_block(
            regtest,
            2,
            genesis.hash(),
            prev_mtp,
            coinbase_tx(
                regtest,
                2,
                1,
                vec![crate::transaction::TxOut {
                    value: 0,
                    script_pubkey: vec![0x51],
                }],
            ),
            vec![child.clone(), parent.clone()],
        );
        let snap = utxo.clone();
        assert_eq!(
            utxo.connect_block(wrong_order, |_| prev_mtp),
            Err(super::ConnectError::MissingInputs)
        );
        assert_eq!(utxo, snap);

        let double_spend = crate::transaction::Transaction::new(
            1,
            vec![crate::transaction::TxIn {
                previous_output: seed_out,
                script_sig: Vec::new(),
                sequence: u32::MAX,
                witness: crate::transaction::Witness::default(),
            }],
            vec![crate::transaction::TxOut {
                value: 500,
                script_pubkey: vec![0x51],
            }],
            0,
        )
        .unwrap();
        let double_block = build_checked_block(
            regtest,
            2,
            genesis.hash(),
            prev_mtp,
            coinbase_tx(
                regtest,
                2,
                2,
                vec![crate::transaction::TxOut {
                    value: 0,
                    script_pubkey: vec![0x51],
                }],
            ),
            vec![parent.clone(), double_spend],
        );
        assert_eq!(
            utxo.connect_block(double_block, |_| prev_mtp),
            Err(super::ConnectError::MissingInputs)
        );
        assert_eq!(utxo, snap);

        let valid = build_checked_block(
            regtest,
            2,
            genesis.hash(),
            prev_mtp,
            coinbase_tx(
                regtest,
                2,
                3,
                vec![crate::transaction::TxOut {
                    value: 5_000_000_200,
                    script_pubkey: vec![0x51],
                }],
            ),
            vec![parent.clone(), child.clone()],
        );
        let valid_hash = valid.header().hash();
        utxo.connect_block(valid, |_| prev_mtp).unwrap();
        assert!(!utxo.coins.contains_key(&seed_out));
        assert!(!utxo.coins.contains_key(&crate::transaction::OutPoint {
            txid: parent.txid(),
            vout: 0,
        }));
        assert!(utxo.coins.contains_key(&crate::transaction::OutPoint {
            txid: child.txid(),
            vout: 0,
        }));
        utxo.disconnect_tip(super::DisconnectTip {
            block_hash: valid_hash,
            prev_hash: genesis.hash(),
        });
        assert_eq!(utxo, snap);
    }

    #[test]
    fn coinbase_maturity_inputs_below_outputs_and_error_precedence() {
        let regtest = crate::chainparams::Network::Regtest;
        let genesis = regtest.genesis();
        let prev_mtp = genesis.time;

        let coinbase_at_2 = crate::transaction::OutPoint {
            txid: bitcoin_hashes::sha256d::Hash::from_byte_array([0x22; 32]),
            vout: 0,
        };
        let regular_at_2 = crate::transaction::OutPoint {
            txid: bitcoin_hashes::sha256d::Hash::from_byte_array([0x33; 32]),
            vout: 0,
        };
        let regular_b = crate::transaction::OutPoint {
            txid: bitcoin_hashes::sha256d::Hash::from_byte_array([0x44; 32]),
            vout: 0,
        };
        let missing = crate::transaction::OutPoint {
            txid: bitcoin_hashes::sha256d::Hash::from_byte_array([0x55; 32]),
            vout: 0,
        };

        let make_utxo = |height| {
            utxo_at(
                regtest,
                height,
                genesis.hash(),
                vec![
                    (
                        coinbase_at_2,
                        super::Coin {
                            output: crate::transaction::TxOut {
                                value: 100,
                                script_pubkey: vec![0x51],
                            },
                            height: nonzero(2),
                            is_coinbase: true,
                        },
                    ),
                    (
                        regular_at_2,
                        super::Coin {
                            output: crate::transaction::TxOut {
                                value: 30,
                                script_pubkey: vec![0x51],
                            },
                            height: nonzero(2),
                            is_coinbase: false,
                        },
                    ),
                    (
                        regular_b,
                        super::Coin {
                            output: crate::transaction::TxOut {
                                value: 20,
                                script_pubkey: vec![0x51],
                            },
                            height: nonzero(2),
                            is_coinbase: false,
                        },
                    ),
                ],
            )
        };

        let spend_coinbase = crate::transaction::Transaction::new(
            1,
            vec![crate::transaction::TxIn {
                previous_output: coinbase_at_2,
                script_sig: Vec::new(),
                sequence: u32::MAX,
                witness: crate::transaction::Witness::default(),
            }],
            vec![crate::transaction::TxOut {
                value: 100,
                script_pubkey: vec![0x51],
            }],
            0,
        )
        .unwrap();

        let mut at_100 = make_utxo(100);
        let depth_99 = build_checked_block(
            regtest,
            101,
            genesis.hash(),
            prev_mtp,
            coinbase_tx(
                regtest,
                101,
                1,
                vec![crate::transaction::TxOut {
                    value: 0,
                    script_pubkey: vec![0x51],
                }],
            ),
            vec![spend_coinbase.clone()],
        );
        assert_eq!(
            at_100.connect_block(depth_99, |_| prev_mtp),
            Err(super::ConnectError::PrematureCoinbaseSpend)
        );

        let mut at_101 = make_utxo(101);
        let depth_100 = build_checked_block(
            regtest,
            102,
            genesis.hash(),
            prev_mtp,
            coinbase_tx(
                regtest,
                102,
                2,
                vec![crate::transaction::TxOut {
                    value: 0,
                    script_pubkey: vec![0x51],
                }],
            ),
            vec![spend_coinbase],
        );
        at_101.connect_block(depth_100, |_| prev_mtp).unwrap();

        let same_block_cb = coinbase_tx(
            regtest,
            3,
            3,
            vec![crate::transaction::TxOut {
                value: 100,
                script_pubkey: vec![0x51],
            }],
        );
        let spend_same_cb = crate::transaction::Transaction::new(
            1,
            vec![crate::transaction::TxIn {
                previous_output: crate::transaction::OutPoint {
                    txid: same_block_cb.txid(),
                    vout: 0,
                },
                script_sig: Vec::new(),
                sequence: u32::MAX,
                witness: crate::transaction::Witness::default(),
            }],
            vec![crate::transaction::TxOut {
                value: 100,
                script_pubkey: vec![0x51],
            }],
            0,
        )
        .unwrap();
        let mut at_2 = make_utxo(2);
        let depth_0 = build_checked_block(
            regtest,
            3,
            genesis.hash(),
            prev_mtp,
            same_block_cb,
            vec![spend_same_cb],
        );
        assert_eq!(
            at_2.connect_block(depth_0, |_| prev_mtp),
            Err(super::ConnectError::PrematureCoinbaseSpend)
        );

        let two_inputs_exact = crate::transaction::Transaction::new(
            1,
            vec![
                crate::transaction::TxIn {
                    previous_output: regular_at_2,
                    script_sig: Vec::new(),
                    sequence: u32::MAX,
                    witness: crate::transaction::Witness::default(),
                },
                crate::transaction::TxIn {
                    previous_output: regular_b,
                    script_sig: Vec::new(),
                    sequence: u32::MAX,
                    witness: crate::transaction::Witness::default(),
                },
            ],
            vec![crate::transaction::TxOut {
                value: 50,
                script_pubkey: vec![0x51],
            }],
            0,
        )
        .unwrap();
        let two_inputs_over = crate::transaction::Transaction::new(
            1,
            vec![
                crate::transaction::TxIn {
                    previous_output: regular_at_2,
                    script_sig: Vec::new(),
                    sequence: u32::MAX,
                    witness: crate::transaction::Witness::default(),
                },
                crate::transaction::TxIn {
                    previous_output: regular_b,
                    script_sig: Vec::new(),
                    sequence: u32::MAX,
                    witness: crate::transaction::Witness::default(),
                },
            ],
            vec![crate::transaction::TxOut {
                value: 51,
                script_pubkey: vec![0x51],
            }],
            0,
        )
        .unwrap();
        let mut at_2 = make_utxo(2);
        let over_block = build_checked_block(
            regtest,
            3,
            genesis.hash(),
            prev_mtp,
            coinbase_tx(
                regtest,
                3,
                4,
                vec![crate::transaction::TxOut {
                    value: 0,
                    script_pubkey: vec![0x51],
                }],
            ),
            vec![two_inputs_over],
        );
        assert_eq!(
            at_2.connect_block(over_block, |_| prev_mtp),
            Err(super::ConnectError::InputsBelowOutputs)
        );
        let exact_block = build_checked_block(
            regtest,
            3,
            genesis.hash(),
            prev_mtp,
            coinbase_tx(
                regtest,
                3,
                5,
                vec![crate::transaction::TxOut {
                    value: 0,
                    script_pubkey: vec![0x51],
                }],
            ),
            vec![two_inputs_exact],
        );
        at_2.connect_block(exact_block, |_| prev_mtp).unwrap();

        let missing_before_premature = crate::transaction::Transaction::new(
            2,
            vec![
                crate::transaction::TxIn {
                    previous_output: coinbase_at_2,
                    script_sig: Vec::new(),
                    sequence: 99,
                    witness: crate::transaction::Witness::default(),
                },
                crate::transaction::TxIn {
                    previous_output: missing,
                    script_sig: Vec::new(),
                    sequence: 99,
                    witness: crate::transaction::Witness::default(),
                },
            ],
            vec![crate::transaction::TxOut {
                value: 999,
                script_pubkey: vec![0x51],
            }],
            0,
        )
        .unwrap();
        let mut at_2 = make_utxo(2);
        let prec_1 = build_checked_block(
            regtest,
            3,
            genesis.hash(),
            prev_mtp,
            coinbase_tx(
                regtest,
                3,
                6,
                vec![crate::transaction::TxOut {
                    value: 0,
                    script_pubkey: vec![0x51],
                }],
            ),
            vec![missing_before_premature],
        );
        assert_eq!(
            at_2.connect_block(prec_1, |_| prev_mtp),
            Err(super::ConnectError::MissingInputs)
        );

        let premature_before_value = crate::transaction::Transaction::new(
            2,
            vec![crate::transaction::TxIn {
                previous_output: coinbase_at_2,
                script_sig: Vec::new(),
                sequence: 99,
                witness: crate::transaction::Witness::default(),
            }],
            vec![crate::transaction::TxOut {
                value: 999,
                script_pubkey: vec![0x51],
            }],
            0,
        )
        .unwrap();
        let prec_2 = build_checked_block(
            regtest,
            3,
            genesis.hash(),
            prev_mtp,
            coinbase_tx(
                regtest,
                3,
                7,
                vec![crate::transaction::TxOut {
                    value: 0,
                    script_pubkey: vec![0x51],
                }],
            ),
            vec![premature_before_value],
        );
        assert_eq!(
            at_2.connect_block(prec_2, |_| prev_mtp),
            Err(super::ConnectError::PrematureCoinbaseSpend)
        );

        let value_before_sequence = crate::transaction::Transaction::new(
            2,
            vec![crate::transaction::TxIn {
                previous_output: regular_at_2,
                script_sig: Vec::new(),
                sequence: 99,
                witness: crate::transaction::Witness::default(),
            }],
            vec![crate::transaction::TxOut {
                value: 31,
                script_pubkey: vec![0x51],
            }],
            0,
        )
        .unwrap();
        let prec_3 = build_checked_block(
            regtest,
            3,
            genesis.hash(),
            prev_mtp,
            coinbase_tx(
                regtest,
                3,
                8,
                vec![crate::transaction::TxOut {
                    value: 0,
                    script_pubkey: vec![0x51],
                }],
            ),
            vec![value_before_sequence],
        );
        assert_eq!(
            at_2.connect_block(prec_3, |_| prev_mtp),
            Err(super::ConnectError::InputsBelowOutputs)
        );
    }

    #[test]
    fn bip30_rejects_unspent_duplicates_and_allows_historical_mainnet_overwrites_with_clean_undo() {
        let mainnet = crate::chainparams::Network::Mainnet;
        let genesis = mainnet.genesis();
        let prev_mtp = genesis.time;

        let dup_cb = coinbase_tx(
            mainnet,
            1,
            7,
            vec![crate::transaction::TxOut {
                value: 5_000_000_000,
                script_pubkey: vec![0x51],
            }],
        );
        let mut utxo = super::UtxoSet::new(mainnet);
        let first = build_checked_block(
            mainnet,
            1,
            genesis.hash(),
            prev_mtp,
            dup_cb.clone(),
            Vec::new(),
        );
        utxo.connect_block(first, |_| prev_mtp).unwrap();
        let second = build_checked_block(
            mainnet,
            2,
            utxo.best_block(),
            prev_mtp + 1,
            dup_cb,
            Vec::new(),
        );
        let before = utxo.clone();
        assert_eq!(
            utxo.connect_block(second, |_| prev_mtp + 1),
            Err(super::ConnectError::DuplicateTxId)
        );
        assert_eq!(utxo, before);

        let unspendable_cb = coinbase_tx(
            mainnet,
            1,
            8,
            vec![crate::transaction::TxOut {
                value: 0,
                script_pubkey: vec![0x6a],
            }],
        );
        let mut utxo_unspendable = super::UtxoSet::new(mainnet);
        let b1 = build_checked_block(
            mainnet,
            1,
            genesis.hash(),
            prev_mtp,
            unspendable_cb.clone(),
            Vec::new(),
        );
        utxo_unspendable.connect_block(b1, |_| prev_mtp).unwrap();
        let b2 = build_checked_block(
            mainnet,
            2,
            utxo_unspendable.best_block(),
            prev_mtp + 1,
            unspendable_cb,
            Vec::new(),
        );
        utxo_unspendable
            .connect_block(b2, |_| prev_mtp + 1)
            .unwrap();

        let seed_out = crate::transaction::OutPoint {
            txid: bitcoin_hashes::sha256d::Hash::from_byte_array([0x66; 32]),
            vout: 0,
        };
        let dup_tx = crate::transaction::Transaction::new(
            1,
            vec![crate::transaction::TxIn {
                previous_output: seed_out,
                script_sig: Vec::new(),
                sequence: u32::MAX,
                witness: crate::transaction::Witness::default(),
            }],
            vec![crate::transaction::TxOut {
                value: 10,
                script_pubkey: vec![0x51],
            }],
            0,
        )
        .unwrap();
        let mut utxo_dup_rest = utxo_at(
            mainnet,
            1,
            genesis.hash(),
            vec![
                (
                    seed_out,
                    super::Coin {
                        output: crate::transaction::TxOut {
                            value: 10,
                            script_pubkey: vec![0x51],
                        },
                        height: nonzero(1),
                        is_coinbase: false,
                    },
                ),
                (
                    crate::transaction::OutPoint {
                        txid: dup_tx.txid(),
                        vout: 0,
                    },
                    super::Coin {
                        output: crate::transaction::TxOut {
                            value: 10,
                            script_pubkey: vec![0x51],
                        },
                        height: nonzero(1),
                        is_coinbase: false,
                    },
                ),
            ],
        );
        let dup_rest_block = build_checked_block(
            mainnet,
            2,
            genesis.hash(),
            prev_mtp,
            coinbase_tx(
                mainnet,
                2,
                9,
                vec![crate::transaction::TxOut {
                    value: 0,
                    script_pubkey: vec![0x51],
                }],
            ),
            vec![dup_tx],
        );
        assert_eq!(
            utxo_dup_rest.connect_block(dup_rest_block, |_| prev_mtp),
            Err(super::ConnectError::DuplicateTxId)
        );

        let block_91842 = crate::fixtures::block(crate::fixtures::MAINNET_BLOCK_91842);
        let cb_91842_txid = block_91842.transactions.as_ref().unwrap().first.txid();
        let cb_91842_outpoint = crate::transaction::OutPoint {
            txid: cb_91842_txid,
            vout: 0,
        };
        let old_coin_91812 = super::Coin {
            output: crate::transaction::TxOut {
                value: 5_000_000_000,
                script_pubkey: vec![0x51],
            },
            height: nonzero(91_812),
            is_coinbase: true,
        };
        let mtp_91841 = block_91842.header.time - 1;
        let pos_91842 = crate::chain::BlockPosition::new(
            mainnet,
            nonzero(91_842),
            block_91842.header.hash(),
            mtp_91841,
        );
        let checked_91842 = crate::block::CheckedBlock::from_checked(
            pos_91842,
            crate::block::PositionedBlock::new(block_91842.clone(), pos_91842.position())
                .unwrap()
                .check()
                .unwrap(),
        )
        .unwrap();
        let mut utxo_91842 = utxo_at(
            mainnet,
            91_841,
            block_91842.header.prev,
            vec![(cb_91842_outpoint, old_coin_91812.clone())],
        );
        let before_91842 = utxo_91842.clone();
        utxo_91842
            .connect_block(checked_91842, |_| mtp_91841)
            .unwrap();
        assert_eq!(utxo_91842.coins[&cb_91842_outpoint].height, nonzero(91_842));
        utxo_91842.disconnect_tip(super::DisconnectTip {
            block_hash: block_91842.header.hash(),
            prev_hash: block_91842.header.prev,
        });
        assert_eq!(utxo_91842, before_91842);

        let wrong_height_pos = crate::chain::BlockPosition::new(
            mainnet,
            nonzero(91_841),
            block_91842.header.hash(),
            mtp_91841,
        );
        let wrong_height_91842 = crate::block::CheckedBlock::from_checked(
            wrong_height_pos,
            crate::block::PositionedBlock::new(block_91842.clone(), wrong_height_pos.position())
                .unwrap()
                .check()
                .unwrap(),
        )
        .unwrap();
        let mut utxo_wrong = utxo_at(
            mainnet,
            91_840,
            block_91842.header.prev,
            vec![(cb_91842_outpoint, old_coin_91812)],
        );
        assert_eq!(
            utxo_wrong.connect_block(wrong_height_91842, |_| mtp_91841),
            Err(super::ConnectError::DuplicateTxId)
        );

        let block_91880 = crate::fixtures::block(crate::fixtures::MAINNET_BLOCK_91880);
        let txs_91880 = block_91880.transactions.as_ref().unwrap();
        let cb_91880_outpoint = crate::transaction::OutPoint {
            txid: txs_91880.first.txid(),
            vout: 0,
        };
        let spend_input = txs_91880.rest[0].inputs()[0].previous_output;
        let spend_out_value: i64 = txs_91880.rest[0]
            .outputs()
            .iter()
            .map(|output| output.value)
            .sum();
        let old_coin_91722 = super::Coin {
            output: crate::transaction::TxOut {
                value: 5_000_000_000,
                script_pubkey: vec![0x51],
            },
            height: nonzero(91_722),
            is_coinbase: true,
        };
        let spent_coin_91880 = super::Coin {
            output: crate::transaction::TxOut {
                value: spend_out_value,
                script_pubkey: vec![0x51],
            },
            height: nonzero(91_000),
            is_coinbase: false,
        };
        let mtp_91879 = block_91880.header.time - 1;
        let pos_91880 = crate::chain::BlockPosition::new(
            mainnet,
            nonzero(91_880),
            block_91880.header.hash(),
            mtp_91879,
        );
        let checked_91880 = crate::block::CheckedBlock::from_checked(
            pos_91880,
            crate::block::PositionedBlock::new(block_91880.clone(), pos_91880.position())
                .unwrap()
                .check()
                .unwrap(),
        )
        .unwrap();
        let mut utxo_91880 = utxo_at(
            mainnet,
            91_879,
            block_91880.header.prev,
            vec![
                (cb_91880_outpoint, old_coin_91722.clone()),
                (spend_input, spent_coin_91880.clone()),
            ],
        );
        let before_91880 = utxo_91880.clone();
        utxo_91880
            .connect_block(checked_91880.clone(), |_| mtp_91879)
            .unwrap();
        assert_eq!(utxo_91880.coins[&cb_91880_outpoint].height, nonzero(91_880));
        assert!(!utxo_91880.coins.contains_key(&spend_input));
        utxo_91880.disconnect_tip(super::DisconnectTip {
            block_hash: block_91880.header.hash(),
            prev_hash: block_91880.header.prev,
        });
        assert_eq!(utxo_91880, before_91880);

        let mut utxo_91880_dup_rest = utxo_at(
            mainnet,
            91_879,
            block_91880.header.prev,
            vec![
                (cb_91880_outpoint, old_coin_91722),
                (spend_input, spent_coin_91880),
                (
                    crate::transaction::OutPoint {
                        txid: txs_91880.rest[0].txid(),
                        vout: 0,
                    },
                    super::Coin {
                        output: crate::transaction::TxOut {
                            value: 1,
                            script_pubkey: vec![0x51],
                        },
                        height: nonzero(91_000),
                        is_coinbase: false,
                    },
                ),
            ],
        );
        assert_eq!(
            utxo_91880_dup_rest.connect_block(checked_91880, |_| mtp_91879),
            Err(super::ConnectError::DuplicateTxId)
        );
    }

    #[test]
    fn bip68_sequence_locks_enforce_activation_version_flags_height_and_time() {
        let mainnet = crate::chainparams::Network::Mainnet;
        let regtest = crate::chainparams::Network::Regtest;
        let genesis = regtest.genesis();
        let out_a = crate::transaction::OutPoint {
            txid: bitcoin_hashes::sha256d::Hash::from_byte_array([0x71; 32]),
            vout: 0,
        };

        let make_spend = |version: u32, sequence: u32| {
            crate::transaction::Transaction::new(
                version,
                vec![crate::transaction::TxIn {
                    previous_output: out_a,
                    script_sig: Vec::new(),
                    sequence,
                    witness: crate::transaction::Witness::default(),
                }],
                vec![crate::transaction::TxOut {
                    value: 100,
                    script_pubkey: vec![0x51],
                }],
                0,
            )
            .unwrap()
        };

        let run = |network: crate::chainparams::Network,
                   coin_height: usize,
                   block_height: usize,
                   version: u32,
                   sequence: u32,
                   mtp_fn: &dyn Fn(usize) -> u32| {
            let prev_hash = network.genesis().hash();
            let prev_mtp = mtp_fn(block_height - 1);
            let mut utxo = utxo_at(
                network,
                block_height - 1,
                prev_hash,
                vec![(
                    out_a,
                    super::Coin {
                        output: crate::transaction::TxOut {
                            value: 100,
                            script_pubkey: vec![0x51],
                        },
                        height: nonzero(coin_height),
                        is_coinbase: false,
                    },
                )],
            );
            let block = build_checked_block(
                network,
                block_height,
                prev_hash,
                prev_mtp,
                coinbase_tx(
                    network,
                    block_height,
                    1,
                    vec![crate::transaction::TxOut {
                        value: 0,
                        script_pubkey: vec![0x51],
                    }],
                ),
                vec![make_spend(version, sequence)],
            );
            utxo.connect_block(block, mtp_fn).map(|_| ())
        };

        let fixed_mtp = |_: usize| 1_000_000_u32;
        assert_eq!(run(mainnet, 419_320, 419_327, 2, 100, &fixed_mtp), Ok(()));
        assert_eq!(
            run(mainnet, 419_320, 419_328, 2, 100, &fixed_mtp),
            Err(super::ConnectError::NonFinalSequence)
        );
        assert_eq!(
            run(mainnet, 419_320, 419_329, 2, 100, &fixed_mtp),
            Err(super::ConnectError::NonFinalSequence)
        );

        assert_eq!(run(regtest, 2, 3, 0, 100, &fixed_mtp), Ok(()));
        assert_eq!(run(regtest, 2, 3, 1, 100, &fixed_mtp), Ok(()));
        assert_eq!(
            run(regtest, 2, 3, 2, 100, &fixed_mtp),
            Err(super::ConnectError::NonFinalSequence)
        );
        assert_eq!(
            run(regtest, 2, 3, u32::MAX, 100, &fixed_mtp),
            Err(super::ConnectError::NonFinalSequence)
        );
        assert_eq!(
            run(
                regtest,
                2,
                3,
                2,
                crate::transaction::SEQUENCE_LOCK_TIME_DISABLE_FLAG | 100,
                &fixed_mtp
            ),
            Ok(())
        );
        assert_eq!(
            run(
                regtest,
                2,
                3,
                2,
                crate::transaction::SEQUENCE_LOCK_TIME_DISABLE_FLAG
                    | crate::transaction::SEQUENCE_LOCK_TIME_TYPE_FLAG
                    | 100,
                &fixed_mtp
            ),
            Ok(())
        );

        assert_eq!(run(regtest, 2, 3, 2, 1, &fixed_mtp), Ok(()));
        assert_eq!(run(regtest, 2, 3, 2, 0x0001_0001, &fixed_mtp), Ok(()));
        assert_eq!(
            run(regtest, 2, 3, 2, 2, &fixed_mtp),
            Err(super::ConnectError::NonFinalSequence)
        );
        assert_eq!(run(regtest, 2, 5, 2, 3, &fixed_mtp), Ok(()));
        assert_eq!(
            run(regtest, 2, 5, 2, 4, &fixed_mtp),
            Err(super::ConnectError::NonFinalSequence)
        );

        let same_block_utxo = utxo_at(
            regtest,
            1,
            genesis.hash(),
            vec![(
                out_a,
                super::Coin {
                    output: crate::transaction::TxOut {
                        value: 100,
                        script_pubkey: vec![0x51],
                    },
                    height: nonzero(1),
                    is_coinbase: false,
                },
            )],
        );
        let parent = make_spend(2, 0);
        let child_ok = crate::transaction::Transaction::new(
            2,
            vec![crate::transaction::TxIn {
                previous_output: crate::transaction::OutPoint {
                    txid: parent.txid(),
                    vout: 0,
                },
                script_sig: Vec::new(),
                sequence: 0,
                witness: crate::transaction::Witness::default(),
            }],
            vec![crate::transaction::TxOut {
                value: 100,
                script_pubkey: vec![0x51],
            }],
            0,
        )
        .unwrap();
        let child_fail = crate::transaction::Transaction::new(
            2,
            vec![crate::transaction::TxIn {
                previous_output: crate::transaction::OutPoint {
                    txid: parent.txid(),
                    vout: 0,
                },
                script_sig: Vec::new(),
                sequence: 1,
                witness: crate::transaction::Witness::default(),
            }],
            vec![crate::transaction::TxOut {
                value: 100,
                script_pubkey: vec![0x51],
            }],
            0,
        )
        .unwrap();
        let child_time_fail = crate::transaction::Transaction::new(
            2,
            vec![crate::transaction::TxIn {
                previous_output: crate::transaction::OutPoint {
                    txid: parent.txid(),
                    vout: 0,
                },
                script_sig: Vec::new(),
                sequence: crate::transaction::SEQUENCE_LOCK_TIME_TYPE_FLAG | 1,
                witness: crate::transaction::Witness::default(),
            }],
            vec![crate::transaction::TxOut {
                value: 100,
                script_pubkey: vec![0x51],
            }],
            0,
        )
        .unwrap();
        let child_time_ok = crate::transaction::Transaction::new(
            2,
            vec![crate::transaction::TxIn {
                previous_output: crate::transaction::OutPoint {
                    txid: parent.txid(),
                    vout: 0,
                },
                script_sig: Vec::new(),
                sequence: crate::transaction::SEQUENCE_LOCK_TIME_TYPE_FLAG,
                witness: crate::transaction::Witness::default(),
            }],
            vec![crate::transaction::TxOut {
                value: 100,
                script_pubkey: vec![0x51],
            }],
            0,
        )
        .unwrap();
        for (child, expected) in [
            (child_fail, Err(super::ConnectError::NonFinalSequence)),
            (child_time_fail, Err(super::ConnectError::NonFinalSequence)),
            (child_ok, Ok(())),
            (child_time_ok, Ok(())),
        ] {
            let mut copy = same_block_utxo.clone();
            let block = build_checked_block(
                regtest,
                2,
                genesis.hash(),
                1_000_000,
                coinbase_tx(
                    regtest,
                    2,
                    2,
                    vec![crate::transaction::TxOut {
                        value: 0,
                        script_pubkey: vec![0x51],
                    }],
                ),
                vec![parent.clone(), child],
            );
            assert_eq!(
                copy.connect_block(block, |_| 1_000_000).map(|_| ()),
                expected
            );
        }
        same_block_utxo.height();

        let step_mtp = |h: usize| match h {
            0 => 1_000,
            1 => 2_000,
            2 => 3_000,
            3 => 5_000,
            4 => 3_512,
            _ => 3_511,
        };
        assert_eq!(
            run(
                regtest,
                3,
                5,
                2,
                crate::transaction::SEQUENCE_LOCK_TIME_TYPE_FLAG | 1,
                &step_mtp
            ),
            Ok(())
        );
        assert_eq!(
            run(
                regtest,
                3,
                6,
                2,
                crate::transaction::SEQUENCE_LOCK_TIME_TYPE_FLAG | 1,
                &step_mtp
            ),
            Err(super::ConnectError::NonFinalSequence)
        );
        let genesis_time_mtp = |h: usize| if h == 0 { 10_000 } else { 10_512 };
        assert_eq!(
            run(
                regtest,
                1,
                2,
                2,
                crate::transaction::SEQUENCE_LOCK_TIME_TYPE_FLAG | 1,
                &genesis_time_mtp
            ),
            Ok(())
        );
        let genesis_time_short = |h: usize| if h == 0 { 10_000 } else { 10_511 };
        assert_eq!(
            run(
                regtest,
                1,
                2,
                2,
                crate::transaction::SEQUENCE_LOCK_TIME_TYPE_FLAG | 1,
                &genesis_time_short
            ),
            Err(super::ConnectError::NonFinalSequence)
        );
    }

    #[test]
    fn block_sigops_cost_combines_coinbase_legacy_p2sh_and_witness_at_80000_boundary() {
        let regtest = crate::chainparams::Network::Regtest;
        let genesis = regtest.genesis();
        let prev_mtp = genesis.time;

        let out_p2sh = crate::transaction::OutPoint {
            txid: bitcoin_hashes::sha256d::Hash::from_byte_array([0x81; 32]),
            vout: 0,
        };
        let out_p2wpkh = crate::transaction::OutPoint {
            txid: bitcoin_hashes::sha256d::Hash::from_byte_array([0x82; 32]),
            vout: 0,
        };
        let out_p2wsh = crate::transaction::OutPoint {
            txid: bitcoin_hashes::sha256d::Hash::from_byte_array([0x83; 32]),
            vout: 0,
        };
        let make_utxo = || {
            utxo_at(
                regtest,
                1,
                genesis.hash(),
                vec![
                    (
                        out_p2sh,
                        super::Coin {
                            output: crate::transaction::TxOut {
                                value: 100,
                                script_pubkey: p2sh_script(),
                            },
                            height: nonzero(1),
                            is_coinbase: false,
                        },
                    ),
                    (
                        out_p2wpkh,
                        super::Coin {
                            output: crate::transaction::TxOut {
                                value: 100,
                                script_pubkey: p2wpkh_script(),
                            },
                            height: nonzero(1),
                            is_coinbase: false,
                        },
                    ),
                    (
                        out_p2wsh,
                        super::Coin {
                            output: crate::transaction::TxOut {
                                value: 100,
                                script_pubkey: p2wsh_script(),
                            },
                            height: nonzero(1),
                            is_coinbase: false,
                        },
                    ),
                ],
            )
        };

        let make_block = |witness_checksigs: usize| {
            let coinbase = coinbase_tx(
                regtest,
                2,
                1,
                vec![crate::transaction::TxOut {
                    value: 0,
                    script_pubkey: vec![0xac],
                }],
            );
            let mut tx_legacy_script = vec![0xae; 999];
            tx_legacy_script.extend(std::iter::repeat_n(0xac, 17));
            let tx = crate::transaction::Transaction::new(
                1,
                vec![
                    crate::transaction::TxIn {
                        previous_output: out_p2sh,
                        script_sig: vec![0x02, 0x51, 0xae],
                        sequence: u32::MAX,
                        witness: crate::transaction::Witness::default(),
                    },
                    crate::transaction::TxIn {
                        previous_output: out_p2wpkh,
                        script_sig: Vec::new(),
                        sequence: u32::MAX,
                        witness: crate::transaction::Witness::default(),
                    },
                    crate::transaction::TxIn {
                        previous_output: out_p2wsh,
                        script_sig: Vec::new(),
                        sequence: u32::MAX,
                        witness: witness_from(&[&vec![0xac; witness_checksigs]]),
                    },
                ],
                vec![crate::transaction::TxOut {
                    value: 300,
                    script_pubkey: tx_legacy_script,
                }],
                0,
            )
            .unwrap();
            build_checked_block(regtest, 2, genesis.hash(), prev_mtp, coinbase, vec![tx])
        };

        let mut utxo = make_utxo();
        utxo.connect_block(make_block(3), |_| prev_mtp).unwrap();

        let mut utxo = make_utxo();
        let before = utxo.clone();
        assert_eq!(
            utxo.connect_block(make_block(4), |_| prev_mtp),
            Err(super::ConnectError::SigOpsTooMany)
        );
        assert_eq!(utxo, before);
    }

    #[test]
    fn disconnect_tip_unwinds_multiple_blocks_back_to_earlier_snapshots() {
        let regtest = crate::chainparams::Network::Regtest;
        let genesis = regtest.genesis();
        let mut utxo = super::UtxoSet::new(regtest);
        let snap_0 = utxo.clone();

        let cb1 = coinbase_tx(
            regtest,
            1,
            1,
            vec![crate::transaction::TxOut {
                value: 5_000_000_000,
                script_pubkey: vec![0x51],
            }],
        );
        let b1 = build_checked_block(regtest, 1, genesis.hash(), genesis.time, cb1, Vec::new());
        let h1 = b1.header().hash();
        utxo.connect_block(b1, |_| genesis.time).unwrap();
        let snap_1 = utxo.clone();

        let cb2 = coinbase_tx(
            regtest,
            2,
            2,
            vec![crate::transaction::TxOut {
                value: 5_000_000_000,
                script_pubkey: vec![0x51],
            }],
        );
        let b2 = build_checked_block(regtest, 2, h1, genesis.time + 1, cb2, Vec::new());
        let h2 = b2.header().hash();
        utxo.connect_block(b2, |_| genesis.time + 1).unwrap();

        assert_eq!(utxo.height(), 2);
        assert_eq!(utxo.best_block(), h2);
        utxo.disconnect_tip(super::DisconnectTip {
            block_hash: h2,
            prev_hash: h1,
        });
        assert_eq!(utxo, snap_1);
        utxo.disconnect_tip(super::DisconnectTip {
            block_hash: h1,
            prev_hash: genesis.hash(),
        });
        assert_eq!(utxo, snap_0);
        assert_eq!(utxo.height(), 0);
        assert_eq!(utxo.best_block(), genesis.hash());
    }

    #[test]
    fn connect_block_produces_deterministic_undo_across_independent_sets() {
        let regtest = crate::chainparams::Network::Regtest;
        let genesis = regtest.genesis();
        let prev_mtp = genesis.time;

        let out_a = crate::transaction::OutPoint {
            txid: bitcoin_hashes::sha256d::Hash::from_byte_array([0x11; 32]),
            vout: 0,
        };
        let out_b = crate::transaction::OutPoint {
            txid: bitcoin_hashes::sha256d::Hash::from_byte_array([0x22; 32]),
            vout: 1,
        };
        let out_c = crate::transaction::OutPoint {
            txid: bitcoin_hashes::sha256d::Hash::from_byte_array([0x33; 32]),
            vout: 0,
        };
        let seed_coins = vec![
            (
                out_a,
                super::Coin {
                    output: crate::transaction::TxOut {
                        value: 100,
                        script_pubkey: vec![0x51],
                    },
                    height: nonzero(1),
                    is_coinbase: false,
                },
            ),
            (
                out_b,
                super::Coin {
                    output: crate::transaction::TxOut {
                        value: 200,
                        script_pubkey: vec![0x51],
                    },
                    height: nonzero(1),
                    is_coinbase: false,
                },
            ),
            (
                out_c,
                super::Coin {
                    output: crate::transaction::TxOut {
                        value: 300,
                        script_pubkey: vec![0x51],
                    },
                    height: nonzero(1),
                    is_coinbase: false,
                },
            ),
        ];
        let spend = |input: crate::transaction::OutPoint, value_a: i64, value_b: i64| {
            crate::transaction::Transaction::new(
                1,
                vec![crate::transaction::TxIn {
                    previous_output: input,
                    script_sig: Vec::new(),
                    sequence: u32::MAX,
                    witness: crate::transaction::Witness::default(),
                }],
                vec![
                    crate::transaction::TxOut {
                        value: value_a,
                        script_pubkey: vec![0x51],
                    },
                    crate::transaction::TxOut {
                        value: value_b,
                        script_pubkey: vec![0x51],
                    },
                ],
                0,
            )
            .unwrap()
        };
        let block = build_checked_block(
            regtest,
            2,
            genesis.hash(),
            prev_mtp,
            coinbase_tx(
                regtest,
                2,
                1,
                vec![
                    crate::transaction::TxOut {
                        value: 10,
                        script_pubkey: vec![0x51],
                    },
                    crate::transaction::TxOut {
                        value: 20,
                        script_pubkey: vec![0x51],
                    },
                ],
            ),
            vec![
                spend(out_a, 40, 60),
                spend(out_b, 80, 120),
                spend(out_c, 150, 150),
            ],
        );

        let mut first = utxo_at(regtest, 1, genesis.hash(), seed_coins.clone());
        first.connect_block(block.clone(), |_| prev_mtp).unwrap();
        let undo = first.undo.last().unwrap();
        assert!(undo.created.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(undo.spent.windows(2).all(|pair| pair[0].0 < pair[1].0));
        for _ in 0..8 {
            let mut other = utxo_at(regtest, 1, genesis.hash(), seed_coins.clone());
            other.connect_block(block.clone(), |_| prev_mtp).unwrap();
            assert_eq!(other, first);
        }
    }
}
