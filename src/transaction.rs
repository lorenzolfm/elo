use crate::serialize::{Decode, Encode};

const WITNESS_MARKER: u8 = 0x00;

const WITNESS_FLAG: u8 = 0x01;

pub(crate) const WITNESS_SCALE_FACTOR: usize = 4;

pub(crate) const BLOCK_WEIGHT_MAX: usize = 4_000_000;

pub(crate) const BLOCK_BASE_SIZE_MAX: usize = BLOCK_WEIGHT_MAX / WITNESS_SCALE_FACTOR;

const _: () = assert!(BLOCK_BASE_SIZE_MAX * WITNESS_SCALE_FACTOR == BLOCK_WEIGHT_MAX);

pub(crate) const COIN: i64 = 100_000_000;

pub(crate) const MONEY_MAX: i64 = 21_000_000 * COIN;

const _: () = assert!(MONEY_MAX == 2_100_000_000_000_000);
const _: () = assert!(MONEY_MAX <= i64::MAX / 2);

const COINBASE_SCRIPT_SIZE_MIN: usize = 2;

const COINBASE_SCRIPT_SIZE_MAX: usize = 100;

const SCRIPT_SIZE_MAX: usize = 10_000;

const LOCK_TIME_THRESHOLD: u32 = 500_000_000;

const SEQUENCE_FINAL: u32 = u32::MAX;

pub(crate) const SEQUENCE_LOCKTIME_DISABLE_FLAG: u32 = 1 << 31;

pub(crate) const SEQUENCE_LOCKTIME_TYPE_FLAG: u32 = 1 << 22;

pub(crate) const SEQUENCE_LOCKTIME_MASK: u32 = 0x0000_ffff;

pub(crate) const SEQUENCE_LOCKTIME_GRANULARITY: u32 = 9;

const MULTISIG_PUBKEYS_COUNT_MAX: usize = 20;

pub(crate) const OP_PUSHDATA1: u8 = 0x4c;

const OP_PUSHDATA2: u8 = 0x4d;

const OP_PUSHDATA4: u8 = 0x4e;

const OP_1_OFFSET: u8 = 0x50;

const OP_1: u8 = 0x51;

const OP_16: u8 = 0x60;

const OP_RETURN: u8 = 0x6a;

const OP_EQUAL: u8 = 0x87;

const OP_HASH160: u8 = 0xa9;

const OP_CHECKSIG: u8 = 0xac;

const OP_CHECKSIGVERIFY: u8 = 0xad;

const OP_CHECKMULTISIG: u8 = 0xae;

const OP_CHECKMULTISIGVERIFY: u8 = 0xaf;

const P2SH_SCRIPT_SIZE: usize = 23;

const P2SH_HASH_SIZE: u8 = 20;

const WITNESS_V0_KEYHASH_SIZE: usize = 20;

const WITNESS_V0_SCRIPTHASH_SIZE: usize = 32;

const TX_INPUTS_COUNT_MAX: usize = BLOCK_BASE_SIZE_MAX / TxIn::SIZE_MIN;

const TX_OUTPUTS_COUNT_MAX: usize = BLOCK_BASE_SIZE_MAX / TxOut::SIZE_MIN;

const _: () = assert!(usize::BITS >= u32::BITS);
const _: () = assert!(TX_INPUTS_COUNT_MAX * TxIn::SIZE_MIN <= BLOCK_BASE_SIZE_MAX);
const _: () = assert!((TX_INPUTS_COUNT_MAX + 1) * TxIn::SIZE_MIN > BLOCK_BASE_SIZE_MAX);
const _: () = assert!(TX_OUTPUTS_COUNT_MAX * TxOut::SIZE_MIN <= BLOCK_BASE_SIZE_MAX);
const _: () = assert!((TX_OUTPUTS_COUNT_MAX + 1) * TxOut::SIZE_MIN > BLOCK_BASE_SIZE_MAX);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransactionError {
    InputsEmpty,
    OutputsEmpty,
    BaseSizeTooLarge,
    OutputNegative,
    OutputTooLarge,
    OutputsTotalTooLarge,
    DuplicateInputs,
    CoinbaseScriptSize,
    NullOutPoint,
}

impl std::fmt::Display for TransactionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransactionError::InputsEmpty => write!(f, "a transaction has no inputs"),
            TransactionError::OutputsEmpty => write!(f, "a transaction has no outputs"),
            TransactionError::BaseSizeTooLarge => {
                write!(
                    f,
                    "a transaction is larger than {BLOCK_BASE_SIZE_MAX} bytes without witness"
                )
            }
            TransactionError::OutputNegative => write!(f, "a transaction output value is negative"),
            TransactionError::OutputTooLarge => {
                write!(f, "a transaction output value is above {MONEY_MAX}")
            }
            TransactionError::OutputsTotalTooLarge => {
                write!(
                    f,
                    "the sum of transaction output values is above {MONEY_MAX}"
                )
            }
            TransactionError::DuplicateInputs => {
                write!(f, "a transaction spends the same outpoint twice")
            }
            TransactionError::CoinbaseScriptSize => {
                write!(
                    f,
                    "the coinbase scriptSig length is outside {COINBASE_SCRIPT_SIZE_MIN}..={COINBASE_SCRIPT_SIZE_MAX}"
                )
            }
            TransactionError::NullOutPoint => {
                write!(f, "a non-coinbase transaction has a null outpoint")
            }
        }
    }
}

impl std::error::Error for TransactionError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct OutPoint {
    pub(crate) txid: bitcoin_hashes::sha256d::Hash,
    pub(crate) vout: u32,
}

impl OutPoint {
    fn is_null(&self) -> bool {
        self.txid.as_byte_array() == &[0; 32] && self.vout == u32::MAX
    }
}

impl Encode for OutPoint {
    fn encode(&self, out: &mut Vec<u8>) {
        self.txid.encode(out);
        self.vout.encode(out);
    }
}

impl Decode for OutPoint {
    fn decode(input: &mut &[u8]) -> Result<Self, crate::serialize::Error> {
        Ok(Self {
            txid: Decode::decode(input)?,
            vout: u32::decode(input)?,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
enum WitnessStack {
    #[default]
    Empty,
    NonEmpty {
        count: std::num::NonZeroUsize,
        bytes: Vec<u8>,
    },
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Witness(WitnessStack);

impl Witness {
    pub(crate) fn is_empty(&self) -> bool {
        matches!(self.0, WitnessStack::Empty)
    }

    pub(crate) fn reserved_value(&self) -> Option<[u8; 32]> {
        match &self.0 {
            WitnessStack::NonEmpty { count, bytes } if count.get() == 1 => match bytes.as_slice() {
                [32, value @ ..] => {
                    assert_eq!(value.len(), 32);
                    value.try_into().ok()
                }
                _ => None,
            },
            _ => None,
        }
    }

    fn last_item(&self) -> Option<&[u8]> {
        let WitnessStack::NonEmpty { count, bytes } = &self.0 else {
            return None;
        };
        let mut input = bytes.as_slice();
        let mut last: &[u8] = &[];
        for _ in 0..count.get() {
            last = crate::serialize::read_bytes(&mut input).expect("validated witness stack");
        }
        assert!(input.is_empty());
        Some(last)
    }

    fn encoded_size(&self) -> usize {
        match &self.0 {
            WitnessStack::Empty => 1,
            WitnessStack::NonEmpty { count, bytes } => {
                assert!(bytes.len() >= count.get());
                crate::serialize::compact_size_length(count.get()) + bytes.len()
            }
        }
    }
}

impl Encode for Witness {
    fn encode(&self, out: &mut Vec<u8>) {
        let start = out.len();
        match &self.0 {
            WitnessStack::Empty => crate::serialize::write_compact_size(out, 0),
            WitnessStack::NonEmpty { count, bytes } => {
                crate::serialize::write_compact_size(out, count.get());
                out.extend_from_slice(bytes);
            }
        }
        assert_eq!(out.len() - start, self.encoded_size());
    }
}

impl Decode for Witness {
    fn decode(input: &mut &[u8]) -> Result<Self, crate::serialize::Error> {
        let count = crate::serialize::read_compact_size(input)?;
        let Some(count) = std::num::NonZeroUsize::new(count) else {
            return Ok(Self(WitnessStack::Empty));
        };
        let stack = *input;
        for _ in 0..count.get() {
            crate::serialize::read_bytes(input)?;
        }
        let bytes = stack[..stack.len() - input.len()].to_vec();
        assert!(bytes.len() >= count.get());
        Ok(Self(WitnessStack::NonEmpty { count, bytes }))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TxIn {
    pub(crate) previous_output: OutPoint,
    pub(crate) script_sig: Vec<u8>,
    pub(crate) sequence: u32,
    pub(crate) witness: Witness,
}

impl TxIn {
    fn encoded_size(&self) -> usize {
        let size = 32
            + size_of::<u32>()
            + crate::serialize::compact_size_length(self.script_sig.len())
            + self.script_sig.len()
            + size_of::<u32>();
        assert!(size >= TxIn::SIZE_MIN);
        assert!(size <= TxIn::SIZE_MIN + 4 + self.script_sig.len());
        size
    }
}

impl Encode for TxIn {
    fn encode(&self, out: &mut Vec<u8>) {
        let start = out.len();
        self.previous_output.encode(out);
        crate::serialize::write_string(out, &self.script_sig);
        self.sequence.encode(out);
        assert_eq!(out.len() - start, self.encoded_size());
    }
}

impl Decode for TxIn {
    fn decode(input: &mut &[u8]) -> Result<Self, crate::serialize::Error> {
        Ok(Self {
            previous_output: OutPoint::decode(input)?,
            script_sig: crate::serialize::read_bytes(input)?.to_vec(),
            sequence: u32::decode(input)?,
            witness: Witness::default(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TxOut {
    pub(crate) value: i64,
    pub(crate) script_pubkey: Vec<u8>,
}

impl TxOut {
    pub(crate) fn is_unspendable(&self) -> bool {
        self.script_pubkey.first() == Some(&OP_RETURN) || self.script_pubkey.len() > SCRIPT_SIZE_MAX
    }

    fn encoded_size(&self) -> usize {
        let size = size_of::<i64>()
            + crate::serialize::compact_size_length(self.script_pubkey.len())
            + self.script_pubkey.len();
        assert!(size >= TxOut::SIZE_MIN);
        assert!(size <= TxOut::SIZE_MIN + 4 + self.script_pubkey.len());
        size
    }
}

impl Encode for TxOut {
    fn encode(&self, out: &mut Vec<u8>) {
        let start = out.len();
        self.value.encode(out);
        crate::serialize::write_string(out, &self.script_pubkey);
        assert_eq!(out.len() - start, self.encoded_size());
    }
}

impl Decode for TxOut {
    fn decode(input: &mut &[u8]) -> Result<Self, crate::serialize::Error> {
        Ok(Self {
            value: i64::decode(input)?,
            script_pubkey: crate::serialize::read_bytes(input)?.to_vec(),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LockTime {
    Unlocked,
    Height(std::num::NonZeroU32),
    Time(u32),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct NonEmptyInputs(Vec<TxIn>);

impl NonEmptyInputs {
    fn new(inputs: Vec<TxIn>) -> Option<Self> {
        (!inputs.is_empty()).then_some(Self(inputs))
    }

    fn as_slice(&self) -> &[TxIn] {
        assert!(!self.0.is_empty());
        &self.0
    }

    fn split_first(&self) -> (&TxIn, &[TxIn]) {
        self.0.split_first().expect("non-empty inputs")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Transfers {
    Empty,
    NonEmpty {
        inputs: NonEmptyInputs,
        outputs: Vec<TxOut>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Transaction {
    pub(crate) version: u32,
    transfers: Transfers,
    lock_time: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CheckedTransaction {
    transaction: Transaction,
    value_out: i64,
    legacy_sigop_count: usize,
}

impl Transaction {
    #[cfg(any(test, fuzzing))]
    pub(crate) fn new(
        version: u32,
        inputs: Vec<TxIn>,
        outputs: Vec<TxOut>,
        lock_time: u32,
    ) -> Option<Self> {
        let transfers = match NonEmptyInputs::new(inputs) {
            Some(inputs) => Transfers::NonEmpty { inputs, outputs },
            None if outputs.is_empty() => Transfers::Empty,
            None => return None,
        };
        Some(Self {
            version,
            transfers,
            lock_time,
        })
    }

    #[cfg(any(test, fuzzing))]
    pub(crate) fn inputs(&self) -> &[TxIn] {
        self.inputs_slice()
    }

    fn inputs_slice(&self) -> &[TxIn] {
        match &self.transfers {
            Transfers::Empty => &[],
            Transfers::NonEmpty { inputs, .. } => inputs.as_slice(),
        }
    }

    pub(crate) fn outputs(&self) -> &[TxOut] {
        match &self.transfers {
            Transfers::Empty => &[],
            Transfers::NonEmpty { outputs, .. } => outputs,
        }
    }

    pub(crate) fn lock_time(&self) -> LockTime {
        match std::num::NonZeroU32::new(self.lock_time) {
            None => LockTime::Unlocked,
            Some(value) if value.get() < LOCK_TIME_THRESHOLD => LockTime::Height(value),
            Some(value) => LockTime::Time(value.get()),
        }
    }

    #[cfg(test)]
    pub(crate) fn lock_time_raw(&self) -> u32 {
        self.lock_time
    }

    pub(crate) fn txid(&self) -> bitcoin_hashes::sha256d::Hash {
        let expected = self.size_without_witness();
        let mut bytes = Vec::with_capacity(expected);
        self.encode_without_witness(&mut bytes);
        assert_eq!(bytes.len(), expected);
        assert!(bytes.len() >= Transaction::SIZE_MIN);
        bitcoin_hashes::sha256d::Hash::hash(&bytes)
    }

    pub(crate) fn wtxid(&self) -> bitcoin_hashes::sha256d::Hash {
        let expected = self.size_with_witness();
        let mut bytes = Vec::with_capacity(expected);
        self.encode(&mut bytes);
        assert_eq!(bytes.len(), expected);
        assert!(bytes.len() >= Transaction::SIZE_MIN);
        bitcoin_hashes::sha256d::Hash::hash(&bytes)
    }

    pub(crate) fn size_without_witness(&self) -> usize {
        let inputs = self.inputs_slice();
        let outputs = self.outputs();
        let inputs_size: usize = inputs.iter().map(TxIn::encoded_size).sum();
        let outputs_size: usize = outputs.iter().map(TxOut::encoded_size).sum();
        let size = size_of::<u32>()
            + crate::serialize::compact_size_length(inputs.len())
            + inputs_size
            + crate::serialize::compact_size_length(outputs.len())
            + outputs_size
            + size_of::<u32>();
        assert!(size >= Transaction::SIZE_MIN);
        assert!(size >= Transaction::SIZE_MIN + inputs_size + outputs_size);
        size
    }

    pub(crate) fn witness_bytes(&self) -> usize {
        if self.has_witness() {
            let inputs = self.inputs_slice();
            let stacks_size: usize = inputs
                .iter()
                .map(|input| input.witness.encoded_size())
                .sum();
            let size = size_of::<u8>() + size_of::<u8>() + stacks_size;
            assert!(size >= 4);
            assert!(size > size_of::<u8>() + size_of::<u8>() + inputs.len());
            size
        } else {
            0
        }
    }

    pub(crate) fn size_with_witness(&self) -> usize {
        let base = self.size_without_witness();
        let witness = self.witness_bytes();
        let size = base + witness;
        assert!(size >= base);
        assert!(size >= Transaction::SIZE_MIN);
        size
    }

    pub(crate) fn has_witness(&self) -> bool {
        self.inputs_slice()
            .iter()
            .any(|input| !input.witness.is_empty())
    }

    pub(crate) fn coinbase_input(&self) -> Option<&TxIn> {
        match &self.transfers {
            Transfers::NonEmpty { inputs, .. } => match inputs.split_first() {
                (input, []) if input.previous_output.is_null() => Some(input),
                _ => None,
            },
            Transfers::Empty => None,
        }
    }

    #[cfg(test)]
    pub(crate) fn check(&self) -> Result<CheckedTransaction, TransactionError> {
        let mut seen = std::collections::HashSet::new();
        self.clone().into_checked_with_seen(&mut seen)
    }

    pub(crate) fn into_checked_with_seen(
        self,
        seen: &mut std::collections::HashSet<OutPoint>,
    ) -> Result<CheckedTransaction, TransactionError> {
        let Transfers::NonEmpty { inputs, outputs } = &self.transfers else {
            return Err(TransactionError::InputsEmpty);
        };
        if outputs.is_empty() {
            return Err(TransactionError::OutputsEmpty);
        }
        if self.size_without_witness() > BLOCK_BASE_SIZE_MAX {
            return Err(TransactionError::BaseSizeTooLarge);
        }
        let inputs_slice = inputs.as_slice();
        assert!(inputs_slice.len() <= TX_INPUTS_COUNT_MAX);
        assert!(outputs.len() <= TX_OUTPUTS_COUNT_MAX);

        let mut total: i64 = 0;
        for output in outputs {
            if output.value < 0 {
                return Err(TransactionError::OutputNegative);
            }
            if output.value > MONEY_MAX {
                return Err(TransactionError::OutputTooLarge);
            }
            assert!(total >= 0);
            assert!(total <= MONEY_MAX);
            total += output.value;
            if total > MONEY_MAX {
                return Err(TransactionError::OutputsTotalTooLarge);
            }
        }
        assert!(total >= 0);
        assert!(total <= MONEY_MAX);

        match inputs.split_first() {
            (_, []) => {}
            (first, [second]) => {
                if first.previous_output == second.previous_output {
                    return Err(TransactionError::DuplicateInputs);
                }
            }
            (_, _) => {
                seen.clear();
                for input in inputs_slice {
                    if !seen.insert(input.previous_output) {
                        return Err(TransactionError::DuplicateInputs);
                    }
                }
                assert_eq!(seen.len(), inputs_slice.len());
            }
        }

        if let Some(coinbase) = self.coinbase_input() {
            let script_length = coinbase.script_sig.len();
            if !(COINBASE_SCRIPT_SIZE_MIN..=COINBASE_SCRIPT_SIZE_MAX).contains(&script_length) {
                return Err(TransactionError::CoinbaseScriptSize);
            }
        } else if inputs_slice
            .iter()
            .any(|input| input.previous_output.is_null())
        {
            return Err(TransactionError::NullOutPoint);
        }

        let legacy_sigop_count = legacy_sigop_count(inputs_slice, outputs);
        Ok(CheckedTransaction {
            transaction: self,
            value_out: total,
            legacy_sigop_count,
        })
    }

    fn encode_without_witness(&self, out: &mut Vec<u8>) {
        self.version.encode(out);
        match &self.transfers {
            Transfers::Empty => {
                crate::serialize::write_compact_size(out, 0);
                crate::serialize::write_compact_size(out, 0);
            }
            Transfers::NonEmpty { inputs, outputs } => {
                write_vector(out, inputs.as_slice());
                write_vector(out, outputs);
            }
        }
        self.lock_time.encode(out);
    }
}

impl CheckedTransaction {
    pub(crate) fn version(&self) -> u32 {
        self.transaction.version
    }

    pub(crate) fn inputs(&self) -> &[TxIn] {
        let inputs = self.transaction.inputs_slice();
        assert!(!inputs.is_empty());
        assert!(inputs.len() <= TX_INPUTS_COUNT_MAX);
        inputs
    }

    pub(crate) fn outputs(&self) -> &[TxOut] {
        let outputs = self.transaction.outputs();
        assert!(!outputs.is_empty());
        assert!(outputs.len() <= TX_OUTPUTS_COUNT_MAX);
        outputs
    }

    pub(crate) fn coinbase_input(&self) -> Option<&TxIn> {
        self.transaction.coinbase_input()
    }

    pub(crate) fn txid(&self) -> bitcoin_hashes::sha256d::Hash {
        self.transaction.txid()
    }

    pub(crate) fn value_out(&self) -> i64 {
        assert!(self.value_out >= 0);
        assert!(self.value_out <= MONEY_MAX);
        self.value_out
    }

    pub(crate) fn legacy_sigop_count(&self) -> usize {
        self.legacy_sigop_count
    }

    #[cfg(test)]
    pub(crate) fn transaction(&self) -> &Transaction {
        &self.transaction
    }

    pub(crate) fn is_final(&self, height: usize, time: u32) -> bool {
        let inputs = self.inputs();
        let satisfied = match self.transaction.lock_time() {
            LockTime::Unlocked => return true,
            LockTime::Height(lock_height) => {
                usize::try_from(lock_height.get()).expect("u32 fits in usize") < height
            }
            LockTime::Time(lock_time) => lock_time < time,
        };
        if satisfied {
            return true;
        }
        inputs.iter().all(|input| input.sequence == SEQUENCE_FINAL)
    }
}

fn legacy_sigop_count(inputs: &[TxIn], outputs: &[TxOut]) -> usize {
    assert!(inputs.len() <= TX_INPUTS_COUNT_MAX);
    assert!(outputs.len() <= TX_OUTPUTS_COUNT_MAX);
    let mut count: usize = 0;
    let mut script_bytes: usize = 0;
    for input in inputs {
        script_bytes = script_bytes.saturating_add(input.script_sig.len());
        count = count.saturating_add(script_sigop_count(&input.script_sig, false));
    }
    for output in outputs {
        script_bytes = script_bytes.saturating_add(output.script_pubkey.len());
        count = count.saturating_add(script_sigop_count(&output.script_pubkey, false));
    }
    assert!(count <= script_bytes.saturating_mul(MULTISIG_PUBKEYS_COUNT_MAX));
    count
}

pub(crate) fn input_p2sh_and_witness_sigop_cost(input: &TxIn, prevout: &TxOut) -> usize {
    if is_p2sh(&prevout.script_pubkey) {
        let Some(redeem_script) = last_push_data(&input.script_sig) else {
            return 0;
        };
        script_sigop_count(redeem_script, true)
            .saturating_mul(WITNESS_SCALE_FACTOR)
            .saturating_add(witness_v0_sigops(redeem_script, &input.witness))
    } else {
        witness_v0_sigops(&prevout.script_pubkey, &input.witness)
    }
}

fn is_p2sh(script: &[u8]) -> bool {
    script.len() == P2SH_SCRIPT_SIZE
        && script[0] == OP_HASH160
        && script[1] == P2SH_HASH_SIZE
        && script[P2SH_SCRIPT_SIZE - 1] == OP_EQUAL
}

fn witness_v0_sigops(script: &[u8], witness: &Witness) -> usize {
    match script {
        [0x00, 20, program @ ..] if program.len() == WITNESS_V0_KEYHASH_SIZE => 1,
        [0x00, 32, program @ ..] if program.len() == WITNESS_V0_SCRIPTHASH_SIZE => witness
            .last_item()
            .map_or(0, |witness_script| script_sigop_count(witness_script, true)),
        _ => 0,
    }
}

fn last_push_data(mut script: &[u8]) -> Option<&[u8]> {
    let mut last: &[u8] = &[];
    while !script.is_empty() {
        let length_before = script.len();
        let (opcode, data) = next_script_op(&mut script)?;
        if opcode > OP_16 {
            return None;
        }
        assert!(script.len() < length_before);
        last = data;
    }
    Some(last)
}

fn next_script_op<'a>(script: &mut &'a [u8]) -> Option<(u8, &'a [u8])> {
    let (&opcode, rest) = script.split_first()?;
    let (data, rest) = match opcode {
        0..OP_PUSHDATA1 => rest.split_at_checked(usize::from(opcode))?,
        OP_PUSHDATA1 => {
            let (&size, rest) = rest.split_first()?;
            rest.split_at_checked(usize::from(size))?
        }
        OP_PUSHDATA2 => {
            let (bytes, rest) = rest.split_first_chunk::<2>()?;
            let size = usize::from(u16::from_le_bytes(*bytes));
            rest.split_at_checked(size)?
        }
        OP_PUSHDATA4 => {
            let (bytes, rest) = rest.split_first_chunk::<4>()?;
            let size = usize::try_from(u32::from_le_bytes(*bytes)).expect("u32 fits in usize");
            rest.split_at_checked(size)?
        }
        _ => (&[][..], rest),
    };
    *script = rest;
    Some((opcode, data))
}

fn script_sigop_count(mut script: &[u8], accurate: bool) -> usize {
    let initial_length = script.len();
    let mut count: usize = 0;
    let mut last_opcode: Option<u8> = None;
    while !script.is_empty() {
        let length_before = script.len();
        let Some((opcode, _)) = next_script_op(&mut script) else {
            break;
        };
        assert!(script.len() < length_before);
        match opcode {
            OP_CHECKSIG | OP_CHECKSIGVERIFY => {
                count = count.saturating_add(1);
            }
            OP_CHECKMULTISIG | OP_CHECKMULTISIGVERIFY => {
                let sigops = match last_opcode {
                    Some(prev @ OP_1..=OP_16) if accurate => usize::from(prev - OP_1_OFFSET),
                    _ => MULTISIG_PUBKEYS_COUNT_MAX,
                };
                count = count.saturating_add(sigops);
            }
            _ => {}
        }
        last_opcode = Some(opcode);
    }
    assert!(count <= initial_length.saturating_mul(MULTISIG_PUBKEYS_COUNT_MAX));
    count
}

impl Encode for Transaction {
    fn encode(&self, out: &mut Vec<u8>) {
        match &self.transfers {
            Transfers::NonEmpty { inputs, outputs } if self.has_witness() => {
                let inputs = inputs.as_slice();
                self.version.encode(out);
                WITNESS_MARKER.encode(out);
                WITNESS_FLAG.encode(out);
                write_vector(out, inputs);
                write_vector(out, outputs);
                for input in inputs {
                    input.witness.encode(out);
                }
                self.lock_time.encode(out);
            }
            Transfers::Empty | Transfers::NonEmpty { .. } => {
                self.encode_without_witness(out);
            }
        }
    }
}

impl Decode for Transaction {
    fn decode(input: &mut &[u8]) -> Result<Self, crate::serialize::Error> {
        let version = u32::decode(input)?;
        let inputs: Vec<TxIn> = read_vector(input)?;
        let transfers = if let Some(inputs) = NonEmptyInputs::new(inputs) {
            let outputs = read_vector(input)?;
            Transfers::NonEmpty { inputs, outputs }
        } else {
            let flags = u8::decode(input)?;
            if flags == 0 {
                Transfers::Empty
            } else {
                let inputs: Vec<TxIn> = read_vector(input)?;
                let outputs: Vec<TxOut> = read_vector(input)?;
                if flags & WITNESS_FLAG == 0 {
                    return Err(crate::serialize::Error::TransactionFlags(flags));
                }
                let Some(mut inputs) = NonEmptyInputs::new(inputs) else {
                    return Err(crate::serialize::Error::SuperfluousWitness);
                };
                for transaction_input in &mut inputs.0 {
                    transaction_input.witness = Witness::decode(input)?;
                }
                if inputs
                    .0
                    .iter()
                    .all(|transaction_input| transaction_input.witness.is_empty())
                {
                    return Err(crate::serialize::Error::SuperfluousWitness);
                }
                if flags & !WITNESS_FLAG != 0 {
                    return Err(crate::serialize::Error::TransactionFlags(flags));
                }
                Transfers::NonEmpty { inputs, outputs }
            }
        };
        Ok(Self {
            version,
            transfers,
            lock_time: u32::decode(input)?,
        })
    }
}

pub(crate) trait SizeMin {
    const SIZE_MIN: usize;
}

impl SizeMin for TxIn {
    const SIZE_MIN: usize = 32 + 4 + 1 + 4;
}

impl SizeMin for TxOut {
    const SIZE_MIN: usize = 8 + 1;
}

impl SizeMin for Transaction {
    const SIZE_MIN: usize = 4 + 1 + 1 + 4;
}

pub(crate) fn write_vector<T: Encode>(out: &mut Vec<u8>, items: &[T]) {
    crate::serialize::write_compact_size(out, items.len());
    for item in items {
        item.encode(out);
    }
}

pub(crate) fn read_item<T: Decode + SizeMin>(
    input: &mut &[u8],
) -> Result<T, crate::serialize::Error> {
    let length = input.len();
    let item = T::decode(input)?;
    assert!(length - input.len() >= T::SIZE_MIN);
    Ok(item)
}

pub(crate) fn read_items<T: Decode + SizeMin>(
    input: &mut &[u8],
    count: usize,
) -> Result<Vec<T>, crate::serialize::Error> {
    let mut items = Vec::with_capacity(count.min(input.len() / T::SIZE_MIN));
    for _ in 0..count {
        items.push(read_item(input)?);
    }
    Ok(items)
}

pub(crate) fn read_vector<T: Decode + SizeMin>(
    input: &mut &[u8],
) -> Result<Vec<T>, crate::serialize::Error> {
    let count = crate::serialize::read_compact_size(input)?;
    read_items(input, count)
}

#[cfg(test)]
mod tests {
    use crate::serialize::{Decode, Encode};

    fn decode(bytes: &[u8]) -> Result<super::Transaction, crate::serialize::Error> {
        let mut input = bytes;
        let transaction = super::Transaction::decode(&mut input);
        assert!(transaction.is_err() || input.is_empty());
        transaction
    }

    fn spend(witness_flags: u8, witness: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0x02, 0x00, 0x00, 0x00, 0x00, witness_flags, 0x01];
        bytes.extend_from_slice(&[0xaa; 32]);
        bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff]);
        bytes.extend_from_slice(&[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        bytes.extend_from_slice(witness);
        bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        bytes
    }

    #[test]
    fn witness_spend_round_trips_and_keeps_its_txid_without_the_witness() {
        let bytes = spend(0x01, &[0x02, 0x01, 0xbb, 0x00]);
        let transaction = decode(&bytes).unwrap();
        let mut encoded = Vec::new();
        transaction.encode(&mut encoded);
        assert_eq!(encoded, bytes);

        assert!(transaction.has_witness());
        let mut without = Vec::new();
        transaction.encode_without_witness(&mut without);
        assert_eq!(transaction.size_without_witness(), bytes.len() - 6);
        assert_eq!(
            [
                &bytes[..4],
                &bytes[6..bytes.len() - 8],
                &bytes[bytes.len() - 4..]
            ]
            .concat(),
            without
        );
        assert_eq!(
            transaction.txid(),
            bitcoin_hashes::sha256d::Hash::hash(&without)
        );
        assert_eq!(
            transaction.wtxid(),
            bitcoin_hashes::sha256d::Hash::hash(&bytes)
        );
    }

    #[test]
    fn witness_flag_with_only_empty_stacks_is_superfluous() {
        assert_eq!(
            decode(&spend(0x01, &[0x00])),
            Err(crate::serialize::Error::SuperfluousWitness)
        );
        let no_inputs_witness = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00];
        assert_eq!(
            decode(&no_inputs_witness),
            Err(crate::serialize::Error::SuperfluousWitness)
        );
    }

    #[test]
    fn unknown_flags_are_refused_after_the_witness() {
        assert_eq!(
            decode(&spend(0x02, &[])),
            Err(crate::serialize::Error::TransactionFlags(0x02))
        );
        assert_eq!(
            decode(&spend(0x03, &[0x01, 0x00])),
            Err(crate::serialize::Error::TransactionFlags(0x03))
        );
        assert_eq!(
            decode(&spend(0x03, &[0x00])),
            Err(crate::serialize::Error::SuperfluousWitness)
        );
    }

    #[test]
    fn outputs_need_an_input() {
        let output = super::TxOut {
            value: 0,
            script_pubkey: Vec::new(),
        };
        assert_eq!(
            super::Transaction::new(1, Vec::new(), vec![output], 0),
            None
        );
        assert_eq!(
            super::Transaction::new(1, Vec::new(), Vec::new(), 0),
            Some(super::Transaction {
                version: 1,
                transfers: super::Transfers::Empty,
                lock_time: 0,
            })
        );
    }

    #[test]
    fn no_inputs_and_zero_flags_is_a_transaction_with_no_outputs() {
        let bytes = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00];
        let transaction = decode(&bytes).unwrap();
        assert!(transaction.inputs().is_empty());
        assert!(transaction.outputs().is_empty());
        assert_eq!(
            transaction.lock_time(),
            super::LockTime::Height(std::num::NonZeroU32::new(5).unwrap())
        );
    }

    fn smallest<T>(item: T)
    where
        T: Decode + Encode + super::SizeMin + PartialEq + std::fmt::Debug,
    {
        let mut bytes = vec![0x01];
        item.encode(&mut bytes);
        assert_eq!(bytes.len(), 1 + T::SIZE_MIN);
        assert_eq!(super::read_vector(&mut &bytes[..]), Ok(vec![item]));
    }

    #[test]
    fn size_min_is_the_size_of_the_smallest_item() {
        smallest(super::TxIn {
            previous_output: super::OutPoint {
                txid: bitcoin_hashes::sha256d::Hash::from_byte_array([0; 32]),
                vout: 0,
            },
            script_sig: Vec::new(),
            sequence: 0,
            witness: super::Witness::default(),
        });
        smallest(super::TxOut {
            value: 0,
            script_pubkey: Vec::new(),
        });
        smallest(super::Transaction {
            version: 1,
            transfers: super::Transfers::Empty,
            lock_time: 0,
        });
    }

    #[test]
    fn witness_stack_needs_every_item() {
        assert_eq!(
            super::Witness::decode(&mut &[0x02, 0x01, 0xbb][..]),
            Err(crate::serialize::Error::UnexpectedEnd)
        );
    }

    #[test]
    fn reserved_value_is_one_item_of_32_bytes() {
        let witness = |bytes: &[u8]| super::Witness::decode(&mut &bytes[..]).unwrap();
        let one = [&[0x01, 0x20][..], &[0xcc; 32]].concat();
        assert_eq!(witness(&one).reserved_value(), Some([0xcc; 32]));

        assert_eq!(super::Witness::default().reserved_value(), None);
        let short = [&[0x01, 0x1f][..], &[0xcc; 31]].concat();
        assert_eq!(witness(&short).reserved_value(), None);
        let two = [&[0x02, 0x20][..], &[0xcc; 32], &[0x00]].concat();
        assert_eq!(witness(&two).reserved_value(), None);
    }

    #[test]
    fn coinbase_input_is_the_one_null_outpoint() {
        let null = super::OutPoint {
            txid: bitcoin_hashes::sha256d::Hash::from_byte_array([0; 32]),
            vout: u32::MAX,
        };
        let input = |previous_output| super::TxIn {
            previous_output,
            script_sig: Vec::new(),
            sequence: 0,
            witness: super::Witness::default(),
        };
        let transaction = |inputs| super::Transaction::new(1, inputs, Vec::new(), 0).unwrap();

        assert!(transaction(Vec::new()).coinbase_input().is_none());
        assert!(transaction(vec![input(null)]).coinbase_input().is_some());
        assert!(
            transaction(vec![input(null), input(null)])
                .coinbase_input()
                .is_none()
        );
        let vout_zero = super::OutPoint { vout: 0, ..null };
        assert!(
            transaction(vec![input(vout_zero)])
                .coinbase_input()
                .is_none()
        );
        let txid_one = super::OutPoint {
            txid: bitcoin_hashes::sha256d::Hash::from_byte_array([1; 32]),
            ..null
        };
        assert!(
            transaction(vec![input(txid_one)])
                .coinbase_input()
                .is_none()
        );
    }

    fn outpoint(byte: u8, vout: u32) -> super::OutPoint {
        super::OutPoint {
            txid: bitcoin_hashes::sha256d::Hash::from_byte_array([byte; 32]),
            vout,
        }
    }

    fn tx_in(previous_output: super::OutPoint, script_sig: Vec<u8>, sequence: u32) -> super::TxIn {
        super::TxIn {
            previous_output,
            script_sig,
            sequence,
            witness: super::Witness::default(),
        }
    }

    fn tx_out(value: i64, script_pubkey: Vec<u8>) -> super::TxOut {
        super::TxOut {
            value,
            script_pubkey,
        }
    }

    fn transaction(
        inputs: Vec<super::TxIn>,
        outputs: Vec<super::TxOut>,
        lock_time: u32,
    ) -> super::Transaction {
        super::Transaction::new(1, inputs, outputs, lock_time).unwrap()
    }

    fn valid_spend() -> super::Transaction {
        transaction(
            vec![tx_in(outpoint(1, 0), Vec::new(), super::SEQUENCE_FINAL)],
            vec![tx_out(0, Vec::new())],
            0,
        )
    }

    fn valid_coinbase(script_sig: Vec<u8>) -> super::Transaction {
        transaction(
            vec![tx_in(
                outpoint(0, u32::MAX),
                script_sig,
                super::SEQUENCE_FINAL,
            )],
            vec![tx_out(0, Vec::new())],
            0,
        )
    }

    #[test]
    fn check_transaction_enforces_core_rules() {
        let check = |tx: &super::Transaction| tx.check().map(|_| ());
        let check_with_seen = |tx: &super::Transaction, seen: &mut _| {
            tx.clone().into_checked_with_seen(seen).map(|_| ())
        };

        assert_eq!(check(&valid_spend()), Ok(()));
        assert_eq!(check(&valid_coinbase(vec![0; 2])), Ok(()));
        assert_eq!(check(&valid_coinbase(vec![0; 100])), Ok(()));

        assert_eq!(
            check(&transaction(Vec::new(), Vec::new(), 0)),
            Err(super::TransactionError::InputsEmpty)
        );
        assert_eq!(
            check(&transaction(
                vec![tx_in(outpoint(1, 0), Vec::new(), super::SEQUENCE_FINAL)],
                Vec::new(),
                0
            )),
            Err(super::TransactionError::OutputsEmpty)
        );

        let at_limit = transaction(
            vec![tx_in(outpoint(1, 0), Vec::new(), super::SEQUENCE_FINAL)],
            vec![tx_out(0, vec![0; super::BLOCK_BASE_SIZE_MAX - 64])],
            0,
        );
        assert_eq!(at_limit.size_without_witness(), super::BLOCK_BASE_SIZE_MAX);
        assert_eq!(check(&at_limit), Ok(()));
        let oversize = transaction(
            vec![tx_in(outpoint(1, 0), Vec::new(), super::SEQUENCE_FINAL)],
            vec![tx_out(0, vec![0; super::BLOCK_BASE_SIZE_MAX - 63])],
            0,
        );
        assert_eq!(
            oversize.size_without_witness(),
            super::BLOCK_BASE_SIZE_MAX + 1
        );
        assert_eq!(
            check(&oversize),
            Err(super::TransactionError::BaseSizeTooLarge)
        );

        assert_eq!(
            check(&transaction(
                vec![tx_in(outpoint(1, 0), Vec::new(), super::SEQUENCE_FINAL)],
                vec![tx_out(-1, Vec::new())],
                0
            )),
            Err(super::TransactionError::OutputNegative)
        );
        assert_eq!(
            check(&transaction(
                vec![tx_in(outpoint(1, 0), Vec::new(), super::SEQUENCE_FINAL)],
                vec![tx_out(super::MONEY_MAX, Vec::new())],
                0
            )),
            Ok(())
        );
        assert_eq!(
            check(&transaction(
                vec![tx_in(outpoint(1, 0), Vec::new(), super::SEQUENCE_FINAL)],
                vec![tx_out(super::MONEY_MAX + 1, Vec::new())],
                0
            )),
            Err(super::TransactionError::OutputTooLarge)
        );
        assert_eq!(
            check(&transaction(
                vec![tx_in(outpoint(1, 0), Vec::new(), super::SEQUENCE_FINAL)],
                vec![tx_out(super::MONEY_MAX, Vec::new()), tx_out(0, Vec::new())],
                0
            )),
            Ok(())
        );
        assert_eq!(
            check(&transaction(
                vec![tx_in(outpoint(1, 0), Vec::new(), super::SEQUENCE_FINAL)],
                vec![tx_out(super::MONEY_MAX, Vec::new()), tx_out(1, Vec::new())],
                0
            )),
            Err(super::TransactionError::OutputsTotalTooLarge)
        );

        let mut seen = std::collections::HashSet::new();
        assert_eq!(check_with_seen(&valid_spend(), &mut seen), Ok(()));
        assert_eq!(seen.capacity(), 0);
        assert_eq!(
            check_with_seen(
                &transaction(
                    vec![
                        tx_in(outpoint(1, 0), Vec::new(), 0),
                        tx_in(outpoint(1, 1), Vec::new(), 0),
                    ],
                    vec![tx_out(0, Vec::new())],
                    0
                ),
                &mut seen
            ),
            Ok(())
        );
        assert_eq!(seen.capacity(), 0);
        assert_eq!(
            check_with_seen(
                &transaction(
                    vec![
                        tx_in(outpoint(1, 0), Vec::new(), 0),
                        tx_in(outpoint(1, 0), Vec::new(), 0),
                    ],
                    vec![tx_out(0, Vec::new())],
                    0
                ),
                &mut seen
            ),
            Err(super::TransactionError::DuplicateInputs)
        );
        assert_eq!(seen.capacity(), 0);

        let three_distinct = transaction(
            vec![
                tx_in(outpoint(1, 0), Vec::new(), 0),
                tx_in(outpoint(1, 1), Vec::new(), 0),
                tx_in(outpoint(1, 2), Vec::new(), 0),
            ],
            vec![tx_out(0, Vec::new())],
            0,
        );
        assert_eq!(check_with_seen(&three_distinct, &mut seen), Ok(()));
        assert_eq!(check_with_seen(&three_distinct, &mut seen), Ok(()));
        assert_eq!(
            check_with_seen(
                &transaction(
                    vec![
                        tx_in(outpoint(1, 0), Vec::new(), 0),
                        tx_in(outpoint(1, 1), Vec::new(), 0),
                        tx_in(outpoint(1, 0), Vec::new(), 0),
                    ],
                    vec![tx_out(0, Vec::new())],
                    0
                ),
                &mut seen
            ),
            Err(super::TransactionError::DuplicateInputs)
        );

        assert_eq!(
            check(&valid_coinbase(vec![0; 1])),
            Err(super::TransactionError::CoinbaseScriptSize)
        );
        assert_eq!(
            check(&valid_coinbase(vec![0; 101])),
            Err(super::TransactionError::CoinbaseScriptSize)
        );
        assert_eq!(
            check(&transaction(
                vec![
                    tx_in(outpoint(1, 0), Vec::new(), 0),
                    tx_in(outpoint(0, u32::MAX), Vec::new(), 0),
                ],
                vec![tx_out(0, Vec::new())],
                0
            )),
            Err(super::TransactionError::NullOutPoint)
        );
    }

    #[test]
    fn is_final_checks_lock_time_and_sequences() {
        let with = |lock_time, sequences: &[u32]| {
            transaction(
                sequences
                    .iter()
                    .enumerate()
                    .map(|(index, &sequence)| {
                        tx_in(
                            outpoint(1, u32::try_from(index).unwrap()),
                            Vec::new(),
                            sequence,
                        )
                    })
                    .collect(),
                vec![tx_out(0, Vec::new())],
                lock_time,
            )
        };
        assert_eq!(with(0, &[0]).lock_time(), super::LockTime::Unlocked);
        assert_eq!(
            with(super::LOCK_TIME_THRESHOLD - 1, &[0]).lock_time(),
            super::LockTime::Height(
                std::num::NonZeroU32::new(super::LOCK_TIME_THRESHOLD - 1).unwrap()
            )
        );
        assert_eq!(
            with(super::LOCK_TIME_THRESHOLD, &[0]).lock_time(),
            super::LockTime::Time(super::LOCK_TIME_THRESHOLD)
        );
        assert!(with(0, &[0]).check().unwrap().is_final(0, 0));
        assert!(with(99, &[0]).check().unwrap().is_final(100, 0));
        assert!(!with(100, &[0]).check().unwrap().is_final(100, 0));
        assert!(
            with(100, &[super::SEQUENCE_FINAL])
                .check()
                .unwrap()
                .is_final(100, 0)
        );
        assert!(
            !with(100, &[super::SEQUENCE_FINAL, super::SEQUENCE_FINAL - 1])
                .check()
                .unwrap()
                .is_final(100, 0)
        );
        assert!(
            with(super::LOCK_TIME_THRESHOLD - 1, &[0])
                .check()
                .unwrap()
                .is_final(500_000_000, 0)
        );
        assert!(
            !with(super::LOCK_TIME_THRESHOLD - 1, &[0])
                .check()
                .unwrap()
                .is_final(499_999_999, 600_000_000)
        );
        assert!(
            with(super::LOCK_TIME_THRESHOLD, &[0])
                .check()
                .unwrap()
                .is_final(0, 500_000_001)
        );
        assert!(
            !with(super::LOCK_TIME_THRESHOLD, &[0])
                .check()
                .unwrap()
                .is_final(600_000_000, 500_000_000)
        );
        assert!(
            with(
                super::LOCK_TIME_THRESHOLD,
                &[super::SEQUENCE_FINAL, super::SEQUENCE_FINAL]
            )
            .check()
            .unwrap()
            .is_final(0, 500_000_000)
        );
    }

    #[test]
    fn legacy_sigop_count_matches_core_inaccurate_script_scan() {
        let count = |script: &[u8]| super::script_sigop_count(script, false);
        assert_eq!(count(&[]), 0);
        assert_eq!(count(&[super::OP_CHECKSIG]), 1);
        assert_eq!(count(&[super::OP_CHECKSIGVERIFY]), 1);
        assert_eq!(count(&[super::OP_CHECKMULTISIG]), 20);
        assert_eq!(count(&[super::OP_CHECKMULTISIGVERIFY]), 20);
        assert_eq!(count(&[0x51, super::OP_CHECKMULTISIG]), 20);
        assert_eq!(count(&[0x6a, super::OP_CHECKSIG]), 1);
        assert_eq!(count(&[0xba]), 0);
        assert_eq!(count(&[0x00, super::OP_CHECKSIG]), 1);
        assert_eq!(count(&[0x01, super::OP_CHECKSIG, super::OP_CHECKSIG]), 1);
        assert_eq!(count(&[0x02, super::OP_CHECKSIG]), 0);

        let mut push_75 = vec![0x4b];
        push_75.resize(1 + 75, super::OP_CHECKSIG);
        push_75.push(super::OP_CHECKSIG);
        assert_eq!(count(&push_75), 1);

        assert_eq!(count(&[super::OP_PUSHDATA1]), 0);
        assert_eq!(count(&[super::OP_PUSHDATA1, super::OP_CHECKSIG]), 0);
        assert_eq!(count(&[super::OP_PUSHDATA1, 2, super::OP_CHECKSIG]), 0);
        assert_eq!(
            count(&[
                super::OP_PUSHDATA1,
                2,
                super::OP_CHECKSIG,
                super::OP_CHECKMULTISIG,
                super::OP_CHECKSIG,
            ]),
            1
        );
        let mut push_76 = vec![super::OP_PUSHDATA1, 76];
        push_76.resize(2 + 76, super::OP_CHECKSIG);
        push_76.push(super::OP_CHECKSIG);
        assert_eq!(count(&push_76), 1);

        assert_eq!(count(&[super::OP_PUSHDATA2, 1]), 0);
        assert_eq!(count(&[super::OP_PUSHDATA2, 2, 0, super::OP_CHECKSIG]), 0);
        assert_eq!(
            count(&[
                super::OP_PUSHDATA2,
                1,
                0,
                super::OP_CHECKSIG,
                super::OP_CHECKSIG,
            ]),
            1
        );

        assert_eq!(count(&[super::OP_PUSHDATA4, 1, 0, 0]), 0);
        assert_eq!(
            count(&[super::OP_PUSHDATA4, 2, 0, 0, 0, super::OP_CHECKSIG]),
            0
        );
        assert_eq!(
            count(&[
                super::OP_PUSHDATA4,
                1,
                0,
                0,
                0,
                super::OP_CHECKSIG,
                super::OP_CHECKSIG,
            ]),
            1
        );

        let tx = transaction(
            vec![tx_in(outpoint(1, 0), vec![super::OP_CHECKSIG], 0)],
            vec![tx_out(0, vec![super::OP_CHECKMULTISIG])],
            0,
        );
        assert_eq!(tx.check().unwrap().legacy_sigop_count(), 21);
    }

    #[test]
    fn size_with_and_without_witness_match_encoding() {
        let bytes = spend(0x01, &[0x02, 0x01, 0xbb, 0x00]);
        let tx = decode(&bytes).unwrap();
        assert_eq!(tx.size_with_witness(), bytes.len());
        let mut without = Vec::new();
        tx.encode_without_witness(&mut without);
        assert_eq!(tx.size_without_witness(), without.len());

        let mut mixed_input = tx_in(outpoint(1, 0), Vec::new(), 0);
        mixed_input.witness = super::Witness::decode(&mut &[0x01, 0x01, 0xbb][..]).unwrap();
        let mixed = transaction(
            vec![mixed_input, tx_in(outpoint(1, 1), Vec::new(), 0)],
            vec![tx_out(0, Vec::new())],
            0,
        );
        let mut mixed_encoded = Vec::new();
        mixed.encode(&mut mixed_encoded);
        assert_eq!(mixed.size_with_witness(), mixed_encoded.len());
        assert_eq!(decode(&mixed_encoded), Ok(mixed));

        let empty = transaction(Vec::new(), Vec::new(), 0);
        let mut empty_encoded = Vec::new();
        empty.encode(&mut empty_encoded);
        assert_eq!(empty.size_without_witness(), empty_encoded.len());
        assert_eq!(empty.size_with_witness(), empty_encoded.len());

        let legacy = valid_spend();
        let mut encoded = Vec::new();
        legacy.encode(&mut encoded);
        assert_eq!(legacy.size_without_witness(), encoded.len());
        assert_eq!(legacy.size_with_witness(), encoded.len());
    }

    #[test]
    fn unspendable_outputs_are_op_return_or_above_script_size_max() {
        assert!(!tx_out(0, Vec::new()).is_unspendable());
        assert!(tx_out(0, vec![super::OP_RETURN]).is_unspendable());
        assert!(tx_out(0, vec![super::OP_RETURN, 0x01, 0xaa]).is_unspendable());
        assert!(!tx_out(0, vec![super::OP_1, super::OP_RETURN]).is_unspendable());
        assert!(!tx_out(0, vec![super::OP_1; super::SCRIPT_SIZE_MAX]).is_unspendable());
        assert!(tx_out(0, vec![super::OP_1; super::SCRIPT_SIZE_MAX + 1]).is_unspendable());
    }

    #[test]
    fn accurate_p2sh_and_witness_sigop_cost_matches_core() {
        assert_eq!(
            super::script_sigop_count(&[super::OP_1, super::OP_CHECKMULTISIG], true),
            1
        );
        assert_eq!(
            super::script_sigop_count(&[super::OP_16, super::OP_CHECKMULTISIGVERIFY], true),
            16
        );
        assert_eq!(
            super::script_sigop_count(&[0x00, super::OP_CHECKMULTISIG], true),
            20
        );
        assert_eq!(
            super::script_sigop_count(&[0x50, super::OP_CHECKMULTISIG], true),
            20
        );
        assert_eq!(
            super::script_sigop_count(&[0x61, super::OP_CHECKMULTISIG], true),
            20
        );
        assert_eq!(
            super::script_sigop_count(&[super::OP_CHECKMULTISIG], true),
            20
        );
        assert_eq!(
            super::script_sigop_count(&[0x01, super::OP_1, super::OP_CHECKMULTISIG], true),
            20
        );

        let p2sh_script = || {
            let mut script = vec![super::OP_HASH160, super::P2SH_HASH_SIZE];
            script.extend_from_slice(&[0x11; 20]);
            script.push(super::OP_EQUAL);
            script
        };
        let witness_from = |items: &[&[u8]]| {
            let mut bytes = Vec::new();
            crate::serialize::write_compact_size(&mut bytes, items.len());
            for item in items {
                crate::serialize::write_string(&mut bytes, item);
            }
            super::Witness::decode(&mut bytes.as_slice()).unwrap()
        };
        let cost = |script_sig: Vec<u8>, witness: super::Witness, script_pubkey: Vec<u8>| {
            let mut input = tx_in(outpoint(1, 0), script_sig, super::SEQUENCE_FINAL);
            input.witness = witness;
            super::input_p2sh_and_witness_sigop_cost(&input, &tx_out(0, script_pubkey))
        };

        assert_eq!(
            cost(Vec::new(), super::Witness::default(), vec![super::OP_1]),
            0
        );
        assert_eq!(
            cost(Vec::new(), super::Witness::default(), p2sh_script()),
            0
        );
        let redeem = [super::OP_1_OFFSET + 2, super::OP_CHECKMULTISIG];
        let mut push_redeem = vec![u8::try_from(redeem.len()).unwrap()];
        push_redeem.extend_from_slice(&redeem);
        assert_eq!(
            cost(
                push_redeem.clone(),
                super::Witness::default(),
                p2sh_script()
            ),
            2 * super::WITNESS_SCALE_FACTOR
        );
        let mut non_push_only = vec![0x61];
        non_push_only.extend_from_slice(&push_redeem);
        assert_eq!(
            cost(non_push_only, super::Witness::default(), p2sh_script()),
            0
        );
        let mut op_16_last = push_redeem.clone();
        op_16_last.push(super::OP_16);
        assert_eq!(
            cost(op_16_last, super::Witness::default(), p2sh_script()),
            0
        );
        let mut op_16_first = vec![super::OP_16];
        op_16_first.extend_from_slice(&push_redeem);
        assert_eq!(
            cost(op_16_first, super::Witness::default(), p2sh_script()),
            2 * super::WITNESS_SCALE_FACTOR
        );
        assert_eq!(
            cost(
                vec![0x02, super::OP_CHECKSIG],
                super::Witness::default(),
                p2sh_script()
            ),
            0
        );
        let mut two_pushes = vec![0x01, super::OP_CHECKSIG];
        two_pushes.extend_from_slice(&push_redeem);
        assert_eq!(
            cost(two_pushes, super::Witness::default(), p2sh_script()),
            2 * super::WITNESS_SCALE_FACTOR
        );
        for mut bad_p2sh in [
            p2sh_script()[..22].to_vec(),
            [p2sh_script(), vec![0x00]].concat(),
            {
                let mut s = p2sh_script();
                s[0] = 0x00;
                s
            },
            {
                let mut s = p2sh_script();
                s[1] = 0x13;
                s
            },
            {
                let mut s = p2sh_script();
                s[22] = 0x88;
                s
            },
        ] {
            assert_eq!(
                cost(
                    push_redeem.clone(),
                    super::Witness::default(),
                    std::mem::take(&mut bad_p2sh)
                ),
                0
            );
        }

        let mut p2wpkh = vec![0x00, 20];
        p2wpkh.extend_from_slice(&[0x22; 20]);
        assert_eq!(
            cost(Vec::new(), super::Witness::default(), p2wpkh.clone()),
            1
        );

        let mut p2wsh = vec![0x00, 32];
        p2wsh.extend_from_slice(&[0x33; 32]);
        assert_eq!(
            cost(Vec::new(), super::Witness::default(), p2wsh.clone()),
            0
        );
        let witness_script = [
            super::OP_1_OFFSET + 3,
            super::OP_CHECKMULTISIG,
            super::OP_CHECKSIG,
        ];
        let wit = witness_from(&[&[super::OP_CHECKSIG], &witness_script]);
        assert_eq!(cost(Vec::new(), wit.clone(), p2wsh.clone()), 4);

        let mut p2tr = vec![super::OP_1, 32];
        p2tr.extend_from_slice(&[0x44; 32]);
        assert_eq!(cost(Vec::new(), wit.clone(), p2tr), 0);
        let mut v16 = vec![super::OP_16, 20];
        v16.extend_from_slice(&[0x44; 20]);
        assert_eq!(cost(Vec::new(), wit.clone(), v16), 0);
        for bad_witness_program in [
            vec![0x00, 1, 0xaa],
            [&[0x00, 41][..], &[0xaa; 41]].concat(),
            [&[0x00, 20][..], &[0xaa; 19]].concat(),
            [&[0x00, 20][..], &[0xaa; 21]].concat(),
            [&[0x00, 32][..], &[0xaa; 31]].concat(),
            [&[0x00, 32][..], &[0xaa; 33]].concat(),
            [&[0x00, 2][..], &[0xaa; 2]].concat(),
            [&[0x50, 20][..], &[0xaa; 20]].concat(),
            [&[0x61, 20][..], &[0xaa; 20]].concat(),
        ] {
            assert_eq!(cost(Vec::new(), wit.clone(), bad_witness_program), 0);
        }

        let mut push_p2wpkh = vec![u8::try_from(p2wpkh.len()).unwrap()];
        push_p2wpkh.extend_from_slice(&p2wpkh);
        assert_eq!(
            cost(push_p2wpkh, super::Witness::default(), p2sh_script()),
            1
        );

        let mut push_p2wsh = vec![u8::try_from(p2wsh.len()).unwrap()];
        push_p2wsh.extend_from_slice(&p2wsh);
        assert_eq!(cost(push_p2wsh, wit, p2sh_script()), 4);
    }
}
