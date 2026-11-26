use crate::serialize::{Decode, Encode};

const WITNESS_MARKER: u8 = 0x00;

const WITNESS_FLAG: u8 = 0x01;

pub(crate) const WITNESS_SCALE_FACTOR: usize = 4;

pub(crate) const BLOCK_WEIGHT_MAX: usize = 4_000_000;

pub(crate) const BLOCK_BASE_SIZE_MAX: usize = BLOCK_WEIGHT_MAX / WITNESS_SCALE_FACTOR;

const _: () = assert!(BLOCK_BASE_SIZE_MAX * WITNESS_SCALE_FACTOR == BLOCK_WEIGHT_MAX);

const COIN: i64 = 100_000_000;

pub(crate) const MONEY_MAX: i64 = 21_000_000 * COIN;

const _: () = assert!(MONEY_MAX == 2_100_000_000_000_000);
const _: () = assert!(MONEY_MAX <= i64::MAX / 2);

const COINBASE_SCRIPT_SIZE_MIN: usize = 2;

const COINBASE_SCRIPT_SIZE_MAX: usize = 100;

const LOCK_TIME_THRESHOLD: u32 = 500_000_000;

const SEQUENCE_FINAL: u32 = u32::MAX;

const MULTISIG_PUBKEYS_COUNT_MAX: usize = 20;

const OP_PUSHDATA1: u8 = 0x4c;

const OP_PUSHDATA2: u8 = 0x4d;

const OP_PUSHDATA4: u8 = 0x4e;

const OP_CHECKSIG: u8 = 0xac;

const OP_CHECKSIGVERIFY: u8 = 0xad;

const OP_CHECKMULTISIG: u8 = 0xae;

const OP_CHECKMULTISIGVERIFY: u8 = 0xaf;

const _: () = assert!(usize::BITS >= u32::BITS);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransactionError {
    InputsEmpty,
    OutputsEmpty,
    Oversize,
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
            TransactionError::Oversize => {
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
pub(crate) struct Witness {
    count: usize,
    bytes: Vec<u8>,
}

impl Witness {
    pub(crate) fn is_empty(&self) -> bool {
        assert_eq!(self.count == 0, self.bytes.is_empty());
        self.count == 0
    }

    pub(crate) fn reserved_value(&self) -> Option<[u8; 32]> {
        match (self.count, self.bytes.as_slice()) {
            (1, [32, value @ ..]) => {
                assert_eq!(value.len(), 32);
                value.try_into().ok()
            }
            _ => None,
        }
    }

    fn encoded_size(&self) -> usize {
        assert_eq!(self.count == 0, self.bytes.is_empty());
        crate::serialize::compact_size_len(self.count) + self.bytes.len()
    }
}

impl Encode for Witness {
    fn encode(&self, out: &mut Vec<u8>) {
        crate::serialize::write_compact_size(out, self.count);
        out.extend_from_slice(&self.bytes);
    }
}

impl Decode for Witness {
    fn decode(input: &mut &[u8]) -> Result<Self, crate::serialize::Error> {
        let count = crate::serialize::read_compact_size(input)?;
        let stack = *input;
        for _ in 0..count {
            crate::serialize::read_bytes(input)?;
        }
        let bytes = stack[..stack.len() - input.len()].to_vec();
        assert!(bytes.len() >= count);
        assert_eq!(count == 0, bytes.is_empty());
        Ok(Self { count, bytes })
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
            + crate::serialize::compact_size_len(self.script_sig.len())
            + self.script_sig.len()
            + size_of::<u32>();
        assert!(size >= TxIn::SIZE_MIN);
        size
    }
}

impl Encode for TxIn {
    fn encode(&self, out: &mut Vec<u8>) {
        self.previous_output.encode(out);
        crate::serialize::write_string(out, &self.script_sig);
        self.sequence.encode(out);
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
    fn encoded_size(&self) -> usize {
        let size = size_of::<i64>()
            + crate::serialize::compact_size_len(self.script_pubkey.len())
            + self.script_pubkey.len();
        assert!(size >= TxOut::SIZE_MIN);
        size
    }
}

impl Encode for TxOut {
    fn encode(&self, out: &mut Vec<u8>) {
        self.value.encode(out);
        crate::serialize::write_string(out, &self.script_pubkey);
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Transaction {
    pub(crate) version: u32,
    inputs: Vec<TxIn>,
    outputs: Vec<TxOut>,
    pub(crate) lock_time: u32,
}

impl Transaction {
    #[cfg(test)]
    pub(crate) fn new(
        version: u32,
        inputs: Vec<TxIn>,
        outputs: Vec<TxOut>,
        lock_time: u32,
    ) -> Option<Self> {
        (!inputs.is_empty() || outputs.is_empty()).then_some(Self {
            version,
            inputs,
            outputs,
            lock_time,
        })
    }

    #[cfg(test)]
    pub(crate) fn inputs(&self) -> &[TxIn] {
        &self.inputs
    }

    pub(crate) fn outputs(&self) -> &[TxOut] {
        &self.outputs
    }

    pub(crate) fn txid(&self) -> bitcoin_hashes::sha256d::Hash {
        let expected = self.size_without_witness();
        let mut bytes = Vec::with_capacity(expected);
        self.encode_without_witness(&mut bytes);
        assert_eq!(bytes.len(), expected);
        bitcoin_hashes::sha256d::Hash::hash(&bytes)
    }

    pub(crate) fn wtxid(&self) -> bitcoin_hashes::sha256d::Hash {
        let expected = self.size_with_witness();
        let mut bytes = Vec::with_capacity(expected);
        self.encode(&mut bytes);
        assert_eq!(bytes.len(), expected);
        bitcoin_hashes::sha256d::Hash::hash(&bytes)
    }

    pub(crate) fn size_without_witness(&self) -> usize {
        let inputs_size: usize = self.inputs.iter().map(TxIn::encoded_size).sum();
        let outputs_size: usize = self.outputs.iter().map(TxOut::encoded_size).sum();
        let size = size_of::<u32>()
            + crate::serialize::compact_size_len(self.inputs.len())
            + inputs_size
            + crate::serialize::compact_size_len(self.outputs.len())
            + outputs_size
            + size_of::<u32>();
        assert!(size >= Transaction::SIZE_MIN);
        size
    }

    pub(crate) fn size_with_witness(&self) -> usize {
        let base = self.size_without_witness();
        if !self.has_witness() {
            return base;
        }
        let witness_size: usize = self
            .inputs
            .iter()
            .map(|input| input.witness.encoded_size())
            .sum();
        let size = base + size_of::<u8>() + size_of::<u8>() + witness_size;
        assert!(size > base);
        size
    }

    pub(crate) fn has_witness(&self) -> bool {
        self.inputs.iter().any(|input| !input.witness.is_empty())
    }

    pub(crate) fn coinbase_input(&self) -> Option<&TxIn> {
        match self.inputs.as_slice() {
            [input] if input.previous_output.is_null() => Some(input),
            _ => None,
        }
    }

    pub(crate) fn check(&self) -> Result<(), TransactionError> {
        if self.inputs.is_empty() {
            return Err(TransactionError::InputsEmpty);
        }
        if self.outputs.is_empty() {
            return Err(TransactionError::OutputsEmpty);
        }
        if self.size_without_witness() > BLOCK_BASE_SIZE_MAX {
            return Err(TransactionError::Oversize);
        }

        let mut total: i64 = 0;
        for output in &self.outputs {
            if output.value < 0 {
                return Err(TransactionError::OutputNegative);
            }
            if output.value > MONEY_MAX {
                return Err(TransactionError::OutputTooLarge);
            }
            assert!(total <= MONEY_MAX);
            total += output.value;
            if total > MONEY_MAX {
                return Err(TransactionError::OutputsTotalTooLarge);
            }
        }

        let mut seen = std::collections::HashSet::with_capacity(self.inputs.len());
        for input in &self.inputs {
            if !seen.insert(input.previous_output) {
                return Err(TransactionError::DuplicateInputs);
            }
        }

        if let Some(coinbase) = self.coinbase_input() {
            if !(COINBASE_SCRIPT_SIZE_MIN..=COINBASE_SCRIPT_SIZE_MAX)
                .contains(&coinbase.script_sig.len())
            {
                return Err(TransactionError::CoinbaseScriptSize);
            }
        } else if self
            .inputs
            .iter()
            .any(|input| input.previous_output.is_null())
        {
            return Err(TransactionError::NullOutPoint);
        }

        Ok(())
    }

    pub(crate) fn is_final(&self, height: usize, time: u32) -> bool {
        if self.lock_time == 0 {
            return true;
        }
        let satisfied = if self.lock_time < LOCK_TIME_THRESHOLD {
            usize::try_from(self.lock_time).expect("u32 fits in usize") < height
        } else {
            self.lock_time < time
        };
        if satisfied {
            return true;
        }
        self.inputs
            .iter()
            .all(|input| input.sequence == SEQUENCE_FINAL)
    }

    pub(crate) fn legacy_sigop_count(&self) -> usize {
        let mut count: usize = 0;
        for input in &self.inputs {
            count = count.saturating_add(script_legacy_sigop_count(&input.script_sig));
        }
        for output in &self.outputs {
            count = count.saturating_add(script_legacy_sigop_count(&output.script_pubkey));
        }
        count
    }

    fn encode_without_witness(&self, out: &mut Vec<u8>) {
        self.version.encode(out);
        write_vector(out, &self.inputs);
        write_vector(out, &self.outputs);
        self.lock_time.encode(out);
    }
}

fn script_legacy_sigop_count(mut script: &[u8]) -> usize {
    let mut count: usize = 0;
    while let Some((&opcode, rest)) = script.split_first() {
        let length_before = script.len();
        script = rest;
        if opcode <= OP_PUSHDATA4 {
            let push_size = if opcode < OP_PUSHDATA1 {
                usize::from(opcode)
            } else if opcode == OP_PUSHDATA1 {
                let Some((&size, rest)) = script.split_first() else {
                    break;
                };
                script = rest;
                usize::from(size)
            } else if opcode == OP_PUSHDATA2 {
                let Some((bytes, rest)) = script.split_first_chunk::<2>() else {
                    break;
                };
                script = rest;
                usize::from(u16::from_le_bytes(*bytes))
            } else {
                assert_eq!(opcode, OP_PUSHDATA4);
                let Some((bytes, rest)) = script.split_first_chunk::<4>() else {
                    break;
                };
                script = rest;
                usize::try_from(u32::from_le_bytes(*bytes)).expect("u32 fits in usize")
            };
            let Some((_, rest)) = script.split_at_checked(push_size) else {
                break;
            };
            script = rest;
        } else if opcode == OP_CHECKSIG || opcode == OP_CHECKSIGVERIFY {
            count = count.saturating_add(1);
        } else if opcode == OP_CHECKMULTISIG || opcode == OP_CHECKMULTISIGVERIFY {
            count = count.saturating_add(MULTISIG_PUBKEYS_COUNT_MAX);
        }
        assert!(script.len() < length_before);
    }
    count
}

impl Encode for Transaction {
    fn encode(&self, out: &mut Vec<u8>) {
        if !self.has_witness() {
            self.encode_without_witness(out);
            return;
        }
        self.version.encode(out);
        WITNESS_MARKER.encode(out);
        WITNESS_FLAG.encode(out);
        write_vector(out, &self.inputs);
        write_vector(out, &self.outputs);
        for input in &self.inputs {
            input.witness.encode(out);
        }
        self.lock_time.encode(out);
    }
}

impl Decode for Transaction {
    fn decode(input: &mut &[u8]) -> Result<Self, crate::serialize::Error> {
        let version = u32::decode(input)?;
        let mut inputs: Vec<TxIn> = read_vector(input)?;
        let mut flags = 0;
        let mut outputs = Vec::new();
        if inputs.is_empty() {
            flags = u8::decode(input)?;
            if flags != 0 {
                inputs = read_vector(input)?;
                outputs = read_vector(input)?;
            }
        } else {
            outputs = read_vector(input)?;
        }
        if flags & WITNESS_FLAG != 0 {
            for transaction_input in &mut inputs {
                transaction_input.witness = Witness::decode(input)?;
            }
            if inputs
                .iter()
                .all(|transaction_input| transaction_input.witness.is_empty())
            {
                return Err(crate::serialize::Error::SuperfluousWitness);
            }
        }
        if flags & !WITNESS_FLAG != 0 {
            return Err(crate::serialize::Error::TransactionFlags(flags));
        }
        let transaction = Self {
            version,
            inputs,
            outputs,
            lock_time: u32::decode(input)?,
        };
        if transaction.inputs.is_empty() {
            assert!(transaction.outputs.is_empty());
        }
        Ok(transaction)
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

pub(crate) fn read_vector<T: Decode + SizeMin>(
    input: &mut &[u8],
) -> Result<Vec<T>, crate::serialize::Error> {
    let count = crate::serialize::read_compact_size(input)?;
    let mut items = Vec::with_capacity(count.min(input.len() / T::SIZE_MIN));
    for _ in 0..count {
        let length = input.len();
        items.push(T::decode(input)?);
        assert!(length - input.len() >= T::SIZE_MIN);
    }
    Ok(items)
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
                inputs: Vec::new(),
                outputs: Vec::new(),
                lock_time: 0,
            })
        );
    }

    #[test]
    fn no_inputs_and_zero_flags_is_a_transaction_with_no_outputs() {
        let bytes = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00];
        let transaction = decode(&bytes).unwrap();
        assert!(transaction.inputs.is_empty());
        assert!(transaction.outputs.is_empty());
        assert_eq!(transaction.lock_time, 5);
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
            inputs: Vec::new(),
            outputs: Vec::new(),
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
        let transaction = |inputs| super::Transaction {
            version: 1,
            inputs,
            outputs: Vec::new(),
            lock_time: 0,
        };

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

    fn valid_spend() -> super::Transaction {
        super::Transaction {
            version: 1,
            inputs: vec![tx_in(outpoint(1, 0), Vec::new(), super::SEQUENCE_FINAL)],
            outputs: vec![tx_out(0, Vec::new())],
            lock_time: 0,
        }
    }

    fn valid_coinbase(script_sig: Vec<u8>) -> super::Transaction {
        super::Transaction {
            version: 1,
            inputs: vec![tx_in(
                outpoint(0, u32::MAX),
                script_sig,
                super::SEQUENCE_FINAL,
            )],
            outputs: vec![tx_out(0, Vec::new())],
            lock_time: 0,
        }
    }

    #[test]
    fn check_transaction_enforces_core_rules() {
        assert_eq!(valid_spend().check(), Ok(()));
        assert_eq!(valid_coinbase(vec![0; 2]).check(), Ok(()));
        assert_eq!(valid_coinbase(vec![0; 100]).check(), Ok(()));

        assert_eq!(
            super::Transaction {
                inputs: Vec::new(),
                outputs: Vec::new(),
                ..valid_spend()
            }
            .check(),
            Err(super::TransactionError::InputsEmpty)
        );
        assert_eq!(
            super::Transaction {
                outputs: Vec::new(),
                ..valid_spend()
            }
            .check(),
            Err(super::TransactionError::OutputsEmpty)
        );

        let at_limit = super::Transaction {
            outputs: vec![tx_out(0, vec![0; super::BLOCK_BASE_SIZE_MAX - 64])],
            ..valid_spend()
        };
        assert_eq!(at_limit.size_without_witness(), super::BLOCK_BASE_SIZE_MAX);
        assert_eq!(at_limit.check(), Ok(()));
        let oversize = super::Transaction {
            outputs: vec![tx_out(0, vec![0; super::BLOCK_BASE_SIZE_MAX - 63])],
            ..valid_spend()
        };
        assert_eq!(
            oversize.size_without_witness(),
            super::BLOCK_BASE_SIZE_MAX + 1
        );
        assert_eq!(oversize.check(), Err(super::TransactionError::Oversize));

        assert_eq!(
            super::Transaction {
                outputs: vec![tx_out(-1, Vec::new())],
                ..valid_spend()
            }
            .check(),
            Err(super::TransactionError::OutputNegative)
        );
        assert_eq!(
            super::Transaction {
                outputs: vec![tx_out(super::MONEY_MAX, Vec::new())],
                ..valid_spend()
            }
            .check(),
            Ok(())
        );
        assert_eq!(
            super::Transaction {
                outputs: vec![tx_out(super::MONEY_MAX + 1, Vec::new())],
                ..valid_spend()
            }
            .check(),
            Err(super::TransactionError::OutputTooLarge)
        );
        assert_eq!(
            super::Transaction {
                outputs: vec![tx_out(super::MONEY_MAX, Vec::new()), tx_out(0, Vec::new()),],
                ..valid_spend()
            }
            .check(),
            Ok(())
        );
        assert_eq!(
            super::Transaction {
                outputs: vec![tx_out(super::MONEY_MAX, Vec::new()), tx_out(1, Vec::new()),],
                ..valid_spend()
            }
            .check(),
            Err(super::TransactionError::OutputsTotalTooLarge)
        );

        assert_eq!(
            super::Transaction {
                inputs: vec![
                    tx_in(outpoint(1, 0), Vec::new(), 0),
                    tx_in(outpoint(1, 1), Vec::new(), 0),
                ],
                ..valid_spend()
            }
            .check(),
            Ok(())
        );
        assert_eq!(
            super::Transaction {
                inputs: vec![
                    tx_in(outpoint(1, 0), Vec::new(), 0),
                    tx_in(outpoint(1, 0), Vec::new(), 0),
                ],
                ..valid_spend()
            }
            .check(),
            Err(super::TransactionError::DuplicateInputs)
        );

        assert_eq!(
            valid_coinbase(vec![0; 1]).check(),
            Err(super::TransactionError::CoinbaseScriptSize)
        );
        assert_eq!(
            valid_coinbase(vec![0; 101]).check(),
            Err(super::TransactionError::CoinbaseScriptSize)
        );
        assert_eq!(
            super::Transaction {
                inputs: vec![
                    tx_in(outpoint(1, 0), Vec::new(), 0),
                    tx_in(outpoint(0, u32::MAX), Vec::new(), 0),
                ],
                ..valid_spend()
            }
            .check(),
            Err(super::TransactionError::NullOutPoint)
        );
    }

    #[test]
    fn is_final_checks_lock_time_and_sequences() {
        let with = |lock_time, sequences: &[u32]| super::Transaction {
            inputs: sequences
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
            lock_time,
            ..valid_spend()
        };
        assert!(with(0, &[0]).is_final(0, 0));
        assert!(with(99, &[0]).is_final(100, 0));
        assert!(!with(100, &[0]).is_final(100, 0));
        assert!(with(100, &[super::SEQUENCE_FINAL]).is_final(100, 0));
        assert!(!with(100, &[super::SEQUENCE_FINAL, super::SEQUENCE_FINAL - 1]).is_final(100, 0));
        assert!(with(super::LOCK_TIME_THRESHOLD - 1, &[0]).is_final(500_000_000, 0));
        assert!(!with(super::LOCK_TIME_THRESHOLD - 1, &[0]).is_final(499_999_999, 600_000_000));
        assert!(with(super::LOCK_TIME_THRESHOLD, &[0]).is_final(0, 500_000_001));
        assert!(!with(super::LOCK_TIME_THRESHOLD, &[0]).is_final(600_000_000, 500_000_000));
        assert!(
            with(
                super::LOCK_TIME_THRESHOLD,
                &[super::SEQUENCE_FINAL, super::SEQUENCE_FINAL]
            )
            .is_final(0, 500_000_000)
        );
    }

    #[test]
    fn legacy_sigop_count_matches_core_inaccurate_script_scan() {
        let count = super::script_legacy_sigop_count;
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

        let tx = super::Transaction {
            inputs: vec![tx_in(outpoint(1, 0), vec![super::OP_CHECKSIG], 0)],
            outputs: vec![tx_out(0, vec![super::OP_CHECKMULTISIG])],
            ..valid_spend()
        };
        assert_eq!(tx.legacy_sigop_count(), 21);
    }

    #[test]
    fn size_with_and_without_witness_match_encoding() {
        let bytes = spend(0x01, &[0x02, 0x01, 0xbb, 0x00]);
        let tx = decode(&bytes).unwrap();
        assert_eq!(tx.size_with_witness(), bytes.len());
        let mut without = Vec::new();
        tx.encode_without_witness(&mut without);
        assert_eq!(tx.size_without_witness(), without.len());

        let legacy = valid_spend();
        let mut encoded = Vec::new();
        legacy.encode(&mut encoded);
        assert_eq!(legacy.size_without_witness(), encoded.len());
        assert_eq!(legacy.size_with_witness(), encoded.len());
    }
}
