use crate::serialize::{Decode, Encode};

const WITNESS_MARKER: u8 = 0x00;

const WITNESS_FLAG: u8 = 0x01;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    pub(crate) inputs: Vec<TxIn>,
    pub(crate) outputs: Vec<TxOut>,
    pub(crate) lock_time: u32,
}

impl Transaction {
    pub(crate) fn txid(&self) -> bitcoin_hashes::sha256d::Hash {
        let mut bytes = Vec::new();
        self.encode_without_witness(&mut bytes);
        bitcoin_hashes::sha256d::Hash::hash(&bytes)
    }

    pub(crate) fn wtxid(&self) -> bitcoin_hashes::sha256d::Hash {
        let mut bytes = Vec::new();
        self.encode(&mut bytes);
        bitcoin_hashes::sha256d::Hash::hash(&bytes)
    }

    pub(crate) fn size_without_witness(&self) -> usize {
        let mut bytes = Vec::new();
        self.encode_without_witness(&mut bytes);
        bytes.len()
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

    fn encode_without_witness(&self, out: &mut Vec<u8>) {
        if self.inputs.is_empty() {
            assert!(self.outputs.is_empty());
        }
        self.version.encode(out);
        write_vector(out, &self.inputs);
        write_vector(out, &self.outputs);
        self.lock_time.encode(out);
    }
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
}
