//! Raptor-10 implementation of the Conet `BlockCodec` port.
//!
//! The reliability core exposes monotonic logical symbol IDs. Raptor-10
//! reserves a range after the systematic source symbols for precode vectors,
//! so this adapter maps logical repair IDs past that range before calling the
//! published engine.

use std::collections::{HashMap, HashSet};

use fountain_engine::types::DecodeStatus as EngineDecodeStatus;
use fountain_engine::{CodeScheme, DataOperator};
use fountain_scheme::rfc::r10::{Raptor10Decoder, Raptor10Encoder, Raptor10SysCode};
use fountain_utility::VecDataOperater;
use conet_core::{
    BlockCodec, BlockId, BlockShape, CodecError, DecodeStatus, PayloadCopyCounter, SymbolId,
    SymbolMeta,
};

/// Raptor-10 adapter configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FountainCodecConfig {
    /// Bytes in every source and coded symbol.
    pub symbol_len: usize,
    /// Raptor-10's published implementation is exercised from K = 4 upward.
    pub minimum_source_symbols: usize,
}

impl Default for FountainCodecConfig {
    fn default() -> Self {
        Self {
            symbol_len: 512,
            minimum_source_symbols: 4,
        }
    }
}

struct EncodedBlock {
    shape: BlockShape,
    encoder: Raptor10Encoder,
}

struct DecodedBlock {
    shape: BlockShape,
    decoder: Raptor10Decoder,
    received: HashSet<usize>,
    recovered: bool,
    taken: bool,
}

/// Real Raptor-10 encoder/decoder on both sides of one reliability session.
///
/// A transfer instance should be used on one side only. `add_block` registers
/// source data for semantic encoding; `accumulate` creates receive-side state
/// from the block metadata carried by the first symbol.
pub struct FountainBlockCodec {
    config: FountainCodecConfig,
    sources: HashMap<BlockId, EncodedBlock>,
    decoders: HashMap<BlockId, DecodedBlock>,
    copies: PayloadCopyCounter,
}

impl FountainBlockCodec {
    pub fn new(
        config: FountainCodecConfig,
        copies: PayloadCopyCounter,
    ) -> Result<Self, CodecError> {
        if config.symbol_len == 0 {
            return Err(CodecError::InvalidSymbolLength);
        }
        if config.minimum_source_symbols < 2 {
            return Err(CodecError::InvalidSourceSymbols);
        }
        Ok(Self {
            config,
            sources: HashMap::new(),
            decoders: HashMap::new(),
            copies,
        })
    }

    pub fn add_block(
        &mut self,
        block_id: BlockId,
        data: Vec<u8>,
    ) -> Result<BlockShape, CodecError> {
        if self.sources.contains_key(&block_id) || self.decoders.contains_key(&block_id) {
            return Err(CodecError::DuplicateBlock(block_id));
        }
        if data.is_empty() {
            return Err(CodecError::InvalidSourceSymbols);
        }

        let source_symbols = data
            .len()
            .div_ceil(self.config.symbol_len)
            .max(self.config.minimum_source_symbols);
        let source_symbols =
            u32::try_from(source_symbols).map_err(|_| CodecError::BlockTooLarge)?;
        let shape = BlockShape::new(source_symbols, self.config.symbol_len, data.len())?;
        let padded_len = (shape.source_symbols as usize)
            .checked_mul(shape.symbol_len)
            .ok_or(CodecError::BlockTooLarge)?;
        let mut padded = data;
        padded.resize(padded_len, 0);

        let mut operator = VecDataOperater::new(shape.symbol_len);
        for index in 0..shape.source_symbols as usize {
            let start = index * shape.symbol_len;
            operator.insert_vector(&padded[start..start + shape.symbol_len], index);
        }
        let scheme = Raptor10SysCode::new_with_default_setting(shape.source_symbols as usize);
        let encoder =
            Raptor10Encoder::new_with_operator(scheme, Box::new(operator), shape.symbol_len);
        self.sources
            .insert(block_id, EncodedBlock { shape, encoder });
        Ok(shape)
    }

    pub fn copies(&self) -> &PayloadCopyCounter {
        &self.copies
    }

    fn physical_symbol_id(shape: BlockShape, logical: SymbolId) -> Result<usize, CodecError> {
        let logical = usize::try_from(logical.get()).map_err(|_| CodecError::BlockTooLarge)?;
        let scheme = Raptor10SysCode::new_with_default_setting(shape.source_symbols as usize);
        let params = scheme.get_params();
        if logical < params.k {
            return Ok(logical);
        }
        params
            .num_total()
            .checked_add(logical - params.k)
            .ok_or(CodecError::BlockTooLarge)
    }

    fn validate_symbol(shape: BlockShape, symbol: &[u8]) -> Result<(), CodecError> {
        if symbol.len() != shape.symbol_len {
            return Err(CodecError::WrongSymbolLength {
                expected: shape.symbol_len,
                actual: symbol.len(),
            });
        }
        Ok(())
    }
}

impl BlockCodec for FountainBlockCodec {
    fn block_shape(&self, block_id: BlockId) -> Option<BlockShape> {
        self.sources
            .get(&block_id)
            .map(|block| block.shape)
            .or_else(|| self.decoders.get(&block_id).map(|block| block.shape))
    }

    fn encode(
        &mut self,
        block_id: BlockId,
        symbol_id: SymbolId,
        out: &mut [u8],
    ) -> Result<usize, CodecError> {
        let block = self
            .sources
            .get_mut(&block_id)
            .ok_or(CodecError::UnknownBlock(block_id))?;
        if out.len() != block.shape.symbol_len {
            return Err(CodecError::WrongOutputLength {
                expected: block.shape.symbol_len,
                actual: out.len(),
            });
        }
        let physical = Self::physical_symbol_id(block.shape, symbol_id)?;
        let data_id = block
            .encoder
            .encode_coded_vector(physical)
            .ok_or(CodecError::BlockTooLarge)?;
        let coded = block.encoder.get_data_vector(data_id);
        if coded.len() != out.len() {
            return Err(CodecError::WrongOutputLength {
                expected: out.len(),
                actual: coded.len(),
            });
        }
        out.copy_from_slice(coded);
        self.copies.record_copy();
        Ok(out.len())
    }

    fn accumulate(&mut self, meta: SymbolMeta, symbol: &[u8]) -> Result<DecodeStatus, CodecError> {
        Self::validate_symbol(meta.shape, symbol)?;
        let physical = Self::physical_symbol_id(meta.shape, meta.symbol_id)?;

        let block = match self.decoders.entry(meta.block_id) {
            std::collections::hash_map::Entry::Occupied(entry) => {
                if entry.get().shape != meta.shape {
                    return Err(CodecError::BlockShapeMismatch);
                }
                entry.into_mut()
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                let scheme =
                    Raptor10SysCode::new_with_default_setting(meta.shape.source_symbols as usize);
                let operator = VecDataOperater::new(meta.shape.symbol_len);
                let decoder = Raptor10Decoder::new_with_operator(
                    scheme,
                    Box::new(operator),
                    meta.shape.symbol_len,
                );
                entry.insert(DecodedBlock {
                    shape: meta.shape,
                    decoder,
                    received: HashSet::new(),
                    recovered: false,
                    taken: false,
                })
            }
        };

        if block.recovered || !block.received.insert(physical) {
            return Ok(DecodeStatus::Duplicate);
        }
        let status = block.decoder.add_coded_vector(physical, symbol);
        self.copies.record_copy();
        if status == EngineDecodeStatus::Decoded {
            block.recovered = true;
            Ok(DecodeStatus::BlockRecovered)
        } else {
            Ok(DecodeStatus::NeedMore)
        }
    }

    fn take_recovered_block(&mut self, block_id: BlockId) -> Option<Vec<u8>> {
        let block = self.decoders.get_mut(&block_id)?;
        if !block.recovered || block.taken {
            return None;
        }

        let mut recovered =
            Vec::with_capacity(block.shape.source_symbols as usize * block.shape.symbol_len);
        for source_index in 0..block.shape.source_symbols as usize {
            recovered.extend_from_slice(block.decoder.get_data_vector(source_index));
        }
        recovered.truncate(block.shape.block_len);
        block.taken = true;
        self.copies.record_copy();
        Some(recovered)
    }
}
