use conet_core::{BlockCodec, BlockId, DecodeStatus, PayloadCopyCounter, SymbolId, SymbolMeta};
use conet_fountain::{FountainBlockCodec, FountainCodecConfig};

fn codec() -> FountainBlockCodec {
    FountainBlockCodec::new(
        FountainCodecConfig {
            symbol_len: 32,
            minimum_source_symbols: 4,
        },
        PayloadCopyCounter::new(),
    )
    .unwrap()
}

#[test]
fn raptor10_systematic_symbols_recover_the_registered_file_block() {
    let block = BlockId::new(1);
    let source = (0..=255).cycle().take(517).collect::<Vec<_>>();
    let mut encoder = codec();
    let shape = encoder.add_block(block, source.clone()).unwrap();
    assert_eq!(shape.source_symbols, 17);

    let mut decoder = codec();
    let mut symbol = vec![0; shape.symbol_len];
    for index in 0..shape.source_symbols {
        let logical = SymbolId::new(index as u64);
        assert_eq!(
            encoder.encode(block, logical, &mut symbol).unwrap(),
            shape.symbol_len
        );
        let status = decoder
            .accumulate(
                SymbolMeta {
                    block_id: block,
                    symbol_id: logical,
                    shape,
                },
                &symbol,
            )
            .unwrap();
        if index + 1 == shape.source_symbols {
            assert_eq!(status, DecodeStatus::BlockRecovered);
        }
    }

    assert_eq!(decoder.take_recovered_block(block).unwrap(), source);
}

#[test]
fn raptor10_repair_symbols_recover_when_systematic_symbols_are_missing() {
    let block = BlockId::new(2);
    let source = b"repair symbols must carry the missing source data".repeat(8);
    let mut encoder = codec();
    let shape = encoder.add_block(block, source.clone()).unwrap();
    let dropped = 1_u64;
    let budget = shape.source_symbols as u64 * 2;
    let mut decoder = codec();
    let mut symbol = vec![0; shape.symbol_len];
    let mut recovered = false;

    for logical in 0..budget {
        if logical == dropped {
            continue;
        }
        let symbol_id = SymbolId::new(logical);
        encoder.encode(block, symbol_id, &mut symbol).unwrap();
        let status = decoder
            .accumulate(
                SymbolMeta {
                    block_id: block,
                    symbol_id,
                    shape,
                },
                &symbol,
            )
            .unwrap();
        if status == DecodeStatus::BlockRecovered {
            recovered = true;
            break;
        }
    }

    assert!(recovered, "stated sufficient budget was not sufficient");
    assert_eq!(decoder.take_recovered_block(block).unwrap(), source);
}

#[test]
fn raptor10_recovers_k33_under_periodic_twenty_percent_loss() {
    let block = BlockId::new(3);
    let source = (0..=255).cycle().take(8_193).collect::<Vec<_>>();
    let mut encoder = FountainBlockCodec::new(
        FountainCodecConfig {
            symbol_len: 256,
            minimum_source_symbols: 4,
        },
        PayloadCopyCounter::new(),
    )
    .unwrap();
    let shape = encoder.add_block(block, source.clone()).unwrap();
    assert_eq!(shape.source_symbols, 33);
    let mut decoder = FountainBlockCodec::new(
        FountainCodecConfig {
            symbol_len: 256,
            minimum_source_symbols: 4,
        },
        PayloadCopyCounter::new(),
    )
    .unwrap();
    let mut symbol = vec![0; shape.symbol_len];
    let mut recovered_at = None;
    for logical in 0..256_u64 {
        if logical % 5 == 4 {
            continue;
        }
        let symbol_id = SymbolId::new(logical);
        encoder.encode(block, symbol_id, &mut symbol).unwrap();
        let status = decoder
            .accumulate(
                SymbolMeta {
                    block_id: block,
                    symbol_id,
                    shape,
                },
                &symbol,
            )
            .unwrap();
        if status == DecodeStatus::BlockRecovered {
            recovered_at = Some(logical + 1);
            break;
        }
    }
    println!("recovered_at={recovered_at:?}");
    assert!(recovered_at.is_some());
    assert_eq!(decoder.take_recovered_block(block).unwrap(), source);
}
