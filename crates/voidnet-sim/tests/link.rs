//! Simulator behaviour: determinism, rates, reordering.
//! Поведение имитатора: детерминизм, доли потерь, перестановка.

use voidnet_sim::{Link, Params, Pcg32, TraceHash};

fn run(seed: u64, params: Params, n: u32) -> (u64, voidnet_sim::Stats) {
    let mut link = Link::new(params, seed);
    let mut now = 0u64;
    for i in 0..n {
        now += 1_000;
        link.send(now, &i.to_le_bytes());
        while link.poll(now).is_some() {}
    }
    while let Some(t) = link.next_arrival() {
        now = now.max(t);
        link.poll(now);
    }
    (link.trace(), link.stats)
}

fn lossy() -> Params {
    Params {
        jitter_us: 5_000,
        loss_permille: 100,
        dup_permille: 50,
        reorder_permille: 100,
        reorder_delay_us: 30_000,
        ..Params::default()
    }
}

#[test]
fn pcg32_matches_reference_vector() {
    // First outputs of pcg32 (seed 42, stream 54) from the reference implementation.
    let mut r = Pcg32::new(42, 54);
    let got: Vec<u32> = (0..6).map(|_| r.next_u32()).collect();
    assert_eq!(
        got,
        [
            0xa15c_02b7,
            0x7b47_f409,
            0xba1d_3330,
            0x83d2_f293,
            0xbfa4_784b,
            0xcbed_606e
        ]
    );
}

#[test]
fn same_seed_same_run_different_seed_different_run() {
    let a = run(1, lossy(), 20_000);
    let b = run(1, lossy(), 20_000);
    let c = run(2, lossy(), 20_000);
    assert_eq!(a, b);
    assert_ne!(a.0, c.0);
}

#[test]
fn golden_trace_is_stable() {
    // If this number changes, the simulator or the PRNG changed behaviour.
    // Run on Windows and Linux: a different value means non-determinism.
    let (hash, stats) = run(7, lossy(), 5_000);
    assert_eq!(stats.sent, 5_000);
    assert_eq!(
        hash, 0x0a15_4ae5_bd57_a881,
        "golden trace changed: {hash:#018x}"
    );
}

#[test]
fn rates_are_close_to_the_requested_ones() {
    let n = 100_000u32;
    let (_, s) = run(3, lossy(), n);
    let pct = |x: u64| x as f64 * 100.0 / f64::from(n);
    assert!((pct(s.lost) - 10.0).abs() < 0.5, "loss {}", pct(s.lost));
    assert!(
        (pct(s.duplicated) - 4.5).abs() < 0.5,
        "dup {}",
        pct(s.duplicated)
    );
    assert!(
        (pct(s.reordered) - 9.0).abs() < 0.5,
        "reorder {}",
        pct(s.reordered)
    );
    assert_eq!(s.delivered, s.sent - s.lost + s.duplicated);
}

#[test]
fn reordering_really_changes_arrival_order() {
    let mut link = Link::new(lossy(), 11);
    let mut now = 0;
    for i in 0..2_000u32 {
        now += 1_000;
        link.send(now, &i.to_le_bytes());
    }
    let mut last = None;
    let mut inversions = 0;
    now += 1_000_000;
    while let Some(d) = link.poll(now) {
        let v = u32::from_le_bytes(d.try_into().unwrap());
        if let Some(l) = last {
            if v < l {
                inversions += 1;
            }
        }
        last = Some(v);
    }
    assert!(inversions > 50, "inversions {inversions}");
}

#[test]
fn blackout_and_mtu_drop() {
    let p = Params {
        blackout: Some((10_000, 20_000)),
        max_datagram: 100,
        ..Params::default()
    };
    let mut link = Link::new(p, 1);
    link.send(5_000, &[0u8; 10]);
    link.send(15_000, &[0u8; 10]);
    link.send(25_000, &[0u8; 10]);
    link.send(26_000, &[0u8; 200]);
    assert_eq!(link.stats.blackout, 1);
    assert_eq!(link.stats.oversize, 1);
    assert_eq!(link.in_flight(), 2);
}

#[test]
fn trace_hash_is_fnv1a() {
    let mut h = TraceHash::default();
    h.bytes(b"a");
    assert_eq!(h.value(), 0xAF63_DC4C_8601_EC8C);
}
