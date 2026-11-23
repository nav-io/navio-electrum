# Per-coin privacy score for BLSCT outputs.
#
# privacy_bits(tx) = log2(foreign_inputs + 1) + min(privacy_bits(own inputs))
#
# where foreign_inputs counts the inputs of the transaction that are not
# this wallet's coins. A transaction that spends none of our coins (a plain
# receive, a staking reward, a coinbase) scores 0: the sender knows the
# coin. Our own send's change keeps the lowest score of the coins it spent;
# an aggregate (ours with covers, or someone else's that spent a cover
# candidate we served) adds log2(foreign + 1) on top of that.
#
# Every output of ours in a tx that spends one of our coins takes the tx's
# score: change, a served cover coming back, and a payment to us inside
# that aggregate alike.
#
# Scores are stored as integer milli-bits on the coin dict
# ('privacy_mbits'); an absent key means unknown (e.g. coins synced before
# the score existed, or a coin whose own input score is unknown). This
# mirrors navio-core's src/wallet/privacy_score.{h,cpp} (floor of the log
# term, saturation, same-tx inputs, every own output taking the tx score): keep them in step.

import math
from typing import Callable, Dict, List, Optional, Sequence, TypeVar

from .i18n import _
from .util import NotEnoughFunds


PRIVACY_KEY = 'privacy_mbits'
MBITS_PER_BIT = 1000
MBITS_MAX = 2 ** 32 - 2   # core: uint32, max value encodes "unknown"
UNKNOWN_BUCKET = -1
UNKNOWN_TEXT = '\u2013'   # en dash: shown for an unknown score


def log2_mbits(n: int) -> int:
    """floor(1000 * log2(n)) for n >= 1, exact for powers of two
    (core Log2MilliBits)."""
    if n < 1:
        raise ValueError('n must be >= 1')
    whole = n.bit_length() - 1
    lower = whole * MBITS_PER_BIT
    if n & (n - 1) == 0:
        return lower
    milli = math.floor(math.log2(n) * MBITS_PER_BIT)
    return min(max(milli, lower), lower + MBITS_PER_BIT - 1)


def privacy_mbits(foreign_inputs: int,
                  own_input_mbits: Sequence[Optional[int]]) -> Optional[int]:
    """Score (milli-bits) of a tx with `foreign_inputs` non-wallet inputs
    that spends own coins scored `own_input_mbits` (None = unknown).
    -> None when any own input is unknown (core ComputePrivacyMilliBits)."""
    if foreign_inputs < 0:
        raise ValueError('foreign_inputs must be >= 0')
    if not own_input_mbits:
        return 0
    if any(m is None for m in own_input_mbits):
        return None
    lowest = min(min(own_input_mbits), MBITS_MAX)
    return min(lowest + log2_mbits(foreign_inputs + 1), MBITS_MAX)


class TxPrivacy:
    """Privacy context of one transaction, for scoring its outputs of ours.

    `input_hashes`: every input (spent output hash) of the tx, ours and
    foreign. `created_hashes`: the tx's own output hashes; an input spending
    one of them (a chain of sends a staker merged into one block tx) counts
    as neither own nor foreign. `outputs`: the wallet's {output_hash: coin}.
    """

    def __init__(self, input_hashes: Sequence[str], outputs: Dict[str, dict],
                 created_hashes: Sequence[str] = ()):
        created = set(created_hashes)
        own = []
        self.foreign = 0
        for h in input_hashes:
            if h in created:
                continue
            d = outputs.get(h)
            if d is None:
                self.foreign += 1
                continue
            own.append(d.get(PRIVACY_KEY))
        self.tx_mbits = privacy_mbits(self.foreign, own)

    def score_output(self) -> Optional[int]:
        """Score of any of our outputs of this tx: the tx's score."""
        return self.tx_mbits


def mbits_to_bits(mbits: Optional[int]) -> Optional[float]:
    return None if mbits is None else mbits / 1000


def bits_to_mbits(bits: Optional[float]) -> Optional[int]:
    return None if bits is None else int(round(bits * 1000))


def format_bits(mbits: Optional[int], unknown: str = UNKNOWN_TEXT) -> str:
    """Display form: bits with 2 decimals, `unknown` when not known."""
    return unknown if mbits is None else f'{mbits / 1000:.2f}'


def bucket(mbits: Optional[int]) -> int:
    """floor(bits); unknown scores form the lowest bucket."""
    return UNKNOWN_BUCKET if mbits is None else mbits // 1000


def result_mbits(input_mbits: Sequence[Optional[int]]) -> Optional[int]:
    """Score our plain send's new outputs (change) will get: the lowest
    input score (covers only add to it). None if any input is unknown."""
    return privacy_mbits(0, list(input_mbits))


def spread_exceeds(input_mbits: Sequence[Optional[int]], limit_mbits: int = 1000) -> bool:
    """True when the known scores of the coins differ by more than
    `limit_mbits` (used to warn on manual coin selection)."""
    known = [m for m in input_mbits if m is not None]
    return bool(known) and max(known) - min(known) > limit_mbits


C = TypeVar('C')


class NotEnoughPrivateFunds(NotEnoughFunds):
    """Funds would suffice, but not with coins at or above the requested
    minimum privacy score. A NotEnoughFunds, so existing handlers keep
    working."""

    def __init__(self, min_bits: float):
        super().__init__(min_bits)
        self.min_bits = min_bits

    def __str__(self):
        return _('Not enough funds with privacy score >= {} bits').format(
            f'{self.min_bits:g}')


def select_by_privacy(coins: Sequence[C], greedy: Callable[[Sequence[C]], Optional[List[C]]],
                      mbits_of: Callable[[C], Optional[int]], *,
                      min_mbits: Optional[int] = None) -> Optional[List[C]]:
    """Privacy-aware coin selection around an existing `greedy` selector
    (coins in preference order -> selected list, or None if they cannot
    pay).

    - Hard floor: with `min_mbits`, coins below it or unknown are dropped.
    - Soft preference: coins are bucketed by floor(bits) (unknown lowest);
      the lowest bucket that can pay on its own is used, so poorly mixed
      coins go first and scores are not mixed. Otherwise the selection
      falls back to all (eligible) coins.

    `coins` keep their order inside a bucket. -> None if nothing pays."""
    if min_mbits is not None:
        coins = [c for c in coins
                 if mbits_of(c) is not None and mbits_of(c) >= min_mbits]
    buckets = {}  # type: Dict[int, List[C]]
    for c in coins:
        buckets.setdefault(bucket(mbits_of(c)), []).append(c)
    if len(buckets) > 1:
        for b in sorted(buckets):
            sel = greedy(buckets[b])
            if sel is not None:
                return sel
    return greedy(coins)
