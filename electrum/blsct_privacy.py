# Per-coin privacy score for BLSCT outputs.
#
# privacy_bits(out) = log2(foreign_inputs + 1) + min(privacy_bits(own inputs))
#
# where foreign_inputs counts the inputs of the containing transaction that
# are not this wallet's coins. A transaction that spends none of our coins
# (a plain receive, a staking reward, a coinbase) gives score 0: the sender
# knows the coin. Our own send's change keeps the lowest score of the coins
# it spent; an aggregate (ours with covers, or someone else's that spent a
# cover candidate we served) adds log2(foreign + 1) on top of that.
#
# Scores are stored as integer milli-bits on the coin dict
# ('privacy_mbits'); an absent key means unknown (e.g. coins synced before
# the score existed, or a coin whose own input score is unknown). The same
# formula is implemented by navio-core's wallet: keep them in step.

import math
from typing import Callable, Dict, List, Optional, Sequence, TypeVar

from .i18n import _
from .util import NotEnoughFunds


PRIVACY_KEY = 'privacy_mbits'
UNKNOWN_BUCKET = -1
UNKNOWN_TEXT = '\u2013'   # en dash: shown for an unknown score


def privacy_mbits(foreign_inputs: int,
                  own_input_mbits: Sequence[Optional[int]]) -> Optional[int]:
    """Score (milli-bits) of an output of a tx with `foreign_inputs`
    non-wallet inputs that spends own coins scored `own_input_mbits`
    (None = unknown). -> None when any own input is unknown.

    Integer form of round(1000 * (log2(f + 1) + min_bits)): input scores
    are already whole milli-bits, so only the log term is rounded."""
    if foreign_inputs < 0:
        raise ValueError('foreign_inputs must be >= 0')
    if not own_input_mbits:
        return 0
    if any(m is None for m in own_input_mbits):
        return None
    return int(round(1000 * math.log2(foreign_inputs + 1))) + min(own_input_mbits)


def score_for_inputs(input_hashes: Sequence[str],
                     outputs: Dict[str, dict]) -> Optional[int]:
    """Score for an output of a tx spending `input_hashes` (all its inputs,
    by output hash), given the wallet's {output_hash: coin dict}. Inputs
    not in `outputs` are foreign."""
    own = [h for h in input_hashes if h in outputs]
    foreign = len(input_hashes) - len(own)
    return privacy_mbits(foreign, [outputs[h].get(PRIVACY_KEY) for h in own])


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
