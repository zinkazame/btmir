# btmir/trust/models.py
# These are the core data structures the entire system uses.
# Everything — collector, engine, detector, API — speaks this language.

from dataclasses import dataclass, field
from typing import List


@dataclass
class BGPUpdate:
    """
    A single BGP announcement received from the network.
    This is the raw input to our system.
    """
    timestamp:   float       # when we received this
    peer_asn:    int         # which AS sent us this update
    peer_ip:     str         # IP address of the peer
    prefix:      str         # the IP block being announced e.g. "1.2.3.0/24"
    as_path:     List[int]   # full path e.g. [1299, 3356, 13335]
    origin_asn:  int         # last AS in path — the one claiming ownership
    announced:   bool        # True = announce, False = withdraw


@dataclass
class TrustScore:
    """
    The result of evaluating one AS through the trust engine.
    """
    asn:         int
    wb:          float   # security evaluation score
    wd:          float   # direct trust score
    wr:          float   # indirect recommendation score
    final:       float   # T = alpha*WB + beta*WD + gamma*WR
    is_isolated: bool    # True if final score is below threshold
    reason:      str     # human readable explanation of the decision
    @property
    def verdict(self) -> str:
        return "ISOLATED" if self.is_isolated else "TRUSTED"