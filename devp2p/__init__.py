# -*- coding: utf-8 -*-
# ############# version ##################
from pkg_resources import get_distribution, DistributionNotFound
import os.path
try:
    _dist = get_distribution('devp2p')
    # Normalize case for Windows systems
    dist_loc = os.path.normcase(_dist.location)
    here = os.path.normcase(__file__)
    if not here.startswith(os.path.join(dist_loc, 'devp2p')):
        # not installed, but there is another version that *is*
        raise DistributionNotFound
except DistributionNotFound:
    __version__ = 'dirty'
else:
    __version__ = _dist.version
# ########### endversion ##################
