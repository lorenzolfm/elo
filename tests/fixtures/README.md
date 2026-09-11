# Fixtures

Every file here is bytes Bitcoin Core produced, never bytes elo produced.

A codec test that round-trips our encoder through our decoder proves nothing:
both halves can be wrong in the same direction and the test still passes. These
captures are the anchor that makes the tests mean something.

Each fixture carries a `.md` note beside it recording what produced it — Core
version, network, command line, date.
