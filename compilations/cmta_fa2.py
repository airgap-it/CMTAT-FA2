import smartpy as sp

from contracts.cmta_fa2 import CMTAFA2, LedgerKey, NULL_ADDRESS

# change the NULL_ADDRESS, to the address you want the admin to be.
sp.add_compilation_target("CMTAFA2", CMTAFA2({LedgerKey.make(0, NULL_ADDRESS):1})) 