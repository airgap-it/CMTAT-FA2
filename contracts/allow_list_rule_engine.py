import smartpy as sp
from contracts.cmta_fa2 import CMTAFA2ErrorMessage
from contracts.fa2 import Transfer

class AllowListRuleEngine(sp.Contract):
    def __init__(self, allow_list={}):
        self.init(allow_list=sp.set_type_expr(allow_list, sp.TBigMap(sp.TAddress, sp.TUnit))) 
        
    @sp.entry_point
    def validate_transfer(self, transfer):
        sp.set_type(transfer, Transfer.get_type())
        with sp.for_('tx', transfer.txs) as tx:
            sp.verify(self.data.allow_list.contains(transfer.from_), message=CMTAFA2ErrorMessage.CANNOT_TRANSFER)
            sp.verify(self.data.allow_list.contains(tx.to_), message=CMTAFA2ErrorMessage.CANNOT_TRANSFER)