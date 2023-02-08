import smartpy as sp

from contracts.freeze_rule_engine import FreezeRuleEngine
from contracts.cmta_fa2 import NULL_ADDRESS

sp.add_compilation_target("FreezeRuleEngine", FreezeRuleEngine(NULL_ADDRESS, {NULL_ADDRESS:sp.unit}))