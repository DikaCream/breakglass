# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
"""VulnerableVault: the pre-fix draft of SafeVault, kept as a live fixture.

This is the historical buggy version of the demo vault: withdraw_for()
moves any account's balance out with no access check, and pays the CALLER,
so anyone can drain anyone. It exists so the exploit reports in the tests
quote the exact code that is deployed, and anyone can diff it against the
patched contracts/safe_vault.py in the same repository. It is deliberately
not wired to the breaker: an unprotected contract is exactly what the
breaker is for.
"""

from genlayer import *  # noqa: F401 - re-exports gl
import genlayer.gl as gl
from genlayer.py.types import Address, u256


class VulnerableVault(gl.Contract):
    owner_addr: Address
    balances: TreeMap[Address, u256]
    total_deposits: u256

    def __init__(self):
        self.owner_addr = gl.message.sender_address
        self.total_deposits = u256(0)

    @gl.public.view
    def self_address(self) -> str:
        return str(gl.message.contract_address)

    @gl.public.write.payable
    def deposit(self) -> u256:
        if int(gl.message.value) <= 0:
            raise gl.vm.UserError("deposit something")
        to = gl.message.sender_address
        cur = int(self.balances.get(to, u256(0)))
        self.balances[to] = u256(cur + int(gl.message.value))
        self.total_deposits = u256(int(self.total_deposits) + int(gl.message.value))
        return u256(cur + int(gl.message.value))

    @gl.public.write
    def withdraw(self, amount: u256) -> None:
        to = gl.message.sender_address
        cur = int(self.balances.get(to, u256(0)))
        if int(amount) <= 0 or int(amount) > cur:
            raise gl.vm.UserError("withdraw more than your balance")
        gl.emit_transfer(to, value=u256(int(amount)))
        self.balances[to] = u256(cur - int(amount))

    @gl.public.write
    def withdraw_for(self, from_hex: str, amount: u256) -> None:
        # BUG: no authorization at all. The funds come out of ``from``'s
        # balance and land in the CALLER's wallet: anyone can drain anyone.
        src = Address(from_hex)
        cur = int(self.balances.get(src, u256(0)))
        if int(amount) <= 0 or int(amount) > cur:
            raise gl.vm.UserError("withdraw more than that balance")
        to = gl.message.sender_address
        self.balances[src] = u256(cur - int(amount))
        gl.emit_transfer(to, value=u256(int(amount)))

    @gl.public.view
    def balance_of(self, who_hex: str) -> int:
        return int(self.balances.get(Address(who_hex), u256(0)))

    @gl.public.view
    def vault_stats(self) -> dict:
        return {
            "total_deposits": self.total_deposits,
            "owner": self.owner_addr,
        }
