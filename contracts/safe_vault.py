# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
"""SafeVault: the demo target that pulls its own brakes.

A minimal vault a team might actually deploy. Every sensitive write consults
the BreakGlass breaker first: while an accepted alarm against this vault
stands unpaused, the vault refuses to move money. The gate is pull-model, so
the vault keeps working with no keeper and no cron: it just reads the
breaker's verdict for itself before acting.

Registration is a two-sided handshake. The vault pins its breaker at deploy
time and answers the breaker's consent read from
``breakglass_registration``: the breaker accepts a registration only when
it is the pinned breaker and the registrant is the vault's own owner. The
breaker's registry stays the single source of truth for who is protected.
"""

from genlayer import *  # noqa: F401 - re-exports gl
import genlayer.gl as gl
from genlayer.py.types import Address, u256


class SafeVault(gl.Contract):
    breaker_addr: Address
    owner_addr: Address
    balances: TreeMap[Address, u256]
    total_deposits: u256
    paused_halt: bool
    last_gate_check: str
    registration_open: bool

    def __init__(self, breaker_hex: str):
        self.breaker_addr = Address(breaker_hex)
        self.owner_addr = gl.message.sender_address
        self.total_deposits = u256(0)
        self.paused_halt = False
        self.last_gate_check = ""
        self.registration_open = False

    # ------------------------------------------------- the consent surface
    @gl.public.view
    def breakglass_registration(self) -> dict:
        """What a breaker reads before accepting this vault.

        Reports the pinned breaker, the vault's own owner, and whether a
        registration handshake has already landed and is still open. A
        breaker only accepts a registration when it is the pinned one, the
        registrant is this owner, and no open registration stands.
        """
        return {
            "breaker": self.breaker_addr,
            "owner": self.owner_addr,
            "registered": self.registration_open,
        }

    def _only_owner(self) -> None:
        if gl.message.sender_address != self.owner_addr:
            raise gl.vm.UserError("only the owner can arm or disarm the local gate")

    @gl.public.write
    def arm_gate(self, enabled: bool) -> None:
        """Arm or disarm the local pull-model gate.

        The owner flips this once the breaker's registry shows the vault as
        protected (the consent read is the binding handshake; this flag only
        decides whether the vault consults the breaker before moving money).
        It is a convenience switch for the demo, not a safety feature: the
        breaker's registry, not this flag, decides who is protected.
        """
        self._only_owner()
        self.registration_open = bool(enabled)

    # ------------------------------------------------------------- the gate
    def _gate(self) -> None:
        """Consult the brakes: refuse to move money while either stands.

        The owner's halt outranks everything. The breaker's verdict is read
        fresh on every movement — when the breaker resumes us, money moves
        again with nothing to clear here.
        """
        if self.paused_halt:
            raise gl.vm.UserError("the owner halted this vault")
        b = gl.get_contract_at(self.breaker_addr)
        verdict = b.view().is_paused(str(gl.message.contract_address))
        self.last_gate_check = "paused" if verdict else "clear"
        if verdict:
            raise gl.vm.UserError(
                "the breaker has paused this vault: an accepted exploit alarm stands"
            )

    @gl.public.view
    def self_address(self) -> str:
        """The address this vault presents to the breaker's pause check."""
        return str(gl.message.contract_address)

    @gl.public.view
    def gate_status(self) -> str:
        if self.paused_halt:
            return "halted"
        b = gl.get_contract_at(self.breaker_addr)
        verdict = b.view().is_paused(str(gl.message.contract_address))
        return "paused" if verdict else "clear"

    # ----------------------------------------------------------- the vault
    @gl.public.write.payable
    def deposit(self) -> u256:
        self._gate()
        if int(gl.message.value) <= 0:
            raise gl.vm.UserError("deposit something")
        to = gl.message.sender_address
        cur = int(self.balances.get(to, u256(0)))
        self.balances[to] = u256(cur + int(gl.message.value))
        self.total_deposits = u256(int(self.total_deposits) + int(gl.message.value))
        return u256(cur + int(gl.message.value))

    @gl.public.write
    def withdraw(self, amount: u256) -> None:
        self._gate()
        to = gl.message.sender_address
        cur = int(self.balances.get(to, u256(0)))
        if int(amount) <= 0 or int(amount) > cur:
            raise gl.vm.UserError("withdraw more than your balance")
        self.balances[to] = u256(cur - int(amount))
        self.total_deposits = u256(int(self.total_deposits) - int(amount))
        gl.emit_transfer(to, value=u256(int(amount)))

    @gl.public.write
    def halt(self) -> None:
        """The owner's own brake, independent of the breaker."""
        if gl.message.sender_address != self.owner_addr:
            raise gl.vm.UserError("only the owner can stop the vault")
        self.paused_halt = True

    @gl.public.write
    def resume(self) -> None:
        """Release the owner's brake. The breaker's verdict still applies."""
        if gl.message.sender_address != self.owner_addr:
            raise gl.vm.UserError("only the owner can resume the vault")
        self.paused_halt = False

    # -------------------------------------------------------------- views
    @gl.public.view
    def balance_of(self, who_hex: str) -> int:
        return int(self.balances.get(Address(who_hex), u256(0)))

    @gl.public.view
    def vault_stats(self) -> dict:
        return {
            "total_deposits": self.total_deposits,
            "paused_halt": self.paused_halt,
            "last_gate_check": self.last_gate_check,
            "owner": self.owner_addr,
            "breaker": self.breaker_addr,
            "registration_open": self.registration_open,
        }
