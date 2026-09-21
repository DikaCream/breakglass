# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
"""A stand-in breaker for vault gate tests.

Direct mode cannot hold two deployed contracts at once, so the vault tests
point at this stub instead of a real BreakGlass deployment. It answers the
one question the vault asks — ``is_paused`` — from a flag fixed at deploy
time. The real breaker and its verdict logic are covered by the breaker
suite; the live two-contract path runs on StudioNet.
"""

from genlayer import *  # noqa: F401 - re-exports gl
import genlayer.gl as gl


class VaultPauser(gl.Contract):
    answer: bool

    def __init__(self, answer: bool = True):
        self.answer = bool(answer)

    @gl.public.view
    def is_paused(self, who_hex: str) -> bool:
        return self.answer
