# Copyright (c) 2021 Emanuele Bellocchia
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

"""
Module for BIP32 keys derivation based on ed25519-blake2b curve.
Reference: https://github.com/satoshilabs/slips/blob/master/slip-0010.md
"""

# Imports
from bip_utils.bip.bip32.bip32_ed25519_slip_base import Bip32Ed25519SlipBaseConst, Bip32Ed25519SlipBase
from bip_utils.ecc import EllipticCurveTypes


class Bip32Ed25519Blake2bSlipConst:
    """Class container for BIP32 ed25519-blake2b constants."""

    # Elliptic curve type
    CURVE_TYPE: EllipticCurveTypes = EllipticCurveTypes.ED25519_BLAKE2B


class Bip32Ed25519Blake2bSlip(Bip32Ed25519SlipBase):
    """
    BIP32 ed25519-blake2b class.
    It allows master key generation and children keys derivation using ed25519-blake2b curve.
    Derivation based on SLIP-0010.
    """

    #
    # Public methods
    #

    @staticmethod
    def CurveType() -> EllipticCurveTypes:
        """
        Return the elliptic curve type.

        Returns:
            EllipticCurveTypes: Curve type
        """
        return Bip32Ed25519Blake2bSlipConst.CURVE_TYPE

    #
    # Protected methods
    #

    @staticmethod
    def _MasterKeyHmacKey() -> bytes:
        """
        Return the HMAC key for generating the master key.

        Returns:
            bytes: HMAC key
        """
        return Bip32Ed25519SlipBaseConst.MASTER_KEY_HMAC_KEY
