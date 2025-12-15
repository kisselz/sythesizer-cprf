"""
This file serves as a reference implementation for the
synthesizer-based CPRF from the paper: 

"Constrained Pseudorandom Functions from Pseudorandom Synthesizers"

Copyright (C) 2025  Zachary A Kissel

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program; if not, see <https://www.gnu.org/licenses/>.
"""
from Crypto.Hash import CMAC
from Crypto.Cipher import AES
import secrets

def cmacPRF(key, val):
    """
    gnerate a PRF value using the AES-CMAC PRF.
    
    :param key: the key for the PRF
    :param val: the value for the CPRF.
    """
    f = CMAC.new(key, ciphermod = AES)
    f.update(val)
    return f.digest()

def keyGen():
    """
    Generate a new master key for the CPRF. The run time is O(n) where 
    n is the number of bits in the input size.
    """

    # Generate the random key each location holds a random 16 byte number.
    keyMat = [[secrets.token_bytes(16) for _ in range(128)] for _ in range(2)]
    return (cmacPRF, keyMat)

def eval(key, val):
    """
    Evaluate the CPRF on val using key. The run time is O(lg n) where 
    n is the number bits in val. The number of PRF evaluations is O(n).
    
    :param key: the key for the CPRF
    :param val: the value (bitstring) to evaluate.
    """
    binrep =  list(''.join(f'{byte:08b}' for byte in val))
    leaves = []
    (prf, keyMat) = key     # unpack the key.
    
    # Build the leaves of the synthesizer.
    for i in range(0, len(binrep), 2):
        leaves.append(prf(
            keyMat[int(binrep[i])][i], 
            keyMat[int(binrep[i + 1])][i+1]))
    
    # Determine the root of the tree.
    while len(leaves) > 1:
        tmp = []
        for i in range(0, len(leaves), 2):
            tmp.append(prf(leaves[i], leaves[i+1]))
        leaves = tmp

    return leaves[0]

def constrain(msk, pattern):
    """
    Given master key msk and the bit-fixing pattern 
    produce the corresponding constrained key. he run time is 
    O(n) where n is the number of bits in the value.
    
    :param msk: the master key
    :param pattern: the bit fixing pattern as a string over alphabet
                    {0, 1, *}.
    """
    (prf, keyMat) = msk
    
    # Make a copy of the key matrix. 
    newKey = [[keyMat[row][col] for col in range(128)] for row in range(2)]

    # fill out the key matrix
    for i in range(len(pattern)):
        if pattern[i] == '1':
            newKey[0][i] = secrets.token_bytes(16)
        elif pattern[i] == '0':
            newKey[1][i] = secrets.token_bytes(16)

    return (prf, newKey)