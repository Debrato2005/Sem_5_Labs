# ============================================================
# DES — COMPLETE CONCEPT SUMMARY
# ============================================================
#
# DES (Data Encryption Standard) is a symmetric block cipher.
# It encrypts a 64-bit plaintext block using an effective
# 56-bit secret key and produces a 64-bit ciphertext.
#
# IMPORTANT IDEA:
# DES's algorithm is NOT secret. An attacker can know:
#   - IP and FP tables
#   - E expansion table
#   - all 8 S-boxes
#   - P permutation
#   - key-schedule tables PC-1 and PC-2
#   - 16 rounds
#   - the entire DES algorithm
#
# Only the SECRET KEY is supposed to be unknown.
# This follows the basic principle that security should depend
# on the key, not on hiding the algorithm.
#
#
# ------------------------------------------------------------
# 1. WHY IS THE DES KEY 56 BITS?
# ------------------------------------------------------------
#
# DES accepts a 64-bit key, but 8 bits are parity bits.
#
#       64-bit supplied key
#       ├── 56 actual key bits
#       └── 8 parity bits
#
# Therefore:
#
#       keyspace = 2^56
#
# There are about 72 quadrillion possible DES keys.
#
# The parity bits do NOT increase the cryptographic keyspace.
#
#
# ------------------------------------------------------------
# 2. KEYSPACE VS ROUNDS
# ------------------------------------------------------------
#
# These are two different concepts.
#
# KEYSPACE:
#   How many possible secret keys exist?
#
#   DES      → 2^56
#   AES-128  → 2^128
#   AES-256  → 2^256
#
# ROUND/CIPHER STRUCTURE:
#   How complicated is the transformation performed by each key?
#
# For BRUTE FORCE, keyspace is the critical factor.
#
# For CRYPTANALYSIS, the internal structure (S-boxes, rounds,
# diffusion, key schedule, etc.) becomes important.
#
#
# ------------------------------------------------------------
# 3. OVERALL DES STRUCTURE
# ------------------------------------------------------------
#
#       64-bit plaintext
#              |
#              v
#       Initial Permutation (IP)
#              |
#              v
#          L0       R0
#              |
#              v
#        16 Feistel rounds
#              |
#              v
#       Final Permutation (FP)
#              |
#              v
#       64-bit ciphertext
#
# The lab manual describes this IP -> 16 rounds -> FP structure.
# :contentReference[oaicite:0]{index=0}
#
#
# ------------------------------------------------------------
# 4. WHAT HAPPENS IN ONE DES ROUND?
# ------------------------------------------------------------
#
#       Li = R(i-1)
#
#       Ri = L(i-1) XOR F(R(i-1), Ki)
#
# F does:
#
#       R (32 bits)
#            |
#            v
#       Expansion E
#            |
#          48 bits
#            |
#         XOR Ki
#            |
#          48 bits
#            |
#         S-boxes
#            |
#          32 bits
#            |
#       P permutation
#            |
#          32 bits
#
# The result of F is XORed with the left half.
#
#
# ------------------------------------------------------------
# 5. WHY EXPANSION E?
# ------------------------------------------------------------
#
# R has 32 bits but the round key has 48 bits.
#
# Therefore:
#
#       32 bits -> 48 bits
#
# E does NOT create new information.
# Some bits are duplicated.
#
# It also makes neighboring groups overlap before entering
# the S-boxes.
#
#
# ------------------------------------------------------------
# 6. WHY XOR WITH THE ROUND KEY?
# ------------------------------------------------------------
#
# This introduces the SECRET KEY into every round.
#
#       Expanded R
#           XOR
#           Ki
#           |
#           v
#        48 bits
#
# The attacker knows the XOR operation but does not know Ki.
#
#
# ------------------------------------------------------------
# 7. WHAT DO THE S-BOXES DO?
# ------------------------------------------------------------
#
# DES has 8 different S-boxes:
#
#       S1 S2 S3 S4 S5 S6 S7 S8
#
# Each performs:
#
#       6 bits -> 4 bits
#
# Therefore:
#
#       8 * 6 = 48 input bits
#       8 * 4 = 32 output bits
#
# So:
#
#       48 bits -> S-boxes -> 32 bits
#
# For a 6-bit input:
#
#       abcdef
#       ^    ^
#       |    |
#       +----+ -> row
#
#       middle 4 bits -> column
#
# The row and column select an entry in the S-box table.
#
#
# ------------------------------------------------------------
# 8. WHAT DOES "NONLINEAR" MEAN?
# ------------------------------------------------------------
#
# NONLINEAR DOES NOT MEAN:
#
#       "There is no mathematical relationship."
#
# It means:
#
#       The relationship cannot be represented as a simple
#       linear function of the input bits.
#
# Example of a simple linear operation:
#
#       y = x XOR K
#
# A DES S-box instead uses a deliberately designed lookup
# mapping:
#
#       input -> output
#
# The mapping is completely known.
#
# So an S-box itself is NOT secret and can be analyzed/reversed
# as a lookup table.
#
# Nonlinear != impossible to solve.
#
# Example:
#
#       x^2 = 25
#
# is nonlinear but easily solved:
#
#       x = +/-5
#
#
# ------------------------------------------------------------
# 9. WHY EIGHT DIFFERENT S-BOXES?
# ------------------------------------------------------------
#
# S1, S2, ..., S8 use different mappings.
#
# They all perform the same type of operation (6 -> 4), but
# their actual mappings are different.
#
# This provides the nonlinear/confusion properties needed by
# the cipher and avoids simply repeating one identical mapping.
#
#
# ------------------------------------------------------------
# 10. WHY THE P PERMUTATION?
# ------------------------------------------------------------
#
# After the S-boxes, there are 32 bits.
#
# P rearranges these bits.
#
# Its important purpose is DIFFUSION.
#
# Without good diffusion, the output of one S-box could remain
# relatively isolated.
#
# With P:
#
#       S-box output
#            |
#            v
#       P permutation
#            |
#            v
#       bits distributed
#            |
#            v
#       next round
#
# Bits originating from one S-box can eventually influence
# different S-boxes in later rounds.
#
#
# ------------------------------------------------------------
# 11. WHY 16 ROUNDS?
# ------------------------------------------------------------
#
# One round does not provide enough mixing.
#
# Repeating the process:
#
#       Round 1
#       Round 2
#       ...
#       Round 16
#
# repeatedly applies:
#
#       key mixing
#       nonlinear substitution
#       diffusion
#
# This produces the avalanche effect:
#
#       small input change
#             |
#             v
#       increasingly many changed bits
#             |
#             v
#       large portion of ciphertext changes
#
# 16 is NOT a magical mathematically required number.
#
# It was a design trade-off between:
#
#       security
#       performance
#       implementation cost
#
# Too few rounds could provide insufficient security margin.
# More rounds would increase computational cost.
#
#
# ------------------------------------------------------------
# 12. WHY FEISTEL?
# ------------------------------------------------------------
#
# DES uses a Feistel structure:
#
#       Li = R(i-1)
#       Ri = L(i-1) XOR F(R(i-1), Ki)
#
# The important property is:
#
#       F does NOT need to be invertible.
#
# This is useful because the S-box transformation:
#
#       6 bits -> 4 bits
#
# is many-to-one and therefore cannot be uniquely inverted.
#
# Nevertheless, the complete Feistel round can be reversed.
#
# Given Li, Ri and Ki:
#
#       R(i-1) = Li
#
#       L(i-1) = Ri XOR F(Li, Ki)
#
# Therefore DES can decrypt even though F/S-boxes themselves
# are not individually invertible.
#
#
# ------------------------------------------------------------
# 13. INITIAL PERMUTATION (IP)
# ------------------------------------------------------------
#
# IP simply rearranges the 64 input bits according to a fixed,
# public table.
#
#       64 bits
#          |
#          v
#          IP
#          |
#          v
#       same 64 bits, different order
#
# IP:
#   - does not increase keyspace
#   - does not introduce nonlinearity
#   - does not hide information
#   - is not secret
#
# It therefore does NOT provide the main cryptographic strength
# of DES.
#
# Historically, IP/FP were largely related to the hardware
# implementation/design of DES.
#
#
# ------------------------------------------------------------
# 14. FINAL PERMUTATION (FP)
# ------------------------------------------------------------
#
# FP is essentially the inverse of IP:
#
#       FP = IP^-1
#
# Therefore:
#
#       plaintext
#          |
#          v
#          IP
#          |
#       16 rounds
#          |
#          v
#          FP
#          |
#          v
#       ciphertext
#
# IP and FP are known fixed permutations.
#
# They do not make brute-force key search harder in any
# meaningful way.
#
#
# ------------------------------------------------------------
# 15. WHICH PARTS ACTUALLY PROVIDE SECURITY?
# ------------------------------------------------------------
#
#       S-boxes
#          -> nonlinear confusion
#
#       XOR with round key
#          -> secret-key dependence
#
#       E + P
#          -> mixing/diffusion
#
#       16 rounds
#          -> repeated mixing and avalanche
#
#       IP + FP
#          -> fixed rearrangement, little cryptographic
#             significance
#
#
# ------------------------------------------------------------
# 16. WHAT IS CRYPTANALYSIS?
# ------------------------------------------------------------
#
# The attacker is assumed to know essentially everything:
#
#       algorithm
#       IP
#       FP
#       E
#       P
#       all S-boxes
#       key schedule
#       number of rounds
#       possibly plaintext/ciphertext pairs
#
# The unknown thing is:
#
#       SECRET KEY
#
# Therefore cryptanalysis is NOT:
#
#       "Figure out the DES algorithm."
#
# It is:
#
#       "Use the known DES structure and observed data to
#        recover the unknown key more efficiently than
#        simply trying every key."
#
#
# ------------------------------------------------------------
# 17. CAN THE KEY BE MATHEMATICALLY RECOVERED?
# ------------------------------------------------------------
#
# YES.
#
# DES can be viewed as:
#
#       C = DES(P, K)
#
# We know P, C and DES.
# We want K.
#
# Therefore:
#
#       DES(P, K) = C
#
# is a mathematical problem involving the unknown key.
#
# The correct key absolutely exists.
#
# There is no rule saying a nonlinear equation cannot be solved.
#
# The problem is COMPUTATIONAL FEASIBILITY.
#
#
# ------------------------------------------------------------
# 18. WHY CAN'T WE JUST REVERSE ALL THE OPERATIONS?
# ------------------------------------------------------------
#
# We CAN reverse DES if we know the key.
#
#       Ciphertext
#            |
#          reverse FP
#            |
#       reverse round 16 using K16
#            |
#       reverse round 15 using K15
#            |
#            ...
#            |
#       reverse round 1 using K1
#            |
#         plaintext
#
# But:
#
#       K1, K2, ..., K16
#
# are generated from the unknown 56-bit master key.
#
# So while reversing round 16, we immediately need K16.
#
# We do not have it.
#
# Thus:
#
#       reversing DES WITH the key = easy
#
#       recovering the key FROM plaintext/ciphertext = hard
#
#
# ------------------------------------------------------------
# 19. BRUTE FORCE
# ------------------------------------------------------------
#
# Brute force simply tries every possible key.
#
# Conceptually:
#
#       for every possible key:
#           decrypt ciphertext
#           check whether plaintext is valid
#
# DES has:
#
#       2^56 possible keys
#
# On average, exhaustive search requires about:
#
#       2^55 attempts
#
# The attacker needs some way to recognize the correct plaintext,
# such as:
#
#       known plaintext
#       recognizable text
#       file format
#       protocol structure
#       checksum/authentication information
#
#
# ------------------------------------------------------------
# 20. WHY DID DES BECOME BROKEN?
# ------------------------------------------------------------
#
# DES's major practical weakness was its 56-bit key.
#
# Computing hardware became powerful enough to search the
# keyspace using specialized hardware.
#
# The famous EFF "Deep Crack" machine demonstrated practical
# exhaustive DES key search in 1998, finding a DES challenge
# key in roughly 56 hours.
#
# Therefore:
#
#       sophisticated 16-round cipher
#                 +
#       only 56-bit key
#                 |
#                 v
#       brute force eventually becomes practical
#
# The important point:
#
# DES was NOT primarily defeated by someone simply "reverse
# engineering the tables."
#
# The keyspace eventually became too small.
#
#
# ------------------------------------------------------------
# 21. BRUTE FORCE VS CRYPTANALYSIS
# ------------------------------------------------------------
#
# BRUTE FORCE:
#
#       Try K1
#       Try K2
#       Try K3
#       ...
#       Try all possible keys
#
# Important factor:
#
#       KEYSPACE
#
#
# CRYPTANALYSIS:
#
#       Analyze DES structure
#             |
#             v
#       find mathematical/statistical properties
#             |
#             v
#       eliminate key candidates
#             |
#             v
#       recover key with less work than exhaustive search
#
# Important factors:
#
#       S-boxes
#       rounds
#       diffusion
#       key schedule
#       statistical properties
#
#
# ------------------------------------------------------------
# 22. DIFFERENTIAL CRYPTANALYSIS
# ------------------------------------------------------------
#
# Differential cryptanalysis studies how differences propagate
# through the cipher.
#
# Take two plaintexts:
#
#       P1
#       P2
#
# Calculate:
#
#       ΔP = P1 XOR P2
#
# Encrypt both:
#
#       P1 -> DES -> C1
#       P2 -> DES -> C2
#
# Then:
#
#       ΔC = C1 XOR C2
#
# Because DES S-boxes have specific differential properties,
# some input/output differences occur with particular
# probabilities.
#
# An attacker can exploit these statistical biases to obtain
# information about portions of the round key.
#
# This is an example of cryptanalysis:
#
#       exploit structure
#       rather than blindly trying every key.
#
#
# ------------------------------------------------------------
# 23. LINEAR CRYPTANALYSIS
# ------------------------------------------------------------
#
# Linear cryptanalysis looks for approximate statistical
# relationships between:
#
#       plaintext bits
#       ciphertext bits
#       key bits
#
# A relationship might occur slightly more or less often than
# the 50% probability expected from a random relationship.
#
# One observation is not useful.
#
# With enough observations, a small statistical bias can reveal
# information about key bits.
#
# Again:
#
#       the attacker already knows the S-boxes.
#
# The attack exploits their mathematical properties.
#
#
# ------------------------------------------------------------
# 24. WHY "EVERYTHING IS KNOWN" IS NOT A PROBLEM
# ------------------------------------------------------------
#
# Cryptography intentionally assumes:
#
#       Algorithm = PUBLIC
#       Key       = SECRET
#
# Therefore:
#
#       knowing DES
#             |
#             v
#       does NOT automatically give K
#
# The real problem is:
#
#       P + C + complete DES
#               |
#               v
#           unknown K
#               |
#               v
#       recover K efficiently
#
#
# ------------------------------------------------------------
# 25. NONLINEARITY VS SOLVABILITY
# ------------------------------------------------------------
#
# A very important correction:
#
#       nonlinear != impossible
#
# Example:
#
#       x^2 = 25
#
# is nonlinear but easy to solve.
#
# Similarly, DES's S-boxes have completely known mathematical
# mappings.
#
# "Nonlinear" only means the mapping isn't a simple linear
# relationship over the relevant binary variables.
#
# DES's difficulty comes from combining:
#
#       56 unknown key bits
#       +
#       nonlinear S-boxes
#       +
#       16 rounds
#       +
#       key schedule
#       +
#       diffusion
#
# into a very complicated key-recovery problem.
#
#
# ------------------------------------------------------------
# 26. MATHEMATICALLY POSSIBLE VS COMPUTATIONALLY FEASIBLE
# ------------------------------------------------------------
#
# This is the central idea of the entire discussion.
#
# The DES key CAN theoretically be found.
#
# But:
#
#       mathematically possible
#               !=
#       computationally practical
#
# Example:
#
# Finding one specific grain of sand is mathematically possible.
# Finding it by checking an astronomically large number of
# candidates is computationally impractical.
#
# Cryptographic security is therefore largely about making
# key recovery computationally infeasible.
#
#
# ============================================================
# FINAL MENTAL MODEL
# ============================================================
#
#                         DES
#                          |
#             +------------+------------+
#             |                         |
#          KEYSPACE                 STRUCTURE
#             |                         |
#          56 bits              S-boxes + rounds
#             |                         |
#           2^56                nonlinear + diffusion
#             |                         |
#             v                         v
#        BRUTE FORCE              CRYPTANALYSIS
#             |                         |
#       try every key             exploit patterns
#             |                         |
#             +------------+------------+
#                          |
#                          v
#                    RECOVER KEY
#
# The most important conclusions:
#
# 1. DES's algorithm and tables are public.
# 2. The 8 DES S-boxes provide the important nonlinear
#    transformation.
# 3. E expands 32 -> 48 so the data can mix with the
#    48-bit round key and creates overlapping groups.
# 4. P spreads S-box outputs to create diffusion across rounds.
# 5. 16 rounds repeatedly apply these transformations to
#    produce strong mixing/avalanche.
# 6. IP and FP are fixed public permutations and are NOT the
#    main source of DES's security.
# 7. Feistel structure makes DES reversible even though the
#    S-box transformation itself is not invertible.
# 8. The DES key is effectively 56 bits, giving 2^56 possible
#    keys.
# 9. Brute force means trying the possible keys.
# 10. Cryptanalysis tries to exploit mathematical/statistical
#     properties of the cipher to do better than brute force.
# 11. Nonlinear does NOT mean "no mathematical relationship"
#     or "cannot be solved."
# 12. DES key recovery is mathematically possible; the issue is
#     whether it can be done efficiently.
# 13. DES eventually became obsolete primarily because its
#     56-bit key became vulnerable to practical exhaustive
#     search.
# ============================================================


IP = [
    58,50,42,34,26,18,10,2, 60,52,44,36,28,20,12,4,
    62,54,46,38,30,22,14,6, 64,56,48,40,32,24,16,8,
    57,49,41,33,25,17,9,1, 59,51,43,35,27,19,11,3,
    61,53,45,37,29,21,13,5, 63,55,47,39,31,23,15,7
]

FP = [
    40,8,48,16,56,24,64,32, 39,7,47,15,55,23,63,31,
    38,6,46,14,54,22,62,30, 37,5,45,13,53,21,61,29,
    36,4,44,12,52,20,60,28, 35,3,43,11,51,19,59,27,
    34,2,42,10,50,18,58,26, 33,1,41,9,49,17,57,25
]

E = [
    32,1,2,3,4,5, 4,5,6,7,8,9,
    8,9,10,11,12,13, 12,13,14,15,16,17,
    16,17,18,19,20,21, 20,21,22,23,24,25,
    24,25,26,27,28,29, 28,29,30,31,32,1
]

P = [
    16,7,20,21,29,12,28,17,
    1,15,23,26,5,18,31,10,
    2,8,24,14,32,27,3,9,
    19,13,30,6,22,11,4,25
]

PC1 = [
    57,49,41,33,25,17,9, 1,58,50,42,34,26,18,
    10,2,59,51,43,35,27, 19,11,3,60,52,44,36,
    63,55,47,39,31,23,15, 7,62,54,46,38,30,22,
    14,6,61,53,45,37,29, 21,13,5,28,20,12,4
]

PC2 = [
    14,17,11,24,1,5, 3,28,15,6,21,10,
    23,19,12,4,26,8, 16,7,27,20,13,2,
    41,52,31,37,47,55, 30,40,51,45,33,48,
    44,49,39,56,34,53, 46,42,50,36,29,32
]

SHIFTS = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]

SBOX = [
[
[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
[0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
[4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],
[15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]],

[
[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],
[3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
[0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],
[13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]],

[
[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],
[13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
[13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],
[1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]],

[
[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],
[13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
[10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],
[3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]],

[
[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],
[14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
[4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],
[11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]],

[
[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],
[10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
[9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],
[4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]],

[
[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],
[13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
[1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],
[6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]],

[
[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],
[1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
[7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],
[2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]
]
]
# DES CONSTANT TABLES
# These tables define the fixed permutations, substitutions, and key-scheduling
# operations used by DES. They are part of the DES specification and remain
# unchanged for every encryption/decryption operation.
#
# IP    : Initial Permutation — rearranges the 64-bit plaintext before rounds.
# FP    : Final Permutation — inverse of IP; rearranges the 64-bit result after
#         the 16 Feistel rounds to produce the 64-bit ciphertext.
# E     : Expansion Permutation — expands the 32-bit right half to 48 bits so
#         it can be XORed with the 48-bit round key.
# P     : Permutation — rearranges the 32 bits produced by the S-boxes.
# PC1   : Permuted Choice 1 — selects 56 bits from the original 64-bit key
#         (8 parity bits are discarded) and splits them into C and D halves.
# PC2   : Permuted Choice 2 — selects 48 bits from the rotated C and D halves
#         to generate each round key.
# SHIFTS: Number of left circular shifts applied to C and D in each of the
#         16 key-schedule rounds.
# SBOX  : Eight 6-to-4-bit substitution boxes. Each S-box converts 6 input
#         bits into 4 output bits, reducing the 48-bit expanded/XORed value
#         back to 32 bits and providing DES's main non-linearity.
#
# Together, these constants implement the fixed parts of DES:
# 64-bit plaintext → IP → 16 Feistel rounds → FP → 64-bit ciphertext.
# The key schedule uses PC1 → left shifts → PC2 to generate 16 × 48-bit keys.


#the table arent 0 indexed they are 1 indexed
def permute(bits,table):
    return "".join(bits[i-1] for i in table)

def xor(a,b):
    return "".join(str(int(x)^int(y)) for x,y in zip(a,b))
#does bit by bit xor btw binary strings x,y are each bits from pairs 
# from zip (a,b)
#a,b are binary strings

#In DES, shifts are used during the key-schedule generation, 
# not directly on the plaintext during the 16 encryption rounds.

#des works on 64 bit input blockd if text longer then 
#its divided into 64 bits blocks

# DES itself does not operate on text or hexadecimal characters. 
# DES operates on bits.
#Text and keys must first be represented as bytes, and 
# bytes are represented as bits.
#each char has an ascii value and to bits therefore each char is 8bits/1byte#ie char->ascii->bis

# DES key schedule:
# The original DES key is 64 bits, including 8 parity bits.
# PC1 removes the 8 parity bits and permutes the remaining 56 bits.
# The 56-bit key is split into two 28-bit halves, C and D.
# C and D are circularly left-shifted according to the DES shift schedule.
# The shifted 56 bits are combined and passed through PC2.
# PC2 selects and permutes 48 bits to produce the round key for each round.
# This process generates 16 different 48-bit round keys, one for each DES round.

def left_shift(bits,n):
    return bits[n:]+bits[:n]

def sbox_substitution(bits): #does 48 bits to 32 bits for it 8sboxes used
    #each box processes 6 bitsthen gives 4 bits
    #REMEMBER BITS IS BINARY STRING
    result=""

    for i in range(8):
        block=bits[i*6:(i+1)*6]
# The first and last bits of the 6-bit block determine the S-box row.
# The middle four bits determine the S-box column.
# These values select one entry from the 4 × 16 S-box table,
# which produces a 4-bit output.
        row=int(block[0]+block[5],2)#,2 means binary compulsory
        col=int(block[1:5],2)

        result+=format(SBOX[i][row][col],"04b") # rememember binary string 
    #therefore gets concatenated
    return result

def generate_keys(key):
    key=permute(key,PC1)#64 to 56
    #PC1 converts the 64-bit DES key to 56 bits by selecting only 
    # the 56 positions listed in the PC1 table.

    c=key[:28] #first 28 bits
    d=key[28:] #last 28 bits

    keys=[]

    for shift in SHIFTS:
        c=left_shift(c,shift)
        d=left_shift(d,shift)

        keys.append(permute(c+d,PC2))#28+28->56->pc2->4bit key
    return keys

def feistel(right,key): #rigth key goes through the feistel
  #8 32bit with 48bit key to give 32 bits output
    expanded=permute(right,E)#32->48
    x=xor(expanded,key)
    x=sbox_substitution(x)
    return permute(x,P)

# DES encryption and decryption use the same Feistel structure.
# The only major difference is the order of the round keys.
#
# Encryption: K1 -> K2 -> ... -> K16
# Decryption: K16 -> K15 -> ... -> K1
#
# This works because DES is a Feistel cipher.
#
# For each round:
# new_left  = right
# new_right = left XOR feistel(right, round_key)
#
# So decryption can use the same DES code by simply reversing
# the 16 generated round keys.
#
# In short:
# DES decryption = DES encryption with round keys reversed.
def des_block(block,key,decrypt=False):
    round_keys=generate_keys(key)
    if decrypt:
        round_keys.reverse()

    block=permute(block,IP)
    l=block[:32]
    r=block[32:]

    for k in round_keys:
        new_l=r
        new_r=xor(l,feistel(r,k))

        l,r=new_l,new_r

    return permute(r+l,FP)

def text_to_bits(text):
    # Convert the text into bytes using UTF-8 encoding.
    # For normal ASCII characters, UTF-8 uses the same byte values as ASCII.
    # Each byte is an integer from 0 to 255 and represents 8 bits.
    #
    # format(byte, "08b") converts each byte value into an 8-bit binary string.
    # "08b" means:
    #   b  → represent the number in binary
    #   8  → use at least 8 positions
    #   0  → add leading zeros if necessary
    #
    # "".join(...) concatenates the 8-bit binary strings of all bytes
    # into one continuous binary string.
    return "".join(format(byte, "08b") for byte in text.encode())

def bits_to_text(bits):
    # Convert the binary string back into its original text.
    #
    # Process the binary string 8 bits at a time because 1 byte = 8 bits.
    # bits[i:i+8] extracts one 8-bit binary block.
    #
    # int(..., 2) converts that binary string into its decimal byte value.
    # The 2 tells Python that the input is a base-2 (binary) number.
    #
    # bytes(...) converts all the resulting integer values into a bytes object.
    data = bytes(
        int(bits[i:i+8], 2)
        for i in range(0, len(bits), 8)
    )
    
    # Decode the bytes back into text using UTF-8.
    return data.decode()

def encrypt(text,key):
    key_bits=text_to_bits(key)
    data=text.encode() #bytes

    pad=8-(len(data)%8) #no. of bytes reqd if exact then also we pad fue to pkcs
    data+=bytes([pad])*pad # we pad it with the pad

    result=b""

    for i in range(0,len(data),8):
        block=data[i:i+8]
        block_bits="".join(format(x,"08b")for x in block)

        encrypted=des_block(block_bits,key_bits)

        result+=bytes(
            int (encrypted[j:j+8],2) for j in range(0,64,8)
        )

    return result.hex().upper()
# Convert the encrypted bytes into a hexadecimal string for safe, readable output.
# Hexadecimal can represent any byte value, unlike text/UTF-8, which may not
# be able to decode arbitrary ciphertext bytes.
# .upper() converts hexadecimal letters (a-f) to uppercase.

def decrypt(ciphertext, key):
    key_bits = text_to_bits(key)

    data = bytes.fromhex(ciphertext)
    result = b''

    for i in range(0, len(data), 8):
        block = data[i:i + 8]
        block_bits = ''.join(format(x, '08b') for x in block)

        decrypted = des_block(block_bits, key_bits, True)

        result += bytes(
            int(decrypted[j:j + 8], 2)
            for j in range(0, 64, 8)
        )

    # Remove padding
    pad = result[-1]#takes the last byte

    if not 1 <= pad <= 8 or result[-pad:] != bytes([pad]) * pad:
        raise ValueError("Invalid padding")

    return result[:-pad].decode()

message=input("enter message:")
key=input("enter the key:")

ciphertext = encrypt(message, key)
plaintext = decrypt(ciphertext, key)

print("Plaintext :", message)
print("Ciphertext:", ciphertext)
print("Decrypted :", plaintext)