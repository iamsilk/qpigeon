# various RNGs Python example

import platform  # to learn the OS we're on
import oqs.rand as oqsrand  # must be explicitly imported
from oqs import oqs_version, oqs_python_version

#######################################################################
# randomness example
#######################################################################

print("liboqs version:", oqs_version())
print("liboqs-python version:", oqs_python_version())

# set the entropy seed to some values
entropy_seed = [0] * 48
for i in range(0, 48):
    entropy_seed[i] = i

oqsrand.randombytes_nist_kat_init_256bit(bytes(entropy_seed))
oqsrand.randombytes_switch_algorithm("NIST-KAT")
print('{:17s}'.format("NIST-KAT:"), ' '.join('{:02X}'.format(x) for x in oqsrand.randombytes(32)))

# we do not yet support OpenSSL under Windows
if platform.system() != "Windows":
    oqsrand.randombytes_switch_algorithm("OpenSSL")
    print('{:17s}'.format("OpenSSL:"), ' '.join('{:02X}'.format(x) for x in oqsrand.randombytes(32)))

oqsrand.randombytes_switch_algorithm("system")
print('{:17s}'.format("System (default):"), ' '.join('{:02X}'.format(x) for x in oqsrand.randombytes(32)))
