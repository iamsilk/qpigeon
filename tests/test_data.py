import oqs
from qpigeon.server.models import User

enabled_sig_mechanisms = oqs.get_enabled_sig_mechanisms()

known_username = 'known_username'
known_sig_alg = 'Dilithium2'
with oqs.Signature(known_sig_alg) as signer:
    known_public_key = signer.generate_keypair()
    known_sig_key_secret = signer.export_secret_key()

def setup_test_data(db):
    user = User(username=known_username,
                sig_alg=known_sig_alg,
                sig_key=known_public_key)
    db.session.add(user)
    db.session.commit()