import oqs
from qpigeon.server.models import User

enabled_sig_mechanisms = oqs.get_enabled_sig_mechanisms()
enabled_kem_mechanisms = oqs.get_enabled_kem_mechanisms()

known_kem_alg = 'Kyber512'
with oqs.KeyEncapsulation(known_kem_alg) as kem:
    known_kem_public_key = kem.generate_keypair()
    known_kem_secret_key = kem.export_secret_key()

known_username = 'known_username'
known_sig_alg = 'Dilithium2'
with oqs.Signature(known_sig_alg) as signer:
    known_sig_public_key = signer.generate_keypair()
    known_sig_secret_key = signer.export_secret_key()
    
    known_kem_signature = signer.sign(known_kem_public_key)
    
kem_alg = 'Kyber512'
with oqs.KeyEncapsulation(kem_alg) as kem:
    kem_public_key = kem.generate_keypair()
    kem_secret_key = kem.export_secret_key()

sig_alg = 'Dilithium2'
with oqs.Signature(sig_alg) as signer:
    public_key = signer.generate_keypair()
    secret_key = signer.export_secret_key()
    
    kem_signature = signer.sign(kem_public_key)


def setup_test_data(db):
    user = User(username=known_username,
                sig_alg=known_sig_alg,
                sig_key=known_sig_public_key,
                kem_alg=known_kem_alg,
                kem_key=known_kem_public_key,
                kem_signature=known_kem_signature)
    db.session.add(user)
    db.session.commit()