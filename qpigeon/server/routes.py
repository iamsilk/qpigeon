from flask import Blueprint, current_app, request, session, jsonify
from .models import db, User, Contact
from .auth import data_verification_required
import secrets
import base64
import oqs

api = Blueprint('api', __name__)


@api.route('/server/key', methods=['GET'])
def server_key():
    return jsonify({
        'sig_alg': current_app.config['SERVER_SIG_ALG'],
        'sig_public_key': current_app.config['SERVER_SIG_PUBLIC_KEY'],
        'kem_alg': current_app.config['SERVER_KEM_ALG'],
        'kem_public_key': current_app.config['SERVER_KEM_PUBLIC_KEY'],
        'kem_signature': current_app.config['SERVER_KEM_SIGNATURE']
    }), 200


@api.route('/register/challenge', methods=['POST'])
def register_challenge():
    data = request.get_json()

    ## Input validation

    username = data.get('username')
    sig_alg = data.get('sig_alg')
    sig_key = data.get('sig_key')

    # Check if username, sig_alg, and sig_key are present

    if not username or not isinstance(username, str):
        return jsonify({"message": "Username required"}), 400
    if not sig_alg or not isinstance(sig_alg, str):
        return jsonify({"message": "Signature algorithm required"}), 400
    if not sig_key or not isinstance(sig_key, str):
        return jsonify({"message": "Signature key required"}), 400

    # Check if signature is base64 encoded

    try:
        sig_key = base64.b64decode(sig_key, validate=True)
    except Exception:
        return jsonify({"message": "Signature key must be base64 encoded"}), 400

    # Check if signature algorithm is enabled

    if sig_alg not in oqs.get_enabled_sig_mechanisms():
        return jsonify({"message": "Signature algorithm not enabled"}), 400
    
    # Check if username is length

    min_username_len = 4
    max_username_len = 64

    if len(username) < min_username_len or len(username) > max_username_len:
        return jsonify({"message": f"Username must be between {min_username_len} and {max_username_len} characters"}), 400

    # Generate challenge

    challenge = secrets.token_bytes(256)

    # Save registration details to session

    session['register_username'] = username
    session['register_sig_alg'] = sig_alg
    session['register_sig_key'] = sig_key
    session['register_challenge'] = challenge

    # Return challenge

    return jsonify({
        'challenge': base64.b64encode(challenge).decode()
    }), 200

@api.route('/register/submit', methods=['POST'])
def register_submit():
    data = request.get_json()

    # Get registration details from session

    username = session.pop('register_username', None)
    sig_alg = session.pop('register_sig_alg', None)
    sig_key = session.pop('register_sig_key', None)
    challenge = session.pop('register_challenge', None)

    # Check if challenge was requested

    if not username or not sig_alg or not sig_key or not challenge:
        return jsonify({"message": "No challenge requested"}), 400
    
    # Get signed challenge

    challenge_signed = data.get('challenge_signed')

    if not challenge_signed or not isinstance(challenge_signed, str):
        return jsonify({"message": "Signed challenge required"}), 400
    
    # Check if signed challenge is base64 encoded

    try:
        challenge_signed = base64.b64decode(challenge_signed, validate=True)
    except Exception:
        return jsonify({"message": "Signed challenge must be base64 encoded"}), 400
    
    # Verify signed challenge

    with oqs.Signature(sig_alg) as signer:
        if not signer.verify(challenge, challenge_signed, sig_key):
            return jsonify({"message": "Invalid signature"}), 400

    # Create user

    user = User(username=username, sig_alg=sig_alg, sig_key=sig_key)
    db.session.add(user)

    try:
        db.session.commit()
        return jsonify({"message": "Registration successful"}), 201
    except Exception as e:
        db.session.rollback()

        if 'UNIQUE constraint failed: user.username' in str(e):
            return jsonify({"message": "Username already taken"}), 400
        return jsonify({"message": "Error creating user"}), 400



@api.route('/login/challenge', methods=['POST'])
def login_challenge():
    data = request.get_json()

    ## Input validation

    username = data.get('username')

    # Check if username is present

    if not username or not isinstance(username, str):
        return jsonify({"message": "Username required"}), 400
    
    # Save login details to session, generate challenge

    session['challenge_username'] = data['username']
    session['challenge_bytes'] = secrets.token_bytes(256)

    # Return challenge

    return jsonify({
        'challenge': base64.b64encode(session['challenge_bytes']).decode()
    })
    
@api.route('/login/submit', methods=['POST'])
def login_submit():
    data = request.get_json()

    # Get login details from session

    username = session.pop('challenge_username', None)
    challenge = session.pop('challenge_bytes', None)

    # Check if challenge was requested

    if not username or not challenge:
        return jsonify({"message": "No challenge"}), 400
    
    # Get signed challenge

    challenge_signed = data.get('challenge_signed')

    if not challenge_signed or not isinstance(challenge_signed, str):
        return jsonify({"message": "Signed challenge required"}), 400
    
    # Check if signed challenge is base64 encoded

    try:
        challenge_signed = base64.b64decode(challenge_signed, validate=True)
    except Exception:
        return jsonify({"message": "Signed challenge must be base64 encoded"}), 400
    
    # Check if user exists
    
    user = User.query.filter_by(username=username).first()

    if not user: # TODO: Delay response to prevent timing attacks
        return jsonify({"message": "Invalid username or signature"}), 400
    
    # Verify signed challenge

    with oqs.Signature(user.sig_alg) as signer:
        if not signer.verify(challenge, challenge_signed, user.sig_key):
            return jsonify({"message": "Invalid username or signature"}), 400
    
    # Get signed challenge

    session['username'] = username

    return jsonify({"message": "Login successful"}), 200

@api.route('/contact/add', methods=['POST'])
@data_verification_required([
    ('username', str)
])
def contact_add(user, signature, timestamp, nonce, action, username):
    # Check if user exists
    other_user = User.query.filter_by(username=username).first()
    if not other_user:
        return jsonify({"message": "User not found"}), 400
    
    outgoing_contact = Contact.query.filter_by(user=user, contact=other_user).first()
    incoming_contact = Contact.query.filter_by(user=other_user, contact=user).first()

    # Check if contact already established
    if outgoing_contact and incoming_contact:
        return jsonify({"message": "Contact already established"}), 400
    
    signed_request = {
        'signature': base64.b64encode(signature).decode(),
        'timestamp': timestamp,
        'nonce': base64.b64encode(nonce).decode(),
        'action': action,
        'username': username
    }
    
    try:
        # If no contact request exists at all, create a new one
        if not outgoing_contact and not incoming_contact:
            contact_request = Contact(user=user, contact=other_user, signed_request=signed_request)
            db.session.add(contact_request)
            db.session.commit()
            
            return jsonify({"message": "Contact request sent"}), 200
        
        # If outgoing contact request exists, update it
        if outgoing_contact:
            outgoing_contact.signed_request = signed_request
            db.session.commit()
            
            return jsonify({"message": "Contact request sent"}), 200
        
        # Only option left:
        # If incoming contact request exists, accept it
        incoming_contact.signed_accept = signed_request
        outgoing_contact = Contact(
            user=user,
            contact=other_user,
            signed_request=signed_request,
            signed_accept=incoming_contact.signed_request
        )
        db.session.add(outgoing_contact)
        db.session.commit()
        
        return jsonify({"message": "Contact request accepted"}), 200
    except Exception:
        db.session.rollback()
        return jsonify({"message": "Error sending contact request"}), 400


@api.route('/contact/remove', methods=['POST'])
@data_verification_required([
    ('username', str)
])
def contact_remove(user, signature, timestamp, nonce, action, username):
    # Get user
    other_user = User.query.filter_by(username=username).first()
    if not other_user:
        # TODO: Avoid timing attacks
        return jsonify({"message": "Contact request not found"}), 400
    
    # Check if contact request exists    
    outgoing_contact = Contact.query.filter_by(user=user, contact=other_user).first()
    incoming_contact = Contact.query.filter_by(user=other_user, contact=user).first()
    
    # If no contacts exist either way, say the request was revoked
    if not outgoing_contact and not incoming_contact:
        # Tell the user that the contact request was cancelled, even if it didn't exist
        # This avoids the user being able to tell if their request was rejected or ignored
        # TODO: Avoid timing attacks
        return jsonify({"message": "Contact request cancelled"}), 200
    
    try:
        # If only outgoing contact exists, cancel the request
        if outgoing_contact and not incoming_contact:
            db.session.delete(outgoing_contact)
            db.session.commit()
            
            return jsonify({"message": "Contact request cancelled"}), 200
        
        # If only incoming contact exists, reject the request
        if incoming_contact and not outgoing_contact:
            db.session.delete(incoming_contact)
            db.session.commit()
            
            return jsonify({"message": "Contact request rejected"}), 200
        
        # Last option:
        # If both contacts exist, remove them
        db.session.delete(outgoing_contact)
        db.session.delete(incoming_contact)
        db.session.commit()
        
        return jsonify({"message": "Contact removed"}), 200
    except Exception:
        db.session.rollback()
        return jsonify({"message": "Error rejecting contact request"}), 400

@api.route('/contact/requests', methods=['GET'])
@data_verification_required()
def contact_request_list(user, signature, timestamp, nonce, action):
    return jsonify({
        'requests': [{
            'username': request.user.username,
            'sig_alg': request.user.sig_alg,
            'sig_key': base64.b64encode(request.user.sig_key).decode(),
            'signed_request': request.signed_request
        } for request in user.contact_requests if request.signed_accept is None]
    }), 200

@api.route('/contact/list', methods=['GET'])
@data_verification_required()
def contact_list(user, signature, timestamp, nonce, action):
    return jsonify({
        'contacts': [{
            'username': contact.contact.username,
            'sig_alg': contact.contact.sig_alg,
            'sig_key': base64.b64encode(contact.contact.sig_key).decode(),
            'signed_accept': contact.signed_accept
        } for contact in user.contacts if contact.signed_accept is not None]
    }), 200