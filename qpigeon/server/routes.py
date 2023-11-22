from flask import Blueprint, request, session, jsonify
from .models import db, User, Contact, ContactRequest, UserNonces
from .auth import auth_required, user_required
import time
import secrets
import base64
import oqs
from .config import Config

api = Blueprint('api', __name__)

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

@api.route('/contact/request/send', methods=['POST'])
@auth_required
@user_required
def contact_request_send(user):
    data = request.get_json()

    ## Input validation

    username = data.get('username')

    timestamp = data.get('timestamp')
    nonce = data.get('nonce')  # check the nonce

    # Check the timestamp is valid
    if time.time() - timestamp > Config.TIME_THRESHOLD:
        return jsonify({"message": "Timeout"}), 400

    # Check if username is present
    if not username or not isinstance(username, str):
        return jsonify({"message": "Username required"}), 400
    
    # Check if user exists
    requestee = User.query.filter_by(username=username).first()
    if not requestee:
        return jsonify({"message": "User not found"}), 400

    # Verify the nonce
    if nonce in UserNonces.query.filter_by(user_id=requestee.id).all():
        return jsonify({"message": "Nonce already exists"}), 400

    contact_nonce = UserNonces(user_id=requestee.id, nonce=base64.b64decode(nonce))
    db.session.add(contact_nonce)

    # Check if contact already exists
    if requestee in user.contacts:
        return jsonify({"message": "Contact already exists"}), 400


    # Check if contact request already exists
    existing_contact_request = ContactRequest.query.filter_by(requester=user, requestee=requestee).first()
    if existing_contact_request:
        # Spoof if the request was previously denied. Sender should
        # not be able to tell the difference between a request that
        # was denied and a request that was ignored.
        # TODO: Delay response to prevent timing attacks
        return jsonify({"message": "Contact request sent"}), 200
    
    # Create contact request
    contact_request = ContactRequest(requester=user, requestee=requestee)
    db.session.add(contact_request)

    try:
        db.session.commit()
        return jsonify({"message": "Contact request sent"}), 200
    except Exception:
        db.session.rollback()
        return jsonify({"message": "Error creating contact request"}), 400

@api.route('/contact/request', methods=['GET'])
@auth_required
@user_required
def contact_request_list(user):
    return jsonify({
        'requests': [{
            'username': request.requester.username,
            'sig_alg': request.requester.sig_alg,
            'sig_key': base64.b64encode(request.requester.sig_key).decode()
        } for request in user.incoming_contact_requests]
    }), 200

@api.route('/contact/request', methods=['POST'])
@auth_required
@user_required
def contact_request_accept(user):
    data = request.get_json()

    ## Input validation
    username = data.get('username')

    # Check if username is present
    if not username or not isinstance(username, str):
        return jsonify({"message": "Username required"}), 400
    
    # Get user
    requester = User.query.filter_by(username=username).first()
    if not requester:
        # TODO: Avoid timing attacks
        return jsonify({"message": "Contact request not found"}), 400
    
    # Check if contact request exists
    contact_request = ContactRequest.query.filter_by(requester=requester, requestee=user).first()

    if not contact_request:
        return jsonify({"message": "Contact request not found"}), 400
    
    # Create contact
    contact = Contact(user=user, contact=requester)
    contact_reverse = Contact(user=requester, contact=user)
    db.session.add(contact)
    db.session.add(contact_reverse)

    # Delete contact request
    db.session.delete(contact_request)

    try:
        db.session.commit()
        return jsonify({"message": "Contact request accepted"}), 200
    except Exception:
        db.session.rollback()
        return jsonify({"message": "Error accepting contact request"}), 400

@api.route('/contact/request', methods=['DELETE'])
@auth_required
@user_required
def contact_request_reject(user):
    data = request.get_json()

    ## Input validation
    username = data.get('username')

    # Check if username is present
    if not username or not isinstance(username, str):
        return jsonify({"message": "Username required"}), 400
    
    # Get user
    requester = User.query.filter_by(username=username).first()
    if not requester:
        # TODO: Avoid timing attacks
        return jsonify({"message": "Contact request not found"}), 400
    
    # Check if contact request exists
    contact_request = ContactRequest.query.filter_by(requester=requester, requestee=user).first()

    if not contact_request:
        return jsonify({"message": "Contact request not found"}), 400
    
    # Delete contact request
    db.session.delete(contact_request)

    try:
        db.session.commit()
        return jsonify({"message": "Contact request rejected"}), 200
    except Exception:
        db.session.rollback()
        return jsonify({"message": "Error rejecting contact request"}), 400

@api.route('/contact', methods=['GET'])
@auth_required
@user_required
def contact_list(user):
    return jsonify({
        'contacts': [{
            'username': contact.contact.username,
            'sig_alg': contact.contact.sig_alg,
            'sig_key': base64.b64encode(contact.contact.sig_key).decode()
        } for contact in user.contacts]
    }), 200

@api.route('/contact', methods=['DELETE'])
@auth_required
@user_required
def contact_remove(user):
    data = request.get_json()

    ## Input validation

    username = data.get('username')

    # Check if username is present
    if not username or not isinstance(username, str):
        return jsonify({"message": "Username required"}), 400
    
    # Get user
    contact_user = User.query.filter_by(username=username).first()
    if not contact_user:
        # TODO: Avoid timing attacks
        return jsonify({"message": "Contact not found"}), 400
    
    # Check if contact exists
    contact = Contact.query.filter_by(user=user, contact=contact_user).first()
    contact_reverse = Contact.query.filter_by(user=contact_user, contact=user).first()
    if not contact and not contact_reverse:
        return jsonify({"message": "Contact not found"}), 400
    
    # Delete contact
    if contact:
        db.session.delete(contact)
    if contact_reverse:
        db.session.delete(contact_reverse)

    try:
        db.session.commit()
        return jsonify({"message": "Contact removed"}), 200
    except Exception:
        db.session.rollback()
        return jsonify({"message": "Error removing contact"}), 400