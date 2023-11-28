from functools import wraps
from flask import current_app, request, jsonify, session
from .models import User
import base64
import datetime
from qpigeon.shared.crypto import verify_signature, decrypt_data
from qpigeon.server import db
from qpigeon.server.models import UserNonces


def auth_required(f):
    
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return jsonify(message='Authentication required'), 401
        return f(*args, **kwargs)
    
    return decorated_function


def user_required(f):

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return jsonify(message='Authentication required'), 401
        
        # get user from db
        user = User.query.filter_by(username=session['username']).first()
        if not user:
            return jsonify(message='Authentication required'), 401
        
        # add user to kwargs
        kwargs['user'] = user

        return f(*args, **kwargs)

    return decorated_function


def verify_action(action):
    return request.path == action
    
def verify_timestamp(timestamp):
    time_threshold = current_app.config['TIME_THRESHOLD']
    return datetime.datetime.now(datetime.UTC).timestamp() - timestamp < time_threshold

def verify_nonce(user, nonce):
    return nonce not in user.nonces

def data_verification_required(data_fields: list[tuple[str, type]]=[]):
    def data_verification_required_outer(f):
        @wraps(f)
        def data_verification_required_inner(*args, **kwargs):
            data = request.get_json()
            
            # Input validation
            
            signature = data.get('signature')
            timestamp = data.get('timestamp')
            nonce = data.get('nonce')
            action = data.get('action')

            for field, field_type in data_fields:
                if field not in data or not isinstance(data[field], field_type):
                    return jsonify({"message": f"{field.capitalize()} required"}), 400
            
            if not signature or not isinstance(signature, str):
                return jsonify({"message": "Signature required"}), 400

            try:
                signature = base64.b64decode(signature, validate=True)
            except Exception:
                return jsonify({"message": "Signature must be base64 encoded"}), 400
            
            if not timestamp or (not isinstance(timestamp, int) and not isinstance(timestamp, float)):
                return jsonify({"message": "Timestamp required"}), 400
            
            if not nonce or not isinstance(nonce, str):
                return jsonify({"message": "Nonce required"}), 400
            
            try:
                nonce = base64.b64decode(nonce, validate=True)
            except Exception:
                return jsonify({"message": "Nonce must be base64 encoded"}), 400
            
            if not action or not isinstance(action, str):
                return jsonify({"message": "Action required"}), 400
            
            # Get user
            
            if 'username' not in session:
                return jsonify(message='Authentication required'), 401
            
            # get user from db
            user = User.query.filter_by(username=session['username']).first()
            if not user:
                return jsonify(message='Authentication required'), 401
            
            kwargs['user'] = user
            
            # Get data args for signature
            
            data_args = [data[field] for field, _ in data_fields]                
            
            # Verify action, timestamp, nonce, and signature
            
            if not verify_action(action):
                return jsonify({"message": "Invalid action"}), 400
            
            if not verify_timestamp(timestamp):
                return jsonify({"message": "Invalid timestamp"}), 400
            
            if not verify_nonce(user, nonce):
                return jsonify({"message": "Invalid nonce"}), 400
            
            if not verify_signature(user.sig_alg, user.sig_key, signature, timestamp, nonce, action, *data_args):
                return jsonify({"message": "Invalid signature"}), 400
            
            # Add nonce to user
            
            contact_nonce = UserNonces(user_id=user.id, nonce=nonce)
            db.session.add(contact_nonce)
            db.session.commit()
            
            # Add kwargs
            
            kwargs['user'] = user
            kwargs['signature'] = signature
            kwargs['timestamp'] = timestamp
            kwargs['nonce'] = nonce
            kwargs['action'] = action
            
            for field, _ in data_fields:
                kwargs[field] = data[field]
        
            return f(*args, **kwargs)
        
        return data_verification_required_inner
    return data_verification_required_outer