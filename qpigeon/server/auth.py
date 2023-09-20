# auth.py (create a new file)
from functools import wraps
from flask import request, jsonify, session
from .models import db, User

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