from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    sig_alg = db.Column(db.String(80), nullable=False)
    sig_key = db.Column(db.LargeBinary, nullable=False)

    contacts = db.relationship(
        'Contact',
        foreign_keys='Contact.user_id',
        backref='user',
        lazy=True
        )
    
    incoming_contacts = db.relationship(
        'Contact',
        foreign_keys='Contact.contact_id',
        backref='contact',
        lazy=True
        )
    
    incoming_contact_requests = db.relationship(
        'ContactRequest',
        foreign_keys='ContactRequest.requestee_id',
        backref='requestee',
        lazy=True
        )

    nonces = db.relationship(
        'UserNonces',
        foreign_keys='UserNonces.user_id',
        backref='user',
        lazy=True
        )

    outgoing_contact_requests = db.relationship(
        'ContactRequest',
        foreign_keys='ContactRequest.requester_id',
        backref='requester',
        lazy=True
        )

class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    contact_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    db.UniqueConstraint('user_id', 'contact_id', name='unique_contact')
    db.Index('contact_user_id_idx', 'user_id')

class ContactRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    requester_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    requestee_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    db.UniqueConstraint('requester_id', 'requestee_id', name='unique_contact_request')
    db.Index('requestee_id_idx', 'requestee_id')

class UserNonces(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    nonce = db.Column(db.LargeBinary, nullable=False)

    db.UniqueConstraint('user_id', 'nonce', name='unique_user_nonce')
    db.Index('user_nonce_idx', 'user_id')
