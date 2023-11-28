from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    sig_alg = db.Column(db.String(80), nullable=False)
    sig_key = db.Column(db.LargeBinary, nullable=False)
    kem_alg = db.Column(db.String(80), nullable=False)
    kem_key = db.Column(db.LargeBinary, nullable=False)
    kem_signature = db.Column(db.LargeBinary, nullable=False)

    contacts = db.relationship(
        'Contact',
        foreign_keys='Contact.user_id',
        backref='user',
        lazy=True
    )
    
    contact_requests = db.relationship(
        'Contact',
        foreign_keys='Contact.contact_id',
        backref='contact',
        lazy=True
    )

    nonces = db.relationship(
        'UserNonces',
        foreign_keys='UserNonces.user_id',
        backref='user',
        lazy=True
    )
    
    outgoing_messages = db.relationship(
        'Message',
        foreign_keys='Message.sender_id',
        backref='sender',
        lazy=True
    )
    
    incoming_messages = db.relationship(
        'Message',
        foreign_keys='Message.recipient_id',
        backref='recipient',
        lazy=True
    )


class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    contact_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    signed_accept = db.Column(db.JSON, nullable=True)
    signed_request = db.Column(db.JSON, nullable=False)

    db.UniqueConstraint('user_id', 'contact_id', name='unique_contact')
    db.Index('user_id_idx', 'user_id')
    db.Index('contact_id_idx', 'contact_id')


class UserNonces(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    nonce = db.Column(db.LargeBinary, nullable=False)

    db.UniqueConstraint('user_id', 'nonce', name='unique_user_nonce')
    db.Index('user_nonce_idx', 'user_id')


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.Integer, nullable=False)
    signed_message = db.Column(db.JSON, nullable=False)

    db.Index('sender_id_idx', 'sender_id')
    db.Index('recipient_id_idx', 'recipient_id')