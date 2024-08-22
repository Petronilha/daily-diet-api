from database import db
from flask_login import UserMixin

class Diet(db.Model):
  
  id = db.Column(db.Integer, primary_key=True)
  name = db.Column(db.String(80), nullable=False)
  description = db.Column(db.String(120))
  date = db.Column(db.String(120), nullable=False)
  diet = db.Column(db.String(80), nullable=False, default='Esta dentro da dieta')
  
  user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
  user = db.relationship('User', backref=db.backref('meals', lazy=True))
  



class User(db.Model, UserMixin):
  id = db.Column(db.Integer, primary_key=True)
  username = db.Column(db.String(80), nullable=False, unique=True)
  password = db.Column(db.String(80), nullable=False)
  

