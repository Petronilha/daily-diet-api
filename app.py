from flask import Flask, request, jsonify
from models.diet import Diet, User
from database import db
from flask_login import LoginManager, login_user, current_user, login_required, logout_user
import bcrypt

app = Flask(__name__)
app.config['SECRET_KEY'] = "your_secret_key"
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:admin123@127.0.0.1:3306/daily-diet'

login_manager = LoginManager()
db.init_app(app)
login_manager.init_app(app)

login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
  return User.query.get(user_id)

# Login system
@app.route('/login', methods=['POST'])
def login():
  data = request.json
  username = data.get("username")
  password = data.get("password")
  
  if username and password:
    user = User.query.filter_by(username=username).first()
    
    if user and bcrypt.checkpw(str.encode(password), str.encode(user.password)):
      login_user(user)
      print(current_user.is_authenticated)
      return jsonify({"message": "Autenticacao realizada com sucesso"})
  
  return jsonify({"message": "Credenciais invalidas"}), 400

# Logout System
@app.route('/logout', methods=['GET'])
@login_required
def logout():
  logout_user()
  return jsonify({"message": "Logout realizado com sucesso"})

# Create User
@app.route('/user', methods=['POST'])
@login_required
def create_user():
  data = request.json
  username = data.get('username')
  password = data.get('password')
  
  if username and password:
    hashed_passwd = bcrypt.hashpw(str.encode(password), bcrypt.gensalt())
    user = User(username=username, password=hashed_passwd)
    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "Usuario cadastrado com sucesso"})
  
  return jsonify({"message": "Dados invalidos"}), 400

# Delete user 
@app.route('/user/<int:user_id>', methods=['DELETE'])
@login_required
def delete_user(user_id):
  user = User.query.get(user_id)
  
  if user:
    db.session.delete(user)
    db.session.commit()
    
    return jsonify({"message": f"Usuario {user_id} deletado com sucesso"})
  
  return jsonify({"message": "Usuario nao encontrado"})

# Create meals 
@app.route('/meal', methods=['POST'])
@login_required
def create_diet():
  data = request.json
  print(current_user.id)
  user = User.query.get(current_user.id)
  name = data.get('name')
  description = data.get('description')
  date = data.get('date')
  diet = data.get('diet')

  if name and date and diet:
    diet = Diet(name=name, description=description, date=date, diet=diet, user=user)
    db.session.add(diet)
    db.session.commit()
    return jsonify({"message": "Cadastro de refeicao efetuado"})

  return jsonify({"message": "Cadastro nao efetuado"})

# Get all meals
@app.route('/meal', methods=['GET'])
@login_required
def get_meals():
  meal = Diet.query.filter_by(user_id=current_user.id).all()
  banco = []
  for i in range(len(meal)):
    output = {
      "name": meal[i].name,
      "description": meal[i].description,
      "date": meal[i].date,
      "diet": meal[i].diet
    }
    banco.append(output)
  return banco

# Get meals by ID
@app.route('/meal/<int:id>', methods=['GET'])
@login_required
def get_meal(id):
  get_by_user = Diet.query.filter_by(user_id=current_user.id).all()
  try:
    meal = get_by_user[id - 1]

    if meal:
      output = {
        "name": meal.name,
        "description": meal.description,
        "date": meal.date,
        "diet": meal.diet
      }
      return output
    
    return jsonify({"message": "Refeicao nao encontrada"}), 404
  except:
    return jsonify({"message": "Refeicao nao encontrada"}), 404
    

# Update meal by ID
@app.route('/meal/<int:id>', methods=['PUT'])
@login_required
def update_meal(id):
  get_by_user = Diet.query.filter_by(user_id=current_user.id).all()
  data = request.json
  try:
    meal = get_by_user[id - 1]
    
    if meal and data:
      meal.name = data.get("name")
      meal.description = data.get("description")
      meal.date = data.get("date")
      meal.diet = data.get("diet")
      db.session.commit()
      
      return jsonify({"message": f"Refeicao {id} atualizada com sucesso"})

    return jsonify({"message": "Refeicao nao encontrada"}), 404
  except:
    return jsonify({"message": "Refeicao nao encontrada"}), 404
    

# Delete meal by ID
@app.route('/meal/<int:id>', methods=['DELETE'])
@login_required
def delete_meal(id):
  get_by_user = Diet.query.filter_by(user_id=current_user.id).all()
  try:
    meal = get_by_user[id - 1]

    if meal:
      db.session.delete(meal)
      db.session.commit()

      return jsonify({"message": f"Refeicao {id} deletado com sucesso"})

    return jsonify({"message": "Refeicao nao encontrada"}), 404
  except:
    return jsonify({"message": "Refeicao nao encontrada"}), 404



if __name__ == '__main__':
  app.run(debug=True)