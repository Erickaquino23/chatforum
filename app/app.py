from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'sua_chave_secreta'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///usuarios.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Inicialização do banco de dados e do SocketIO
db = SQLAlchemy(app)
socketio = SocketIO(app)

# Modelo para a tabela de usuários
class Usuario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)

# Modelo para a tabela de mensagens
class Mensagem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), db.ForeignKey('usuario.username'), nullable=False)
    conteudo = db.Column(db.String(500), nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp(), nullable=False)

with app.app_context():
    db.create_all()

@app.route('/')
def home():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    usuario = Usuario.query.filter_by(username=username).first()
    if usuario and check_password_hash(usuario.password_hash, password):
        session['username'] = username
        return redirect(url_for('chat'))
    else:
        flash('Usuário ou senha incorretos. Tente novamente.', 'error')
        return redirect(url_for('home'))

@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('As senhas não coincidem. Tente novamente.', 'error')
            return redirect(url_for('cadastro'))

        if Usuario.query.filter_by(username=username).first():
            flash('Nome de usuário já existe. Escolha outro.', 'error')
            return redirect(url_for('cadastro'))

        password_hash = generate_password_hash(password)
        novo_usuario = Usuario(username=username, password_hash=password_hash)

        db.session.add(novo_usuario)
        db.session.commit()

        flash('Cadastro realizado com sucesso! Faça login para continuar.', 'success')
        return redirect(url_for('home'))

    return render_template('cadastro.html')

@app.route('/chat')
def chat():
    if 'username' not in session:
        return redirect(url_for('home'))

    mensagens = Mensagem.query.order_by(Mensagem.timestamp.asc()).all()
    return render_template('chat.html', username=session['username'], mensagens=mensagens)

@socketio.on('send_message')
def handle_send_message(data):
    conteudo = data['conteudo']
    username = session.get('username')

    if username:
        nova_mensagem = Mensagem(username=username, conteudo=conteudo)
        db.session.add(nova_mensagem)
        db.session.commit()

        emit('receive_message', {
            'username': username,
            'conteudo': conteudo,
            'id': nova_mensagem.id
        }, broadcast=True)

@socketio.on('delete_message')
def handle_delete_message(data):
    mensagem = Mensagem.query.get(data['id'])
    if mensagem:
        db.session.delete(mensagem)
        db.session.commit()

        # Emite um evento para todos os clientes notificando a exclusão
        emit('delete_message', data['id'], broadcast=True)

if __name__ == '__main__':
    socketio.run(app, debug=True)
