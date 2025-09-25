from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
from datetime import datetime

# Initialisierung der Flask-App
app = Flask(__name__)
app.config['SECRET_KEY'] = 'technikag-lager-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///inventory.db'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max-limit

# Stellen Sie sicher, dass der Upload-Ordner existiert
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialisierung der Datenbank
db = SQLAlchemy(app)

# Initialisierung des Login-Managers
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Modelle
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_number = db.Column(db.String(50), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    shelf = db.Column(db.String(50))
    position = db.Column(db.String(50))
    box = db.Column(db.String(50))
    status = db.Column(db.String(20), default='available')  # available, borrowed
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class ItemLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, db.ForeignKey('item.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(50), nullable=False)  # borrowed, returned, edited
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    notes = db.Column(db.Text)
    
    item = db.relationship('Item', backref=db.backref('logs', lazy=True))
    user = db.relationship('User', backref=db.backref('logs', lazy=True))

class Settings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    logo_path = db.Column(db.String(255))
    company_name = db.Column(db.String(100), default='Technik AG')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routen
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    settings = Settings.query.first()
    return render_template('loading.html', settings=settings)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Ungültiger Benutzername oder Passwort', 'danger')
    
    settings = Settings.query.first()
    return render_template('login.html', settings=settings)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    items_count = Item.query.count()
    borrowed_count = Item.query.filter_by(status='borrowed').count()
    settings = Settings.query.first()
    return render_template('dashboard.html', items_count=items_count, borrowed_count=borrowed_count, settings=settings)

@app.route('/items')
@login_required
def items():
    search = request.args.get('search', '')
    status_filter = request.args.get('status', '')
    
    query = Item.query
    
    if search:
        query = query.filter(
            (Item.item_number.contains(search)) |
            (Item.name.contains(search)) |
            (Item.description.contains(search)) |
            (Item.shelf.contains(search)) |
            (Item.position.contains(search)) |
            (Item.box.contains(search))
        )
    
    if status_filter:
        query = query.filter_by(status=status_filter)
    
    items = query.order_by(Item.item_number).all()
    settings = Settings.query.first()
    return render_template('items.html', items=items, search=search, status_filter=status_filter, settings=settings)

@app.route('/items/add', methods=['GET', 'POST'])
@login_required
def add_item():
    if request.method == 'POST':
        item_number = request.form.get('item_number')
        name = request.form.get('name')
        description = request.form.get('description')
        shelf = request.form.get('shelf')
        position = request.form.get('position')
        box = request.form.get('box')
        
        # Überprüfen, ob die Artikelnummer bereits existiert
        existing_item = Item.query.filter_by(item_number=item_number).first()
        if existing_item:
            flash('Diese Artikelnummer existiert bereits', 'danger')
            return redirect(url_for('add_item'))
        
        new_item = Item(
            item_number=item_number,
            name=name,
            description=description,
            shelf=shelf,
            position=position,
            box=box,
            status='available'
        )
        
        db.session.add(new_item)
        db.session.commit()
        
        # Protokollieren der Aktion
        log_entry = ItemLog(
            item_id=new_item.id,
            user_id=current_user.id,
            action='created',
            notes=f'Artikel erstellt: {name}'
        )
        db.session.add(log_entry)
        db.session.commit()
        
        flash('Artikel erfolgreich hinzugefügt', 'success')
        return redirect(url_for('items'))
    
    settings = Settings.query.first()
    return render_template('add_item.html', settings=settings)

@app.route('/items/<int:item_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_item(item_id):
    item = Item.query.get_or_404(item_id)
    
    if request.method == 'POST':
        item.item_number = request.form.get('item_number')
        item.name = request.form.get('name')
        item.description = request.form.get('description')
        item.shelf = request.form.get('shelf')
        item.position = request.form.get('position')
        item.box = request.form.get('box')
        
        db.session.commit()
        
        # Protokollieren der Aktion
        log_entry = ItemLog(
            item_id=item.id,
            user_id=current_user.id,
            action='edited',
            notes=f'Artikel bearbeitet: {item.name}'
        )
        db.session.add(log_entry)
        db.session.commit()
        
        flash('Artikel erfolgreich aktualisiert', 'success')
        return redirect(url_for('items'))
    
    settings = Settings.query.first()
    return render_template('edit_item.html', item=item, settings=settings)

@app.route('/items/<int:item_id>/borrow', methods=['POST'])
@login_required
def borrow_item(item_id):
    item = Item.query.get_or_404(item_id)
    
    if item.status == 'borrowed':
        flash('Dieser Artikel ist bereits entliehen', 'danger')
    else:
        item.status = 'borrowed'
        db.session.commit()
        
        # Protokollieren der Aktion
        log_entry = ItemLog(
            item_id=item.id,
            user_id=current_user.id,
            action='borrowed',
            notes=request.form.get('notes', '')
        )
        db.session.add(log_entry)
        db.session.commit()
        
        flash('Artikel als entliehen markiert', 'success')
    
    return redirect(url_for('items'))

@app.route('/items/<int:item_id>/return', methods=['POST'])
@login_required
def return_item(item_id):
    item = Item.query.get_or_404(item_id)
    
    if item.status == 'available':
        flash('Dieser Artikel ist bereits verfügbar', 'danger')
    else:
        item.status = 'available'
        db.session.commit()
        
        # Protokollieren der Aktion
        log_entry = ItemLog(
            item_id=item.id,
            user_id=current_user.id,
            action='returned',
            notes=request.form.get('notes', '')
        )
        db.session.add(log_entry)
        db.session.commit()
        
        flash('Artikel als zurückgegeben markiert', 'success')
    
    return redirect(url_for('items'))

@app.route('/items/<int:item_id>/logs')
@login_required
def item_logs(item_id):
    item = Item.query.get_or_404(item_id)
    logs = ItemLog.query.filter_by(item_id=item_id).order_by(ItemLog.timestamp.desc()).all()
    settings = Settings.query.first()
    return render_template('item_logs.html', item=item, logs=logs, settings=settings)

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings_page():
    # Überprüfen, ob der Benutzer ein Administrator ist
    if not current_user.is_admin:
        flash('Sie haben keine Berechtigung für diese Seite', 'danger')
        return redirect(url_for('dashboard'))
    
    settings = Settings.query.first()
    if not settings:
        settings = Settings()
        db.session.add(settings)
        db.session.commit()
    
    if request.method == 'POST':
        company_name = request.form.get('company_name')
        
        if company_name:
            settings.company_name = company_name
        
        # Logo-Upload
        if 'logo' in request.files:
            logo_file = request.files['logo']
            if logo_file.filename != '':
                filename = secure_filename(logo_file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                logo_file.save(file_path)
                settings.logo_path = os.path.join('uploads', filename)
        
        db.session.commit()
        flash('Einstellungen gespeichert', 'success')
        return redirect(url_for('settings_page'))
    
    return render_template('settings.html', settings=settings)

@app.route('/users')
@login_required
def users():
    if not current_user.is_admin:
        flash('Sie haben keine Berechtigung für diese Seite', 'danger')
        return redirect(url_for('dashboard'))
    
    users_list = User.query.all()
    settings = Settings.query.first()
    return render_template('users.html', users=users_list, settings=settings)

@app.route('/users/add', methods=['GET', 'POST'])
@login_required
def add_user():
    if not current_user.is_admin:
        flash('Sie haben keine Berechtigung für diese Seite', 'danger')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        is_admin = 'is_admin' in request.form
        
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Dieser Benutzername existiert bereits', 'danger')
            return redirect(url_for('add_user'))
        
        new_user = User(username=username, is_admin=is_admin)
        new_user.set_password(password)
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Benutzer erfolgreich hinzugefügt', 'success')
        return redirect(url_for('users'))
    
    settings = Settings.query.first()
    return render_template('add_user.html', settings=settings)

@app.route('/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if not current_user.is_admin:
        flash('Sie haben keine Berechtigung für diese Seite', 'danger')
        return redirect(url_for('dashboard'))
    
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        is_admin = 'is_admin' in request.form
        
        # Überprüfen, ob der Benutzername bereits existiert (außer für den aktuellen Benutzer)
        existing_user = User.query.filter(User.username == username, User.id != user_id).first()
        if existing_user:
            flash('Dieser Benutzername existiert bereits', 'danger')
            return redirect(url_for('edit_user', user_id=user_id))
        
        user.username = username
        user.is_admin = is_admin
        
        if password:
            user.set_password(password)
        
        db.session.commit()
        
        flash('Benutzer erfolgreich aktualisiert', 'success')
        return redirect(url_for('users'))
    
    settings = Settings.query.first()
    return render_template('edit_user.html', user=user, settings=settings)

# Initialisierung der Datenbank und Erstellung eines Admin-Benutzers
# Initialisierung der Datenbank und Erstellung eines Admin-Benutzers
def create_tables_and_admin():
    with app.app_context():
        db.create_all()
        
        # Erstellen eines Admin-Benutzers, falls keiner existiert
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(username='admin', is_admin=True)
            admin.set_password('admin')
            db.session.add(admin)
            db.session.commit()
        
        # Erstellen der Einstellungen, falls keine existieren
        settings = Settings.query.first()
        if not settings:
            settings = Settings()
            db.session.add(settings)
            db.session.commit()

# Führe die Initialisierung aus
create_tables_and_admin()

if __name__ == '__main__':
    app.run(debug=True, port=5001)