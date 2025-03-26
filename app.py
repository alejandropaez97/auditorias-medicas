from flask import Flask, request, render_template, redirect, flash, send_from_directory, Response
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Email, Length
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from openpyxl import Workbook
from io import BytesIO
import os

app = Flask(__name__)

# Configuración desde variables de entorno
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'x7k9p!m2q$z')  # Valor por defecto para desarrollo
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///auditorias.db')  # PostgreSQL en producción
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PDF_FOLDER'] = os.getenv('PDF_FOLDER', '/tmp/pdfs')  # Carpeta para PDFs en Render

db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Modelos
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(20), default='user')

class Auditoria(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    paciente = db.Column(db.String(150), nullable=False)
    cedula = db.Column(db.String(20), nullable=False)
    compania_paciente = db.Column(db.String(150), nullable=False)
    examenes = db.Column(db.String(500), nullable=False)
    centro_medico = db.Column(db.String(150), nullable=False)
    resultado = db.Column(db.String(500), nullable=False)
    usuario_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    pdf_path = db.Column(db.String(500))

# Formularios
class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Contraseña', validators=[DataRequired(), Length(min=6)])
    submit = SubmitField('Registrar')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Contraseña', validators=[DataRequired()])
    submit = SubmitField('Iniciar Sesión')

class SolicitudForm(FlaskForm):
    paciente = StringField('Nombre del Paciente', validators=[DataRequired()])
    cedula = StringField('Cédula', validators=[DataRequired(), Length(min=6, max=20)])
    compania = StringField('Compañía del Paciente', validators=[DataRequired()])
    examenes = TextAreaField('Exámenes (separados por comas)', validators=[DataRequired()])
    centro_medico = StringField('Centro Médico', validators=[DataRequired()])
    submit = SubmitField('Enviar Solicitud')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def auditar_solicitud(compania_paciente, examenes):
    examenes_lista = [e.strip().lower() for e in examenes.split(',')]
    resultados = []
    reglas = {
        "Empresa XYZ": {"rayos x": True, "resonancia": False},
        "Compañía ABC": {"rayos x": False, "resonancia": True}
    }
    
    if compania_paciente not in reglas:
        return f"Denegado: Compañía del paciente no reconocida por PRIMEPRE S.A."
    
    for examen in examenes_lista:
        if examen in reglas[compania_paciente]:
            if reglas[compania_paciente][examen]:
                resultados.append(f"Aprobado: {examen.capitalize()} cubierto por PRIMEPRE S.A. para un cliente de {compania_paciente}")
            else:
                resultados.append(f"Denegado: {examen.capitalize()} no cubierto por PRIMEPRE S.A. para un cliente de {compania_paciente}")
        else:
            resultados.append(f"Denegado: {examen.capitalize()} no reconocido por PRIMEPRE S.A. para un cliente de {compania_paciente}")
    
    return "\n".join(resultados)

def generar_pdf(auditoria):
    pdf_folder = app.config['PDF_FOLDER']
    if not os.path.exists(pdf_folder):
        os.makedirs(pdf_folder, exist_ok=True)
    pdf_path = os.path.join(pdf_folder, f"autorizacion_{auditoria.id}.pdf")
    c = canvas.Canvas(pdf_path, pagesize=letter)
    lineas = auditoria.resultado.split('\n')
    y = 750
    for linea in lineas:
        if y < 50:
            c.showPage()
            y = 750
        c.drawString(50, y, linea)
        y -= 15
    c.save()
    return pdf_path

# Rutas
@app.route('/')
def home():
    return redirect('/login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        email = form.email.data
        password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        role = 'admin' if email == 'direccioncomercial@privilegio.med.ec' else 'user'
        user = User(email=email, password=password, role=role)  # Corregido: 'role' en lugar de 'role'
        db.session.add(user)
        db.session.commit()
        flash('Usuario registrado con éxito. Por favor, inicia sesión.', 'success')
        return redirect('/login')
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            if user.password.startswith('$2b$'):
                if bcrypt.check_password_hash(user.password, form.password.data):
                    login_user(user)
                    return redirect('/solicitar')
            else:
                if user.password == form.password.data:
                    user.password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
                    db.session.commit()
                    login_user(user)
                    return redirect('/solicitar')
        flash('Credenciales inválidas. Intenta de nuevo.', 'danger')
    return render_template('login.html', form=form)

@app.route('/solicitar', methods=['GET', 'POST'])
@login_required
def solicitar():
    form = SolicitudForm()
    if form.validate_on_submit():
        paciente = form.paciente.data
        cedula = form.cedula.data
        compania_paciente = form.compania.data
        examenes = form.examenes.data
        centro_medico = form.centro_medico.data
        resultado = auditar_solicitud(compania_paciente, examenes)
        auditoria = Auditoria(
            paciente=paciente,
            cedula=cedula,
            compania_paciente=compania_paciente,
            examenes=examenes,
            centro_medico=centro_medico,
            resultado=resultado,
            usuario_id=current_user.id
        )
        db.session.add(auditoria)
        db.session.commit()
        pdf_path = generar_pdf(auditoria)
        auditoria.pdf_path = pdf_path
        db.session.commit()
        flash(f"Solicitud procesada. PDF almacenado en {pdf_path}", 'success')
        return redirect('/historial')
    return render_template('solicitar.html', form=form)

@app.route('/historial')
@login_required
def historial():
    if current_user.role == 'admin':
        auditorias = Auditoria.query.all()
    else:
        auditorias = Auditoria.query.filter_by(usuario_id=current_user.id).all()
    return render_template('historial.html', auditorias=auditorias)

@app.route('/descargar_pdf/<int:auditoria_id>')
@login_required
def descargar_pdf(auditoria_id):
    auditoria = Auditoria.query.get_or_404(auditoria_id)
    if current_user.role != 'admin' and auditoria.usuario_id != current_user.id:
        return "No tienes permiso para descargar este archivo", 403
    return send_from_directory(app.config['PDF_FOLDER'], f"autorizacion_{auditoria_id}.pdf", as_attachment=True)

@app.route('/exportar_historial')
@login_required
def exportar_historial():
    if current_user.role == 'admin':
        auditorias = Auditoria.query.all()
    else:
        auditorias = Auditoria.query.filter_by(usuario_id=current_user.id).all()
    wb = Workbook()
    ws = wb.active
    ws.title = "Historial de Auditorías"
    headers = ['ID', 'Paciente', 'Cédula', 'Compañía', 'Exámenes', 'Centro Médico', 'Resultado']
    if current_user.role == 'admin':
        headers.append('Usuario ID')
    ws.append(headers)
    for auditoria in auditorias:
        row = [
            auditoria.id,
            auditoria.paciente,
            auditoria.cedula,
            auditoria.compania_paciente,
            auditoria.examenes,
            auditoria.centro_medico,
            auditoria.resultado
        ]
        if current_user.role == 'admin':
            row.append(auditoria.usuario_id)
        ws.append(row)
    output = BytesIO()
    wb.save(output)
    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        headers={"Content-Disposition": "attachment;filename=historial_auditorias.xlsx"}
    )

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Has cerrado sesión exitosamente.', 'success')
    return redirect('/login')

# Crear la base de datos solo en desarrollo
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)