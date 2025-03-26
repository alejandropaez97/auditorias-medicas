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
from openai import OpenAI

app = Flask(__name__)

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'x7k9p!m2q$z')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///auditorias.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PDF_FOLDER'] = os.getenv('PDF_FOLDER', '/tmp/pdfs')

db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

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
    resultado = db.Column(db.String(2000), nullable=False)
    usuario_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    pdf_path = db.Column(db.String(500))

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
    diagnosticos = TextAreaField('Diagnósticos (CIE10 - Descripción, uno por línea)', validators=[DataRequired()])
    centro_medico = StringField('Centro Médico', validators=[DataRequired()])
    submit = SubmitField('Enviar Solicitud')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def auditar_solicitud(paciente, cedula, compania_paciente, examenes, diagnosticos, centro_medico):
    client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))
    
    # Preprocesamos los examenes para evitar \n en la f-string
    examenes_formateados = examenes.replace(',', '\n')
    
    prompt = f"""
    Eres un asistente de auditoría médica para Privilegio Medicina Prepagada. Tu tarea es analizar solicitudes de autorización de procedimientos médicos y responder con un formato específico, evaluando la cobertura según criterios estrictos de pertinencia médica. Sigue estas normas:

    - Solo se cubren exámenes/procedimientos con relación directa al diagnóstico.
    - No se cubren exámenes por descarte, control o rutina.
    - Si un examen depende del resultado de otro, indícalo como "vía reembolso".
    - Cobertura estándar: 80%, salvo excepciones (e.g., maternidad 100%).
    - Terapias físicas: máximo $20 o $35 por sesión según contrato.

    Responde siempre en este formato:
    ```
    Autorización de Procedimientos
    Buenos días estimados,
    Reciban un cordial saludo de quienes conformamos PRIVILEGIO.
    Mediante el presente nos permitimos enviar la auditoría médica del paciente {paciente.upper()}, perteneciente a {compania_paciente.upper()}.

    Paciente:
    Nombre: {paciente.upper()}
    Cédula: {cedula}

    Pedido:
    {examenes_formateados}

    Diagnósticos:
    {diagnosticos}

    Médico Tratante: Médico de Turno
    Fecha Cita: A coordinar con paciente
    Hora Cita: A coordinar con paciente
    Centro Médico: {centro_medico}
    Cobertura
    80%

    Procedimientos Autorizados:
    [Lista de exámenes cubiertos]

    Procedimientos No Autorizados:
    [Lista de exámenes no cubiertos]

    Motivo:
    [Explicación de por qué no se cubren]

    Nota:
    El paciente coordinará los procedimientos autorizados con la central médica. Por favor, asistir con cédula de identidad y pedido médico original.

    Exclusiones Generales:
    PRIVILEGIO MEDICINA PREPAGADA S.A. no cubre IVA, kit de ingreso, insumos de papelería ni cualquier elemento no médico.

    Quedo a la espera de sus comentarios. Gracias de antemano.
    Saludos cordiales,
    Privilegio Medicina Prepagada
    PRIMEPRE S.A.
    DIR: Juan León Mera N21-291 y Jerónimo Carrión, Edificio Sevilla piso 7
    E-MAIL: direccionmedica@privilegio.med.ec
    WEB: www.privilegio.med.ec
    QUITO – ECUADOR
    ```

    Ejemplo de reglas específicas:
    - Diagnóstico E11 (Diabetes): Cubre Glucosa en ayunas, Hemoglobina glicosilada, Microalbuminuria, Creatinina.
    - Diagnóstico N18 (Insuficiencia Renal): Cubre Creatinina, Urea, Microalbuminuria, Electrolitos.
    - No cubre PSA, CA19-9, Electroforesis de Proteínas si no hay diagnóstico relacionado con cáncer.

    Ahora, audita esta solicitud:
    Paciente: {paciente}
    Cédula: {cedula}
    Compañía: {compania_paciente}
    Exámenes: {examenes}
    Diagnósticos: {diagnosticos}
    Centro Médico: {centro_medico}
    """
    
    response = client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[
            {"role": "system", "content": "Eres un auditor médico experto."},
            {"role": "user", "content": prompt}
        ],
        max_tokens=1000,
        temperature=0.3
    )
    
    return response.choices[0].message.content.strip()

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
        user = User(email=email, password=password, role=role)
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
        diagnosticos = form.diagnosticos.data
        centro_medico = form.centro_medico.data
        resultado = auditar_solicitud(paciente, cedula, compania_paciente, examenes, diagnosticos, centro_medico)
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

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)