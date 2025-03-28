from flask import Flask, request, render_template, redirect, flash, send_from_directory, Response
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, FloatField
from wtforms.validators import DataRequired, Email, Length, Optional
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from openpyxl import Workbook
from io import BytesIO
import os
from openai import OpenAI

app = Flask(__name__)

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'x7k9p!m2q$z')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///auditorias.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# Usar carpeta temporal para PDFs (efímera en Render gratuito)
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
    resultado = db.Column(db.Text, nullable=False)
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
    diagnosticos = TextAreaField('Diagnósticos (CIE10 o Descripción, uno por línea)', validators=[DataRequired()])
    centro_medico = StringField('Centro Médico', validators=[DataRequired()])
    cobertura = FloatField('Porcentaje de Cobertura (%)', validators=[Optional()], default=80.0)
    medico_tratante = StringField('Médico Tratante', validators=[Optional()])
    fecha_cita = StringField('Fecha de Cita', validators=[Optional()])
    hora_cita = StringField('Hora de Cita', validators=[Optional()])
    submit = SubmitField('Enviar Solicitud')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def auditar_solicitud(paciente, cedula, compania_paciente, examenes, diagnosticos, centro_medico, cobertura, medico_tratante, fecha_cita, hora_cita):
    client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))
    
    examenes_formateados = examenes.replace(',', '\n')
    cobertura = cobertura if cobertura is not None else 80
    medico_tratante = medico_tratante if medico_tratante else "Médico de Turno"
    fecha_cita = fecha_cita if fecha_cita else "A coordinar con paciente"
    hora_cita = hora_cita if hora_cita else "A coordinar con paciente"
    
    prompt = f"""
    Eres un asistente de auditoría médica para Privilegio Medicina Prepagada. Tu tarea es analizar solicitudes de autorización de procedimientos médicos y responder con un formato específico, evaluando la cobertura según criterios estrictos de pertinencia médica. Sigue estas normas:

    - Evalúa cada examen individualmente según los diagnósticos proporcionados. Autoriza los exámenes que tengan pertinencia médica razonable según las reglas específicas definidas abajo. Si un examen está explícitamente cubierto por al menos uno de los diagnósticos en las reglas específicas, debe autorizarse. Si no hay diagnóstico claro, no autorices ningún examen y explica que se requiere un diagnóstico específico.
    - No se cubren exámenes por descarte, control o rutina, salvo que el diagnóstico lo justifique explícitamente según las reglas específicas.
    - Las pruebas de embarazo (e.g., BETA HCG) nunca se cubren bajo ninguna circunstancia, ya que son para descartar.
    - Si un examen depende del resultado de otro, indícalo como "vía reembolso".
    - Cobertura estándar: {cobertura}%, salvo excepciones (e.g., maternidad 100%).
    - Terapias físicas: máximo $20 o $35 por sesión según contrato.
    - El usuario ingresará solo el código CIE10 (e.g., "A09") o el diagnóstico (e.g., "Gastroenteritis"). En el resultado, siempre muestra el código CIE10 completo seguido de la descripción completa en mayúsculas (e.g., "A09 - GASTROENTERITIS Y COLITIS INFECCIOSAS, NO ESPECIFICADAS").
    - Para los exámenes o procedimientos, aunque el usuario coloque iniciales o nombres parciales (e.g., "BH", "GLUC"), devuelve el nombre completo en mayúsculas en el resultado (e.g., "BIOMETRÍA HEMÁTICA", "GLUCOSA"). En la sección "Pedido", muestra TODOS los exámenes solicitados con sus nombres completos en mayúsculas, independientemente de si son autorizados o no. Usa nombres estándares sin prefijos innecesarios como "BHC" o "HPES".

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
    [Lista de TODOS los exámenes solicitados en mayúsculas con nombre completo, uno por línea]

    Diagnósticos:
    [Completa con el código CIE10 y descripción completa en mayúsculas, uno por línea. Si no hay diagnóstico, indica "NO ESPECIFICADO"]

    Médico Tratante: {medico_tratante}
    Fecha Cita: {fecha_cita}
    Hora Cita: {hora_cita}
    Centro Médico: {centro_medico}
    Cobertura
    {cobertura}%

    Procedimientos Autorizados:
    [Lista de exámenes cubiertos en mayúsculas con nombre completo, uno por línea, o "NINGUNO" si no aplica]

    Procedimientos No Autorizados:
    [Lista de exámenes no cubiertos en mayúsculas con nombre completo, uno por línea]

    Motivo:
    [Explicación detallada de por qué no se cubren los procedimientos no autorizados, basada en las reglas específicas y los diagnósticos]

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

    Ejemplo de reglas específicas (estas tienen prioridad sobre cualquier interpretación general):
    - Diagnóstico E11 (E11 - DIABETES MELLITUS TIPO 2): Cubre GLUCOSA EN AYUNAS, HEMOGLOBINA GLICOSILADA, MICROALBUMINURIA, CREATININA.
    - Diagnóstico N18 (N18 - INSUFICIENCIA RENAL CRÓNICA): Cubre CREATININA, UREA, MICROALBUMINURIA, ELECTROLITOS.
    - Diagnóstico I10 (I10 - HIPERTENSIÓN ESENCIAL): Cubre CREATININA, GLUCOSA, COLESTEROL TOTAL (si hay factores de riesgo).
    - Diagnóstico E782 (E782 - HIPERLIPIDEMIA MIXTA): Cubre COLESTEROL TOTAL, COLESTEROL HDL, COLESTEROL LDL, TRIGLICÉRIDOS.
    - Diagnóstico M139 (M139 - ARTRITIS, NO ESPECIFICADA): Cubre FACTOR REUMATOIDEO CUANTITATIVO, CREATININA.
    - Diagnóstico A09 (A09 - GASTROENTERITIS Y COLITIS INFECCIOSAS, NO ESPECIFICADAS): Cubre BIOMETRÍA HEMÁTICA, ELECTROLITOS.
    - Diagnóstico J11 (J11 - INFLUENZA DEBIDA A VIRUS NO IDENTIFICADO): Cubre BIOMETRÍA HEMÁTICA.
    - Diagnóstico R104 (R104 - OTROS DOLORES ABDOMINALES Y LOS NO ESPECIFICADOS): Cubre BIOMETRÍA HEMÁTICA (para inflamación o anemia), HELICOBACTER PYLORI EN HECES (infección gastrointestinal), ELECTROLITOS (desequilibrios), RADIOGRAFÍA ABDOMINAL (evaluar obstrucciones o causas estructurales).
    - Diagnóstico K590 (K590 - CONSTIPACIÓN): Cubre ELECTROLITOS (desequilibrios metabólicos), RADIOGRAFÍA ABDOMINAL (descartar obstrucción).
    - No cubre PSA, CA19-9, ELECTROFORESIS DE PROTEÍNAS si no hay diagnóstico relacionado con cáncer.
    - Pruebas de embarazo (e.g., BETA HCG) nunca se cubren, ya que son para descartar.

    Ahora, audita esta solicitud:
    Paciente: {paciente}
    Cédula: {cedula}
    Compañía: {compania_paciente}
    Exámenes: {examenes}
    Diagnósticos: {diagnosticos}
    Centro Médico: {centro_medico}
    Cobertura: {cobertura}%
    Médico Tratante: {medico_tratante}
    Fecha Cita: {fecha_cita}
    Hora Cita: {hora_cita}
    """
    
    response = client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[
            {"role": "system", "content": "Eres un auditor médico experto con conocimiento de códigos CIE10 y nombres completos de exámenes médicos."},
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

    # Generar el PDF siempre que se solicite (no confiamos en almacenamiento persistente)
    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=letter,
        leftMargin=72,
        rightMargin=72,
        topMargin=72,
        bottomMargin=72
    )
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name='CustomText',
        fontName='Helvetica',
        fontSize=9,
        leading=12,
        textColor=colors.black
    ))
    styles.add(ParagraphStyle(
        name='Header',
        fontName='Helvetica-Bold',
        fontSize=10,
        leading=12,
        textColor=colors.darkblue,
        spaceAfter=6
    ))

    content = []
    logo_path = os.path.join(app.static_folder, 'images', 'logo.png')
    if os.path.exists(logo_path):
        logo = Image(logo_path, width=100, height=50)
        content.append(logo)
        content.append(Spacer(1, 12))

    texto = auditoria.resultado.replace('```', '').strip()
    lineas = texto.split('\n')
    current_section = []
    for linea in lineas:
        linea = linea.strip()
        if not linea:
            if current_section:
                content.append(Paragraph('\n'.join(current_section), styles['CustomText']))
                content.append(Spacer(1, 6))
            current_section = []
        elif linea.isupper() or linea.startswith(('Autorización', 'Paciente:', 'Pedido:', 'Diagnósticos:', 'Cobertura', 'Procedimientos Autorizados:', 'Procedimientos No Autorizados:', 'Motivo:', 'Nota:', 'Exclusiones Generales:')):
            if current_section:
                content.append(Paragraph('\n'.join(current_section), styles['CustomText']))
                content.append(Spacer(1, 6))
            content.append(Paragraph(linea, styles['Header']))
            current_section = []
        else:
            current_section.append(linea)
    
    if current_section:
        content.append(Paragraph('\n'.join(current_section), styles['CustomText']))

    doc.build(content)
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
        cobertura = form.cobertura.data
        medico_tratante = form.medico_tratante.data
        fecha_cita = form.fecha_cita.data
        hora_cita = form.hora_cita.data
        
        resultado = auditar_solicitud(paciente, cedula, compania_paciente, examenes, diagnosticos, centro_medico, cobertura, medico_tratante, fecha_cita, hora_cita)
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
    
    # Regenerar el PDF cada vez si no existe (efímero en Render gratuito)
    pdf_path = generar_pdf(auditoria)
    auditoria.pdf_path = pdf_path
    db.session.commit()
    
    return send_from_directory(
        app.config['PDF_FOLDER'],
        f"autorizacion_{auditoria_id}.pdf",
        as_attachment=True,
        mimetype='application/pdf',
        attachment_filename=f"autorizacion_{auditoria_id}.pdf"
    )

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