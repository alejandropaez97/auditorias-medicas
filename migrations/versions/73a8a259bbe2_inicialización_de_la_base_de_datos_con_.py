"""Inicialización de la base de datos con User y Auditoria

Revision ID: 73a8a259bbe2
Revises: 
Create Date: 2025-03-27 06:11:20.005924
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '73a8a259bbe2'
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    op.create_table('user',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('email', sa.String(length=150), nullable=False),
        sa.Column('password', sa.String(length=150), nullable=False),
        sa.Column('role', sa.String(length=20), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('email')
    )
    op.create_table('auditoria',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('paciente', sa.String(length=150), nullable=False),
        sa.Column('cedula', sa.String(length=20), nullable=False),
        sa.Column('compania_paciente', sa.String(length=150), nullable=False),
        sa.Column('examenes', sa.String(length=500), nullable=False),
        sa.Column('centro_medico', sa.String(length=150), nullable=False),
        sa.Column('resultado', sa.Text(), nullable=False),
        sa.Column('usuario_id', sa.Integer(), nullable=False),
        sa.Column('pdf_path', sa.String(length=500), nullable=True),
        sa.ForeignKeyConstraint(['usuario_id'], ['user.id']),
        sa.PrimaryKeyConstraint('id')
    )

def downgrade():
    op.drop_table('auditoria')
    op.drop_table('user')