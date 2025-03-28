"""Inicialización de la base de datos con User y Auditoria

Revision ID: 73a8a259bbe2
Revises: 
Create Date: 2025-03-27 06:11:20.005924
"""
from alembic import op
import sqlalchemy as sa

revision = '73a8a259bbe2'
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    # Modificar la columna existente en lugar de crear la tabla
    with op.batch_alter_table('auditoria', schema=None) as batch_op:
        batch_op.alter_column('resultado',
                             existing_type=sa.String(length=500),  # Ajusta según el tamaño actual en Render
                             type_=sa.Text(),
                             existing_nullable=False)

def downgrade():
    with op.batch_alter_table('auditoria', schema=None) as batch_op:
        batch_op.alter_column('resultado',
                             existing_type=sa.Text(),
                             type_=sa.String(length=500),  # Vuelve al tamaño original
                             existing_nullable=False)