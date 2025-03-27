from alembic import op
import sqlalchemy as sa

revision = '73a8a259bbe2'
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    with op.batch_alter_table('auditoria', schema=None) as batch_op:
        batch_op.alter_column('resultado',
                              existing_type=sa.String(length=2000),
                              type_=sa.Text(),
                              existing_nullable=False)

def downgrade():
    with op.batch_alter_table('auditoria', schema=None) as batch_op:
        batch_op.alter_column('resultado',
                              existing_type=sa.Text(),
                              type_=sa.String(length=2000),
                              existing_nullable=False)