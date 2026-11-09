"""Scope repository mappings to active SBOM evidence identities."""

from alembic import op
import sqlalchemy as sa

revision = '48ae9207bc61'
down_revision = 'de1339f8135e'
branch_labels = None
depends_on = None


def upgrade():
    op.drop_table('package_repositories')
    op.create_table(
        'package_repositories',
        sa.Column('package_id', sa.Uuid(), sa.ForeignKey('packages.id', ondelete='CASCADE'), primary_key=True),
        sa.Column('evidence_key', sa.String(64), primary_key=True),
        sa.Column('repository', sa.String(255), nullable=True),
        sa.Column('source', sa.String(16), nullable=False),
        sa.Column('evidence', sa.Text(), nullable=True),
        sa.Column('deprecated', sa.Boolean(), nullable=True),
        sa.Column('deprecated_reason', sa.Text(), nullable=True),
        sa.Column('resolved_at', sa.DateTime(), nullable=False),
    )


def downgrade():
    op.execute(sa.text('DELETE FROM package_repositories'))
    with op.batch_alter_table('package_repositories') as batch_op:
        batch_op.drop_column('evidence_key')