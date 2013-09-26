"""cluster_id for tests and composite primary key for test set

Revision ID: 13b5469f7dc9
Revises: 483c01433a67
Create Date: 2013-09-26 16:43:53.916864

"""

# revision identifiers, used by Alembic.
revision = '13b5469f7dc9'
down_revision = '483c01433a67'

from alembic import op
import sqlalchemy as sa


def upgrade():
### commands auto generated by Alembic - please adjust! ###
    op.alter_column('test_sets', 'cluster_id',
               existing_type=sa.INTEGER(),
               nullable=False)
    op.add_column('tests', sa.Column('cluster_id', sa.Integer(), nullable=False))
    ### end Alembic commands ###


def downgrade():
### commands auto generated by Alembic - please adjust! ###
    op.drop_column('tests', 'cluster_id')
    op.alter_column('test_sets', 'cluster_id',
               existing_type=sa.INTEGER(),
               nullable=True)
    ### end Alembic commands ###
