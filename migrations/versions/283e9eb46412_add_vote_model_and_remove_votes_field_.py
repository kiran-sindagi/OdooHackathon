"""Add Vote model and remove votes field from Answer

Revision ID: 283e9eb46412
Revises: e4623185c7a4
Create Date: 2025-07-12 11:41:58.722101

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '283e9eb46412'
down_revision = 'e4623185c7a4'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('vote',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('answer_id', sa.Integer(), nullable=False),
    sa.Column('value', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['answer_id'], ['answer.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('user_id', 'answer_id', name='unique_user_answer_vote')
    )
    with op.batch_alter_table('answer', schema=None) as batch_op:
        batch_op.drop_column('votes')

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('answer', schema=None) as batch_op:
        batch_op.add_column(sa.Column('votes', sa.INTEGER(), nullable=True))

    op.drop_table('vote')
    # ### end Alembic commands ###
