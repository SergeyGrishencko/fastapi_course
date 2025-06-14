"""add unit_price column to association table

Revision ID: ef7fd18de95a
Revises: c24828ff6b04
Create Date: 2025-05-28 18:07:09.077256

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'ef7fd18de95a'
down_revision: Union[str, None] = 'c24828ff6b04'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('order_product_association', sa.Column('unit_price', sa.Integer(), server_default='0', nullable=False))
    # ### end Alembic commands ###


def downgrade() -> None:
    """Downgrade schema."""
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('order_product_association', 'unit_price')
    # ### end Alembic commands ###
