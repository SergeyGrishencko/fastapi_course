import asyncio

from sqlalchemy import select
from sqlalchemy.engine import Result
from sqlalchemy.orm import joinedload, selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from core.models import db_helper, User, Profile, Post, Order, Product, OrderProductAssociation

async def create_user(session: AsyncSession, username: str) -> User:
    user = User(username=username)
    session.add(user)
    await session.commit()
    print("user", user)
    return user

async def get_user_by_username(session: AsyncSession, username: str) -> User | None:
    stmt = select(User).where(User.username==username)
    user: User | None = await session.scalar(stmt)
    print("found user", username, user)
    return user

async def create_user_profile(
        session: AsyncSession, 
        user_id: int, 
        first_name: str | None = None,
        last_name: str | None = None
    ) -> Profile:
    profile = Profile(
        user_id=user_id,
        first_name=first_name,
        last_name=last_name
    )
    session.add(profile)
    await session.commit()
    return profile

async def show_users_with_profiles(session: AsyncSession):
    stmt = select(User).options(joinedload(User.profile)).order_by(User.id)
    users = await session.scalars(stmt)
    for user in users:
        print(user)
        print(user.profile.first_name)

async def create_posts(session: AsyncSession, user_id: int, *posts_titles: str) -> list[Post]:
    posts = [
        Post(title=title, user_id=user_id)
        for title in posts_titles
    ]
    session.add_all(posts)
    await session.commit()
    print(posts)
    return posts

async def get_user_with_posts(
        session: AsyncSession
):
    stmt = select(User).options(selectinload(User.posts)).order_by(User.id)
    result: Result = await session.execute(stmt)
    users = await session.scalars(stmt)

    for user in users: 
        print("**" * 10)
        print(user)
        for post in user.posts:
            print("-", post)

async def get_posts_with_authors(session: AsyncSession):
    stmt = select(Post).options(joinedload(Post.user)).order_by(Post.id)
    posts = await session.scalars(stmt)

    for post in posts:
        print("post", post)
        print("authors", post.user)

async def get_profiles_with_users_and_users_with_posts(session: AsyncSession):
    stmt = (
        select(Profile)
        .options(
            joinedload(Profile.user).selectinload(User.posts),
        )
        .order_by(Profile.id)
    )

    profiles = await session.scalars(stmt)

    for profile in profiles:
        print(profile.first_name, profile.user)
        print(profile.user.posts)

async def main_relations(sesison: AsyncSession):
    pass

async def create_order(
        session: AsyncSession, 
        promocode: str | None = None
) -> Order:
    order = Order(promocode=promocode)

    session.add(order)
    await session.commit()

    return order

async def create_product(
        session: AsyncSession,
        name: str,
        description: str,
        price: int
) -> Product:
    product = Product(name=name, description=description, price=price)

    session.add(product)
    await session.commit()

    return product

async def create_orders_and_products(session: AsyncSession):
    order_one = await create_order(session)
    order_promo = await create_order(session, promocode="promo")

    mouse = await create_product(
        session, 
        name="Mouse", 
        description="Great gaming mouse",
        price=123
    )
    keyboard = await create_product(
        session, 
        name="Keyboard", 
        description="Great gaming keyboard",
        price=149
    )
    display = await create_product(
        session, 
        name="Display", 
        description="Office display",
        price=299
    )

    order_one = await session.scalar(
        select(Order)
        .where(Order.id == order_one.id)
        .options(
            selectinload(Order.products)
        ),
    )
    order_promo = await session.scalar(
        select(Order)
        .where(Order.id == order_promo.id)
        .options(
            selectinload(Order.products)
        ),
    )

    order_one.products.append(mouse)
    order_one.products.append(keyboard)
    order_promo.products.append(keyboard)
    order_promo.products.append(display)

    await session.commit()

async def get_orders_with_products(session: AsyncSession) -> list[Order]:
    stmt = (
        select(Order)
        .options(
            selectinload(Order.products)
            )
        .order_by(Order.id)
    )
    orders = await session.scalars(stmt)

    return list(orders)

async def demo_get_orders_with_products_through_secondary(session: AsyncSession):
    orders = await get_orders_with_products(session)
    for order in orders:
        print(order.id, order.promocode, order.created_at)
        for product in order.products:
            print("-", product.id, product.name, product.price)

async def get_orders_with_products_association(session: AsyncSession) -> list[Order]:
    stmt = (
        select(Order)
        .options(
            selectinload(Order.products_details).joinedload(OrderProductAssociation.product),
            )
        .order_by(Order.id)
    )
    orders = await session.scalars(stmt)

    return list(orders)

async def demo_get_orders_with_products_with_association(session: AsyncSession):
    orders = await get_orders_with_products_association(session=session)

    for order in orders:
        print(order.id, order.promocode, order.created_at, "products:")
        for order_product_details in order.products_details:
            print(
                "-", 
                order_product_details.product.name,
                order_product_details.product.price,
                "qty:", order_product_details.count
            )

async def create_gift_product_for_existing_orders(session: AsyncSession):
    orders = await get_orders_with_products_association(session)
    gift_product = await create_product(
        session,
        name="Gift",
        description="Gift for you",
        price=0,
    )
    for order in orders:
        order.products_details.append(OrderProductAssociation(
            count=1,
            unit_price=0,
            product=gift_product,
        ))
    
    await session.commit()

async def demo_m2m(session: AsyncSession):
    await demo_get_orders_with_products_with_association(session)
    # await create_gift_product_for_existing_orders(session)

async def main():
    async with db_helper.session_factory() as session:
        # await main_relations(session)
        await demo_m2m(session)

if __name__ == '__main__':
    asyncio.run(main())