from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.persistence.models.user import UserModel
from app.domain.iam.password_policy import lock_deadline


class UserRepository:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def get_by_email(self, email: str) -> Optional[UserModel]:
        return await self.db.scalar(select(UserModel).where(UserModel.email == email.strip().lower()))

    async def get_by_id(self, user_id: str) -> Optional[UserModel]:
        return await self.db.scalar(select(UserModel).where(UserModel.id == user_id))

    async def list_all(self) -> List[UserModel]:
        return list((await self.db.scalars(select(UserModel).order_by(UserModel.created_at))).all())

    async def add(self, user: UserModel) -> UserModel:
        user.email = user.email.strip().lower()
        self.db.add(user)
        await self.db.flush()
        return user

    async def register_failure(self, user: UserModel) -> None:
        user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
        deadline = lock_deadline(user.failed_login_attempts)
        if deadline:
            user.locked_until = deadline
        await self.db.flush()

    async def register_success(self, user: UserModel) -> None:
        user.failed_login_attempts = 0
        user.locked_until = None
        user.last_login_at = datetime.now(timezone.utc)
        await self.db.flush()
