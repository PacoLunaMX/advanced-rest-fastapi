from pydantic import BaseModel
from pydantic_settings import SettingsConfigDict


class UserPostIn(BaseModel):
    body: str


class UserPost(UserPostIn):
    id: int
    model_config = SettingsConfigDict(from_attributes=True)


class CommentIn(BaseModel):
    body: str
    post_id: int


class Comment(CommentIn):
    id: int
    model_config = SettingsConfigDict(from_attributes=True)


class UserPostWithComments(BaseModel):
    post: UserPost
    comments: list[Comment]
