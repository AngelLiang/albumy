# -*- coding: utf-8 -*-
"""
    :author: Grey Li (李辉)
    :url: http://greyli.com
    :copyright: © 2018 Grey Li <withlihui@gmail.com>
    :license: MIT, see LICENSE for more details.
"""
import os
from datetime import datetime

from flask import current_app
from flask_avatars import Identicon
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

from albumy.extensions import db, whooshee

# 角色与权限的关系表
# relationship table
roles_permissions = db.Table('roles_permissions',
                             db.Column('role_id', db.Integer, db.ForeignKey('role.id')),
                             db.Column('permission_id', db.Integer, db.ForeignKey('permission.id'))
                             )


class Permission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(30), unique=True)
    roles = db.relationship('Role', secondary=roles_permissions, back_populates='permissions')


class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(30), unique=True)
    users = db.relationship('User', back_populates='role')
    permissions = db.relationship('Permission', secondary=roles_permissions, back_populates='roles')

    @staticmethod
    def init_role():
        roles_permissions_map = {
            # 'Guest': [],
            # 'Blocked': [],
            'Locked': ['FOLLOW', 'COLLECT'],
            'User': ['FOLLOW', 'COLLECT', 'COMMENT', 'UPLOAD'],
            'Moderator': ['FOLLOW', 'COLLECT', 'COMMENT', 'UPLOAD', 'MODERATE'],
            'Administrator': ['FOLLOW', 'COLLECT', 'COMMENT', 'UPLOAD', 'MODERATE', 'ADMINISTER']
        }

        for role_name in roles_permissions_map:
            role = Role.query.filter_by(name=role_name).first()
            if role is None:
                role = Role(name=role_name)
                db.session.add(role)
            role.permissions = []
            for permission_name in roles_permissions_map[role_name]:
                permission = Permission.query.filter_by(name=permission_name).first()
                if permission is None:
                    permission = Permission(name=permission_name)
                    db.session.add(permission)
                role.permissions.append(permission)
        db.session.commit()


# relationship object
class Follow(db.Model):
    """关注模型"""
    # 关注对象
    follower_id = db.Column(db.Integer, db.ForeignKey('user.id'),
                            primary_key=True)
    # 关注者
    followed_id = db.Column(db.Integer, db.ForeignKey('user.id'),
                            primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    follower = db.relationship('User', foreign_keys=[follower_id], back_populates='following', lazy='joined')
    followed = db.relationship('User', foreign_keys=[followed_id], back_populates='followers', lazy='joined')


# relationship object
class Collect(db.Model):
    """收藏模型"""
    # 收藏者
    collector_id = db.Column(db.Integer, db.ForeignKey('user.id'),
                             primary_key=True)
    # 收藏对象，这里可以考虑用 generic foreign key
    collected_id = db.Column(db.Integer, db.ForeignKey('photo.id'),
                             primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    collector = db.relationship('User', back_populates='collections', lazy='joined')
    collected = db.relationship('Photo', back_populates='collectors', lazy='joined')


@whooshee.register_model('name', 'username')
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, index=True)
    email = db.Column(db.String(254), unique=True, index=True)
    password_hash = db.Column(db.String(128))
    name = db.Column(db.String(30))
    website = db.Column(db.String(255))
    # 简介
    bio = db.Column(db.String(120))
    # 城市信息
    location = db.Column(db.String(50))
    # 用户加入时间
    member_since = db.Column(db.DateTime, default=datetime.utcnow)

    # 头像信息
    avatar_s = db.Column(db.String(64))
    avatar_m = db.Column(db.String(64))
    avatar_l = db.Column(db.String(64))
    avatar_raw = db.Column(db.String(64))

    confirmed = db.Column(db.Boolean, default=False)
    locked = db.Column(db.Boolean, default=False)  # 锁定
    active = db.Column(db.Boolean, default=True)  # 启用

    public_collections = db.Column(db.Boolean, default=True)
    # 是否接收评论通知
    receive_comment_notification = db.Column(db.Boolean, default=True)
    # 是否接收关注通知
    receive_follow_notification = db.Column(db.Boolean, default=True)
    # 是否接收收藏通知
    receive_collect_notification = db.Column(db.Boolean, default=True)

    role_id = db.Column(db.Integer, db.ForeignKey('role.id'))

    # 关系对象
    role = db.relationship('Role', back_populates='users')
    photos = db.relationship('Photo', back_populates='author', cascade='all')
    comments = db.relationship('Comment', back_populates='author', cascade='all')
    notifications = db.relationship('Notification', back_populates='receiver', cascade='all')
    collections = db.relationship('Collect', back_populates='collector', cascade='all')
    following = db.relationship('Follow', foreign_keys=[Follow.follower_id], back_populates='follower',
                                lazy='dynamic', cascade='all')
    followers = db.relationship('Follow', foreign_keys=[Follow.followed_id], back_populates='followed',
                                lazy='dynamic', cascade='all')

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        self.generate_avatar()
        self.follow(self)  # follow self
        self.set_role()

    def set_password(self, password):
        """设置密码"""
        self.password_hash = generate_password_hash(password)

    def set_role(self):
        if self.role is None:
            if self.email == current_app.config['ALBUMY_ADMIN_EMAIL']:
                self.role = Role.query.filter_by(name='Administrator').first()
            else:
                self.role = Role.query.filter_by(name='User').first()
            db.session.commit()

    def validate_password(self, password):
        """验证密码"""
        return check_password_hash(self.password_hash, password)

    def follow(self, user):
        if not self.is_following(user):
            follow = Follow(follower=self, followed=user)
            db.session.add(follow)
            db.session.commit()

    def unfollow(self, user):
        follow = self.following.filter_by(followed_id=user.id).first()
        if follow:
            db.session.delete(follow)
            db.session.commit()

    def is_following(self, user):
        if user.id is None:  # when follow self, user.id will be None
            return False
        return self.following.filter_by(followed_id=user.id).first() is not None

    def is_followed_by(self, user):
        return self.followers.filter_by(follower_id=user.id).first() is not None

    @property
    def followed_photos(self):
        return Photo.query.join(Follow, Follow.followed_id == Photo.author_id).filter(Follow.follower_id == self.id)

    def collect(self, photo):
        if not self.is_collecting(photo):
            collect = Collect(collector=self, collected=photo)
            db.session.add(collect)
            db.session.commit()

    def uncollect(self, photo):
        collect = Collect.query.with_parent(self).filter_by(collected_id=photo.id).first()
        if collect:
            db.session.delete(collect)
            db.session.commit()

    def is_collecting(self, photo):
        return Collect.query.with_parent(self).filter_by(collected_id=photo.id).first() is not None

    def lock(self):
        """锁定"""
        self.locked = True
        self.role = Role.query.filter_by(name='Locked').first()
        db.session.commit()

    def unlock(self):
        """解锁"""
        self.locked = False
        self.role = Role.query.filter_by(name='User').first()
        db.session.commit()

    def block(self):
        """禁用"""
        self.active = False
        db.session.commit()

    def unblock(self):
        """解禁"""
        self.active = True
        db.session.commit()

    def generate_avatar(self):
        """生成头像"""
        avatar = Identicon()
        filenames = avatar.generate(text=self.username)
        self.avatar_s = filenames[0]
        self.avatar_m = filenames[1]
        self.avatar_l = filenames[2]
        db.session.commit()

    @property
    def is_admin(self):
        return self.role.name == 'Administrator'

    @property
    def is_active(self):
        return self.active

    def can(self, permission_name):
        """判断user的权限"""

        # permission = Permission.query.filter_by(name=permission_name).first()
        # return permission is not None and self.role is not None and permission in self.role.permissions
        """
        $ flask shell
        >>> admin = User.query.get(1)
        ...
        >>> admin.can('ADMINISTER')

        2019-09-29 09:40:10,451 INFO sqlalchemy.engine.base.Engine ('ADMINISTER', 1, 0)
        2019-09-29 09:40:10,456 INFO sqlalchemy.engine.base.Engine SELECT role.id AS role_id, role.name AS role_name
        FROM role
        WHERE role.id = ?
        2019-09-29 09:40:10,595 INFO sqlalchemy.engine.base.Engine (4,)

        2019-09-29 09:40:10,634 INFO sqlalchemy.engine.base.Engine SELECT permission.id AS permission_id, permission.name AS permission_name
        FROM permission, roles_permissions
        WHERE ? = roles_permissions.role_id AND permission.id = roles_permissions.permission_id
        2019-09-29 09:40:10,777 INFO sqlalchemy.engine.base.Engine (4,)

        True
        """

        # 查询优化
        permission = Permission.query.filter(
            Permission.name == permission_name,
            roles_permissions.c.permission_id == Permission.id,
            Role.id == roles_permissions.c.role_id,
            User.role_id == Role.id,
        ).first()
        """
        $ flask shell
        >>> admin = User.query.get(1)
        ...
        >>> admin.can('ADMINISTER')

        2019-09-29 09:42:27,235 INFO sqlalchemy.engine.base.Engine SELECT permission.id AS permission_id, permission.name AS permission_name
        FROM permission, roles_permissions, role, user
        WHERE permission.name = ? AND roles_permissions.permission_id = permission.id AND roles_permissions.role_id = role.id AND user.role_id = role.id
        LIMIT ? OFFSET ?
        2019-09-29 09:42:27,424 INFO sqlalchemy.engine.base.Engine ('ADMINISTER', 1, 0)

        True
        """
        return permission is not None

# photo 和 tag 关系表
tagging = db.Table('tagging',
                   db.Column('photo_id', db.Integer, db.ForeignKey('photo.id')),
                   db.Column('tag_id', db.Integer, db.ForeignKey('tag.id'))
                   )


@whooshee.register_model('description')
class Photo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(500))
    filename = db.Column(db.String(64))
    filename_s = db.Column(db.String(64))
    filename_m = db.Column(db.String(64))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    can_comment = db.Column(db.Boolean, default=True)
    flag = db.Column(db.Integer, default=0)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    author = db.relationship('User', back_populates='photos')
    comments = db.relationship('Comment', back_populates='photo', cascade='all')
    collectors = db.relationship('Collect', back_populates='collected', cascade='all')
    tags = db.relationship('Tag', secondary=tagging, back_populates='photos')


@whooshee.register_model('name')
class Tag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), index=True, unique=True)

    photos = db.relationship('Photo', secondary=tagging, back_populates='tags')


class Comment(db.Model):
    """评论"""
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    flag = db.Column(db.Integer, default=0)

    replied_id = db.Column(db.Integer, db.ForeignKey('comment.id'))
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    photo_id = db.Column(db.Integer, db.ForeignKey('photo.id'))

    photo = db.relationship('Photo', back_populates='comments')
    author = db.relationship('User', back_populates='comments')
    replies = db.relationship('Comment', back_populates='replied', cascade='all')
    replied = db.relationship('Comment', back_populates='replies', remote_side=[id])


class Notification(db.Model):
    """消息通知"""
    id = db.Column(db.Integer, primary_key=True)
    # 消息正文
    message = db.Column(db.Text, nullable=False)
    # 消息状态
    is_read = db.Column(db.Boolean, default=False)
    # 时间戳
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    # 接收者
    # Notification模型与User模型是一对多关系
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    receiver = db.relationship('User', back_populates='notifications')


@db.event.listens_for(User, 'after_delete', named=True)
def delete_avatars(**kwargs):
    target = kwargs['target']
    for filename in [target.avatar_s, target.avatar_m, target.avatar_l, target.avatar_raw]:
        if filename is not None:  # avatar_raw may be None
            path = os.path.join(current_app.config['AVATARS_SAVE_PATH'], filename)
            if os.path.exists(path):  # not every filename map a unique file
                os.remove(path)


@db.event.listens_for(Photo, 'after_delete', named=True)
def delete_photos(**kwargs):
    target = kwargs['target']
    for filename in [target.filename, target.filename_s, target.filename_m]:
        path = os.path.join(current_app.config['ALBUMY_UPLOAD_PATH'], filename)
        if os.path.exists(path):  # not every filename map a unique file
            os.remove(path)
