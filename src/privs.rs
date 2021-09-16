// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use nix::unistd::{Group, User};
use privdrop::PrivDrop;
use std::{borrow::Cow, env};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PrivError {
    #[error("error finding group uid {0}")]
    FindGroup(u32, #[source] nix::Error),
    #[error("error finding user {0}")]
    FindUser(String, #[source] nix::Error),
    #[error("group id not found and must exist: {0}")]
    GroupNotFound(u32),
    #[error("error dropping privileges: {0}")]
    PrivDrop(#[from] privdrop::PrivDropError),
    #[error("user not found and must exist: {0}")]
    UserNotFound(String),
}

pub struct PrivDropInfo<'a, 'b, 'c> {
    user_name: Option<&'a str>,
    group_name: Option<&'b str>,
    default_user_name: &'c str,
}

impl<'a, 'b, 'c> PrivDropInfo<'a, 'b, 'c> {
    pub fn new(default_user_name: &'c str) -> Self {
        Self {
            user_name: None,
            group_name: None,
            default_user_name,
        }
    }

    pub fn user_name(&mut self, user_name: &'a str) -> &mut Self {
        self.user_name = Some(user_name);
        self
    }

    pub fn group_name(&mut self, group_name: &'b str) -> &mut Self {
        self.group_name = Some(group_name);
        self
    }
}

pub fn privdrop(info: PrivDropInfo<'_, '_, '_>) -> Result<(), PrivError> {
    let user_name = match info.user_name {
        Some(user_name) => Cow::from(user_name),
        None => Cow::from(determine_user(info.default_user_name)),
    };
    let group_name = match info.group_name {
        Some(group_name) => Cow::from(group_name),
        None => Cow::from(determine_group(&user_name)?),
    };

    PrivDrop::default()
        .user(user_name.as_ref())
        .group(group_name.as_ref())
        .apply()
        .map_err(From::from)
}

fn determine_user(default_user: impl AsRef<str>) -> String {
    if let Ok(sudo_user) = env::var("SUDO_USER") {
        if !sudo_user.is_empty() {
            return sudo_user;
        }
    }
    if let Ok(doas_user) = env::var("DOAS_USER") {
        if !doas_user.is_empty() {
            return doas_user;
        }
    }
    return String::from(default_user.as_ref());
}

fn determine_group(user_name: impl AsRef<str>) -> Result<String, PrivError> {
    let user = User::from_name(user_name.as_ref())
        .map_err(|err| PrivError::FindUser(user_name.as_ref().to_string(), err))?
        .ok_or_else(|| PrivError::UserNotFound(user_name.as_ref().to_string()))?;
    let group = Group::from_gid(user.gid)
        .map_err(|err| PrivError::FindGroup(user.gid.as_raw(), err))?
        .ok_or_else(|| PrivError::GroupNotFound(user.gid.as_raw()))?;
    Ok(group.name)
}
