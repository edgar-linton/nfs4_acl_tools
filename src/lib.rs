use bitflags::bitflags;
use bitflags_serde_shim::impl_serde_for_bitflags;
use serde::{Deserialize, Serialize};
use std::{
    io::{Error, Result},
    path::Path,
    process::Command,
};

#[derive(Serialize, Deserialize, PartialEq, Eq, Copy, Clone, Debug)]
pub enum AceType {
    Allow,
    Deny,
    Audit,
    Alarm,
}

bitflags! {
    #[derive(PartialEq, Eq, Copy, Clone, Debug)]
    pub struct AceFlags: u8 {
        const GROUP                = 0b00000001;
        const DIRECTORY_INHERIT    = 0b00000010;
        const FILE_INHERIT         = 0b00000100;
        const NO_PROPAGATE_INHERIT = 0b00001000;
        const INHERIT_ONLY         = 0b00010000;
        const SUCCESSFUL_ACCESS    = 0b00100000;
        const FAILED_ACCESS        = 0b01000000;
    }
}

impl_serde_for_bitflags!(AceFlags);

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Debug)]
pub struct AcePrincipals(pub String);

bitflags! {
    #[derive(PartialEq, Eq, Copy, Clone, Debug)]
    pub struct AcePermissions: u16 {
        const READ_DATA              = 0b0000000000000001;
        const WRITE_DATA             = 0b0000000000000010;
        const APPEND_DATA            = 0b0000000000000100;
        const EXECUTE                = 0b0000000000001000;
        const DELETE                 = 0b0000000000010000;
        const DELETE_CHILD           = 0b0000000000100000;
        const READ_ATTRIBUTES        = 0b0000000001000000;
        const WRITE_ATTRIBUTES       = 0b0000000010000000;
        const READ_NAMED_ATTRIBUTES  = 0b0000000100000000;
        const WRITE_NAMED_ATTRIBUTES = 0b0000001000000000;
        const READ_ACL               = 0b0000010000000000;
        const WRITE_ACL              = 0b0000100000000000;
        const WRITE_OWNER            = 0b0001000000000000;
        const SYNCHRONIZE            = 0b0010000000000000;
    }
}

impl_serde_for_bitflags!(AcePermissions);

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Debug)]
pub struct Ace {
    pub ace_type: AceType,
    pub ace_flags: AceFlags,
    pub ace_principals: AcePrincipals,
    pub ace_permissions: AcePermissions,
}

#[derive(Debug)]
pub struct Acl {
    pub aces: Vec<Ace>,
}

impl Acl {
    /// Parses the output of the nfs4_getfacl command to a Acl
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Acl> {
        if !path.as_ref().exists() {
            return Err(Error::new(
                std::io::ErrorKind::NotFound,
                "The file does not exist",
            ));
        }
        let path_input = path.as_ref().to_str().unwrap_or_default();
        let output = Command::new("nfs4_getfacl").arg(path_input).output()?;
        let output_str = String::from_utf8_lossy(&output.stdout);
        let lines: Vec<&str> = output_str.lines().collect();
        let mut aces: Vec<Ace> = Vec::new();
        for line in lines {
            if line.is_empty() || line.starts_with("#") {
                continue;
            }

            let parts: Vec<&str> = line.split(":").collect();
            if parts.len() != 4 {
                println!("Invalid line: {}", line);
            }

            let ace_type = parts[0].to_string().chars().last().unwrap();
            let ace_flags = parts[1].to_string();
            let ace_principals = parts[2].to_string();
            let ace_permissions = parts[3].to_string();

            let type_ = match ace_type {
                'A' => AceType::Allow,
                'D' => AceType::Deny,
                'U' => AceType::Audit,
                'L' => AceType::Alarm,
                _ => unreachable!("Invalid type: {}", ace_type),
            };

            let mut flags = AceFlags::empty();
            for char in ace_flags.chars() {
                match char {
                    'g' => flags |= AceFlags::GROUP,
                    'd' => flags |= AceFlags::DIRECTORY_INHERIT,
                    'f' => flags |= AceFlags::FILE_INHERIT,
                    'n' => flags |= AceFlags::NO_PROPAGATE_INHERIT,
                    'i' => flags |= AceFlags::INHERIT_ONLY,
                    'S' => flags |= AceFlags::SUCCESSFUL_ACCESS,
                    'F' => flags |= AceFlags::FAILED_ACCESS,
                    _ => {
                        println!("Invalid flag: {}", char);
                        break;
                    }
                }
            }

            let principals = AcePrincipals(ace_principals);

            let mut permissions = AcePermissions::empty();
            for char in ace_permissions.chars() {
                match char {
                    'r' => permissions |= AcePermissions::READ_DATA,
                    'w' => permissions |= AcePermissions::WRITE_DATA,
                    'a' => permissions |= AcePermissions::APPEND_DATA,
                    'x' => permissions |= AcePermissions::EXECUTE,
                    'd' => permissions |= AcePermissions::DELETE,
                    'D' => permissions |= AcePermissions::DELETE_CHILD,
                    't' => permissions |= AcePermissions::READ_ATTRIBUTES,
                    'T' => permissions |= AcePermissions::WRITE_ATTRIBUTES,
                    'n' => permissions |= AcePermissions::READ_NAMED_ATTRIBUTES,
                    'N' => permissions |= AcePermissions::WRITE_NAMED_ATTRIBUTES,
                    'c' => permissions |= AcePermissions::READ_ACL,
                    'C' => permissions |= AcePermissions::WRITE_ACL,
                    'o' => permissions |= AcePermissions::WRITE_OWNER,
                    'y' => permissions |= AcePermissions::SYNCHRONIZE,
                    _ => {
                        println!("Invalid permission: {}", char);
                        break;
                    }
                }
            }

            let ace = Ace {
                ace_type: type_,
                ace_flags: flags,
                ace_principals: principals,
                ace_permissions: permissions,
            };
            aces.push(ace);
        }
        let acl = Acl { aces: aces };

        Ok(acl)
    }

    /// Get all ACEs whose ACE Principale is a Group ID.
    pub fn group_id_aces(self) -> Vec<Ace> {
        let group_aces: Vec<Ace> = self
            .aces
            .into_iter()
            .filter(|ace| {
                ace.ace_principals.0.parse::<u16>().is_ok()
                    && ace.ace_flags.contains(AceFlags::GROUP)
            })
            .collect();

        group_aces
    }
}
