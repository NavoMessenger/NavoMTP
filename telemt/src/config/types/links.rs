use super::*;

/// Proxy link generation settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinksConfig {
    /// List of usernames whose tg:// links to display at startup.
    /// `"*"` = all users, `["alice", "bob"]` = specific users.
    #[serde(default = "default_links_show")]
    pub show: ShowLink,

    /// Public hostname/IP for tg:// link generation (overrides detected IP).
    #[serde(default)]
    pub public_host: Option<String>,

    /// Public port for tg:// link generation.
    /// Overrides listener ports and legacy `server.port`.
    #[serde(default)]
    pub public_port: Option<u16>,
}

impl Default for LinksConfig {
    fn default() -> Self {
        Self {
            show: default_links_show(),
            public_host: None,
            public_port: None,
        }
    }
}

/// In TOML, this can be:
/// - `show_link = "*"`          — show links for all users
/// - `show_link = ["a", "b"]`   — show links for specific users
/// - omitted                    — default depends on the owning config field
#[derive(Debug, Clone, Default)]
pub enum ShowLink {
    /// Don't show any links (default when omitted).
    #[default]
    None,
    /// Show links for all configured users.
    All,
    /// Show links for specific users.
    Specific(Vec<String>),
}

fn default_links_show() -> ShowLink {
    ShowLink::All
}

impl ShowLink {
    /// Returns true if no links should be shown.
    pub fn is_empty(&self) -> bool {
        matches!(self, ShowLink::None) || matches!(self, ShowLink::Specific(v) if v.is_empty())
    }

    /// Resolve the list of user names to display, given all configured users.
    pub fn resolve_users<'a>(&'a self, all_users: &'a HashMap<String, String>) -> Vec<&'a String> {
        match self {
            ShowLink::None => vec![],
            ShowLink::All => {
                let mut names: Vec<&String> = all_users.keys().collect();
                names.sort();
                names
            }
            ShowLink::Specific(names) => names.iter().collect(),
        }
    }
}

impl Serialize for ShowLink {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        match self {
            ShowLink::None => Vec::<String>::new().serialize(serializer),
            ShowLink::All => serializer.serialize_str("*"),
            ShowLink::Specific(v) => v.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for ShowLink {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        use serde::de;

        struct ShowLinkVisitor;

        impl<'de> de::Visitor<'de> for ShowLinkVisitor {
            type Value = ShowLink;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str(r#""*" or an array of user names"#)
            }

            fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<ShowLink, E> {
                if v == "*" {
                    Ok(ShowLink::All)
                } else {
                    Err(de::Error::invalid_value(de::Unexpected::Str(v), &r#""*""#))
                }
            }

            fn visit_seq<A: de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<ShowLink, A::Error> {
                let mut names = Vec::new();
                while let Some(name) = seq.next_element::<String>()? {
                    names.push(name);
                }
                if names.is_empty() {
                    Ok(ShowLink::None)
                } else {
                    Ok(ShowLink::Specific(names))
                }
            }
        }

        deserializer.deserialize_any(ShowLinkVisitor)
    }
}
