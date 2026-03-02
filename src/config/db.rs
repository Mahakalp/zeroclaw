use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension, Result as SqliteResult};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub is_active: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Provider {
    pub id: String,
    pub profile_id: String,
    pub name: String,
    pub api_key: Option<String>,
    pub api_url: Option<String>,
    pub default_model: Option<String>,
    pub temperature: Option<f64>,
    pub is_enabled: bool,
    pub is_default: bool,
    pub priority: i32,
    pub metadata: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Channel {
    pub id: String,
    pub profile_id: String,
    pub channel_type: String,
    pub config: String,
    pub is_enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigHistory {
    pub id: i64,
    pub profile_id: String,
    pub config_snapshot: String,
    pub change_description: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Agent {
    pub id: String,
    pub profile_id: String,
    pub name: String,
    pub provider: String,
    pub model: Option<String>,
    pub api_key: Option<String>,
    pub api_url: Option<String>,
    pub system_prompt: Option<String>,
    pub temperature: Option<f64>,
    pub max_depth: Option<i32>,
    pub agentic: bool,
    pub allowed_tools: Option<String>,
    pub max_iterations: Option<i32>,
    pub metadata: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

pub struct ConfigDatabase {
    conn: Mutex<Connection>,
    path: PathBuf,
}

impl ConfigDatabase {
    pub fn new(data_dir: &PathBuf) -> Result<Self> {
        let db_path = data_dir.join("config.db");

        // Ensure parent directory exists
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let conn = Connection::open(&db_path).context("Failed to open config database")?;

        let db = Self {
            conn: Mutex::new(conn),
            path: db_path,
        };

        db.run_migrations()?;

        Ok(db)
    }

    fn run_migrations(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();

        conn.execute_batch(
            r#"
            -- Schema version tracking
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
            
            -- Key-value config store
            CREATE TABLE IF NOT EXISTS config_store (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
            
            -- Profiles (environments)
            CREATE TABLE IF NOT EXISTS profiles (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                description TEXT,
                is_active BOOLEAN DEFAULT FALSE,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
            
            -- LLM Providers
            CREATE TABLE IF NOT EXISTS providers (
                id TEXT PRIMARY KEY,
                profile_id TEXT REFERENCES profiles(id) ON DELETE CASCADE,
                name TEXT NOT NULL,
                api_key TEXT,
                api_url TEXT,
                default_model TEXT,
                temperature REAL,
                is_enabled BOOLEAN DEFAULT TRUE,
                is_default BOOLEAN DEFAULT FALSE,
                priority INTEGER DEFAULT 0,
                metadata TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(profile_id, name)
            );
            
            -- Agents
            CREATE TABLE IF NOT EXISTS agents (
                id TEXT PRIMARY KEY,
                profile_id TEXT REFERENCES profiles(id) ON DELETE CASCADE,
                name TEXT NOT NULL,
                provider TEXT NOT NULL,
                model TEXT,
                api_key TEXT,
                api_url TEXT,
                system_prompt TEXT,
                temperature REAL,
                max_depth INTEGER,
                agentic BOOLEAN DEFAULT FALSE,
                allowed_tools TEXT,
                max_iterations INTEGER,
                metadata TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(profile_id, name)
            );
            
            -- Messaging Channels
            CREATE TABLE IF NOT EXISTS channels (
                id TEXT PRIMARY KEY,
                profile_id TEXT REFERENCES profiles(id) ON DELETE CASCADE,
                channel_type TEXT NOT NULL,
                config TEXT NOT NULL,
                is_enabled BOOLEAN DEFAULT TRUE,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(profile_id, channel_type)
            );
            
            -- Config History/Versions
            CREATE TABLE IF NOT EXISTS config_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                profile_id TEXT REFERENCES profiles(id) ON DELETE CASCADE,
                config_snapshot TEXT NOT NULL,
                change_description TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
            
            -- Indexes
            CREATE INDEX IF NOT EXISTS idx_profiles_active ON profiles(is_active);
            CREATE INDEX IF NOT EXISTS idx_providers_profile ON providers(profile_id);
            CREATE INDEX IF NOT EXISTS idx_providers_default ON providers(profile_id, is_default);
            CREATE INDEX IF NOT EXISTS idx_channels_profile ON channels(profile_id);
            CREATE INDEX IF NOT EXISTS idx_channels_type ON channels(channel_type);
            CREATE INDEX IF NOT EXISTS idx_history_profile ON config_history(profile_id);
            CREATE INDEX IF NOT EXISTS idx_agents_profile ON agents(profile_id);
            "#,
        )?;

        // Mark migration as applied
        conn.execute(
            "INSERT OR IGNORE INTO schema_migrations (version) VALUES (1)",
            [],
        )?;

        // Migration 2: Add temperature column to providers if missing
        let has_temp: i32 = conn.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('providers') WHERE name = 'temperature'",
            [],
            |row| row.get(0),
        )?;
        if has_temp == 0 {
            conn.execute(
                "ALTER TABLE providers ADD COLUMN temperature REAL DEFAULT 0.7",
                [],
            )?;
            conn.execute(
                "INSERT OR IGNORE INTO schema_migrations (version) VALUES (2)",
                [],
            )?;
        }

        Ok(())
    }

    // ==================== Profiles ====================

    pub fn create_profile(&self, profile: &Profile) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO profiles (id, name, description, is_active, created_at, updated_at) 
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                profile.id,
                profile.name,
                profile.description,
                profile.is_active,
                profile.created_at,
                profile.updated_at
            ],
        )?;
        Ok(())
    }

    pub fn get_profiles(&self) -> Result<Vec<Profile>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, name, description, is_active, created_at, updated_at FROM profiles ORDER BY name"
        )?;

        let profiles = stmt
            .query_map([], |row| {
                Ok(Profile {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    description: row.get(2)?,
                    is_active: row.get(3)?,
                    created_at: row.get(4)?,
                    updated_at: row.get(5)?,
                })
            })?
            .collect::<SqliteResult<Vec<_>>>()?;

        Ok(profiles)
    }

    pub fn get_profile(&self, id: &str) -> Result<Option<Profile>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, name, description, is_active, created_at, updated_at FROM profiles WHERE id = ?1"
        )?;

        let profile = stmt
            .query_row([id], |row| {
                Ok(Profile {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    description: row.get(2)?,
                    is_active: row.get(3)?,
                    created_at: row.get(4)?,
                    updated_at: row.get(5)?,
                })
            })
            .optional()?;

        Ok(profile)
    }

    pub fn get_active_profile(&self) -> Result<Option<Profile>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, name, description, is_active, created_at, updated_at FROM profiles WHERE is_active = TRUE"
        )?;

        let profile = stmt
            .query_row([], |row| {
                Ok(Profile {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    description: row.get(2)?,
                    is_active: row.get(3)?,
                    created_at: row.get(4)?,
                    updated_at: row.get(5)?,
                })
            })
            .optional()?;

        Ok(profile)
    }

    pub fn set_active_profile(&self, id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();

        // Deactivate all profiles
        conn.execute("UPDATE profiles SET is_active = FALSE", [])?;

        // Activate the selected profile
        conn.execute(
            "UPDATE profiles SET is_active = TRUE, updated_at = CURRENT_TIMESTAMP WHERE id = ?1",
            [id],
        )?;

        Ok(())
    }

    pub fn update_profile(&self, profile: &Profile) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE profiles SET name = ?2, description = ?3, updated_at = CURRENT_TIMESTAMP WHERE id = ?1",
            params![profile.id, profile.name, profile.description],
        )?;
        Ok(())
    }

    pub fn delete_profile(&self, id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM profiles WHERE id = ?1", [id])?;
        Ok(())
    }

    // ==================== Providers ====================

    pub fn create_provider(&self, provider: &Provider) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO providers (id, profile_id, name, api_key, api_url, default_model, temperature, is_enabled, is_default, priority, metadata, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                provider.id,
                provider.profile_id,
                provider.name,
                provider.api_key,
                provider.api_url,
                provider.default_model,
                provider.temperature,
                provider.is_enabled,
                provider.is_default,
                provider.priority,
                provider.metadata,
                provider.created_at,
                provider.updated_at
            ],
        )?;
        Ok(())
    }

    pub fn get_providers(&self, profile_id: &str) -> Result<Vec<Provider>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, profile_id, name, api_key, api_url, default_model, temperature, is_enabled, is_default, priority, metadata, created_at, updated_at 
             FROM providers WHERE profile_id = ?1 ORDER BY priority"
        )?;

        let providers = stmt
            .query_map([profile_id], |row| {
                Ok(Provider {
                    id: row.get(0)?,
                    profile_id: row.get(1)?,
                    name: row.get(2)?,
                    api_key: row.get(3)?,
                    api_url: row.get(4)?,
                    default_model: row.get(5)?,
                    temperature: row.get(6)?,
                    is_enabled: row.get(7)?,
                    is_default: row.get(8)?,
                    priority: row.get(9)?,
                    metadata: row.get(10)?,
                    created_at: row.get(11)?,
                    updated_at: row.get(12)?,
                })
            })?
            .collect::<SqliteResult<Vec<_>>>()?;

        Ok(providers)
    }

    pub fn get_provider(&self, id: &str) -> Result<Option<Provider>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, profile_id, name, api_key, api_url, default_model, temperature, is_enabled, is_default, priority, metadata, created_at, updated_at 
             FROM providers WHERE id = ?1"
        )?;

        let provider = stmt
            .query_row([id], |row| {
                Ok(Provider {
                    id: row.get(0)?,
                    profile_id: row.get(1)?,
                    name: row.get(2)?,
                    api_key: row.get(3)?,
                    api_url: row.get(4)?,
                    default_model: row.get(5)?,
                    temperature: row.get(6)?,
                    is_enabled: row.get(7)?,
                    is_default: row.get(8)?,
                    priority: row.get(9)?,
                    metadata: row.get(10)?,
                    created_at: row.get(11)?,
                    updated_at: row.get(12)?,
                })
            })
            .optional()?;

        Ok(provider)
    }

    pub fn get_default_provider(&self, profile_id: &str) -> Result<Option<Provider>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, profile_id, name, api_key, api_url, default_model, temperature, is_enabled, is_default, priority, metadata, created_at, updated_at 
             FROM providers WHERE profile_id = ?1 AND is_default = TRUE"
        )?;

        let provider = stmt
            .query_row([profile_id], |row| {
                Ok(Provider {
                    id: row.get(0)?,
                    profile_id: row.get(1)?,
                    name: row.get(2)?,
                    api_key: row.get(3)?,
                    api_url: row.get(4)?,
                    default_model: row.get(5)?,
                    temperature: row.get(6)?,
                    is_enabled: row.get(7)?,
                    is_default: row.get(8)?,
                    priority: row.get(9)?,
                    metadata: row.get(10)?,
                    created_at: row.get(11)?,
                    updated_at: row.get(12)?,
                })
            })
            .optional()?;

        Ok(provider)
    }

    pub fn update_provider(&self, provider: &Provider) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE providers SET name = ?2, api_key = ?3, api_url = ?4, default_model = ?5, temperature = ?6,
             is_enabled = ?7, is_default = ?8, priority = ?9, metadata = ?10, updated_at = CURRENT_TIMESTAMP 
             WHERE id = ?1",
            params![
                provider.id,
                provider.name,
                provider.api_key,
                provider.api_url,
                provider.default_model,
                provider.temperature,
                provider.is_enabled,
                provider.is_default,
                provider.priority,
                provider.metadata
            ],
        )?;
        Ok(())
    }

    pub fn delete_provider(&self, id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM providers WHERE id = ?1", [id])?;
        Ok(())
    }

    // ==================== Channels ====================

    pub fn create_channel(&self, channel: &Channel) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO channels (id, profile_id, channel_type, config, is_enabled, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                channel.id,
                channel.profile_id,
                channel.channel_type,
                channel.config,
                channel.is_enabled,
                channel.created_at,
                channel.updated_at
            ],
        )?;
        Ok(())
    }

    pub fn get_channels(&self, profile_id: &str) -> Result<Vec<Channel>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, profile_id, channel_type, config, is_enabled, created_at, updated_at 
             FROM channels WHERE profile_id = ?1 ORDER BY channel_type",
        )?;

        let channels = stmt
            .query_map([profile_id], |row| {
                Ok(Channel {
                    id: row.get(0)?,
                    profile_id: row.get(1)?,
                    channel_type: row.get(2)?,
                    config: row.get(3)?,
                    is_enabled: row.get(4)?,
                    created_at: row.get(5)?,
                    updated_at: row.get(6)?,
                })
            })?
            .collect::<SqliteResult<Vec<_>>>()?;

        Ok(channels)
    }

    pub fn get_channel(&self, id: &str) -> Result<Option<Channel>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, profile_id, channel_type, config, is_enabled, created_at, updated_at 
             FROM channels WHERE id = ?1",
        )?;

        let channel = stmt
            .query_row([id], |row| {
                Ok(Channel {
                    id: row.get(0)?,
                    profile_id: row.get(1)?,
                    channel_type: row.get(2)?,
                    config: row.get(3)?,
                    is_enabled: row.get(4)?,
                    created_at: row.get(5)?,
                    updated_at: row.get(6)?,
                })
            })
            .optional()?;

        Ok(channel)
    }

    pub fn get_channels_by_type(
        &self,
        profile_id: &str,
        channel_type: &str,
    ) -> Result<Option<Channel>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, profile_id, channel_type, config, is_enabled, created_at, updated_at 
             FROM channels WHERE profile_id = ?1 AND channel_type = ?2",
        )?;

        let channel = stmt
            .query_row(params![profile_id, channel_type], |row| {
                Ok(Channel {
                    id: row.get(0)?,
                    profile_id: row.get(1)?,
                    channel_type: row.get(2)?,
                    config: row.get(3)?,
                    is_enabled: row.get(4)?,
                    created_at: row.get(5)?,
                    updated_at: row.get(6)?,
                })
            })
            .optional()?;

        Ok(channel)
    }

    pub fn update_channel(&self, channel: &Channel) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE channels SET channel_type = ?2, config = ?3, is_enabled = ?4, updated_at = CURRENT_TIMESTAMP 
             WHERE id = ?1",
            params![
                channel.id,
                channel.channel_type,
                channel.config,
                channel.is_enabled
            ],
        )?;
        Ok(())
    }

    pub fn delete_channel(&self, id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM channels WHERE id = ?1", [id])?;
        Ok(())
    }

    // ==================== Agents ====================

    pub fn create_agent(&self, agent: &Agent) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO agents (id, profile_id, name, provider, model, api_key, api_url, system_prompt, temperature, max_depth, agentic, allowed_tools, max_iterations, metadata, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            params![
                agent.id,
                agent.profile_id,
                agent.name,
                agent.provider,
                agent.model,
                agent.api_key,
                agent.api_url,
                agent.system_prompt,
                agent.temperature,
                agent.max_depth,
                agent.agentic,
                agent.allowed_tools,
                agent.max_iterations,
                agent.metadata,
                agent.created_at,
                agent.updated_at
            ],
        )?;
        Ok(())
    }

    pub fn get_agents(&self, profile_id: &str) -> Result<Vec<Agent>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, profile_id, name, provider, model, api_key, api_url, system_prompt, temperature, max_depth, agentic, allowed_tools, max_iterations, metadata, created_at, updated_at 
             FROM agents WHERE profile_id = ?1 ORDER BY name"
        )?;

        let agents = stmt
            .query_map([profile_id], |row| {
                Ok(Agent {
                    id: row.get(0)?,
                    profile_id: row.get(1)?,
                    name: row.get(2)?,
                    provider: row.get(3)?,
                    model: row.get(4)?,
                    api_key: row.get(5)?,
                    api_url: row.get(6)?,
                    system_prompt: row.get(7)?,
                    temperature: row.get(8)?,
                    max_depth: row.get(9)?,
                    agentic: row.get(10)?,
                    allowed_tools: row.get(11)?,
                    max_iterations: row.get(12)?,
                    metadata: row.get(13)?,
                    created_at: row.get(14)?,
                    updated_at: row.get(15)?,
                })
            })?
            .collect::<SqliteResult<Vec<_>>>()?;

        Ok(agents)
    }

    pub fn get_agent(&self, id: &str) -> Result<Option<Agent>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, profile_id, name, provider, model, api_key, api_url, system_prompt, temperature, max_depth, agentic, allowed_tools, max_iterations, metadata, created_at, updated_at 
             FROM agents WHERE id = ?1"
        )?;

        let agent = stmt
            .query_row([id], |row| {
                Ok(Agent {
                    id: row.get(0)?,
                    profile_id: row.get(1)?,
                    name: row.get(2)?,
                    provider: row.get(3)?,
                    model: row.get(4)?,
                    api_key: row.get(5)?,
                    api_url: row.get(6)?,
                    system_prompt: row.get(7)?,
                    temperature: row.get(8)?,
                    max_depth: row.get(9)?,
                    agentic: row.get(10)?,
                    allowed_tools: row.get(11)?,
                    max_iterations: row.get(12)?,
                    metadata: row.get(13)?,
                    created_at: row.get(14)?,
                    updated_at: row.get(15)?,
                })
            })
            .optional()?;

        Ok(agent)
    }

    pub fn update_agent(&self, agent: &Agent) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE agents SET name = ?2, provider = ?3, model = ?4, api_key = ?5, api_url = ?6, system_prompt = ?7, temperature = ?8, max_depth = ?9, agentic = ?10, allowed_tools = ?11, max_iterations = ?12, metadata = ?13, updated_at = CURRENT_TIMESTAMP 
             WHERE id = ?1",
            params![
                agent.id,
                agent.name,
                agent.provider,
                agent.model,
                agent.api_key,
                agent.api_url,
                agent.system_prompt,
                agent.temperature,
                agent.max_depth,
                agent.agentic,
                agent.allowed_tools,
                agent.max_iterations,
                agent.metadata
            ],
        )?;
        Ok(())
    }

    pub fn delete_agent(&self, id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM agents WHERE id = ?1", [id])?;
        Ok(())
    }

    // ==================== Config History ====================

    pub fn save_config_history(&self, history: &ConfigHistory) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO config_history (profile_id, config_snapshot, change_description, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                history.profile_id,
                history.config_snapshot,
                history.change_description,
                history.created_at
            ],
        )?;

        let id = conn.last_insert_rowid();

        // Keep only last 50 versions
        conn.execute(
            "DELETE FROM config_history WHERE profile_id = ?1 AND id NOT IN (
                SELECT id FROM config_history WHERE profile_id = ?1 ORDER BY created_at DESC LIMIT 50
            )",
            [&history.profile_id],
        )?;

        Ok(id)
    }

    pub fn get_config_history(&self, profile_id: &str, limit: i32) -> Result<Vec<ConfigHistory>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, profile_id, config_snapshot, change_description, created_at 
             FROM config_history WHERE profile_id = ?1 ORDER BY created_at DESC LIMIT ?2",
        )?;

        let history = stmt
            .query_map(params![profile_id, limit], |row| {
                Ok(ConfigHistory {
                    id: row.get(0)?,
                    profile_id: row.get(1)?,
                    config_snapshot: row.get(2)?,
                    change_description: row.get(3)?,
                    created_at: row.get(4)?,
                })
            })?
            .collect::<SqliteResult<Vec<_>>>()?;

        Ok(history)
    }

    pub fn get_config_version(&self, id: i64) -> Result<Option<ConfigHistory>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, profile_id, config_snapshot, change_description, created_at 
             FROM config_history WHERE id = ?1",
        )?;

        let version = stmt
            .query_row([id], |row| {
                Ok(ConfigHistory {
                    id: row.get(0)?,
                    profile_id: row.get(1)?,
                    config_snapshot: row.get(2)?,
                    change_description: row.get(3)?,
                    created_at: row.get(4)?,
                })
            })
            .optional()?;

        Ok(version)
    }

    // ==================== Config Store ====================

    pub fn set_config(&self, key: &str, value: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO config_store (key, value, updated_at) VALUES (?1, ?2, CURRENT_TIMESTAMP)",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn get_config(&self, key: &str) -> Result<Option<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT value FROM config_store WHERE key = ?1")?;
        let value = stmt.query_row([key], |row| row.get(0)).optional()?;
        Ok(value)
    }

    pub fn delete_config(&self, key: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM config_store WHERE key = ?1", [key])?;
        Ok(())
    }

    // ==================== Utility ====================

    pub fn ensure_default_profile(&self) -> Result<Profile> {
        // Check if any profile exists
        if let Some(profile) = self.get_active_profile()? {
            return Ok(profile);
        }

        // Create default profile
        let profile = Profile {
            id: uuid::Uuid::new_v4().to_string(),
            name: "default".to_string(),
            description: Some("Default profile".to_string()),
            is_active: true,
            created_at: chrono::Utc::now().to_rfc3339(),
            updated_at: chrono::Utc::now().to_rfc3339(),
        };

        self.create_profile(&profile)?;

        Ok(profile)
    }
}
