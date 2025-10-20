use rusqlite::MAIN_DB;
use std::path::PathBuf;
use tokio_rusqlite;
use tokio_rusqlite::{Connection, OptionalExtension, Result};

pub struct State {
    pub id: u32,
    pub etag: Option<String>,
    pub last_update: String, //PrimitiveDateTime,
}

pub struct StateDatabase {
    conn: Connection,
}

impl StateDatabase {
    pub async fn open(path: &PathBuf) -> Result<StateDatabase> {
        let conn = Connection::open(path).await?;
        let db = StateDatabase { conn: conn };
        db.create().await?;
        Ok(db)
    }

    pub async fn close(self) -> Result<()> {
        self.conn.close().await
    }

    pub async fn fetch(&self, id: u32) -> Result<Option<State>> {
        self.conn
            .call(move |conn| {
                let mut stmt = conn.prepare("SELECT * FROM document WHERE id = ?")?;
                Ok(stmt.query_row([id], |r| {
                    Ok(Some(State {
                        id: r.get(0)?,
                        etag: r.get(1)?,
                        last_update: r.get(2)?,
                    }))
                })?)
            })
            .await
    }

    pub async fn update(&self, id: u32, etag: Option<String>) -> bool {
        self.conn
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "INSERT INTO document(id, etag, last_update) VALUES(?1, ?2, CURRENT_TIMESTAMP) \
                    ON CONFLICT(id) DO UPDATE SET etag = ?2, last_update = CURRENT_TIMESTAMP",
                )?;
                Ok(stmt.execute((id, etag))?)
            })
            .await
            .is_ok()
    }

    pub async fn is_readonly(&self) -> bool {
        self.conn
            .call(move |conn| Ok(conn.is_readonly(MAIN_DB)?))
            .await
            .unwrap_or(true)
    }

    async fn create(&self) -> Result<()> {
        let result = self
            .conn
            .call(|conn| {
                Ok(conn
                    .query_row(
                        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='document'",
                        [],
                        |r| r.get::<_, u8>(0),
                    )
                    .optional()?)
            })
            .await?;
        if result.is_none() {
            self.conn
                .call(|conn| {
                    Ok(conn.execute(
                        "CREATE TABLE document (\
                            id   INTEGER PRIMARY KEY,\
                            etag TEXT,\
                            last_update DATETIME DEFAULT CURRENT_TIMESTAMP\
                        )",
                        (),
                    )?)
                })
                .await?;
        }
        Ok(())
    }
}
