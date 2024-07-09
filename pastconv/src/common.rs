use std::sync::Arc;

use anyhow::Result;
use datafusion::{
    common::{FileType, GetExt},
    datasource::{file_format::parquet::ParquetFormat, listing::ListingOptions},
    execution::context::SessionContext,
};

pub async fn session(register: &str) -> Result<SessionContext> {
    let ctx: SessionContext = SessionContext::new();
    ctx.register_listing_table(
        "stacks",
        register,
        ListingOptions::new(Arc::new(ParquetFormat::default())).with_file_extension(FileType::PARQUET.get_ext()),
        None,
        None,
    )
    .await?;
    Ok(ctx)
}
