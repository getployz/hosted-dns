//! [`Zone`] backed by one Route 53 hosted zone.

use std::time::Duration;

use aws_sdk_route53::error::DisplayErrorContext;
use aws_sdk_route53::types as r53;

use crate::zone::{Change, ChangeId, RecordSet, RecordType, Zone, ZoneError};

const SYNC_POLL: Duration = Duration::from_secs(3);
const SYNC_TIMEOUT: Duration = Duration::from_secs(300);

/// The production hosted zone.
pub struct Route53 {
    client: aws_sdk_route53::Client,
    zone_id: String,
}

impl Route53 {
    /// Uses credentials and region from the standard AWS environment.
    pub fn new(config: &aws_config::SdkConfig, zone_id: String) -> Self {
        Self {
            client: aws_sdk_route53::Client::new(config),
            zone_id,
        }
    }
}

impl Zone for Route53 {
    async fn record_sets(&self, name: &str) -> Result<Vec<RecordSet>, ZoneError> {
        // Listing starts at `name`; its own sets sort first, so one small page is enough.
        let page = self
            .client
            .list_resource_record_sets()
            .hosted_zone_id(&self.zone_id)
            .start_record_name(name)
            .max_items(10)
            .send()
            .await
            .map_err(zone_error)?;
        Ok(page
            .resource_record_sets()
            .iter()
            .filter(|set| normalize(set.name()) == name)
            .filter_map(|set| {
                // TXT is write-only here: challenges are deleted with the values we wrote.
                let kind = [RecordType::A, RecordType::Aaaa, RecordType::Cname]
                    .into_iter()
                    .find(|kind| rr_type(*kind) == *set.r#type())?;
                Some(RecordSet {
                    name: name.to_owned(),
                    kind,
                    ttl: set.ttl().unwrap_or_default(),
                    values: set
                        .resource_records()
                        .iter()
                        .map(|record| record.value().to_owned())
                        .collect(),
                })
            })
            .collect())
    }

    async fn apply(&self, changes: Vec<Change>) -> Result<ChangeId, ZoneError> {
        let changes = changes
            .into_iter()
            .map(to_r53)
            .collect::<Result<Vec<_>, _>>()
            .map_err(zone_error)?;
        let batch = r53::ChangeBatch::builder()
            .set_changes(Some(changes))
            .build()
            .map_err(zone_error)?;
        let output = self
            .client
            .change_resource_record_sets()
            .hosted_zone_id(&self.zone_id)
            .change_batch(batch)
            .send()
            .await
            .map_err(zone_error)?;
        let id = output
            .change_info()
            .map(|info| info.id().to_owned())
            .ok_or_else(|| ZoneError("Route 53 returned no change id".into()))?;
        Ok(ChangeId(id))
    }

    async fn wait_in_sync(&self, change: &ChangeId) -> Result<(), ZoneError> {
        let wait = async {
            loop {
                let output = self
                    .client
                    .get_change()
                    .id(&change.0)
                    .send()
                    .await
                    .map_err(zone_error)?;
                let in_sync = output
                    .change_info()
                    .is_some_and(|info| *info.status() == r53::ChangeStatus::Insync);
                if in_sync {
                    return Ok(());
                }
                tokio::time::sleep(SYNC_POLL).await;
            }
        };
        tokio::time::timeout(SYNC_TIMEOUT, wait)
            .await
            .map_err(|_| ZoneError(format!("change {} not in sync after 5 min", change.0)))?
    }
}

fn to_r53(change: Change) -> Result<r53::Change, aws_sdk_route53::error::BuildError> {
    let (action, set) = match change {
        Change::Upsert(set) => (r53::ChangeAction::Upsert, set),
        Change::Delete(set) => (r53::ChangeAction::Delete, set),
    };
    let records = set
        .values
        .iter()
        .map(|value| match set.kind {
            RecordType::Txt => format!("\"{value}\""),
            _ => value.clone(),
        })
        .map(|value| r53::ResourceRecord::builder().value(value).build())
        .collect::<Result<Vec<_>, _>>()?;
    let set = r53::ResourceRecordSet::builder()
        .r#type(rr_type(set.kind))
        .name(set.name)
        .ttl(set.ttl)
        .set_resource_records(Some(records))
        .build()?;
    r53::Change::builder()
        .action(action)
        .resource_record_set(set)
        .build()
}

fn rr_type(kind: RecordType) -> r53::RrType {
    match kind {
        RecordType::A => r53::RrType::A,
        RecordType::Aaaa => r53::RrType::Aaaa,
        RecordType::Cname => r53::RrType::Cname,
        RecordType::Txt => r53::RrType::Txt,
    }
}

/// Route 53 returns `\052.acme.ployz.app.` for `*.acme.ployz.app`.
fn normalize(name: &str) -> String {
    name.trim_end_matches('.').replace("\\052", "*")
}

fn zone_error(error: impl std::error::Error) -> ZoneError {
    ZoneError(DisplayErrorContext(error).to_string())
}
