//! [`Zone`] backed by one Route 53 hosted zone.

use aws_sdk_route53::error::DisplayErrorContext;
use aws_sdk_route53::types as r53;

use crate::zone::{Change, RecordSet, RecordType, Zone, ZoneError};

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
                let kind = match set.r#type() {
                    r53::RrType::A => RecordType::A,
                    r53::RrType::Aaaa => RecordType::Aaaa,
                    r53::RrType::Cname => RecordType::Cname,
                    _ => return None,
                };
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

    async fn apply(&self, changes: Vec<Change>) -> Result<(), ZoneError> {
        let changes = changes
            .into_iter()
            .map(to_r53)
            .collect::<Result<Vec<_>, _>>()
            .map_err(zone_error)?;
        let batch = r53::ChangeBatch::builder()
            .set_changes(Some(changes))
            .build()
            .map_err(zone_error)?;
        self.client
            .change_resource_record_sets()
            .hosted_zone_id(&self.zone_id)
            .change_batch(batch)
            .send()
            .await
            .map_err(zone_error)?;
        Ok(())
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
        .map(|value| r53::ResourceRecord::builder().value(value).build())
        .collect::<Result<Vec<_>, _>>()?;
    let kind = match set.kind {
        RecordType::A => r53::RrType::A,
        RecordType::Aaaa => r53::RrType::Aaaa,
        RecordType::Cname => r53::RrType::Cname,
    };
    let set = r53::ResourceRecordSet::builder()
        .name(set.name)
        .r#type(kind)
        .ttl(set.ttl)
        .set_resource_records(Some(records))
        .build()?;
    r53::Change::builder()
        .action(action)
        .resource_record_set(set)
        .build()
}

/// Route 53 returns `\052.acme.ployz.app.` for `*.acme.ployz.app`.
fn normalize(name: &str) -> String {
    name.trim_end_matches('.').replace("\\052", "*")
}

fn zone_error(error: impl std::error::Error) -> ZoneError {
    ZoneError(DisplayErrorContext(error).to_string())
}
