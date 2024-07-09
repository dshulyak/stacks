use std::{collections::HashMap, io::Write, ops::Deref, path::PathBuf, sync::Arc};

use anyhow::Result;
use datafusion::{
    arrow::{
        array::{Array, AsArray, ListArray, RecordBatch},
        datatypes::Int64Type,
    },
    execution::context::SessionContext,
};
use itertools::multizip;
use prost::Message;

use crate::common::session;

mod proto {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/proto/perftools.profiles.rs"));
}

const START_TIME: &str = include_str!("sql/start_time.sql");

const COMMAND_BINDING: &str = "?command";

async fn generate_pprof(ctx: &SessionContext, query: &str) -> Result<proto::Profile> {
    let batch = Batch(ctx.sql(query).await?.collect().await?);
    let mut strings = PprofStringDictionary::new_strings();
    let mut functions = PprofStringDictionary::new_functions();
    let mut function_table = vec![];
    let mut location_table = vec![];
    let mut samples_table = vec![];
    let mut duration = 0;
    let start: i64 = get_start_time(ctx).await?;
    for sampled_stack in batch.iter() {
        let mut locations = vec![];
        for stack in sampled_stack.stacks() {
            match functions.get_or_insert(stack) {
                DictionaryEntry::Existing(function_id) => locations.push(function_id as u64),
                DictionaryEntry::New(function_id) => {
                    let function = proto::Function {
                        id: function_id as u64,
                        name: *strings.get_or_insert(stack),
                        ..Default::default()
                    };
                    let line = proto::Line {
                        function_id: function_id as u64,
                        ..Default::default()
                    };
                    let location = proto::Location {
                        id: function_id as u64,
                        line: vec![line],
                        ..Default::default()
                    };
                    function_table.push(function);
                    location_table.push(location);
                    locations.push(function_id as u64);
                }
            }
        }
        let sample = proto::Sample {
            location_id: locations,
            value: vec![sampled_stack.count, sampled_stack.duration],
            ..Default::default()
        };
        samples_table.push(sample);
        duration += sampled_stack.duration;
    }
    let count_value_type = proto::ValueType {
        r#type: *strings.get_or_insert(COUNT),
        unit: *strings.get_or_insert(SAMPLES),
    };
    let time_value_type = proto::ValueType {
        r#type: *strings.get_or_insert(SAMPLED_CPU),
        unit: *strings.get_or_insert(NS),
    };
    let profile = proto::Profile {
        sample_type: vec![count_value_type, time_value_type],
        sample: samples_table,
        string_table: strings.strings_table(),
        location: location_table,
        function: function_table,
        time_nanos: start,
        duration_nanos: duration,
        ..Default::default()
    };
    Ok(profile)
}

struct Batch(Vec<RecordBatch>);

impl Batch {
    fn iter(&self) -> impl Iterator<Item = Stacks> + '_ {
        self.0.iter().flat_map(|batch| {
            let stacks = batch.column(0).as_any().downcast_ref::<ListArray>().unwrap();
            let count = batch.column(1).as_primitive::<Int64Type>();
            let duration = batch.column(2).as_primitive::<Int64Type>();
            multizip((count.iter(), stacks.iter(), duration.iter())).map(|(count, stacks, duration)| Stacks {
                count: count.unwrap_or(0),
                stacks: stacks.clone(),
                duration: duration.unwrap_or(0),
            })
        })
    }
}

struct Stacks {
    count: i64,
    duration: i64,
    stacks: Option<Arc<dyn Array>>,
}

impl Stacks {
    fn stacks(&self) -> impl Iterator<Item = &str> + '_ {
        self.stacks.as_ref().unwrap().as_string::<i32>().iter().flatten()
    }
}

struct PprofStringDictionary {
    values: HashMap<String, i64>,
    next_idx: i64,
}

const SAMPLES: &str = "samples";
const COUNT: &str = "count";
const SAMPLED_CPU: &str = "sampled_cpu";
const NS: &str = "ns";
const PROCESS: &str = "process";

enum DictionaryEntry {
    Existing(i64),
    New(i64),
}

impl Deref for DictionaryEntry {
    type Target = i64;

    fn deref(&self) -> &Self::Target {
        match self {
            DictionaryEntry::Existing(idx) => idx,
            DictionaryEntry::New(idx) => idx,
        }
    }
}

impl PprofStringDictionary {
    fn new_functions() -> Self {
        // functions dictionary expects 0 to be reserved
        PprofStringDictionary {
            values: HashMap::new(),
            next_idx: 1,
        }
    }

    fn new_strings() -> Self {
        // strings dictinary with prefilled labels used across the profile
        let mut strings = HashMap::new();
        strings.insert("".to_string(), 0);
        strings.insert(SAMPLES.to_string(), 1);
        strings.insert(COUNT.to_string(), 2);
        strings.insert(SAMPLED_CPU.to_string(), 3);
        strings.insert(NS.to_string(), 4);
        strings.insert(PROCESS.to_string(), 5);
        PprofStringDictionary {
            values: strings,
            next_idx: 6,
        }
    }

    fn get_or_insert(&mut self, s: &str) -> DictionaryEntry {
        if let Some(&idx) = self.values.get(s) {
            DictionaryEntry::Existing(idx)
        } else {
            let idx = self.next_idx;
            self.values.insert(s.to_string(), idx);
            self.next_idx += 1;
            DictionaryEntry::New(idx)
        }
    }

    fn strings_table(&self) -> Vec<String> {
        let mut strings = vec!["".to_string(); self.values.len()];
        for (s, &idx) in self.values.iter() {
            strings[idx as usize].clone_from(s);
        }
        strings
    }
}

async fn get_start_time(ctx: &SessionContext) -> Result<i64> {
    let min_timestamp = ctx
        .sql(START_TIME)
        .await?
        .collect()
        .await?
        .into_iter()
        .next()
        .expect("expecting single batch")
        .column(0)
        .as_primitive::<Int64Type>()
        .into_iter()
        .next()
        .expect("expecting single row")
        .expect("single timestamp value");
    Ok(min_timestamp)
}

pub async fn pprof(register: &str, destination: &PathBuf, query: &str, command: Option<&str>) -> Result<()> {
    let mut query = query.to_owned();
    if let Some(command) = command {
        query = query.replace(COMMAND_BINDING, command);
    }
    let ctx = session(register).await?;
    let profile = generate_pprof(&ctx, &query).await?;
    let mut f = std::fs::File::create(destination)?;
    let mut buf = vec![];
    profile.encode(&mut buf)?;
    f.write_all(&buf)?;
    println!("path: {}", destination.display());
    Ok(())
}
