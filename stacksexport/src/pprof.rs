use std::{
    collections::{hash_map, HashMap},
    io::Write,
    ops::Deref,
    path::PathBuf,
    sync::Arc,
};

use anyhow::Result;
use blazesym::{
    helper::read_elf_build_id,
    symbolize::{self, Elf, Input, Source, Symbolized},
};
use datafusion::{
    arrow::{
        array::{Array, AsArray, ListArray, RecordBatch},
        datatypes::{Int64Type, UInt64Type},
    },
    prelude::SessionContext,
};
use itertools::multizip;
use prost::Message;

use crate::common::session;

mod proto {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/proto/perftools.profiles.rs"));
}

const COMMAND_BINDING: &str = "?command";
const BUILID_BINDING: &str = "?buildid";

async fn generate_pprof(ctx: &SessionContext, query: &str, include_offset: bool) -> Result<proto::Profile> {
    let batch = Batch(ctx.sql(query).await?.collect().await?);
    let mut strings = PprofStringDictionary::new_strings();
    let mut functions = PprofStringDictionary::new_functions();
    let mut function_table = vec![];
    let mut location_table = vec![];
    let mut samples_table = vec![];
    let mut duration = 0;
    for sampled_stack in batch.iter() {
        let mut locations = vec![];
        for stack in sampled_stack.stacks() {
            // if we have line information we will see the difference by looking at source.
            // without binary/debuginfo there is no clear way to see that samples are actually
            // collected from different addresses, for this purpose i am adding offset to the name explicitly
            let name = if include_offset {
                format!("{}-{:x}", stack.name, stack.offset)
            } else {
                stack.name.to_string()
            };
            match functions.get_or_insert(name.as_str()) {
                DictionaryEntry::Existing(function_id) => locations.push(function_id as u64),
                DictionaryEntry::New(function_id) => {
                    let function = proto::Function {
                        id: function_id as u64,
                        name: *strings.get_or_insert(name.as_str()),
                        ..Default::default()
                    };
                    let line = proto::Line {
                        function_id: function_id as u64,
                        ..Default::default()
                    };
                    let location = proto::Location {
                        id: function_id as u64,
                        address: stack.address + stack.offset,
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
        duration_nanos: duration,
        ..Default::default()
    };
    Ok(profile)
}

async fn generate_pprof_with_symbolization(
    ctx: &SessionContext,
    query: &str,
    binary: PathBuf,
    include_offset: bool,
) -> Result<proto::Profile> {
    let batch = Batch(ctx.sql(query).await?.collect().await?);
    let columns: Vec<String> = batch.0[0]
        .schema()
        .fields()
        .iter()
        .map(|f| f.name().clone())
        .collect::<Vec<_>>();

    let mut strings = PprofStringDictionary::new_strings();
    let mut functions = PprofStringDictionary::new_functions();
    let mut location_addr_to_index = HashMap::new();
    let mut last_location = 1; // 0 is reserved
    let mut function_table = vec![];
    let mut location_table = vec![];
    let mut samples_table = vec![];
    let mut duration = 0;

    let symbolizer = symbolize::Symbolizer::builder().build();
    let source = Source::Elf(Elf {
        path: binary,
        debug_syms: true,
        _non_exhaustive: (),
    });

    for sampled_stack in batch.iter() {
        let mut locations = vec![];
        let stacks = sampled_stack.stacks().collect::<Vec<_>>();
        let addresses_with_offset = stacks
            .iter()
            .map(|stack| stack.address + stack.offset)
            .collect::<Vec<u64>>();
        let symbolized = symbolizer.symbolize(&source, Input::FileOffset(addresses_with_offset.as_slice()))?;
        for (stack, symbolized) in multizip((stacks.iter(), symbolized)) {
            let fname = if include_offset {
                format!("{}-{:x}", stack.name, stack.offset)
            } else {
                stack.name.to_string()
            };
            let function_id = match functions.get_or_insert(&fname) {
                DictionaryEntry::Existing(function_id) => function_id,
                DictionaryEntry::New(function_id) => {
                    let mut function = proto::Function {
                        id: function_id as u64,
                        name: *strings.get_or_insert(&fname),
                        ..Default::default()
                    };
                    if let Symbolized::Sym(sym) = &symbolized {
                        if let Some(code_info) = &sym.code_info {
                            if let Some(path) = code_info.to_path().as_os_str().to_str() {
                                function.filename = *strings.get_or_insert(path);
                            }
                        }
                    }
                    function_table.push(function);
                    function_id
                }
            };
            match location_addr_to_index.entry(stack.address + stack.offset) {
                hash_map::Entry::Occupied(entry) => {
                    locations.push(*entry.get() as u64);
                }
                hash_map::Entry::Vacant(entry) => {
                    let mut line = proto::Line {
                        function_id: function_id as u64,
                        ..Default::default()
                    };
                    if let Symbolized::Sym(sym) = symbolized {
                        if let Some(code_info) = sym.code_info {
                            if let Some(code_line) = code_info.line {
                                line.line = code_line as i64;
                            }
                            if let Some(column) = code_info.column {
                                line.column = column as i64;
                            }
                        }
                    }
                    let location = proto::Location {
                        id: last_location as u64,
                        address: stack.address + stack.offset,
                        line: vec![line],
                        ..Default::default()
                    };
                    location_table.push(location);
                    locations.push(last_location as u64);
                    entry.insert(last_location);
                    last_location += 1;
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
        r#type: *strings.get_or_insert(columns[1].as_str()),
        ..Default::default()
    };
    let time_value_type = proto::ValueType {
        r#type: *strings.get_or_insert(columns[2].as_str()),
        ..Default::default()
    };
    let profile = proto::Profile {
        sample_type: vec![count_value_type, time_value_type],
        sample: samples_table,
        string_table: strings.strings_table(),
        location: location_table,
        function: function_table,
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
            let count = batch
                .column(1)
                .as_primitive_opt::<Int64Type>()
                .expect("count should be int64");
            let duration = batch
                .column(2)
                .as_primitive_opt::<UInt64Type>()
                .expect("duration should be uint64");
            multizip((count.iter(), stacks.iter(), duration.iter())).map(|(count, stacks, duration)| Stacks {
                count: count.unwrap_or(0),
                stacks,
                duration: duration.unwrap_or(0) as i64,
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
    fn stacks(&self) -> impl Iterator<Item = Stack> + '_ {
        let stack = self
            .stacks
            .as_ref()
            .unwrap()
            .as_struct_opt()
            .expect("should be a struct with 3 arrays");
        let names = stack.column(0).as_string::<i32>();
        let addresses = stack.column(1).as_primitive::<UInt64Type>();
        let offsets = stack.column(2).as_primitive::<UInt64Type>();
        multizip((names, addresses, offsets)).map(|(name, address, offset)| Stack {
            name: name.unwrap(),
            address: address.unwrap(),
            offset: offset.unwrap(),
        })
    }
}

#[derive(Debug)]
struct Stack<'a> {
    name: &'a str,
    address: u64,
    offset: u64,
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

pub(crate) async fn pprof(
    register: &str,
    destination: &PathBuf,
    query: &str,
    command: Option<&str>,
    binary: Option<PathBuf>,
    include_offset: bool,
) -> Result<()> {
    let mut query = query.to_owned();
    if let Some(command) = command {
        query = query.replace(COMMAND_BINDING, command);
    }
    if let Some(path) = &binary {
        if let Some(buildid) = read_elf_build_id(path)? {
            let buildid = buildid.as_ref().iter().fold(Vec::new(), |mut acc, &byte| {
                write!(&mut acc, "{:02x}", byte).unwrap();
                acc
            });
            let buildid = String::from_utf8(buildid)?;
            query = query.replace(BUILID_BINDING, &buildid);
        }
    }
    let ctx = session(register).await?;

    let profile = if let Some(binary) = binary {
        generate_pprof_with_symbolization(&ctx, &query, binary, include_offset).await?
    } else {
        generate_pprof(&ctx, &query, include_offset).await?
    };
    let mut f = std::fs::File::create(destination)?;
    let mut buf = vec![];
    profile.encode(&mut buf)?;
    f.write_all(&buf)?;
    Ok(())
}
