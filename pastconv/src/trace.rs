// subset of the events specified in chrome trace viewer documentation
// https://docs.google.com/document/d/1CvAClvFfyA5R-PhYUmn5OOQtYMH4h6I0nSsKchNAySU/preview#heading=h.yr4qxyxotyw

use std::{cell::RefCell, collections::HashMap, fs::File, path::PathBuf};

use anyhow::{Context, Result};
use datafusion::{
    arrow::array::{
        AsArray, GenericListArray, Int64Array, ListArray, RecordBatch, StringArray, UInt16Array, UInt32Array,
        UInt64Array,
    },
    prelude::SessionContext,
};
use serde::{
    ser::{SerializeMap, SerializeSeq, SerializeStruct},
    Serialize, Serializer,
};
use serde_json::Serializer as JsonSerializer;

fn serialize_vec_string<S>(vec: &[String], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let s = vec.join(",");
    serializer.serialize_str(&s)
}

#[derive(Debug, Serialize)]
enum TimeUnit {
    #[serde(rename = "ns")]
    Nanoseconds,
}

#[derive(Debug, Serialize)]
enum CompletePhase {
    X,
}

#[derive(Debug, Serialize)]
struct CommonArgs {
    #[serde(skip_serializing_if = "Option::is_none")]
    amount: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cpu: Option<u64>,
}

#[derive(Debug, Serialize)]
struct CounterArgs {
    #[serde(skip_serializing_if = "Option::is_none")]
    amount: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rate: Option<u64>,
}

#[derive(Debug, Serialize)]
struct Complete {
    name: String,
    #[serde(
        rename = "cat",
        serialize_with = "serialize_vec_string",
        skip_serializing_if = "Vec::is_empty"
    )]
    categories: Vec<String>,
    #[serde(rename = "ph")]
    phase: CompletePhase,
    #[serde(rename = "ts")]
    start: u64,
    #[serde(rename = "dur")]
    duration: u64,
    tid: u32,
    pid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    sf: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    esf: Option<u64>,
    args: CommonArgs,
}

#[derive(Debug, Serialize)]
enum CounterPhase {
    C,
}

#[derive(Debug, Serialize)]
struct Counter {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(
        rename = "cat",
        serialize_with = "serialize_vec_string",
        skip_serializing_if = "Vec::is_empty"
    )]
    categories: Vec<String>,
    #[serde(rename = "ph")]
    phase: CounterPhase,
    #[serde(rename = "ts")]
    timestamp: u64,
    pid: u32,
    args: CounterArgs,
}

pub(crate) async fn export(ctx: &SessionContext, queries: Vec<String>, out: PathBuf) -> Result<()> {
    let mut output = File::create(out)?;
    let stacks_graph = StackTraceGraph {
        next_id: RefCell::new(0),
        edges: RefCell::new(HashMap::new()),
    };
    let mut serializer = JsonSerializer::new(&mut output);
    {
        let mut object = Serializer::serialize_struct(&mut serializer, "Object", 2)?;
        // collecting all queries results into batches will very likely blowup
        // it would be natural to have an API such as
        //      let field = object.open_field("traceEvents")?;
        //      ... write to field ...
        //      field.end()?;
        let mut batches = vec![];
        for query in queries.into_iter() {
            batches.extend(ctx.sql(&query).await.context(query)?.collect().await?);
        }
        object.serialize_field("traceEvents", &EventsStream(batches, &stacks_graph))?;
        object.serialize_field("displayTimeUnit", &TimeUnit::Nanoseconds)?;
        object.serialize_field("stackFrames", &stacks_graph)?;
        SerializeStruct::end(object)?;
    }
    Ok(())
}

#[derive(Debug)]
struct EventsStream<'a>(Vec<RecordBatch>, &'a StackTraceGraph);

impl<'a> Serialize for EventsStream<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let rows = self.0.iter().map(|batch| batch.num_rows()).sum();
        if rows == 0 {
            return serializer.serialize_none();
        }
        let mut seq = serializer.serialize_seq(Some(rows))?;
        for batch in &self.0 {
            // this columns are always there
            let event_col = batch
                .column_by_name("event")
                .ok_or_else(|| serde::ser::Error::custom("event column must be present"))?
                .as_any()
                .downcast_ref::<StringArray>()
                .expect("event must be utf8 string");
            let name_col = batch
                .column_by_name("name")
                .ok_or_else(|| serde::ser::Error::custom("name column must be present"))?
                .as_any()
                .downcast_ref::<StringArray>()
                .expect("name must be utf8 string");
            let pid_col = batch
                .column_by_name("pid")
                .ok_or_else(|| serde::ser::Error::custom("pid column must be present"))?
                .as_any()
                .downcast_ref::<UInt32Array>()
                .expect("pid must be u32");

            // optional columns
            let start_col = batch
                .column_by_name("start")
                .map(|col| col.as_any().downcast_ref::<Int64Array>().expect("start must be i64"));
            let timestamp_col = batch.column_by_name("timestamp").map(|col| {
                col.as_any()
                    .downcast_ref::<Int64Array>()
                    .expect("timestamp must be i64")
            });
            let duration_col = batch
                .column_by_name("duration")
                .map(|col| col.as_any().downcast_ref::<Int64Array>().expect("duration must be i64"));
            let tid_col = batch
                .column_by_name("tid")
                .map(|col| col.as_any().downcast_ref::<UInt32Array>().expect("tid must be u32"));

            let kind_col = batch.column_by_name("kind").map(|col| {
                col.as_any()
                    .downcast_ref::<StringArray>()
                    .expect("kind must be utf8 string")
            });
            let cpu_col = batch
                .column_by_name("cpu")
                .map(|col| col.as_any().downcast_ref::<UInt16Array>().expect("cpu must be u16"));
            let amount_col = batch
                .column_by_name("amount")
                .map(|col| col.as_any().downcast_ref::<UInt64Array>().expect("amount must be u64"));
            let rate_col = batch
                .column_by_name("rate")
                .map(|col| col.as_any().downcast_ref::<UInt64Array>().expect("rate must be u64"));

            let stack = batch
                .column_by_name("stack")
                .map(|col| col.as_any().downcast_ref::<ListArray>().expect("stack must be list"));
            let end_stack = batch
                .column_by_name("end_stack")
                .map(|col| col.as_any().downcast_ref::<ListArray>().expect("estack must be list"));

            for (i, event) in event_col.iter().enumerate() {
                // let event = event_col.value(i);
                let mut categories = vec![];
                categories.push(format!("command={}", name_col.value(i)));
                if let Some(cpu) = cpu_col {
                    let cpu = cpu.value(i);
                    categories.push(format!("cpu={}", cpu));
                }
                if let Some(kind) = kind_col {
                    let kind = kind.value(i);
                    categories.push(format!("kind={}", kind));
                }

                match event {
                    Some("complete") => {
                        let event = Complete {
                            name: name_col.value(i).to_string(),
                            categories,
                            phase: CompletePhase::X,
                            start: start_col.map(|col| col.value(i) as u64).unwrap_or(0),
                            duration: duration_col.map(|col| col.value(i) as u64).unwrap_or(0),
                            tid: tid_col.map(|col| col.value(i)).unwrap_or(0),
                            pid: pid_col.value(i),
                            sf: if let Some(stack) = stack {
                                Some(collect_stacks_into_graph::<S>(self.1, stack, i)?)
                            } else {
                                None
                            },
                            esf: if let Some(stacks) = end_stack {
                                Some(collect_stacks_into_graph::<S>(self.1, stacks, i)?)
                            } else {
                                None
                            },
                            args: CommonArgs {
                                amount: amount_col.map(|col| col.value(i)),
                                cpu: cpu_col.map(|col| col.value(i) as u64),
                            },
                        };
                        seq.serialize_element(&event)
                    }
                    Some("counter") => {
                        let event = Counter {
                            name: name_col.value(i).to_string(),
                            id: kind_col.map(|col| col.value(i).to_string()),
                            categories,
                            phase: CounterPhase::C,
                            timestamp: timestamp_col.map(|col| col.value(i) as u64).unwrap_or(0),
                            pid: pid_col.value(i),
                            args: CounterArgs {
                                amount: amount_col.map(|col| col.value(i)),
                                rate: rate_col.map(|col| col.value(i)),
                            },
                        };
                        seq.serialize_element(&event)
                    }
                    Some(unknown) => {
                        return Err(serde::ser::Error::custom(format!(
                            "unknown event type: {}. supported events: complete, counter",
                            unknown
                        )));
                    }
                    None => Err(serde::ser::Error::custom("event must be present")),
                }?;
            }
        }
        seq.end()
    }
}

fn collect_stacks_into_graph<S: Serializer>(
    graph: &StackTraceGraph,
    stacks: &GenericListArray<i32>,
    row: usize,
) -> Result<u64, S::Error> {
    let row = stacks.value(row);
    let traces = row
        .as_struct()
        .column_by_name("name")
        .ok_or_else(|| serde::ser::Error::custom("name is not present in results"))?
        .as_any()
        .downcast_ref::<StringArray>()
        .expect("name must be utf8 string")
        .iter()
        .filter_map(|name| name.map(|s| s.to_string()))
        .collect::<Vec<String>>();
    Ok(graph.insert(traces))
}

#[derive(Debug, Serialize, PartialEq, Eq, Hash)]
struct Frame {
    #[serde(skip_serializing_if = "Option::is_none")]
    parent: Option<String>,
    name: String,
}

#[derive(Debug)]
struct StackTraceGraph {
    next_id: RefCell<u64>,
    edges: RefCell<HashMap<Frame, u64>>,
}

impl StackTraceGraph {
    fn insert(&self, traces: Vec<String>) -> u64 {
        let mut parent: Option<String> = None;
        let mut leaf = 0;
        let mut edges = self.edges.borrow_mut();
        for trace in traces {
            let frame = Frame {
                parent: parent.clone(),
                name: trace,
            };
            match edges.get(&frame) {
                Some(id) => {
                    leaf = *id;
                    parent = Some(id.to_string());
                }
                None => {
                    let id = *self.next_id.borrow();
                    self.next_id.replace(id + 1);
                    edges.insert(frame, id);
                    leaf = id;
                    parent = Some(id.to_string());
                }
            }
        }
        leaf
    }
}

impl Serialize for StackTraceGraph {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(self.edges.borrow().len()))?;
        for (frame, id) in self.edges.borrow().iter() {
            let id = id.to_string();
            map.serialize_key(&id)?;
            map.serialize_value(frame)?;
        }
        map.end()
    }
}
