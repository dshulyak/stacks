use probe::probe;
use tracing::{field::Visit, Subscriber};
use tracing_core::span;
use tracing_subscriber::{prelude::*, Registry};

pub fn init() {
    let registry = Registry::default().with(PastSubscriber {});
    tracing::dispatcher::set_global_default(registry.into()).expect("failed to set global subscriber");
}

#[derive(Debug, Clone)]
struct SpanInfo {
    span_id: u64,
    parent_span_id: u64,
    id: u64,
    amount: u64,
    name: [u8; 16],

    exit_stack: bool,
}

const ID: &str = "id";
const THROUGHPUT_METRIC: &str = "amount";
const EXIT_STACK: &str = "exit_stack";

impl Visit for SpanInfo {
    fn record_u64(&mut self, field: &tracing_core::Field, value: u64) {
        match field.name() {
            ID => self.id = value,
            THROUGHPUT_METRIC => self.amount = value,
            _ => {}
        }
    }

    fn record_bool(&mut self, field: &tracing_core::Field, value: bool) {
        if field.name() == EXIT_STACK {
            self.exit_stack = value;
        }
    }

    fn record_debug(&mut self, _: &tracing_core::Field, _: &dyn std::fmt::Debug) {}
}

pub struct PastSubscriber {}

impl<S> tracing_subscriber::Layer<S> for PastSubscriber
where
    S: Subscriber + for<'span> tracing_subscriber::registry::LookupSpan<'span>,
{
    fn on_new_span(&self, attrs: &span::Attributes<'_>, id: &span::Id, ctx: tracing_subscriber::layer::Context<'_, S>) {
        if let Some(span) = ctx.span(id) {
            let name = attrs.metadata().name();
            let buf = {
                let mut buf = [0u8; 16];
                let lth = name.len().min(buf.len());
                buf[..lth].copy_from_slice(name.as_bytes()[..lth].as_ref());
                buf
            };
            let mut info = SpanInfo {
                name: buf,
                parent_span_id: attrs.parent().or(ctx.current_span().id()).map_or(0, |id| id.into_u64()),
                span_id: id.into_u64(),
                id: 0,
                amount: 0,
                exit_stack: false,
            };
            attrs.record(&mut info);
            span.extensions_mut().insert(info);
        }
    }

    fn on_enter(&self, id: &span::Id, ctx: tracing_subscriber::layer::Context<'_, S>) {
        if let Some(span) = ctx.span(id) {
            let extensions = span.extensions();
            let span_info = extensions.get::<SpanInfo>().unwrap();
            probe!(
                past_tracing,
                enter,
                span_info.span_id as *const u64,
                span_info.parent_span_id as *const u64,
                span_info.id as *const u64,
                span_info.amount as *const u64,
                span_info.name.as_ptr()
            );
        }
    }

    fn on_exit(&self, id: &span::Id, ctx: tracing_subscriber::layer::Context<'_, S>) {
        if let Some(span) = ctx.span(id) {
            let extensions = span.extensions();
            let span_info = extensions.get::<SpanInfo>().unwrap();
            if span_info.exit_stack {
                probe!(past_tracing, exit_stack, span_info.span_id as *const u64);
            } else {
                probe!(past_tracing, exit, span_info.span_id as *const u64);
            }
        }
    }

    fn on_close(&self, id: span::Id, ctx: tracing_subscriber::layer::Context<'_, S>) {
        if let Some(span) = ctx.span(&id) {
            let extensions = span.extensions();
            let span_info = extensions.get::<SpanInfo>().unwrap();
            probe!(past_tracing, close, span_info.span_id as *const u64,);
        }
    }
}
