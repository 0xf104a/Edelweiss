use crate::scanner::{ForkEvent, ProcFilter};

/// Default filter that allows all events
pub(crate) struct DefaultFilter{}

impl DefaultFilter{
    pub(crate) fn new() -> Self{
        Self{}
    }
}
impl ProcFilter for DefaultFilter{
    #[inline]
    fn filter(&self, event: ForkEvent) -> bool {
        true
    }
}
