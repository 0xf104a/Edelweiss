use crate::scanner::{ProcEvent, ProcFilter};

/// Default filter that allows all events to pass
pub(crate) struct DefaultFilter{}

impl DefaultFilter{
    pub(crate) fn new() -> Self{
        Self{}
    }
}

impl ProcFilter for DefaultFilter{
    #[inline]
    fn filter(&self, _event: ProcEvent) -> bool {
        true
    }
}
