pub mod boxable;
pub mod tokio;
pub mod startable;
pub mod notifier;

#[macro_export]
macro_rules! any {
    ($x:expr) => {
        $x
    };
    ($x:expr, $($xs:expr),+) => {
        $x || any!($($xs),+)
    };
}

#[macro_export]
macro_rules! sum {
    () => { 0 }; // Optional: return zero when nothing is passed
    ($x:expr $(,)?) => {
        $x
    };
    ($x:expr, $($xs:expr),+ $(,)?) => {
        $x + sum!($($xs),+)
    };
}
