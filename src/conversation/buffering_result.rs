// TODO: replace with `std::task::Poll`
pub enum BufferingResult<T, E> {
    Ready(T),
    Buffering,
    Unrecognized(E),
}

impl<T, E> BufferingResult<T, E> {
    pub fn map<F, U>(self, op: F) -> BufferingResult<U, E>
    where
        F: FnOnce(T) -> U,
    {
        match self {
            BufferingResult::Ready(t) => BufferingResult::Ready(op(t)),
            BufferingResult::Buffering => BufferingResult::Buffering,
            BufferingResult::Unrecognized(e) => BufferingResult::Unrecognized(e),
        }
    }

    pub fn or<F>(self, op: F) -> Self
    where
        F: FnOnce(E) -> Self,
    {
        match self {
            BufferingResult::Ready(t) => BufferingResult::Ready(t),
            BufferingResult::Buffering => BufferingResult::Buffering,
            BufferingResult::Unrecognized(e) => op(e),
        }
    }
}