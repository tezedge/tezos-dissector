use std::ops::Range;

pub fn intersect(space: &Range<usize>, item: Range<usize>) -> Range<usize> {
    if item.end <= space.start {
        0..0
    } else if item.start >= space.end {
        space.len()..space.len()
    } else {
        let start = usize::max(space.start, item.start) - space.start;
        let end = usize::min(space.end, item.end) - space.start;
        start..end
    }
}
