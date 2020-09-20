use bytes::Buf;
use std::ops::Range;
use super::HasBodyRange;

pub trait StoreOffset {
    fn push_limit(&mut self, limit: usize);
    fn pop_limit(&mut self);

    fn offset(&self) -> usize;

    fn following(&self, length: usize) -> Range<usize> {
        self.offset()..(self.offset() + length)
    }
}

#[derive(Clone, Debug)]
pub struct ChunkedDataBuffer<'a, C>
where
    C: HasBodyRange,
{
    data: &'a [u8],
    data_offset: usize,
    chunks: &'a [C],
    chunks_offset: usize,
    limit: usize,
    limits: Vec<usize>,
}

impl<'a, C> ChunkedDataBuffer<'a, C>
where
    C: HasBodyRange,
{
    pub fn new(data: &'a [u8], chunks: &'a [C]) -> Self {
        let mut s = ChunkedDataBuffer {
            data,
            data_offset: 0,
            chunks,
            chunks_offset: 0,
            limit: data.len(),
            limits: Vec::new(),
        };
        s.set_chunk(s.chunks_offset);
        s.limit = s.remaining();
        s
    }

    pub fn chunk(&self) -> usize {
        self.chunks_offset
    }

    pub fn set_chunk(&mut self, chunks_offset: usize) {
        self.chunks_offset = chunks_offset;
        self.data_offset = self
            .chunks
            .get(chunks_offset)
            .map(|c| c.body().start)
            .unwrap_or(usize::MAX);
        self.limit = self.remaining();
    }

    pub fn skip(&mut self) {
        self.set_chunk(self.chunk() + 1);
    }

    pub fn on(&self, space: &Range<usize>) -> bool {
        self.chunks
            .get(self.chunk())
            .map(|c| c.body().start < space.end)
            .unwrap_or(false)
    }

    pub fn complete_group<F>(&mut self, first_chunk: usize, warn: F)
    where
        F: Fn(),
    {
        if self.chunks_offset == first_chunk {
            self.chunks_offset += 1;
            warn();
        }
        self.chunks[(first_chunk + 1)..self.chunks_offset]
            .iter()
            .for_each(C::set_continuation);
    }

    pub fn has(&self, length: usize) -> bool {
        // TODO: optimize it
        self.remaining() >= length
    }

    pub fn advance_safe(&mut self, cnt: usize) -> Result<usize, ()> {
        fn try_advance<'a, C>(s: &mut ChunkedDataBuffer<'a, C>, cnt: usize) -> Result<(), ()>
        where
            C: HasBodyRange,
        {
            if cnt == 0 {
                Ok(())
            } else if s.data_offset + cnt < s.chunks[s.chunks_offset].body().end {
                s.data_offset += cnt;
                Ok(())
            } else {
                // move to the next chunk, skipping the hole
                let rem = s.bytes().len();
                if let Some(next_chunk) = s.chunks.get(s.chunks_offset + 1) {
                    s.chunks_offset += 1;
                    s.data_offset = next_chunk.body().start;
                    try_advance(s, cnt - rem)
                } else if cnt == rem {
                    s.data_offset += cnt;
                    Ok(())
                } else {
                    s.chunks_offset += 1;
                    s.data_offset = s.data.len();
                    Err(())
                }
            }
        }
        if cnt <= self.limit {
            try_advance(self, cnt).map(|()| {
                self.limit -= cnt;
                cnt
            })
        } else {
            Err(())
        }
    }
}

impl<'a, C> StoreOffset for ChunkedDataBuffer<'a, C>
where
    C: HasBodyRange,
{
    fn push_limit(&mut self, limit: usize) {
        self.limits.push(self.limit);
        self.limit = limit;
    }

    fn pop_limit(&mut self) {
        self.limit = self.limits.pop().unwrap_or_else(|| self.remaining());
    }

    fn offset(&self) -> usize {
        self.data_offset
    }
}

impl<'a, C> Buf for ChunkedDataBuffer<'a, C>
where
    C: HasBodyRange,
{
    #[inline]
    fn remaining(&self) -> usize {
        let available = self.bytes().len();
        let remaining = if self.chunks.len() - 1 > self.chunks_offset {
            self.chunks[(self.chunks_offset + 1)..]
                .iter()
                .fold(available, |a, c| {
                    if self.data.len() >= c.body().end {
                        a + c.body().len()
                    } else if self.data.len() > c.body().start {
                        a + (self.data.len() - c.body().start)
                    } else {
                        a
                    }
                })
        } else {
            available
        };
        usize::min(remaining, self.limit)
    }

    #[inline]
    fn bytes(&self) -> &[u8] {
        if self.chunks.len() == self.chunks_offset {
            &[]
        } else {
            let end = self.chunks[self.chunks_offset].body().end;
            &self.data[self.data_offset..usize::min(end, self.data_offset + self.limit)]
        }
    }

    fn advance(&mut self, cnt: usize) {
        let _ = self.advance_safe(cnt).unwrap();
    }
}
