use failure::Fail;
use std::ops::Range;
use super::HasBodyRange;

#[derive(Clone)]
pub struct ChunkedData<'a, C>
where
    C: HasBodyRange,
{
    inner: ChunkedDataInner<'a, C>,
}

impl<'a, C> ChunkedData<'a, C>
where
    C: HasBodyRange,
{
    pub fn new(chunks: &'a [C]) -> Self {
        ChunkedData {
            inner: ChunkedDataInner {
                data_offset: chunks.first().unwrap().body().start,
                chunks,
                chunks_offset: 0,
                limit: None,
                limits: Vec::new(),
            },
        }
}

    pub fn chunk(&self) -> usize {
        self.inner.chunks_offset
    }

    pub fn skip(&mut self) {
        self.inner.chunks_offset += 1;
        self.inner.data_offset = self
            .inner
            .chunks
            .get(self.inner.chunks_offset)
            .map(|c| c.body().start)
            .unwrap_or(usize::MAX);
        self.inner.limit = None;
        self.inner.limits.clear();
    }

    pub fn on(&self, space: &Range<usize>) -> bool {
        self.inner
            .chunks
            .get(self.inner.chunks_offset)
            .map(|c| c.body().start < space.end)
            .unwrap_or(false)
    }

    pub fn complete_group<F>(&mut self, first_chunk: usize, warn: F)
    where
        F: Fn(),
    {
        if self.inner.chunks_offset == first_chunk {
            self.skip();
            warn();
        }
        self.inner.chunks[(first_chunk + 1)..self.inner.chunks_offset]
            .iter()
            .for_each(C::set_continuation);
        self.inner.chunks[first_chunk..(self.inner.chunks_offset - 1)]
            .iter()
            .for_each(C::set_incomplete);
    }

    pub fn inner_mut(&mut self) -> &mut ChunkedDataInner<'a, C> {
        &mut self.inner
    }
}

#[derive(Debug, Fail)]
pub enum DecodingError {
    #[fail(display = "Not enough bytes")]
    NotEnoughData,
    #[fail(display = "Tag size not supported")]
    TagSizeNotSupported,
    #[fail(display = "Tag not found")]
    TagNotFound,
    #[fail(display = "Unexpected option value")]
    UnexpectedOptionDiscriminant,
    #[fail(display = "Path tag should be 0x00 or 0x0f or 0xf0")]
    BadPathTag,
}

#[derive(Clone)]
pub struct ChunkedDataInner<'a, C>
where
    C: HasBodyRange,
{
    data_offset: usize,
    chunks: &'a [C],
    chunks_offset: usize,
    limit: Option<usize>,
    limits: Vec<Option<usize>>,
}

macro_rules! primitive {
    ($method:ident, $t:ty) => {
        pub fn $method(&mut self) -> Result<$t, DecodingError> {
            let mut bytes = [0; std::mem::size_of::<$t>()];
            self.copy_to_slice(bytes.as_mut())?;
            Ok(<$t>::from_be_bytes(bytes))
        }
    };
}

impl<'a, C> ChunkedDataInner<'a, C>
where
    C: HasBodyRange,
{
    #[inline(always)]
    pub fn bytes(&self) -> &[u8] {
        if let Some(chunk) = self.chunks.get(self.chunks_offset) {
            let end = match &self.limit {
                &Some(ref limit) => usize::min(chunk.body().end, self.data_offset + limit.clone()),
                &None => chunk.body().end,
            };
            let offset = chunk.range().start;
            &chunk.data()[(self.data_offset - offset)..(end - offset)]
        } else {
            &[]
        }
    }

    #[inline(always)]
    pub fn remaining(&self) -> usize {
        let limit = self.limit.unwrap_or(usize::MAX);
        let mut available = self.bytes().len();
        if limit < available {
            return limit;
        }
        if self.chunks.len() - 1 > self.chunks_offset {
            for c in &self.chunks[(self.chunks_offset + 1)..] {
                available += c.body().len();
                if limit < available {
                    return limit;
                }
            }
        }
        available
    }

    #[inline(always)]
    pub fn has(&self, length: usize) -> bool {
        let limit = self.limit.unwrap_or(usize::MAX);
        let mut available = self.bytes().len();
        if length <= usize::min(available, limit) {
            return true;
        }
        if self.chunks.len() - 1 > self.chunks_offset {
            for c in &self.chunks[(self.chunks_offset + 1)..] {
                available += c.body().len();
                if length <= usize::min(available, limit) {
                    return true;
                }
            }
        }
        true
    }

    pub fn advance(&mut self, cnt: usize) -> Result<usize, DecodingError> {
        fn try_advance<'a, C>(s: &mut ChunkedDataInner<'a, C>, cnt: usize) -> Result<(), ()>
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
                    s.data_offset = s.chunks.last().unwrap().body().end;
                    Err(())
                }
            }
        }
        if cnt <= self.limit.unwrap_or(usize::MAX) {
            try_advance(self, cnt)
                .map(|()| {
                    if let &mut Some(ref mut limit) = &mut self.limit {
                        *limit -= cnt;
                    }
                    self.limits
                        .iter_mut()
                        .for_each(|limit| limit.iter_mut().for_each(|limit| *limit -= cnt));
                    cnt
                })
                .map_err(|()| DecodingError::NotEnoughData)
        } else {
            Err(DecodingError::NotEnoughData)
        }
    }

    pub fn push_limit(&mut self, limit: usize) {
        self.limits.push(self.limit);
        self.limit = Some(limit);
    }

    pub fn pop_limit(&mut self) {
        self.limit = self.limits.pop().unwrap_or(None);
    }

    pub fn offset(&self) -> usize {
        self.data_offset
    }

    pub fn following(&self, length: usize) -> Range<usize> {
        self.offset()..(self.offset() + length)
    }

    pub fn copy_to_slice(&mut self, slice: &mut [u8]) -> Result<(), DecodingError> {
        let mut offset = 0;

        while offset < slice.len() {
            let source = self.bytes();
            if source.is_empty() {
                return Err(DecodingError::NotEnoughData);
            }

            let cnt = usize::min(source.len(), slice.len() - offset);

            slice[offset..(offset + cnt)].clone_from_slice(&source[..cnt]);

            offset += cnt;

            self.advance(cnt)?;
        }

        Ok(())
    }

    pub fn copy_to_vec(&mut self, length: usize) -> Result<Vec<u8>, DecodingError> {
        if self.has(length) {
            let mut buffer = vec![0; length];
            self.copy_to_slice(buffer.as_mut_slice())?;
            Ok(buffer)
        } else {
            Err(DecodingError::NotEnoughData)
        }
    }

    primitive!(get_u8, u8);
    primitive!(get_i8, i8);
    primitive!(get_u16, u16);
    primitive!(get_i16, i16);
    primitive!(get_u32, u32);
    primitive!(get_i32, i32);
    primitive!(get_i64, i64);
    primitive!(get_f64, f64);
}
