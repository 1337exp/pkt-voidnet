//! Fixed-capacity FIFO. Pushing into a full ring fails; nothing is overwritten.
//! FIFO фиксированной ёмкости. Добавление в полное кольцо не удаётся, ничего не затирается.

/// A FIFO of at most `CAP` items. / Очередь не более `CAP` элементов.
#[derive(Clone, Debug)]
pub struct Ring<T: Copy + Default, const CAP: usize> {
    items: [T; CAP],
    head: usize,
    len: usize,
}

impl<T: Copy + Default, const CAP: usize> Default for Ring<T, CAP> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Copy + Default, const CAP: usize> Ring<T, CAP> {
    pub fn new() -> Self {
        Self {
            items: [T::default(); CAP],
            head: 0,
            len: 0,
        }
    }

    /// Empty the ring without touching the items (they are overwritten before they are read).
    /// Опустошить кольцо, не трогая элементы (их перезаписывают до чтения).
    pub fn reset(&mut self) {
        self.head = 0;
        self.len = 0;
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn free(&self) -> usize {
        CAP - self.len
    }

    /// Append; `false` (and the item is dropped) if the ring is full.
    /// Добавить; `false` (элемент теряется), если кольцо полно.
    pub fn push(&mut self, item: T) -> bool {
        if self.len == CAP {
            return false;
        }
        let tail = (self.head + self.len) % CAP;
        if let Some(slot) = self.items.get_mut(tail) {
            *slot = item;
            self.len += 1;
            true
        } else {
            false
        }
    }

    pub fn pop(&mut self) -> Option<T> {
        if self.len == 0 {
            return None;
        }
        let item = self.items.get(self.head).copied();
        self.head = (self.head + 1) % CAP;
        self.len -= 1;
        item
    }

    pub fn peek(&self) -> Option<&T> {
        if self.len == 0 {
            None
        } else {
            self.items.get(self.head)
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
mod tests {
    use super::*;

    #[test]
    fn fifo_and_wraparound() {
        let mut r: Ring<u32, 3> = Ring::new();
        assert!(r.push(1) && r.push(2) && r.push(3));
        assert!(!r.push(4), "full ring must refuse");
        assert_eq!(r.pop(), Some(1));
        assert!(r.push(4));
        assert_eq!(
            (r.pop(), r.pop(), r.pop(), r.pop()),
            (Some(2), Some(3), Some(4), None)
        );
        for i in 0..10 {
            assert!(r.push(i));
            assert_eq!(r.pop(), Some(i));
        }
        assert_eq!(r.free(), 3);
    }
}
