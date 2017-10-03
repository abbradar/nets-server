use std::borrow::Cow;
use std::ptr;
use std::ops::Deref;

pub trait VecExt : Deref {
  /// **Panics** if `index` is out of bounds.
  fn insert_slice(&mut self, index: usize, s: &Self::Target);
}

impl<T> VecExt for Vec<T> {
  fn insert_slice(&mut self, index: usize, s: &Self::Target) {
    self.reserve(s.len());
    // move the tail, then copy in the string
    unsafe {
      let ptr = self.as_mut_ptr();
      ptr::copy(ptr.offset(index as isize),
                ptr.offset((index + s.len()) as isize),
                self.len() - index);
      ptr::copy_nonoverlapping(s.as_ptr(),
                               ptr.offset(index as isize),
                               s.len());
      let new_len = self.len() + s.len();
      self.set_len(new_len);
    }
  }
}

pub fn escape_str(s: &[u8]) -> Cow<[u8]> {
  let mut r = Cow::Borrowed(s);
  let mut i = 0;
  while i < r.len() {
    let c = r[i];
    if c < (' ' as u8) {
      let rm = r.to_mut();
      rm[i] = '\\' as u8;
      rm.insert_slice(i + 1, format!("{:02x}", c).as_bytes());
      i += 2;
    }
    i += 1;
  }
  return r
}
