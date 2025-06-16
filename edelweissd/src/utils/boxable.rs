use std::collections::HashMap;
use std::convert::TryInto;

pub type Boxed = Vec<u8>;

pub trait Boxable{
    fn boxed(&self) -> Boxed;
}

pub trait Unboxable where Self: Sized {
    fn from_boxed(boxed: &Boxed) -> Option<Self>;
    fn size_in_boxed_bytes(&self) -> usize;
}

pub trait ByteBox{
    fn pack<T: Boxable>(&mut self, data: &T);
}

impl ByteBox for Boxed{
    fn pack<T: Boxable>(&mut self, data: &T){
        self.append(&mut data.boxed());
    }
}

pub struct ByteBoxReader<'a>{
    bytes_box: &'a Boxed,
    offset: usize,
}

impl<'a> ByteBoxReader<'a>{
    pub fn from_boxed(bytes_box: &'a Boxed) -> Self {
        Self{bytes_box, offset: 0usize}
    }

    pub fn read<T: Unboxable>(&mut self) -> Option<T>{
        let result = T::from_boxed(&self.bytes_box[self.offset..].to_vec());
        if result.is_none(){
            return None;
        }
        let result = result.unwrap();
        self.offset += result.size_in_boxed_bytes();
        Some(result)
    }
}

impl<'a> From<&'a Boxed> for ByteBoxReader<'a>{
    fn from(value: &'a Boxed) -> Self {
        ByteBoxReader::from_boxed(value)
    }
}

// Helper macro for primitives
macro_rules! impl_boxable_for_primitive {
    ($($t:ty),*) => {
        $(
            impl Boxable for $t {
                fn boxed(&self) -> Boxed {
                    self.to_le_bytes().to_vec()
                }
            }

            impl Unboxable for $t {
                fn from_boxed(boxed: &Boxed) -> Option<Self> {
                    if boxed.len() < std::mem::size_of::<$t>() {
                        return None;
                    }
                    let bytes: [u8; std::mem::size_of::<$t>()] = boxed[..std::mem::size_of::<$t>()].try_into().ok()?;
                    Some(<$t>::from_le_bytes(bytes))
                }

                fn size_in_boxed_bytes(&self) -> usize {
                    std::mem::size_of::<$t>()
                }
            }
        )*
    };
}

impl_boxable_for_primitive!(usize, u8, u16, u32, u64, i8, i16, i32, i64, f32, f64);

// String
impl Boxable for String {
    fn boxed(&self) -> Boxed {
        let mut boxed = (self.len() as u32).to_le_bytes().to_vec();
        boxed.extend_from_slice(self.as_bytes());
        boxed
    }
}

impl Unboxable for String {
    fn from_boxed(boxed: &Boxed) -> Option<Self> {
        if boxed.len() < 4 {
            return None;
        }
        let len = u32::from_le_bytes(boxed[0..4].try_into().ok()?) as usize;
        if boxed.len() < 4 + len {
            return None;
        }
        let string_bytes = &boxed[4..4 + len];
        Some(String::from_utf8(string_bytes.to_vec()).ok()?)
    }

    fn size_in_boxed_bytes(&self) -> usize {
        4 + self.len()
    }
}

// Vec<T>
impl<T: Boxable + Unboxable> Boxable for Vec<T> {
    fn boxed(&self) -> Boxed {
        let mut result = Vec::new();
        result.extend_from_slice(&(self.len() as u32).to_le_bytes());
        for item in self {
            result.pack(item);
        }
        result
    }
}

impl<T: Unboxable> Unboxable for Vec<T> {
    fn from_boxed(boxed: &Boxed) -> Option<Self> {
        if boxed.len() < 4 {
            return None;
        }
        let len = u32::from_le_bytes(boxed[0..4].try_into().ok()?) as usize;
        let mut items = Vec::with_capacity(len);
        let binding = boxed[4..].to_vec();
        let mut reader = ByteBoxReader::from_boxed(&binding);
        for _ in 0..len {
            items.push(reader.read()?);
        }
        Some(items)
    }

    fn size_in_boxed_bytes(&self) -> usize {
        4 + self.iter().map(|v| v.size_in_boxed_bytes()).sum::<usize>()
    }
}

// HashMap<K, V>
impl<K, V> Boxable for HashMap<K, V>
where
    K: Boxable,
    V: Boxable,
{
    fn boxed(&self) -> Boxed {
        let mut result = Vec::new();
        result.extend_from_slice(&(self.len() as u32).to_le_bytes());
        for (k, v) in self {
            result.pack(k);
            result.pack(v);
        }
        result
    }
}

impl<K, V> Unboxable for HashMap<K, V>
where
    K: Unboxable + Eq + std::hash::Hash,
    V: Unboxable,
{
    fn from_boxed(boxed: &Boxed) -> Option<Self> {
        if boxed.len() < 4 {
            return None;
        }
        let len = u32::from_le_bytes(boxed[0..4].try_into().ok()?) as usize;
        let mut map = HashMap::new();
        let binding = boxed[4..].to_vec();
        let mut reader = ByteBoxReader::from_boxed(&binding);
        for _ in 0..len {
            let k = reader.read()?;
            let v = reader.read()?;
            map.insert(k, v);
        }
        Some(map)
    }

    fn size_in_boxed_bytes(&self) -> usize {
        4 + self.iter().map(|(k, v)| k.size_in_boxed_bytes() + v.size_in_boxed_bytes()).sum::<usize>()
    }
}