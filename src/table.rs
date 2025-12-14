use crate::FswError;
use crate::Result;

/*
 * Table entry format:
 *     own key
 *     left child ptr
 *     right child ptr
 *     own value
 *   key is relative to parent key
 *   ptrs are offsets from end of current entry
 */
struct BuildCtx {
    buf: Vec<u8>,       // built up from back to front
}

pub(crate) fn build(arr: &[(u64, u64)]) -> Result<Vec<u8>> {
    println!("Building table with {} entries", arr.len());
    /*
    let mut arr = Vec::with_capacity(map.len());
    // expand map into array so we can address it by index
    for (key, value) in map {
        arr.push((key as i64, value));
    }
    */
    let mut ctx = BuildCtx {
        buf: Vec::new(),
    };
    build_recurse(&mut ctx, arr, 0)?;

    println!("Built table, size {} bytes", ctx.buf.len());

    ctx.buf.reverse();

    Ok(ctx.buf)
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum Value {
    EmptyPtr,
    RelKey(i64),
    RelPtr(u64),
    Val(u64),
}

//
// encoding:
// ptrs: we limit the table size to 2MB, so 21 bits
//   00-EF: encode as 1 byte
//   F0-F7: first byte with 3 lower bits of value, followd by 2 bytes (little-endian)
//   f8   : EmptyPtr
// values:
//   00-F7: encode as 1 byte
//   F8-FF: first byte with 3 lower bits of value, followd by 2 bytes (little-endian)
// RelKey:
//   -127 to 127: 1 bytes directly. val + 120
//   FF: followed by 8 bytes i64 (little-endian)
//
// Maximum encodable table size is 256k
//
impl Value {
    pub fn as_bytes(&self) -> Result<Vec<u8>> {
        Ok(match self {
            Value::RelKey(v) => {
                if *v >= -127 && *v <= 127 {
                    Vec::from([(*v as i8 + 120) as u8])
                } else {
                    let mut b = Vec::with_capacity(9);
                    b.push(0xff);
                    b.extend(&v.to_le_bytes());
                    b
                }
            }
            Value::RelPtr(v) | Value::Val(v) => {
                if *v <= 0xef {
                    Vec::from([*v as u8])
                } else if *v <= 0x3ffff {
                    let b0 = 0xf0 | (((*v >> 16) as u8) & 0x07);
                    let b1 = (*v & 0xff) as u8;
                    let b2 = ((*v >> 8) & 0xff) as u8;
                    Vec::from([b0, b1, b2])
                } else {
println!("Value too large to encode: {:?}", self);
                    return Err(FswError::TableValueEncodeError);
                }
            }
            Value::EmptyPtr => Vec::from([0xf8]),
        })
    }
    pub fn read_rel_ptr(b: &[u8]) -> Result<(Value, usize)> {
        let Some(v) = b.get(0) else {
            return Err(FswError::TableValueDecodeError);
        };
        if *v < 0xf0 {
            Ok((Value::RelPtr(*v as u64), 1))
        } else if *v >= 0xf0 && *v <= 0xf7 {
            let Some(b1) = b.get(1) else {
                return Err(FswError::TableValueDecodeError);
            };
            let Some(b2) = b.get(2) else {
                return Err(FswError::TableValueDecodeError);
            };
            let val = (((*v as u64 & 0x07) << 16) | ((*b2 as u64) << 8) | (*b1 as u64)) as u64;
            Ok((Value::Val(val), 3))
        } else if *v == 0xf8 {
            Ok((Value::EmptyPtr, 1))
        } else {
            Err(FswError::TableValueDecodeError)
        }
    }
    pub fn read_val(b: &[u8]) -> Result<(Value, usize)> {
        let Some(v) = b.get(0) else {
            return Err(FswError::TableValueDecodeError);
        };
        if *v < 0xf8 {
            Ok((Value::Val(*v as u64), 1))
        } else {
            let Some(b1) = b.get(1) else {
                return Err(FswError::TableValueDecodeError);
            };
            let Some(b2) = b.get(2) else {
                return Err(FswError::TableValueDecodeError);
            };
            let val = (((*v as u64 & 0x07) << 16) | ((*b2 as u64) << 8) | (*b1 as u64)) as u64;
            Ok((Value::Val(val), 3))
        }
    }
    pub fn read_rel_key(b: &[u8]) -> Result<(Value, usize)> {
        let Some(v) = b.get(0) else {
            return Err(FswError::TableValueDecodeError);
        };
        if *v == 0xff {
            if b.len() < 9 {
                return Err(FswError::TableValueDecodeError);
            }
            let key = i64::from_le_bytes(b[1..9].try_into().unwrap());
            Ok((Value::RelKey(key), 9))
        } else {
            let key = (*v as i8 - 120) as i64;
            Ok((Value::RelKey(key), 1))
        }
    }
}

fn push_number(buf: &mut Vec<u8>, n: Value) -> Result<()> {
    let mut b = n.as_bytes()?;
    b.reverse();
    buf.extend(b);
    Ok(())
}

fn build_recurse(
    ctx: &mut BuildCtx,
    arr: &[(u64, u64)],
    parent_key: u64,
) -> Result<u64> {
    if arr.is_empty() {
        return Ok(0);
    }

    let len = arr.len();
    // take out middle key
    let mid = len / 2;
    let left = &arr[..mid];
    let right = &arr[mid + 1..];
    let own_key = arr[mid].0;
    let own_value = arr[mid].1;
//    println!("build_recurse: {} entries, middle {} left len {} right len {}",
//       arr.len(), mid, left.len(), right.len());

    let left_ptr = build_recurse(ctx, left, own_key)?;
    let right_ptr = build_recurse(ctx, right, own_key)?;

    // we build from back to front, so push in reverse order
    push_number(&mut ctx.buf, Value::Val(own_value))?;
    if right_ptr == 0 {
        push_number(&mut ctx.buf, Value::EmptyPtr)?;
    } else {
        let pos = ctx.buf.len() as u64;
        push_number(&mut ctx.buf, Value::RelPtr(pos - right_ptr))?;
    }
    if left_ptr == 0 {
        push_number(&mut ctx.buf, Value::EmptyPtr)?;
    } else {
        let pos = ctx.buf.len() as u64;
        push_number(&mut ctx.buf, Value::RelPtr(pos - left_ptr))?;
    }
    push_number(&mut ctx.buf, Value::RelKey(own_key as i64 - parent_key as i64))?;

    Ok(ctx.buf.len() as u64)
}

// tests
#[cfg(test)]
mod tests {
    use super::*;
    use crate::Result;
    fn traverse_tree_recurse(table: &Vec<u8>, mut offset: usize, parent_key: i64)
        -> Result<()>
    {
        let own_offset = offset;
        let (Value::RelKey(mut own_key), advance) = Value::read_rel_key(&table[offset..])? else {
            panic!("Expected RelKey at offset {}", offset);
        };
        own_key += parent_key;
        offset += advance;
        let (left_ptr, advance) = Value::read_rel_ptr(&table[offset..])?;
        offset += advance;
        let left_offset = offset;
        let (right_ptr, advance) = Value::read_rel_ptr(&table[offset..])?;
        offset += advance;
        let right_offset = offset;
        let (own_value, _) = Value::read_val(&table[offset..])?;
        if let Value::RelPtr(ptr) = left_ptr {
            traverse_tree_recurse(&table, left_offset + ptr as usize, own_key)?;
        }
        println!("Node at offset {}: key {:?}, value {:?}, left {:?}, right {:?}",
            own_offset, own_key, own_value, left_ptr, right_ptr);
        if let Value::RelPtr(ptr) = right_ptr {
            traverse_tree_recurse(&table, right_offset + ptr as usize, own_key)?;
        }
        Ok(())
    }

    #[test]
    fn test_build() {
        let mut arr = Vec::new();
        arr.push((1000, 1));
        arr.push((1005, 2));
        arr.push((1006, 3));
        arr.push((1008, 4));
        arr.push((1012, 5));
        arr.push((1013, 6));
        arr.push((1014, 7));
        let table = build(&arr).unwrap();
        assert!(!table.is_empty());
        println!("Built table: {:?}", table);
        for (i, v) in table.iter().enumerate() {
            println!("{}: {:x?}", i, v);
        }
        traverse_tree_recurse(&table, 0, 0).unwrap();
    }
}
