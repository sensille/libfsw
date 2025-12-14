use std::collections::BTreeMap;
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
    bytes_in_values: usize,
    empty_left_pointers: usize,
    bytes_in_left_ptr: usize,
    empty_right_pointers: usize,
    bytes_in_right_ptr: usize,
    both_pointers_empty: usize,
    bytes_in_keys: usize,
    key_size_hist_pos: [usize; 65],
    key_size_hist_neg: [usize; 65],
    ptr_size_hist: [usize; 65],
    encoded_keys_len_1: usize,
    encoded_keys_len_3: usize,
    encoded_keys_len_9: usize,
    leaf_ptrs: BTreeMap<u64, usize>,
    leaf_keys: [usize; 65],
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
        bytes_in_values: 0,
        empty_left_pointers: 0,
        bytes_in_left_ptr: 0,
        empty_right_pointers: 0,
        bytes_in_right_ptr: 0,
        both_pointers_empty: 0,
        bytes_in_keys: 0,
        key_size_hist_pos: [0; 65],
        key_size_hist_neg: [0; 65],
        encoded_keys_len_1: 0,
        encoded_keys_len_3: 0,
        encoded_keys_len_9: 0,
        leaf_ptrs: BTreeMap::new(),
        leaf_keys: [0; 65],
        ptr_size_hist: [0; 65],
    };
    build_recurse(&mut ctx, arr, 0)?;

    println!("Built table, size {} bytes", ctx.buf.len());
    println!("  bytes in keys: {}", ctx.bytes_in_keys);
    println!("  bytes in values: {}", ctx.bytes_in_values);
    println!("  bytes in left ptrs: {}", ctx.bytes_in_left_ptr);
    println!("    empty left ptrs: {}", ctx.empty_left_pointers);
    println!("  bytes in right ptrs: {}", ctx.bytes_in_right_ptr);
    println!("    empty right ptrs: {}", ctx.empty_right_pointers);
    println!("  nodes with both ptrs empty: {}", ctx.both_pointers_empty);
    println!("  key size histogram pos: {:?}", ctx.key_size_hist_pos);
    println!("  key size histogram neg: {:?}", ctx.key_size_hist_neg);
    println!("  encoded keys length counts: len 1: {}, len 3: {}, len 9: {}",
        ctx.encoded_keys_len_1, ctx.encoded_keys_len_3, ctx.encoded_keys_len_9);
    println!("  leaf ptr size histogram: {:?}", ctx.leaf_ptrs);
    println!("  leaf key size histogram: {:?}", ctx.leaf_keys);
    println!("  ptr size histogram: {:?}", ctx.ptr_size_hist);

    ctx.buf.reverse();

    Ok(ctx.buf)
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum Value {
    EmptyPtr,
    RelKey(i64),
    RelPtr(u64),
    RelTailPtr(u64),
    Val(u64),
}

//
// encoding:
// ptrs: we limit the table size to 2MB, so 21 bits
//   00-EF: encode as 1 byte
//   F0-F7: first byte with 3 lower bits of value, followed by 2 bytes (little-endian)
//   f8   : EmptyPtr
//   f9   : BothPtrEmpty
// values:
//   00-F7: encode as 1 byte
//   F8-FF: first byte with 3 lower bits of value, followed by 2 bytes (little-endian)
// RelKey:
//   00-DE: 1 byte, val + 111
//   DF   : followed by 8 bytes i64 (little-endian)
//   E0-FF: lower 5 bits, followed by 2 bytes (little-endian)
//
// PtrOrTailPtr:
//  01-DF: ptr as 1 byte
//  E0-E7: ptr first byte with 3 lower bits of value, followed by 2 bytes (little-endian)
//  E8-EF: tail ptrs first byte with 3 lower bits of value, followed by 2 bytes (little-endian)
//  F0-FF: tail ptrs as 1 byte
//
// Maximum encodable table size is 256k
//
impl Value {
    pub fn as_bytes(&self) -> Result<Vec<u8>> {
        Ok(match self {
            Value::RelKey(v) => {
                if *v >= -111 && *v <= 111 {
                    Vec::from([(*v as i8 + 111) as u8])
                } else if *v >= -0x1f_ffff && *v <= 0x1f_ffff {
                    let mut b = Vec::with_capacity(3);
                    let v_u = *v as u64;
                    let b0 = 0xe0 | ((v_u as u8) & 0x1f);
                    b.push(b0);
                    b.push((v_u & 0xff) as u8);
                    b.push(((v_u >> 8) & 0xff) as u8);
                    b
                } else {
                    let mut b = Vec::with_capacity(9);
                    b.push(0xff);
                    b.extend(&v.to_le_bytes());
                    b
                }
            }
            Value::RelPtr(v) => {
                if *v <= 0xdf {
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
            Value::RelTailPtr(v) => {
                if *v <= 0x0f {
                    Vec::from([*v as u8 + 0xf0])
                } else if *v <= 0x3ffff {
println!("large tail ptr for value: {:?}", self);
                    let b0 = 0xe8 | (((*v >> 16) as u8) & 0x07);
                    let b1 = (*v & 0xff) as u8;
                    let b2 = ((*v >> 8) & 0xff) as u8;
                    Vec::from([b0, b1, b2])
                } else {
println!("Value too large to encode: {:?}", self);
                    return Err(FswError::TableValueEncodeError);
                }
            }
            Value::Val(v) => {
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
            Value::EmptyPtr => Vec::from([0x00]),
        })
    }
//  E0-E7: ptr first byte with 3 lower bits of value, followed by 2 bytes (little-endian)
//  E8-EF: tail ptrs first byte with 3 lower bits of value, followed by 2 bytes (little-endian)
//  F0-FF: tail ptrs as 1 byte
    pub fn read_rel_ptr(b: &[u8]) -> Result<(Value, usize)> {
        let Some(v) = b.get(0) else {
            return Err(FswError::TableValueDecodeError);
        };
        if *v == 0 {
            Ok((Value::EmptyPtr, 1))
        } else if *v < 0xe0 {
            Ok((Value::RelPtr(*v as u64), 1))
        } else if *v < 0xe8 {
            let Some(b1) = b.get(1) else {
                return Err(FswError::TableValueDecodeError);
            };
            let Some(b2) = b.get(2) else {
                return Err(FswError::TableValueDecodeError);
            };
            let val = (((*v as u64 & 0x07) << 16) | ((*b2 as u64) << 8) | (*b1 as u64)) as u64;
            Ok((Value::RelPtr(val), 3))
        } else if *v < 0xf0 {
            Ok((Value::RelPtr(*v as u64 & 0x0f), 1))
        } else {
            let Some(b1) = b.get(1) else {
                return Err(FswError::TableValueDecodeError);
            };
            let Some(b2) = b.get(2) else {
                return Err(FswError::TableValueDecodeError);
            };
            let val = (((*v as u64 & 0x07) << 16) | ((*b2 as u64) << 8) | (*b1 as u64)) as u64;
            Ok((Value::RelTailPtr(val), 3))
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

fn push_number(buf: &mut Vec<u8>, n: Value) -> Result<usize> {
    let mut b = n.as_bytes()?;
    let l = b.len();
    b.reverse();
    buf.extend(b);
    Ok(l)
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
    // find largest number that creates a tree with no empty pointers
    let mut mid = 0;
    while 2 * mid + 1 + 2 <= len {
        mid = 2 * mid + 1;
    }
    if len == 2 {
        mid = 1; // we want the right pointer to be empty
    }
    let left = &arr[..mid];
    let right = &arr[mid + 1..];
    let own_key = arr[mid].0;
    let own_value = arr[mid].1;
//    println!("build_recurse: {} entries, middle {} left len {} right len {}",
//       arr.len(), mid, left.len(), right.len());

    let left_ptr = build_recurse(ctx, left, own_key)?;
    let right_ptr = build_recurse(ctx, right, own_key)?;

    // we build from back to front, so push in reverse order
    let n = push_number(&mut ctx.buf, Value::Val(own_value))?;
    ctx.bytes_in_values += n;
    if len >= 3 {
        if right_ptr == 0 {
            push_number(&mut ctx.buf, Value::EmptyPtr)?;
            ctx.empty_right_pointers += 1;
            ctx.bytes_in_right_ptr += 1;
        } else {
            let pos = ctx.buf.len() as u64;
            let n = if right.len() <= 3 {
                push_number(&mut ctx.buf, Value::RelTailPtr(pos - right_ptr))?
            } else {
                push_number(&mut ctx.buf, Value::RelPtr(pos - right_ptr))?
            };
            ctx.bytes_in_right_ptr += n;
            if len == 3 {
                *ctx.leaf_ptrs.entry(pos - right_ptr).or_insert(0) += 1;
            }
            ctx.ptr_size_hist[(pos - right_ptr).leading_zeros() as usize] += 1;
        }
        let pos = ctx.buf.len() as u64;
        let n = if left.len() <= 3 {
            push_number(&mut ctx.buf, Value::RelTailPtr(pos - left_ptr))?
        } else {
            push_number(&mut ctx.buf, Value::RelPtr(pos - left_ptr))?
        };
        ctx.bytes_in_left_ptr += n;
        if len == 3 {
            *ctx.leaf_ptrs.entry(pos - left_ptr).or_insert(0) += 1;
        }
        ctx.ptr_size_hist[(pos -left_ptr).leading_zeros() as usize] += 1;
    }

    let rel_key = own_key as i64 - parent_key as i64;
    if rel_key > 0 {
        ctx.key_size_hist_pos[rel_key.leading_zeros() as usize] += 1;
    } else {
        ctx.key_size_hist_neg[rel_key.leading_ones() as usize] += 1;
    };
    let n = push_number(&mut ctx.buf, Value::RelKey(rel_key))?;
    ctx.bytes_in_keys += n;
    match n {
        1 => ctx.encoded_keys_len_1 += 1,
        3 => ctx.encoded_keys_len_3 += 1,
        9 => ctx.encoded_keys_len_9 += 1,
        _ => panic!("Unexpected key length {}", n),
    }
    if len == 3 {
        let v = if rel_key < 0 {
            rel_key.leading_ones()
        } else {
            rel_key.leading_zeros()
        };
        ctx.leaf_keys[v as usize] += 1;
    }


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
