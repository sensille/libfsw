use std::collections::BTreeMap;
use crate::FswError;
use crate::Result;
use rand::prelude::*;

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
    num_values: usize,
    empty_left_pointers: usize,
    bytes_in_left_ptr: usize,
    num_left_ptr: usize,
    empty_right_pointers: usize,
    bytes_in_right_ptr: usize,
    both_pointers_empty: usize,
    bytes_in_keys: usize,
    num_keys: usize,
    key_size_hist_pos: [usize; 65],
    key_size_hist_neg: [usize; 65],
    ptr_size_hist: [usize; 65],
    encoded_keys_len_1: usize,
    encoded_keys_len_2: usize,
    encoded_keys_len_3: usize,
    encoded_keys_len_9: usize,
    leaf_ptrs: BTreeMap<u64, usize>,
    leaf_keys: [usize; 65],
    unmarked_leaves: usize,
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
        encoded_keys_len_2: 0,
        encoded_keys_len_3: 0,
        encoded_keys_len_9: 0,
        leaf_ptrs: BTreeMap::new(),
        leaf_keys: [0; 65],
        ptr_size_hist: [0; 65],
        unmarked_leaves: 0,
        num_values: 0,
        num_keys: 0,
        num_left_ptr: 0,
    };
    build_recurse(&mut ctx, arr, 0, true)?;

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
    println!("  encoded keys length counts: len 1: {}, len 2: {}, len 3: {}, len 9: {}",
        ctx.encoded_keys_len_1, ctx.encoded_keys_len_2,
        ctx.encoded_keys_len_3, ctx.encoded_keys_len_9);
    println!("  leaf ptr size histogram: {:?}", ctx.leaf_ptrs);
    println!("  leaf key size histogram: {:?}", ctx.leaf_keys);
    println!("  ptr size histogram: {:?}", ctx.ptr_size_hist);
    println!("  unmarked leaves: {}", ctx.unmarked_leaves);
    println!("  total keys: {}", ctx.num_keys);
    println!("  total values: {}", ctx.num_values);
    println!("  total left ptrs: {}", ctx.num_left_ptr);

    ctx.buf.reverse();

    Ok(ctx.buf)
}

//
// encoding:
// ptrs: we limit the table size to 2MB, so 21 bits
//   00-CF: encode as 1 byte
//   D0-D8: first byte with 3 lower bits of value, followed by 2 bytes (little-endian)
// leaf ptrs:
//   D8-DF: first byte with 3 lower bits of value, followed by 2 bytes (little-endian)
//   E0-FF: ptr as 1 byte
// values:
//   00-F7: encode as 1 byte
//   F8-FF: first byte with 3 lower bits of value, followed by 2 bytes (little-endian)
// RelKey:
//   00-DE: 1 byte, val + 111
//   DF   : followed by 8 bytes i64 (little-endian)
//   E0-FF: lower 5 bits, followed by 2 bytes (little-endian)
//
// Maximum encodable table size is 256k
//
fn enc_rel_key(v: i64) -> Result<Vec<u8>> {
    let k =
    if v >= -111 && v <= 111 {
        Ok(Vec::from([(v + 111) as u8]))
    } else if v >= -0x1fff && v <= 0x1fff {
        let mut b = Vec::with_capacity(2);
        let v_u = v as u64;
        let b0 = 0xe0 | (((v_u >> 8 )as u8) & 0x1f);
        b.push(b0);
        b.push((v_u & 0xff) as u8);
        Ok(b)
    } else {
        let mut b = Vec::with_capacity(9);
        b.push(0xdf);
        b.extend(&v.to_le_bytes());
        Ok(b)
    }
    ;
    println!("enc_rel_key({}) -> {:x?}", v, k);
    k
}

#[cfg(test)]
fn dec_rel_key(b: &[u8]) -> Result<(i64, usize)> {
    if b.len() < 1 {
        return Err(FswError::TableValueDecodeError);
    }
    if b[0] <= 0xde {
        Ok(((b[0] as i8 - 111) as i64, 1))
    } else if b[0] == 0xdf {
        if b.len() < 9 {
            return Err(FswError::TableValueDecodeError);
        }
        let key = i64::from_le_bytes(b[1..9].try_into().unwrap());
        Ok((key, 9))
    } else {
        if b.len() < 2 {
            return Err(FswError::TableValueDecodeError);
        }
        let mut val = ((b[0] as u64 & 0x1f) << 8) | (b[1] as u64);
        // sign extension
        if val & 0x1000 != 0 {
            val |= !0x1fff;
        }

        Ok((val as i64, 2))
    }
}

fn enc_rel_ptr(v: u64) -> Result<Vec<u8>> {
    if v <= 0xcf {
        Ok(Vec::from([v as u8]))
    } else if v <= 0x3ffff {
        let b0 = 0xd0 | (((v >> 16) as u8) & 0x07);
        let b1 = (v & 0xff) as u8;
        let b2 = ((v >> 8) & 0xff) as u8;
        Ok(Vec::from([b0, b1, b2]))
    } else {
        Err(FswError::TableValueEncodeError)
    }
}

fn enc_rel_leaf_ptr(v: u64) -> Result<Vec<u8>> {
    if v <= 0x1f {
        Ok(Vec::from([v as u8 + 0xe0]))
    } else if v <= 0x3ffff {
        let b0 = 0xd8 | (((v >> 16) as u8) & 0x07);
        let b1 = (v & 0xff) as u8;
        let b2 = ((v >> 8) & 0xff) as u8;
        Ok(Vec::from([b0, b1, b2]))
    } else {
        Err(FswError::TableValueEncodeError)
    }
}

fn enc_leaf_marker() -> Result<Vec<u8>> {
    Ok(Vec::from([0x00]))
}

#[cfg(test)]
fn is_leaf_marker(b: &[u8]) -> Result<bool> {
    if b.len() < 1 {
        return Err(FswError::TableValueDecodeError);
    }
    Ok(b[0] == 0x00)
}

#[cfg(test)]
fn dec_rel_ptr(b: &[u8]) -> Result<(u64, bool, usize)> {
    if b.len() < 1 {
        return Err(FswError::TableValueDecodeError);
    }
    if b[0] <= 0xcf {
        Ok((b[0] as u64, false, 1))
    } else if b[0] <= 0xd7 {
        if b.len() < 3 {
            return Err(FswError::TableValueDecodeError);
        }
        let val = (((b[0] as u64 & 0x07) << 16) | ((b[2] as u64) << 8) | (b[1] as u64)) as u64;
        Ok((val, false, 3))
    } else if b[0] <= 0xdf {
        if b.len() < 3 {
            return Err(FswError::TableValueDecodeError);
        }
        let val = (((b[0] as u64 & 0x07) << 16) | ((b[2] as u64) << 8) | (b[1] as u64)) as u64;
        Ok((val, true, 3))
    } else {
        Ok((b[0] as u64 & 0x1f, true, 1))
    }
}

fn enc_val(v: u64) -> Result<Vec<u8>> {
    if v <= 0xef {
        Ok(Vec::from([v as u8]))
    } else if v <= 0x3ffff {
        let b0 = 0xf0 | (((v >> 16) as u8) & 0x07);
        let b1 = (v & 0xff) as u8;
        let b2 = ((v >> 8) & 0xff) as u8;
        Ok(Vec::from([b0, b1, b2]))
    } else {
        Err(FswError::TableValueEncodeError)
    }
}

#[allow(dead_code)]
fn dec_val(b: &[u8]) -> Result<(u64, usize)> {
    if b.len() < 1 {
        return Err(FswError::TableValueDecodeError);
    }
    if b[0] <= 0xef {
        Ok((b[0] as u64, 1))
    } else {
        if b.len() < 3 {
            return Err(FswError::TableValueDecodeError);
        }
        let val = (((b[0] as u64 & 0x07) << 16) | ((b[2] as u64) << 8) | (b[1] as u64)) as u64;
        Ok((val, 3))
    }
}

fn push(buf: &mut Vec<u8>, mut n: Vec<u8>) -> Result<usize> {
    let l = n.len();
    n.reverse();
    buf.extend(n);
    Ok(l)
}

fn build_recurse(
    ctx: &mut BuildCtx,
    arr: &[(u64, u64)],
    parent_key: u64,
    unmarked_leaf: bool,
) -> Result<u64> {
    // observations:
    //   - due to the rules the split point is chosen, the left subtree will
    //     always be full, so either a node has 2 full leaves or is a leaf itself
    //   - if the left node is a leaf, the right also is
    //   - if the left node is not a leaf, the right may be a leaf. As there is
    //     no right pointer, we can't encode the leafness into the pointer, so
    //     we encode it into the key
    //   - the right node always immediately follows its parent, so we don't need
    //     a right pointer
    //   - to be able to calculate the forward pointers, we have to build from back
    //     to front
    let len = arr.len();

    /*
     * leaf node
     */
    if len <= 3 {
        // <key> [<leaf marker>] <left key> <left value> <own value> <right key> <right value>
        // a key of 0 means the entry is not valid
        // emitted back to front

        let own_key = match len {
            3 => arr[1].0,
            2 => arr[1].0,
            1 => arr[0].0,
            0 => parent_key,    // this entry is a dummy entry, choose it so it is 0
            _ => unreachable!(),
        };

        // right key/value
        if len == 3 {
            let n = push(&mut ctx.buf, enc_val(arr[2].1)?)?;
            ctx.bytes_in_values += n;
            ctx.num_values += 1;
            let n = push(&mut ctx.buf, enc_rel_key(arr[2].0 as i64 - own_key as i64)?)?;
            ctx.bytes_in_keys += n;
            ctx.num_keys += 1;
        } else {
            // dummy entry
            push(&mut ctx.buf, enc_val(0)?)?;
            push(&mut ctx.buf, enc_rel_key(0)?)?;
        }

        // own value
        if len > 0 {
            let own_val = if len >= 2 { arr[1].1 } else { arr[0].1 };
            let n = push(&mut ctx.buf, enc_val(own_val)?)?;
            ctx.bytes_in_values += n;
            ctx.num_values += 1;
        } else {
            // dummy entry
            push(&mut ctx.buf, enc_val(0)?)?;
        }

        // left key/value
        if len >= 2 {
            let n = push(&mut ctx.buf, enc_val(arr[0].1)?)?;
            ctx.bytes_in_values += n;
            ctx.num_values += 1;
            let n = push(&mut ctx.buf, enc_rel_key(arr[0].0 as i64 - own_key as i64)?)?;
            ctx.bytes_in_keys += n;
            ctx.num_keys += 1;
        } else {
            // dummy entry
            push(&mut ctx.buf, enc_val(0)?)?;
            push(&mut ctx.buf, enc_rel_key(0)?)?;
        }

        // leaf marker
        if unmarked_leaf {
            ctx.unmarked_leaves += 1;
            push(&mut ctx.buf, enc_leaf_marker()?)?;
        }

        // own key
        if len >= 1 {
            let n = push(&mut ctx.buf, enc_rel_key(own_key as i64 - parent_key as i64)?)?;
            ctx.bytes_in_keys += n;
            ctx.num_keys += 1;
        } else {
            // dummy entry
            push(&mut ctx.buf, enc_rel_key(0)?)?;
        }

if len <= 3 { println!("Built leaf node with {} entries", len); }

        return Ok(ctx.buf.len() as u64);
    }

    /*
     * intermediate node
     */

    // split_point: find largest number that creates a tree with no empty pointers
    let mut split = 3;
    while 2 * split + 1 + 2 <= len {
        split = 2 * split + 1;
    }
    let left = &arr[..split];
    let right = &arr[split + 1..];
    let own_key = arr[split].0;
    let own_value = arr[split].1;
    //println!("build_recurse: {} entries, split {} left len {} right len {}",
    //   arr.len(), split, left.len(), right.len());

    assert!(left.len() >= 3);
    let left_is_leaf = left.len() == 3;
    let right_is_leaf = right.len() == 3;
    let unmarked_leaf = right_is_leaf && !left_is_leaf;

    // <own key> <left ptr> <own value> <right subtree> <left subtree>
    // built from back to front
    // left subtree
    let left_ptr = build_recurse(ctx, left, own_key, false)?;
    // right subtree
    let right_ptr = build_recurse(ctx, right, own_key, unmarked_leaf)?;

    // own value
    let n = push(&mut ctx.buf, enc_val(own_value)?)?;
    ctx.bytes_in_values += n;
    ctx.num_values += 1;

    // left ptr
    let pos = ctx.buf.len() as u64;
    let n = if left_is_leaf {
        *ctx.leaf_ptrs.entry(pos - right_ptr).or_insert(0) += 1;
        push(&mut ctx.buf, enc_rel_leaf_ptr(pos - left_ptr)?)?
    } else {
        push(&mut ctx.buf, enc_rel_ptr(pos - left_ptr)?)?
    };
    ctx.bytes_in_left_ptr += n;
    ctx.num_left_ptr += 1;
    ctx.ptr_size_hist[(pos -left_ptr).leading_zeros() as usize] += 1;

    // own key
    let rel_key = own_key as i64 - parent_key as i64;
    if rel_key > 0 {
        ctx.key_size_hist_pos[rel_key.leading_zeros() as usize] += 1;
    } else {
        ctx.key_size_hist_neg[rel_key.leading_ones() as usize] += 1;
    };
    let n = push(&mut ctx.buf, enc_rel_key(rel_key)?)?;
    ctx.bytes_in_keys += n;
    ctx.num_keys += 1;
    match n {
        1 => ctx.encoded_keys_len_1 += 1,
        2 => ctx.encoded_keys_len_2 += 1,
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
    fn traverse_tree_recurse(table: &Vec<u8>, mut offset: usize, parent_key: i64, mut is_leaf: bool)
        -> Result<()>
    {
        let own_offset = offset;
        let (mut own_key, advance) = dec_rel_key(&table[offset..])?;
        own_key += parent_key;
println!("key at offset {}: {:?}", offset, own_key);
        offset += advance;

        if !is_leaf {
            if is_leaf_marker(&table[offset..])? {
                offset += 1;
                is_leaf = true;
            }
        }

        if is_leaf {
            let (left_key, advance) = dec_rel_key(&table[offset..])?;
            offset += advance;
            let (left_value, advance) = dec_val(&table[offset..])?;
            offset += advance;
            println!("Leaf at offset {}: left key {:?}, left value {:?}",
                own_offset, own_key + left_key, left_value);
            if left_key != 0 {
                println!("==> {} {}", own_key + left_key, left_value);
            }
            // own value
            let (own_value, advance) = dec_val(&table[offset..])?;
            offset += advance;
            if own_key != parent_key {
                println!("==> {} {}", own_key, own_value);
            }
            // right key/value
            let (right_key, advance) = dec_rel_key(&table[offset..])?;
            offset += advance;
            let (right_value, _) = dec_val(&table[offset..])?;
            println!("Leaf at offset {}: right key {:?}, right value {:?}",
                own_offset, own_key + right_key, right_value);
            if right_key != 0 {
                println!("==> {} {}", own_key + right_key, right_value);
            }

            return Ok(());
        }

        // intermediate node
        // left ptr
        let (left_ptr, left_is_leaf, advance) = dec_rel_ptr(&table[offset..])?;
        println!("left ptr at offset {}: {}, is_leaf {}", offset,
            left_ptr, left_is_leaf);
        offset += advance;

        // descend into left child
        traverse_tree_recurse(&table, offset + left_ptr as usize, own_key, left_is_leaf)?;

        let (own_value, advance) = dec_val(&table[offset..])?;
        println!("val at offset {}: {:?}", offset, own_value);
        offset += advance;

        println!("Node at offset {}: key {:?}, value {:?}, left {:?}",
            own_offset, own_key, own_value, left_ptr);
        println!("==> {} {}", own_key, own_value);

        // descend into right child
        traverse_tree_recurse(&table, offset, own_key, left_is_leaf)?;

        Ok(())
    }

    fn build_test_table(seed: u64, sz: usize) -> Vec<(u64, u64)> {
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);

        let mut table = Vec::new();
        let start_key = rng.random_range(0..1000000);
        for _ in 0..sz {
            let key = if rng.random_range(0..500) == 0 {
                start_key + rng.random_range(1..1000000)
            } else {
                start_key + rng.random_range(1..1000)
            };
            let value = rng.random_range(0..1000);
            table.push((key, value));
        }
        table
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
        traverse_tree_recurse(&table, 0, 0, false).unwrap();
    }

    #[test]
    fn large_test() {
        let arr = build_test_table(0, 10000);
        let table = build(&arr).unwrap();
        println!("Built large table, size {}", table.len());
        traverse_tree_recurse(&table, 0, 0, false).unwrap();
    }
}
