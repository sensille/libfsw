use crate::FswError;
use crate::Result;
use log::{ debug, trace, info };

#[derive(Default)]
struct BuildCtx {
    buf: Vec<u8>,       // resulting table in reverse order
    bytes_in_values: usize,
    bytes_in_ptr: usize,
    bytes_in_keys: usize,
    unmarked_leaves: usize,
}

// keys have to be sorted and strictly increasing
pub(crate) fn build(arr: &[(u64, u64)], max_size: usize) -> Result<(Vec<u8>, usize)> {
    debug!("Building table with {} entries into {} bytes", arr.len(), max_size);

    let mut entries = ((max_size as f64 / 2.6) as usize).min(arr.len());
    let mut left = 1;
    let mut right = arr.len();
    let mut result = None;

    while left < right {
        let mut ctx = BuildCtx { ..Default::default() };
        debug!("Trying with {} entries, left {} right {}", entries, left, right);
        match build_recurse(&mut ctx, &arr[..entries], 0, true) {
            Ok(_) => {},
            Err(FswError::TablePtrEncodeError) => {},
            Err(e) => return Err(e),
        }
        let diff = ctx.buf.len() as f64 - max_size as f64;
        debug!(" size {} diff {} bytes", ctx.buf.len(), diff);
        let adj = (diff.abs() / 2.6).max(1.0) as usize;
        if ctx.buf.len() > max_size {
            right = entries - 1;
            entries = (entries - adj).max(left);
        } else {
            left = entries;
            entries = (entries + adj).min(right);
            result = Some((ctx, entries));
            if diff.abs() < 16.0 {
                break;
            }
        }
        debug!("setting {} entries, left {} right {}", entries, left, right);
    }

    let Some((mut ctx, entries)) = result else {
        return Err(FswError::TableBuildError);
    };
    info!("Built table, size {} bytes", ctx.buf.len());
    info!("  bytes in keys: {}", ctx.bytes_in_keys);
    info!("  bytes in ptrs: {}", ctx.bytes_in_ptr);
    info!("  bytes in values: {}", ctx.bytes_in_values);
    info!("  unmarked leaves: {}", ctx.unmarked_leaves);
    info!("  entries: {}", entries);

    ctx.buf.reverse();

    Ok((ctx.buf, entries))
}

//
//  Table entry format:
//      own key
//      left child ptr or leaf marker
//      own value
//      right subtree
//      left subtree
//
//   key is relative to parent key
//   ptrs are offsets from end of current entry
//   a pointer marks whether it points to a leaf or not
//
//   leaf node format:
//      own key
//      left key
//      left value
//      own value
//      right key
//      right value
//
//   The tree can have one leaf in the tree that is not pointed to by a ptr,
//   thus not explicitly marked as leaf. If present, this is always the rightmost
//   leaf in the tree. All other leaves are full.
//
//   incomplete leaf format;
//      own key       (0 for empty leaf)
//      leaf marker   (can be distinguished from ptrs)
//      left key      (0 if no left entry)
//      left value
//      own value
//      right key     (0 if no right entry)
//      right value
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
//   E0-FF: lower 5 bits, followed by 1 byte (little-endian)
//
// a ptr with value 0 is used to mark a leaf that is pointed to by a non-leaf ptr
//   This can happen only for the last right child
//
// Maximum encodable table size is 256k
//
fn enc_rel_key(v: i64) -> Result<Vec<u8>> {
    if v >= -111 && v <= 111 {
        Ok(Vec::from([(v + 111) as u8]))
    } else if v >= -0x1000 && v < 0x1000 {
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
}

fn dec_rel_key(b: &[u8]) -> Result<(i64, usize)> {
    if b.len() < 1 {
        return Err(FswError::TableValueDecodeError);
    }
    if b[0] <= 0xde {
        Ok(((b[0] as i64 - 111) as i64, 1))
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
        Err(FswError::TablePtrEncodeError)
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
        Err(FswError::TablePtrEncodeError)
    }
}

fn enc_leaf_marker() -> Result<Vec<u8>> {
    Ok(Vec::from([0x00]))
}

fn is_leaf_marker(b: &[u8]) -> Result<bool> {
    if b.len() < 1 {
        return Err(FswError::TableValueDecodeError);
    }
    Ok(b[0] == 0x00)
}

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
            let n = push(&mut ctx.buf, enc_rel_key(arr[2].0 as i64 - own_key as i64)?)?;
            ctx.bytes_in_keys += n;
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
        } else {
            // dummy entry
            push(&mut ctx.buf, enc_val(0)?)?;
        }

        // left key/value
        if len >= 2 {
            let n = push(&mut ctx.buf, enc_val(arr[0].1)?)?;
            ctx.bytes_in_values += n;
            let n = push(&mut ctx.buf, enc_rel_key(arr[0].0 as i64 - own_key as i64)?)?;
            ctx.bytes_in_keys += n;
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
        } else {
            // dummy entry
            push(&mut ctx.buf, enc_rel_key(0)?)?;
        }

        return Ok(ctx.buf.len() as u64);
    }

    /*
     * intermediate node
     */

    // split_point: find largest number that creates a tree with no empty pointers
    let mut split = 3;
    while 2 * split + 1 + 1 <= len {
        split = 2 * split + 1;
    }
    let left = &arr[..split];
    let right = &arr[split + 1..];
    let own_key = arr[split].0;
    let own_value = arr[split].1;
    trace!("build_recurse: {} entries, split {} left len {} right len {} mid key {}",
       arr.len(), split, left.len(), right.len(), own_key);

    assert!(left.len() >= 3);
    let left_is_leaf = left.len() == 3;
    let right_is_leaf = right.len() <= 3;
    let unmarked_leaf = right_is_leaf && !left_is_leaf;

    // <own key> <left ptr> <own value> <right subtree> <left subtree>
    // built from back to front
    // left subtree
    let left_ptr = build_recurse(ctx, left, own_key, false)?;
    // right subtree
    build_recurse(ctx, right, own_key, unmarked_leaf)?;

    // own value
    let n = push(&mut ctx.buf, enc_val(own_value)?)?;
    ctx.bytes_in_values += n;

    // left ptr
    let pos = ctx.buf.len() as u64;
    let n = if left_is_leaf {
        push(&mut ctx.buf, enc_rel_leaf_ptr(pos - left_ptr)?)?
    } else {
        push(&mut ctx.buf, enc_rel_ptr(pos - left_ptr)?)?
    };
    ctx.bytes_in_ptr += n;

    // own key
    let rel_key = own_key as i64 - parent_key as i64;
    let n = push(&mut ctx.buf, enc_rel_key(rel_key)?)?;
    ctx.bytes_in_keys += n;

    Ok(ctx.buf.len() as u64)
}

#[allow(dead_code)]
pub fn traverse_tree_recurse(table: &Vec<u8>, output: &mut Vec<(u64, u64)>, mut offset: usize,
    parent_key: i64, mut is_leaf: bool)
    -> Result<()>
{
    let (mut own_key, advance) = dec_rel_key(&table[offset..])?;
    own_key += parent_key;
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
        if left_key != 0 {
            output.push(((own_key + left_key) as u64, left_value));
        }
        // own value
        let (own_value, advance) = dec_val(&table[offset..])?;
        offset += advance;
        if own_key != parent_key {
            output.push((own_key as u64, own_value));
        }
        // right key/value
        let (right_key, advance) = dec_rel_key(&table[offset..])?;
        offset += advance;
        let (right_value, _) = dec_val(&table[offset..])?;
        if right_key != 0 {
            output.push(((own_key + right_key) as u64, right_value));
        }

        return Ok(());
    }

    // intermediate node
    // left ptr
    let (left_ptr, left_is_leaf, advance) = dec_rel_ptr(&table[offset..])?;
    offset += advance;

    // descend into left child
    traverse_tree_recurse(&table, output, offset + left_ptr as usize, own_key, left_is_leaf)?;

    let (own_value, advance) = dec_val(&table[offset..])?;
    offset += advance;

    output.push((own_key as u64, own_value));

    // descend into right child
    traverse_tree_recurse(&table, output, offset, own_key, left_is_leaf)?;

    Ok(())
}

// find the entry with the largest key with key <= given key
// returns None if given key is smaller than the lowest key in the table
#[allow(dead_code)]
pub fn find_key_upper_bound(table: &[u8], search_key: u64) -> Result<Option<(u64, u64)>> {
    // outline:
    // start at root
    // at each node, decode own key
    //   if given key < own key, go to left child
    //   else go to right child, recording own key as current best
    let mut offset = 0;
    let mut parent_key = 0i64;
    let mut best = None;
    let mut is_leaf = false;

    loop {
        let (mut current_key, advance) = dec_rel_key(&table[offset..])?;
        offset += advance;
println!("current_key: {:x}, parent_key: {:x}, offset: {}", current_key, parent_key, offset);
        if current_key == 0 {
            // dummy entry
            return Ok(best);
        }
        current_key += parent_key;

        if !is_leaf && is_leaf_marker(&table[offset..])? {
            offset += 1;
            is_leaf = true;
        };

        // intermediate node case
        if !is_leaf {
            let (left_ptr, left_is_leaf, advance) = dec_rel_ptr(&table[offset..])?;
            offset += advance;

            parent_key = current_key;

            if search_key < current_key as u64 {
println!("going left: search_key {:x} < current_key {:x}", search_key, current_key);
                // go to left child
                offset += left_ptr as usize;
            } else {
println!("going right: search_key {:x} >= current_key {:x}", search_key, current_key);
                let (current_val, advance) = dec_val(&table[offset..])?;
                offset += advance;
                best = Some((current_key as u64, current_val));
                // continue with right child
            }

            is_leaf = left_is_leaf;
            continue;
        }

        // leaf node case
        let (left_key, advance) = dec_rel_key(&table[offset..])?;
        offset += advance;
        let (left_value, advance) = dec_val(&table[offset..])?;
        offset += advance;

        // own value
        let (own_value, advance) = dec_val(&table[offset..])?;
        offset += advance;

        if search_key < current_key as u64 {
            if left_key != 0 && search_key >= (left_key + current_key) as u64 {
                    return Ok(Some(((left_key + current_key) as u64, left_value)));
            }
            return Ok(best);
        }

        // right key/value
        let (right_key, advance) = dec_rel_key(&table[offset..])?;
        offset += advance;
        let (right_value, _) = dec_val(&table[offset..])?;

        if right_key != 0 && search_key >= (right_key + current_key) as u64 {
            return Ok(Some(((right_key + current_key) as u64, right_value)));
        }

        return Ok(Some((current_key as u64, own_value)));
    }
}
// tests
#[cfg(test)]
mod tests {
    use rand::prelude::*;
    use super::*;
    use crate::Result;

    fn build_test_table(seed: u64, sz: usize) -> Vec<(u64, u64)> {
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);

        let mut table = Vec::new();
        let mut start_key = rng.random_range(0..1000000);
        for _ in 0..sz {
            let key = if rng.random_range(0..500) == 0 {
                start_key + rng.random_range(1..1000000)
            } else {
                start_key + rng.random_range(1..1000)
            };
            start_key = key;
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
        arr.push((1200, 8));
        arr.push((1202, 9));
        arr.push((1205, 10));
        arr.push((1206, 11));
        arr.push((1208, 12));
        let (table, _) = build(&arr, 1000).unwrap();
        assert!(!table.is_empty());
        println!("Built table: {:?}", table);
        for (i, v) in table.iter().enumerate() {
            println!("{}: {:x?}", i, v);
        }
        let mut output = Vec::new();
        traverse_tree_recurse(&table, &mut output, 0, 0, false).unwrap();
        assert_eq!(arr, output);
    }

    #[test]
    fn large_test() {
        for n in 1..10000 {
            let arr = build_test_table(n, n as usize);
            let (table, _) = build(&arr, n as usize * 20).unwrap();
            println!("Built large table, size {}", table.len());
            let mut output = Vec::new();
            traverse_tree_recurse(&table, &mut output, 0, 0, false).unwrap();
            println!("traversed large table, {} entries", n);
            if arr.len() != output.len() {
                // find mismatches
                let mut i = 0;
                let mut j = 0;
                while i < arr.len() && j < output.len() {
                    if arr[i] == output[j] {
                        i += 1;
                        j += 1;
                    } else {
                        println!("mismatch: arr[{}] = {:?}, output[{}] = {:?}",
                            i, arr[i], j, output[j]);
                        if arr[i].0 < output[j].0 {
                            i += 1;
                        } else {
                            j += 1;
                        }
                    }
                }
                while i < arr.len() {
                    println!("extra in arr: arr[{}] = {:?}", i, arr[i]);
                    i += 1;
                }
                while j < output.len() {
                    println!("extra in output: output[{}] = {:?}", j, output[j]);
                    j += 1;
                }
                println!("end of mismatches, i = {}, j = {}", i, j);
            }
            assert_eq!(arr.len(), output.len());
            assert_eq!(arr, output);
        }
    }

    #[test]
    fn test_find_key() {
        let probes = 10000;
        for table_size in 1..10000 {
            println!("testing table size {}", table_size);
            let arr = build_test_table(table_size, table_size as usize);
            let (table, _) = build(&arr, table_size as usize * 20).unwrap();
            let mut output = Vec::new();
            traverse_tree_recurse(&table, &mut output, 0, 0, false).unwrap();
            assert_eq!(arr, output);
            for (key, value) in arr.iter() {
                // exact match
                let res = find_key_upper_bound(&table, *key).unwrap();
                assert!(res.is_some());
                let (found_key, found_value) = res.unwrap();
                assert_eq!(*key, found_key);
                assert_eq!(*value, found_value);
            }
            let lowest_key = arr[0].0;
            let highest_key = arr[arr.len() - 1].0;
            let mut rng = rand::rngs::StdRng::seed_from_u64(0);
            for _ in 0..probes {
                let key = rng.random_range(lowest_key.saturating_sub(1000)..=highest_key + 1000);
                let res = find_key_upper_bound(&table, key).unwrap();
                let expected = match arr.binary_search_by(|(k, _)| k.cmp(&key)) {
                    Ok(idx) => Some(arr[idx]),
                    Err(0) => None,
                    Err(idx) => Some(arr[idx - 1]),
                };
                if expected.is_none() {
                    assert!(res.is_none());
                } else {
                    let (exp_key, exp_value) = expected.unwrap();
                    let (found_key, found_value) = res.unwrap();
                    assert_eq!(exp_key, found_key);
                    assert_eq!(exp_value, found_value);
                }
            }
        }
    }

    #[test]
    fn test_key_encoding() {
        for v in -200000..200000 {
            let enc = enc_rel_key(v).unwrap();
            let (dec, _) = dec_rel_key(&enc).unwrap();
            assert_eq!(v, dec);
        }
    }

    #[test]
    fn test_ptr_encoding() {
        for v in 0..262144 {
            let enc = enc_rel_ptr(v).unwrap();
            let (dec, _, _) = dec_rel_ptr(&enc).unwrap();
            assert_eq!(v, dec);
        }
    }

    #[test]
    fn test_val_encoding() {
        for v in 0..262144 {
            let enc = enc_val(v).unwrap();
            let (dec, _) = dec_val(&enc).unwrap();
            assert_eq!(v, dec);
        }
    }
}
