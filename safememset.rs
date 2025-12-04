#![forbid(unsafe_code)]

/* All code above fn main() from cve-rs (https://github.com/Speykious/cve-rs).
 * I have put it all in one file to emphasize that only standard Rust is used
 * */

/// This function, on its own, is sound:
/// - `_val_a`'s lifetime is `&'a &'b`. This means that `'b` must outlive `'a`, so
///   that the `'a` reference is never dangling. If `'a` outlived `'b` then it could
///   borrow data that's already been dropped.
/// - Therefore, `val_b`, which has a lifetime of `'b`, is valid for `'a`.
#[inline(never)]
pub const fn lifetime_translator<'a, 'b, T: ?Sized>(_val_a: &'a &'b (), val_b: &'b T) -> &'a T {
    val_b
}

/// This does the same thing as [`lifetime_translator`], just for mutable refs.
#[inline(never)]
pub fn lifetime_translator_mut<'a, 'b, T: ?Sized>(
    _val_a: &'a &'b (),
    val_b: &'b mut T,
) -> &'a mut T {
    val_b
}

/// Expands the domain of `'a` to `'b`.
///
/// # Safety
///
/// Safety? What's that?
pub fn expand<'a, 'b, T: ?Sized>(x: &'a T) -> &'b T {
    let f: for<'x> fn(_, &'x T) -> &'b T = lifetime_translator;
    f(STATIC_UNIT, x)
}

/// This does the same thing as [`expand`] for mutable references.
///
/// # Safety
///
/// Safety? What's that?
pub fn expand_mut<'a, 'b, T: ?Sized>(x: &'a mut T) -> &'b mut T {
    let f: for<'x> fn(_, &'x mut T) -> &'b mut T = lifetime_translator_mut;
    f(STATIC_UNIT, x)
}

/// A unit with a static lifetime.
///
/// Thanks to the soundness hole, this lets us cast any value all the way up to
/// a `'static` lifetime, meaning any lifetime we want.
pub const STATIC_UNIT: &&() = &&();

pub fn transmute<A, B>(obj: A) -> B {
    use std::hint::black_box;

    // The layout of `DummyEnum` is approximately
    // DummyEnum {
    //     is_a_or_b: u8,
    //     data: usize,
    // }
    // Note that `data` is shared between `DummyEnum::A` and `DummyEnum::B`.
    // This should hopefully be more reliable than spamming the stack with a value and hoping the memory
    // is placed correctly by the compiler.
    #[allow(dead_code)]
    enum DummyEnum<A, B> {
        A(Option<Box<A>>),
        B(Option<Box<B>>),
    }

    #[inline(never)]
    fn transmute_inner<A, B>(dummy: &mut DummyEnum<A, B>, obj: A) -> B {
        let DummyEnum::B(ref_to_b) = dummy else {
            unreachable!()
        };
        let ref_to_b = expand_mut(ref_to_b);
        *dummy = DummyEnum::A(Some(Box::new(obj)));
        black_box(dummy);

        *ref_to_b.take().unwrap()
    }

    transmute_inner(black_box(&mut DummyEnum::B(None)), obj)
}

fn main() {
    use std::hint::black_box;

    /* black_box is needed for `buf` or the program will safely,
    blazingly, and randomly segfault while reading its own .text memory */

    let buf: [u8; 16] = black_box([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    let bufaddr = transmute::<&[u8; 16], u64>(&buf);

    let mainaddr = transmute::<fn() -> (), usize>(main);
    let mem = transmute::<usize, &[u8; u32::MAX as usize]>(mainaddr);

    println!("Main addr: 0x{:x}", mainaddr);

    let needle: &[u8] = &[0x4c, 0x89, 0xf7, 0x31, 0xf6, 0x48, 0x89, 0xda, 0xff, 0x15];

    /* The data in `needle` is the start of the PLT stub to CRT memset() in the x86_64 ELF rustc compiles
     * this program to on my Linux machine. It is not shellcode, but code inserted by
     * rustc for the rust standard library which calls memset which we will look for.
     * We don't care about that code, but its CALL instruction's operand can be used to find the PLT stub.
     *
     * 0xff 0x15 is the start of a x86_64 CALL opcode. The next 4 bytes are the offset to
     * memcpy's PLT entry (little endian) as encoded by CALL, relative to the instruction
     * after it.
     *
     * The PLT entry itself contains the address of memset in the program's virtual address
     * space (again in little endian), which we can freely call ourselves without using
     * any unsafe code.
     *
     * This technique should work for any function imported by the rust stdlib, though
     * will need adjustment depending on where the stub is relative to main, which
     * I think can change depending on ASLR.
     * */

    if let Some(position) = mem
        .windows(needle.len())
        .position(|window| window == needle)
    {
        println!("Found at position: main + 0x{:x}", position);
        for i in 0..(needle.len() + 4) {
            print!("0x{:x},", mem[position + i]);
        }

        let plt_offset_offset: usize = position + needle.len();

        println!("\nEncoded offset offset: 0x{:x}", plt_offset_offset);

        use std::convert::TryInto;
        let offsetslice = &mem[plt_offset_offset..plt_offset_offset + 4];

        let offset = u32::from_le_bytes(match offsetslice.try_into() {
            Ok(val) => val,
            Err(err) => {
                println!("Error: {}", err);
                return;
            }
        });

        //The 4-byte offset encoded in the CALL opcode is relative to the next instruction's address
        let next_op_addr: usize = mainaddr as usize + plt_offset_offset + 4;
        let call_addr_operand_addr: usize = offset as usize + next_op_addr as usize;
        let plt_entry_addr = transmute::<usize, &[u8; 8]>(call_addr_operand_addr as usize);
        let target_be: usize = usize::from_le_bytes(*plt_entry_addr);

        let safe_memset = transmute::<usize, extern "C" fn(u64, i32, usize)>(target_be);

        safe_memset(bufaddr, 42, 16);

        for ch in buf {
            println!("{}", ch);
        }
    } else {
        println!("PLT stub not found!");
    }
}
