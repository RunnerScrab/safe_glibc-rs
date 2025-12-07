#![forbid(unsafe_code)]

// All fn code not main() or safely_get_fnaddr_from_iat() is from
// cve-rs (https://github.com/Speykious/cve-rs), which uses a
// "soundness" issue in Rust (known since 2015) to somehow
// chain its way into unrestricted type punning.

// I have put what I needed from cve-rs all in this one file to
// emphasize that only nominally "safe" Rust (i.e. Rust without
// any `unsafe` statements/blocks or std::ffi use) is needed to gain
// arbitrary access to glibc functions imported by the Rust stdlib,
// do pointer arithmetic, and anything else C can do.

/// This function works only with JMP/CALL instructions
/// which have an encoded 4 byte offset. You pass a sequence of bytes in
/// or near a function that calls the function you're looking for,
/// adjusting with offset_from_needle as necessary. A bit fragile
fn safely_get_fnaddr_from_iat(needle: &[u8], offset_from_needle: usize) -> usize
{
    let mainaddr = transmute::<fn() -> (), usize>(main);
    let mem = transmute::<usize, &[u8; u32::MAX as usize]>(mainaddr);

    if let Some(position) = mem
        .windows(needle.len())
        .position(|window| window == needle)
    {
        let iat_offset_offset: usize = offset_from_needle + position + needle.len();

        let offsetslice = &mem[iat_offset_offset..iat_offset_offset + 4];
        let signed_offset: i32 = (offsetslice[0] as i32)
            | (offsetslice[1] as i32) << (1 << 3)
            | (offsetslice[2] as i32) << (2 << 3)
            | (offsetslice[3] as i32) << (3 << 3);

        //The 4-byte offset encoded in the CALL opcode is relative to the next instruction's address
        let next_op_addr: usize = mainaddr + iat_offset_offset + 4;
        let ilt_entry_addr: usize = (signed_offset as i64 + next_op_addr as i64) as usize;
        let p_ilt_entry_addr : &usize = transmute::<usize, &usize>(ilt_entry_addr);

        let ilt_entry_val = *p_ilt_entry_addr;

        return ilt_entry_val;
    }
    0
}

#[allow(non_snake_case)]
fn main() {

    let mut winapi : SafeWinapi = SafeWinapi { 
        h_thismodule:0,
        h_kernel32: 0,
        pGetModuleHandleA: 0, 
        pGetProcAddress: 0, 
        pLoadLibraryA: 0 
    };

    winapi.initialize();

    //Now we can load any DLL with all of its functions without using unsafe_code
    let GetStdHandle = winapi.GetProcAddressAsFn::<fn(i32)->usize>(winapi.h_kernel32, "GetStdHandle");
    let WriteConsoleA = winapi.GetProcAddressAsFn::<fn(usize, usize, u32, &mut usize, usize)->u8>(winapi.h_kernel32, "WriteConsoleA");

    let hstdout = GetStdHandle(-11);

    let strbytes = make_c_str("Hello WINAPI!\n");
    let pstrbytes = transmute::<&[u8], usize>(&(*strbytes));

    let mut bwritten : usize = 0;

    println!("kernel32 handle: 0x{:x}", winapi.h_kernel32);
    println!("GetModuleHandleA(0) returned 0x{:x}", winapi.h_thismodule); 

    WriteConsoleA(hstdout, pstrbytes, (strbytes.len() - 1) as u32, &mut bwritten, 0);
    println!("WriteConsoleA wrote {} bytes", bwritten);

}

#[allow(non_snake_case)]
struct SafeWinapi
{
    h_thismodule : usize,
    h_kernel32 : usize,

    pGetModuleHandleA : usize,
    pGetProcAddress : usize,
    pLoadLibraryA : usize
}

#[allow(non_snake_case)]
impl SafeWinapi {

    fn LoadLibraryA(&self, name : &str) -> usize
    {
        let namebytes = make_c_str(name);
        let pnamebytes = transmute::<&[u8], usize>(&(*namebytes));
        let tmpLoadLibraryA = transmute::<usize, fn(usize)->usize>(self.pLoadLibraryA);
        tmpLoadLibraryA(pnamebytes)
    }

    fn GetProcAddress(&self, hmodule : usize, name : &str) -> usize
    {
        let namebytes = make_c_str(name);
        let pnamebytes = transmute::<&[u8], usize>(&(*namebytes));
        let tmpGetProcAddress = transmute::<usize, fn(usize, usize)->usize>(self.pGetProcAddress);
        tmpGetProcAddress(hmodule, pnamebytes)
    }

    fn GetProcAddressAsFn<FnType>(&self, hmodule : usize, name : &str) -> FnType
    {
        transmute::<usize, FnType>(self.GetProcAddress(hmodule, name))
    }

    fn GetModuleHandleA(&self, name : &str) -> usize
    {
        let namebytes = make_c_str(name);
        let pnamebytes = transmute::<&[u8], usize>(&(*namebytes));
        let tmpGetModuleHandleA = transmute::<usize, fn(usize)->usize>(self.pGetModuleHandleA);
        tmpGetModuleHandleA(pnamebytes)      
    }

    fn initialize(&mut self)
    {
        let stub_GetProcAddress : &[u8] = &[0x48, 0x8d, 0x6c, 0x24, 0x20, 0x48, 0x89, 0xd6, 0x48, 0x89, 0xcf];
        let stub_GetModuleHandleA : &[u8] = &[0x48, 0x8d, 0x6c, 0x24, 0x20, 0x48, 0x89, 0xd6, 0x48, 0x89, 0xcf];

        self.pGetProcAddress = safely_get_fnaddr_from_iat(stub_GetProcAddress, 30);
        self.pGetModuleHandleA = safely_get_fnaddr_from_iat(stub_GetModuleHandleA, 9);

        let tmpGetModuleHandleA = transmute::<usize, fn(usize)->usize>(self.pGetModuleHandleA);

        self.h_thismodule = tmpGetModuleHandleA(0);

        self.h_kernel32 = self.GetModuleHandleA("kernel32");

        self.pLoadLibraryA = self.GetProcAddress(self.h_kernel32, "LoadLibraryA");

        //We need to load Kernel32 again because the Rust stdlib only
        //imported some of its available functions, not all
        self.h_kernel32 = self.LoadLibraryA("kernel32");
    }
}

fn make_c_str(seq : &str) -> Vec<u8>
{
    let a = seq.to_string();
    let mut b = a.into_bytes();
    b.push(0_u8);
    b
}

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
