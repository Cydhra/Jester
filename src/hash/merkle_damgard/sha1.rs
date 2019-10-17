const BLOCK_LENGTH_BYTES: usize = 64;
const BLOCK_LENGTH_DOUBLE_WORDS: usize = BLOCK_LENGTH_BYTES / 4;

#[derive(Debug, Copy, Clone)]
pub struct SHA1Hash {
    message_length: u64,
    pub a: u32,
    pub b: u32,
    pub c: u32,
    pub d: u32,
    pub e: u32,
}

impl SHA1Hash {
    /// Create and return the initial state of an MD5 hash before any data has been digested.
    pub const fn initial() -> SHA1Hash {
        return SHA1Hash { message_length: 0, a: 0x67452301, b: 0xEFCDAB89, c: 0x98BADCFE, d: 0x10325476, e: 0xC3D2E1F0 };
    }

    pub fn round_function(&mut self, input_block: &[u32]) {
        assert_eq!(input_block.len(), BLOCK_LENGTH_DOUBLE_WORDS);

        let mut round_state = *self;

        for i in 0..80 {
//            let (scrambled_data, magic_constant) = match i {
//
//                _ => unreachable!()
//            };

            let temp = panic!();
            round_state.e = round_state.d;
            round_state.d = round_state.c;
            round_state.c = panic!();
            round_state.b = round_state.a;
            round_state.a = temp;
        }

        self.a = self.a.wrapping_add(round_state.a);
        self.b = self.b.wrapping_add(round_state.b);
        self.c = self.c.wrapping_add(round_state.c);
        self.d = self.d.wrapping_add(round_state.d);
        self.e = self.e.wrapping_add(round_state.e);
    }
}