pub mod md5;
pub mod sha1;

/// A hash generated from a merkle damgård construction. Hashes that implement that trait get their digest function
/// implemented automatically by this crate
pub trait MerkleDamagardHash: Sized {
    const INITIAL: Self;
    const BLOCK_SIZE: usize;

    fn digest_message(input: &[u8]) -> Self {
        let mut hash_state = Self::INITIAL;
        let message_blocks_count = input.len() / Self::BLOCK_SIZE;

        // digest full blocks
        for block_index in 0..message_blocks_count {
            hash_state.round_function(&input[block_index * Self::BLOCK_SIZE..(block_index + 1) * Self::BLOCK_SIZE]);
        }

        // pad and digest last block
        hash_state.digest_last_block(input);

        return hash_state;
    }

    fn round_function(&mut self, input_block: &[u8]);

    fn digest_last_block(&mut self, input: &[u8]);
}